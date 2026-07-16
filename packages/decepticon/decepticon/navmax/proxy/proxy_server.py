"""Proxy HTTP/HTTPS MITM — intercepte le trafic web pour inspection et modification.

Architecture :
- HTTP : forward simple avec inspection du contenu
- HTTPS : CONNECT → MITM TLS (certificats générés à la volée)
"""

import asyncio
import contextlib
import re
import ssl
from urllib.parse import urlparse

from decepticon.navmax.core.logging import get_logger

from .certs import generate_host_cert
from .interceptor import FlowAction, InterceptedFlow, Interceptor

logger = get_logger(__name__)


MAX_RECV = 65536  # 64 Ko max par chunk
BUFFER_SIZE = 8192


class ProxyServer:
    """Serveur proxy HTTP/HTTPS asynchrone avec interception."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        interceptor: Interceptor | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.interceptor = interceptor or Interceptor()
        self._server: asyncio.AbstractServer | None = None
        self._flows: list[InterceptedFlow] = []
        self._running: bool = False
        self._stopping: bool = False

    @property
    def running(self) -> bool:
        return self._running

    @property
    def flow_count(self) -> int:
        return len(self._flows)

    @property
    def recent_flows(self) -> list[InterceptedFlow]:
        return list(self._flows[-200:])  # Derniers 200 flux

    async def start(self) -> None:
        """Démarre le serveur proxy."""
        self._server = await asyncio.start_server(
            self._handle_client,
            host=self.host,
            port=self.port,
        )
        self._running = True
        logger.info("proxy_démarré", host=self.host, port=self.port)

    async def stop(self) -> None:
        """Arrête le serveur proxy."""
        self._stopping = True
        self._running = False
        if self._server:
            self._server.close()
            try:
                await asyncio.wait_for(self._server.wait_closed(), timeout=10.0)
                logger.info("proxy_arrêt_gracieux")
            except TimeoutError:
                logger.warning("proxy_arrêt_forcé")
        self._stopping = False

    # ------------------------------------------------------------------
    # Gestion des connexions client
    # ------------------------------------------------------------------
    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Point d'entrée pour chaque connexion TCP entrante."""
        try:
            # Lire la première ligne (méthode HTTP ou CONNECT)
            request_line = await asyncio.wait_for(reader.readline(), timeout=30.0)
            if not request_line:
                writer.close()
                return

            request_text = request_line.decode("utf-8", errors="replace").strip()
            logger.debug("proxy_requête", line=request_text[:100])

            parts = request_text.split(" ")
            if len(parts) < 3:
                writer.close()
                return

            method = parts[0].upper()

            if method == "CONNECT":
                await self._handle_connect(reader, writer, parts[1])
            else:
                await self._handle_http(reader, writer, method, parts[1])
        except TimeoutError:
            pass
        except (ConnectionResetError, OSError) as e:
            logger.debug("connexion_perdue", erreur=str(e))
        except (ssl.SSLError, UnicodeDecodeError) as e:
            logger.exception("erreur_proxy", erreur=str(e))
        finally:
            with contextlib.suppress(OSError):
                writer.close()

    # ------------------------------------------------------------------
    # HTTP (non-TLS) — forward + inspection
    # ------------------------------------------------------------------
    async def _handle_http(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        method: str,
        full_url: str,
    ) -> None:
        """Proxy HTTP classique (non chiffré)."""
        parsed = urlparse(full_url)
        host = parsed.hostname or "unknown"
        port = parsed.port or 80
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        # Lire les headers
        headers, body = await self._read_headers_and_body(client_reader)

        # Flow d'interception
        flow = InterceptedFlow(
            method=method,
            host=host,
            port=port,
            path=path,
            request_headers=headers,
            request_body=body,
        )

        action = await self.interceptor.submit(flow)
        if action == FlowAction.DROP:
            client_writer.write(b"HTTP/1.0 403 Forbidden\r\n\r\nBlocked by NavMAX")
            await client_writer.drain()
            return

        # Forwarder au serveur cible
        try:
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=10.0,
            )
        except (TimeoutError, OSError):
            self._flows.append(flow)
            flow.response_status = 502
            return

        # Reconstruire la requête
        request = f"{method} {path} HTTP/1.0\r\n"
        for k, v in headers.items():
            if k.lower() not in ("proxy-connection", "connection"):
                request += f"{k}: {v}\r\n"
        request += "Connection: close\r\n\r\n"
        remote_writer.write(request.encode() + body)
        await remote_writer.drain()

        # Lire la réponse
        try:
            response_line = await asyncio.wait_for(remote_reader.readline(), timeout=30.0)
            resp_text = response_line.decode("utf-8", errors="replace")
            status_match = re.match(r"HTTP/\d\.\d\s+(\d+)", resp_text)
            flow.response_status = int(status_match.group(1)) if status_match else 0

            resp_headers, resp_body = await self._read_headers_and_body(remote_reader)

            # Reconstruire la réponse complète
            full_response = response_line
            for k, v in resp_headers.items():
                full_response += f"{k}: {v}\r\n".encode()
            full_response += b"\r\n" + resp_body

            client_writer.write(full_response)
            await client_writer.drain()

            flow.response_headers = resp_headers
            flow.response_body = resp_body

        except (TimeoutError, ConnectionResetError, OSError) as e:
            flow.response_status = 502
            logger.debug("erreur_réponse", host=host, erreur=str(e))
        finally:
            remote_writer.close()
            with contextlib.suppress(OSError):
                await remote_writer.wait_closed()

        self._flows.append(flow)

    # ------------------------------------------------------------------
    # HTTPS CONNECT → MITM
    # ------------------------------------------------------------------
    async def _handle_connect(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        target: str,
    ) -> None:
        """Tunnel HTTPS avec interception MITM."""
        host, _colon, port_str = target.partition(":")
        port = int(port_str) if port_str else 443

        # 1. Répondre 200 Connection Established au client
        client_writer.write(b"HTTP/1.0 200 Connection Established\r\n\r\n")
        await client_writer.drain()

        # 2. Générer un certificat pour ce hostname
        try:
            cert_pem, key_pem = generate_host_cert(host)
        except (ValueError, OSError) as e:
            logger.exception("échec_cert", host=host, erreur=str(e))
            return

        # 3. Connexion au serveur réel
        try:
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=10.0,
            )
        except (TimeoutError, OSError) as e:
            logger.debug("connexion_cible_échec", host=host, port=port, erreur=str(e))
            return

        # 4. TLS avec le client (en tant que faux serveur)
        server_ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        server_ssl_context.load_cert_chain(
            certfile=self._temp_pem(cert_pem, "cert"),
            keyfile=self._temp_pem(key_pem, "key"),
        )
        server_ssl_context.check_hostname = False
        server_ssl_context.verify_mode = ssl.CERT_NONE

        try:
            client_ssl_reader, client_ssl_writer = await asyncio.open_connection(
                ssl=server_ssl_context,
                sock=client_writer.get_extra_info("socket"),
                server_side=True,
            )

            # 5. Bidirectional relay avec inspection
            await self._relay_https(
                client_ssl_reader,
                client_ssl_writer,
                remote_reader,
                remote_writer,
                host,
                port,
            )
        except ssl.SSLError as e:
            logger.debug("tls_client_échec", host=host, erreur=str(e))
        except (TimeoutError, ConnectionResetError, OSError) as e:
            logger.exception("relay_échec", host=host, erreur=str(e))
        finally:
            remote_writer.close()
            with contextlib.suppress(OSError):
                await remote_writer.wait_closed()

    async def _relay_https(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        remote_reader: asyncio.StreamReader,
        remote_writer: asyncio.StreamWriter,
        host: str,
        port: int,
    ) -> None:
        """Relais bidirectionnel avec inspection des requêtes HTTP décryptées."""
        # Lire la première requête HTTP du client (maintenant décryptée)
        try:
            request_line = await asyncio.wait_for(client_reader.readline(), timeout=30.0)
            if not request_line:
                return

            req_text = request_line.decode("utf-8", errors="replace").strip()
            parts = req_text.split(" ")
            if len(parts) < 2:
                return

            method = parts[0]
            path = parts[1]

            # Lire headers et body
            headers, body = await self._read_headers_and_body(client_reader)

            # Flow d'interception
            flow = InterceptedFlow(
                method=method,
                host=host,
                port=port,
                path=path,
                request_headers=headers,
                request_body=body,
            )

            action = await self.interceptor.submit(flow)
            if action == FlowAction.DROP:
                client_writer.write(b"HTTP/1.0 403 Forbidden\r\n\r\nBlocked by NavMAX")
                await client_writer.drain()
                return

            # Forwarder au serveur
            request = f"{method} {path} HTTP/1.0\r\n"
            for k, v in headers.items():
                if k.lower() != "proxy-connection":
                    request += f"{k}: {v}\r\n"
            request += "\r\n"
            remote_writer.write(request.encode() + body)
            await remote_writer.drain()

            # Lire la réponse
            response_line = await asyncio.wait_for(remote_reader.readline(), timeout=30.0)
            resp_text = response_line.decode("utf-8", errors="replace")
            status_match = re.match(r"HTTP/\d\.\d\s+(\d+)", resp_text)
            flow.response_status = int(status_match.group(1)) if status_match else 0

            resp_headers, resp_body = await self._read_headers_and_body(remote_reader)

            full_response = response_line
            for k, v in resp_headers.items():
                full_response += f"{k}: {v}\r\n".encode()
            full_response += b"\r\n" + resp_body

            client_writer.write(full_response)
            await client_writer.drain()

            flow.response_headers = resp_headers
            flow.response_body = resp_body
            self._flows.append(flow)

        except (TimeoutError, ConnectionResetError, OSError):
            pass

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    async def _read_headers_and_body(
        reader: asyncio.StreamReader,
    ) -> tuple[dict[str, str], bytes]:
        """Lit les en-têtes HTTP et le body d'un flux."""
        headers: dict[str, str] = {}
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=10.0)
            if line in (b"\r\n", b"\n", b""):
                break
            decoded = line.decode("utf-8", errors="replace").strip()
            if ": " in decoded:
                k, v = decoded.split(": ", 1)
                headers[k] = v

        # Lire le body si Content-Length est présent
        content_length = int(headers.get("Content-Length", 0))
        body = b""
        if content_length > 0 and content_length <= 1_048_576:  # 1 Mo max
            body = await asyncio.wait_for(
                reader.readexactly(content_length),
                timeout=10.0,
            )

        return headers, body

    @staticmethod
    def _temp_pem(content: str, suffix: str) -> str:
        """Écrit un PEM temporaire sur disque et retourne le chemin."""
        import tempfile

        f = tempfile.NamedTemporaryFile(
            mode="w+",
            suffix=f".{suffix}.pem",
            delete=False,
        )
        f.write(content)
        f.flush()
        return f.name
