"""NavMAX Tool Wrappers — LangChain-compatible tools for NavMAX modules.

Each submodule wraps a NavMAX domain as langchain tools.
Heavy dependencies (aiohttp, impacket, ldap3, python-nmap) are
lazy-loaded — importing this package does NOT pull them in.

Import specific tool lists directly from submodules:
    from decepticon.tools.navmax.ad_tools import NAVMAX_AD_TOOLS
    from decepticon.tools.navmax.scanner_tools import NAVMAX_SCANNER_TOOLS
    from decepticon.tools.navmax.exploit_tools import EXPLOIT_TOOLS
    from decepticon.tools.navmax.firewall_tools import FIREWALL_TOOLS
"""
