"""Tests for AD package: Kerberos classification, ADCS, DCSync.

BloodHound ingest tests previously sat here and in
``test_ad_bloodhound_tools.py`` against the legacy ``KnowledgeGraph``-
based API. After ``bloodhound.py`` was rewritten to write directly
through ``KGStore.record_observations`` (new ``engagement`` kwarg,
no ``graph`` parameter), those tests no longer match the signature.
They are reintroduced in a dedicated KGStore-mock-based test PR —
see the BloodHound RFC §4.5.
"""

from __future__ import annotations

from decepticon.tools.ad.adcs import analyze_adcs_templates
from decepticon.tools.ad.kerberos import classify_hashcat_hash, parse_ticket


class TestKerberos:
    def test_classifies_tgs_rc4(self) -> None:
        h = classify_hashcat_hash("$krb5tgs$23$*svc$CORP.LOCAL$http/web*$abc$def")
        assert h.kind == "tgs"
        assert h.etype == "rc4"
        assert h.hashcat_mode == 13100
        assert h.principal == "svc"
        assert h.realm == "CORP.LOCAL"

    def test_classifies_asrep_aes256(self) -> None:
        h = classify_hashcat_hash("$krb5asrep$18$user@DOMAIN:abc$def")
        assert h.kind == "asrep"
        assert h.etype == "aes256"

    def test_unknown_format(self) -> None:
        h = classify_hashcat_hash("not-a-hash")
        assert h.kind == "unknown"

    def test_parse_ticket_kirbi(self) -> None:
        # Long base64-ish blob
        t = parse_ticket("A" * 200)
        assert t.kind == "kirbi"


class TestADCS:
    def test_esc1_fires(self) -> None:
        certipy = {
            "Certificate Templates": {
                "User": {
                    "Certificate Name Flag": ["ENROLLEE_SUPPLIES_SUBJECT"],
                    "Extended Key Usage": ["Client Authentication"],
                    "Enrollment Rights": ["Domain Users"],
                    "Enrollment Flag": [],
                    "Authorized Signatures Required": 0,
                }
            },
            "Certificate Authorities": {},
        }
        findings = analyze_adcs_templates(certipy)
        assert any(f.esc == "ESC1" for f in findings)
        assert any(f.severity == "critical" for f in findings)

    def test_esc6_san_flag(self) -> None:
        certipy = {
            "Certificate Templates": {},
            "Certificate Authorities": {"CA": {"EDITF_ATTRIBUTESUBJECTALTNAME2": True}},
        }
        findings = analyze_adcs_templates(certipy)
        assert any(f.esc == "ESC6" for f in findings)

    def test_esc8_http_web_enrollment(self) -> None:
        certipy = {
            "Certificate Templates": {},
            "Certificate Authorities": {
                "CA": {"Web Enrollment": ["http://ca.corp.local/certsrv/"]}
            },
        }
        findings = analyze_adcs_templates(certipy)
        assert any(f.esc == "ESC8" for f in findings)

    def test_esc4_low_priv_write_dacl(self) -> None:
        certipy = {
            "Certificate Templates": {
                "T": {
                    "Certificate Name Flag": [],
                    "Extended Key Usage": [],
                    "Enrollment Rights": [],
                    "Write Dacl Principals": ["Domain Users"],
                    "Enrollment Flag": [],
                }
            },
            "Certificate Authorities": {},
        }
        findings = analyze_adcs_templates(certipy)
        assert any(f.esc == "ESC4" for f in findings)
