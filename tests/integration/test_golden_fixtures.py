"""Golden output of the bundled fixtures; guards optimizations against drift."""

from __future__ import annotations

import re
from pathlib import Path

from privacy_gateway import Gateway

REDACTED = re.compile(r"<[A-Z][A-Z_]*_REDACTED>")

GOLDEN: dict[str, str] = {
    "customer_letter_de.txt": """\
<ORGANIZATION_NAME_001>
Kundenbetreuung
<ADDRESS_001>

Düsseldorf, 12.03.2026

Sehr geehrte Frau <PERSON_FEMALE_001>,

vielen Dank für Ihre Nachricht von gestern Abend.

Ihre Kundennummer: <CUSTOMER_ID_001>
Ihr Konto <ACCOUNT_ID_001> bleibt unverändert bestehen.

Die Gutschrift über 240,00 EUR haben wir auf die IBAN <IBAN_001>
angewiesen. Die Buchung erscheint in zwei Werktagen.

Sie erreichen uns telefonisch unter Tel. <PHONE_001> oder per Mail an
<EMAIL_001>.

Für unsere Unterlagen: geboren am <DATE_OF_BIRTH_001> in <PLACE_OF_BIRTH_001>.

Bei Fragen zur Anlage wenden Sie sich bitte an Herrn <ACADEMIC_TITLE_001> <PERSON_MALE_002>.

Mit freundlichen Grüßen

<PERSON_FEMALE_001>
""",
    "http_request_dump.txt": """\
POST /api/v2/payments HTTP/1.1
Host: <FQDN_001>
User-Agent: checkout-client/2.4.1
Authorization: Bearer <ACCESS_TOKEN_REDACTED>
<COOKIE_001>
<CUSTOM_HEADER_001>
Content-Type: application/json
Content-Length: 268

{
  "reference": "<GENERIC_ID_001>",
  "email": "<EMAIL_002>",
  "amount": "1249.00",
  "password": "<PASSWORD_REDACTED>",
  "api_key": "<API_KEY_REDACTED>",
  "callback": "<URL_001>"
}

HTTP/1.1 202 Accepted
""",
    "incident_ticket_en.txt": """\
Outage summary - checkout platform

Ticket: <TICKET_ID_001>
Incident: <INCIDENT_ID_001>
Severity: high

Reported by Mr <PERSON_MALE_003> after the nightly deployment.

Impact: card payments failed for eighteen minutes.

Affected host: <FQDN_002>
Internal address <PRIVATE_IP_001> forwarded traffic to <PUBLIC_IP_001>.

The failing call was
<URL_002>
and every retry returned HTTP 502.

Root cause: a rotated credential was still cached by the worker pool.
The old access key <AWS_ACCESS_KEY_REDACTED> had been revoked that morning.
The cached bearer credential was
<JWT_REDACTED>

Mitigation: the worker pool was restarted and the cache was flushed.
Follow-up owner: Mr <PERSON_MALE_003>.
""",
    "invoice_de.txt": """\
Nordlicht Handelsgesellschaft mbH
<ADDRESS_002>

Rechnungsnummer: <INVOICE_ID_001>
Rechnungsdatum: 02.02.2026
Kundennummer: <CUSTOMER_ID_002>

Leistungszeitraum: Januar 2026
Nettobetrag: 2.480,00 EUR
Umsatzsteuer 19 Prozent: 471,20 EUR
Gesamtbetrag: 2.951,20 EUR

USt-IdNr.: <TAX_ID_001>
Bankverbindung IBAN: <IBAN_002>
BIC: <BIC_001>

Verwendungszweck: <PAYMENT_REFERENCE_001>

Alternativ per Karte: <CREDIT_CARD_001>, gültig bis <CARD_EXPIRY_001>.
Zahlungsziel: 14 Tage ohne Abzug.
Rückfragen beantwortet unsere Buchhaltung werktags von neun bis siebzehn Uhr.
""",
    "k8s_log_excerpt.txt": """\
2026-03-04T08:12:44Z level=info msg="reconcile started"
namespace: <NAMESPACE_001>
pod: <POD_NAME_001>
container: <CONTAINER_NAME_001>
cluster: <CLUSTER_NAME_001>

2026-03-04T08:12:45Z level=info msg="connecting"
The worker used <DATABASE_CONNECTION_STRING_REDACTED>
and replayed two hundred pending events.

---
apiVersion: v1
kind: Secret
metadata:
  name: payments-db-credentials
  namespace: <NAMESPACE_001>
type: Opaque
data:
  db-password: <KUBERNETES_SECRET_REDACTED>
  api-token: <KUBERNETES_SECRET_REDACTED>
---

2026-03-04T08:13:02Z level=warn msg="retry budget exhausted"
2026-03-04T08:13:07Z level=info msg="reconcile finished"
""",
}


def test_fixtures_pseudonymize_to_the_recorded_output(
    gateway: Gateway, fixtures_dir: Path
) -> None:
    names = sorted(GOLDEN)
    texts = [(fixtures_dir / name).read_text(encoding='utf-8') for name in names]
    session = gateway.session("golden")
    assert session.pseudonymize_many(texts) == [GOLDEN[name] for name in names]


def assert_original_except_redactions(restored: str, original: str) -> None:
    """The restored text is the original with every redacted value replaced by its marker."""
    segments = REDACTED.split(restored)
    cursor = 0
    for index, segment in enumerate(segments):
        found = original.find(segment, cursor)
        assert found >= 0, f"segment not found in the original: {segment[:40]!r}"
        assert index > 0 or found == 0, "the restored text must start at the original start"
        cursor = found + len(segment)
    assert not segments[-1] or cursor == len(original), "must reach the original end"


def test_golden_output_restores_to_the_original(gateway: Gateway, fixtures_dir: Path) -> None:
    names = sorted(GOLDEN)
    originals = [(fixtures_dir / name).read_text(encoding="utf-8") for name in names]
    session = gateway.session("golden")
    session.pseudonymize_many(originals)
    for name, original in zip(names, originals, strict=True):
        restored = gateway.restore(GOLDEN[name], session.session_id, mode="strict").text
        if REDACTED.search(GOLDEN[name]):
            assert_original_except_redactions(restored, original)
        else:
            assert restored == original, name
