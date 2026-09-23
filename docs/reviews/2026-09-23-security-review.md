# Security-Review Local Privacy Gateway – 2026-09-23

Stand: Commit `e958bc8`, 3285 Tests grün. Fünf parallele Review-Agenten (Vault/Krypto, Erkennungs-Bypass, Proxy/Netzwerk, Sharp Edges/Defaults, Test-Abdeckung) plus Bandit. Alle als „reproduziert" markierten Befunde wurden vom Hauptagenten gegen den Code oder per Skript mit synthetischen Werten gegengeprüft. Kein Code geändert.

Konfidenz-Skala: **sicher** = reproduziert oder eindeutig im Code, **wahrscheinlich** = aus Code abgeleitet, nicht ausgeführt, **unsicher** = Hypothese.

## Kritisch

### 1. Proxy fail-open: nicht parsebarer Body geht im Klartext nach oben
`privacy_gateway_proxy/server.py:86-90`, `:264-270`. `_parse_json` gibt bei Decode-Fehler `None` zurück, dann läuft der Original-Body per `_passthrough` unverändert an Anthropic. Reproduziert mit Mock-Upstream: ungültiges JSON, JSON-Liste, `Content-Encoding: gzip`, Pfad `/v1/messages/` (Trailing Slash), `/v1/messages/batches`. Status 200, kein Audit-Eintrag. Claude Code sendet heute keinen dieser Fälle, andere SDK-Clients aber möglicherweise. Konfidenz: sicher.
Fix: POST auf `/v1/messages*` mit nicht-dict Body oder `Content-Encoding` mit 422 ablehnen; Passthrough nur für GET und explizit freigegebene Pfade; jeden Passthrough auditieren.

### 2. Keine Unicode-Normalisierung: Format-Zeichen umgehen jede Regex
`privacy_gateway/detect/__init__.py:42-59`. Text geht roh in alle Stages, NFKC/casefold nur auf Entity-Schlüssel. Reproduziert, jeweils Output == Input, kein LeakageError:
- IBAN mit NBSP (`DE89 3704 …` aus Word/Web), mit Soft-Hyphen (aus PDF), mit Zero-Width-Space.
- Telefon mit NBSP: Vorwahl bleibt stehen, Rest wird maskiert.
- Name in NFD (macOS-typisch): `Frau <PERSON_FEMALE_001>̈ller` – Namensrest im Klartext.
Konfidenz: sicher.
Fix: Normalisierungsstufe vor der Pipeline (NFKC, Entfernen von `Cf`-Zeichen und U+00AD) mit Offset-Map zurück auf den Originaltext, damit Spans gültig bleiben.

### 3. Restore-Orakel: Session-Key client-kontrolliert, kein Auth-/Origin-Check
`privacy_gateway_proxy/session_key.py:14-27`, `server.py:54-75`, `transform.py:70-83`. Jeder Prozess, der 127.0.0.1:8787 erreicht, schickt `metadata.user_id: session_<uuid>` oder Header `X-PGW-Session` plus einen eigenen API-Key und lässt das Modell Tokens echoen; der Proxy restauriert mit dem Vault dieser Session und liefert Klartext. Fallback-Key `default` ist ratbar. Reproduziert mit TestClient. Betroffen: andere lokale Accounts, Webseiten per DNS-Rebinding. Session-UUIDs liegen als Dateinamen in `~/.claude/projects/`. Konfidenz: sicher.
Fix: pro Start ein zufälliges Proxy-Token (Datei 0600) in einem Pflicht-Header; `Host`/`Origin` auf `127.0.0.1`/`localhost` prüfen; `default`-Fallback durch pro-Prozess-Zufallskey ersetzen; Nicht-Loopback-Bind ohne Token ablehnen.

## Hoch

### 4. Leak-Check ist keine unabhängige Linie, Residual-Check in `<…>` abgeschaltet
`privacy_gateway/leakage.py:14`, `:140-145`. Der Check ruft dieselbe Pipeline auf dem Output auf plus Known-Value-Suche. Was im Input nicht erkannt wird, wird im Output nicht erkannt. Zusätzlich überspringt `_ANY_TOKEN = <[^<>\n]{1,80}>` jedes Finding in beliebigen spitzen Klammern: `<DE89370400440532013000>`, `From: <anna@example.com>`, `<AKIA…>` passieren den Residual-Scan. Für `redact`-Klassen ist der Residual-Scan die einzige Kontrolle. Konfidenz: sicher (Unit-Ebene), End-to-End-Auslösung unsicher.
Fix: nur Spans überspringen, die exakt auf `_NUMBERED_TOKEN` oder `<CLASS_REDACTED>` passen.

### 5. Personennamen nur bei exakt einem ASCII-Leerzeichen
`privacy_gateway/detect/context.py:360-363` (`text[end] != " "`). Unverändert durchgereicht: `Anna  Müller`, `Anna\tMüller`, `| Anna | Müller |`, `Müller, Anna` (CSV/Excel-Form), `anna müller`, `Müller` allein ohne Anrede, `Anna Müller-Schmidt` → `<PERSON_001>-Schmidt`. Ohne Anrede auch `Anna\nMüller` (mit Anrede greift die Salutation-Regel). Konfidenz: sicher.
Fix: Trennung als `\s+`, zweites Muster `Nachname, Vorname`, Bindestrich-Nachnamen im Paar-Muster.

### 6. Session kennt nur Surface-Forms, Namensteile im Folge-Turn gehen im Klartext raus
`privacy_gateway/api.py:229-238`, `detect/session.py:40-54`. Turn 1 `Frau Anna Müller` → Token; Turn 2 `Müller bat um Rückruf` → Klartext. Im selben Dokument greift `correlate()`, über Turns nicht. Das ist der Normalfall in der Proxy-Nutzung. Zusatz: dieselbe IBAN in anderer Schreibweise bekommt einen zweiten Token. Konfidenz: sicher. (Bereits als „bekannter Rest-Fall" dokumentiert.)
Fix: Namensteile von `PERSON_FULL_NAME` als eigene Known-Einträge mit derselben Token-Zuordnung; ziffernhaltige Klassen ziffern-normalisiert matchen.

### 7. Fehlende Secret-Muster, darunter Anthropic-Keys
`privacy_gateway/data/default_config.yaml:443-587`, `detect/structured.py:25`, `detect/patterns.py:60`. Nicht erkannt: `sk-ant-api03-…`, `sk-proj-…`, `sk_live_…`, `-----BEGIN PGP PRIVATE KEY BLOCK-----` (PEM-Regex verlangt `PRIVATE KEY-----`), `AZURE_CLIENT_SECRET=…` (Kontextwort-Lookaround `(?<!\w)` kann bei `_`-Nachbarn nie zutreffen). Konfidenz: sicher.
Fix: Muster ergänzen, PGP-Block-Form zulassen, Kontext-Lookaround auf `[^A-Za-z0-9]` lockern.

### 8. Debug-Dump schreibt bei Leak-Fail den Original-Request im Klartext
`privacy_gateway_proxy/server.py:117`, `:252-261`, `cli.py:35-41`. Genau im Fail-closed-Fall entsteht eine persistente Klartext-Kopie. Verzeichnis wird per `mkdir` ohne `mode=0o700` angelegt (Datei 0600, aber kein `O_EXCL`/`O_NOFOLLOW`). `install-launchd` übernimmt `PGW_PROXY_DEBUG_DIR` still ins Plist. Konfidenz: sicher.
Fix: Original-Dump nur hinter separatem Schalter, `mkdir(mode=0o700)`, `O_EXCL|O_NOFOLLOW`, übernommene Variablen beim Install ausgeben, Auto-Löschung.

### 9. `purge()` löscht Zeilen, nicht Bytes
`privacy_gateway/vault.py:101-107`, `:252-257`. Kein `PRAGMA secure_delete`, kein `VACUUM`. Nach Purge stehen Ciphertexte, Tokens und Session-ID weiter in `vault.db`/WAL; mit `vault.key` daneben vollständig rekonstruierbar. Widerspricht Spec §9. Test prüft nur `count(*)`. Konfidenz: sicher (empirisch).
Fix: `PRAGMA secure_delete=ON` beim Connect, `VACUUM` nach Purge, Test auf Dateibytes.

### 10. Tokens ab Nummer 1000 sind für Restore und Leak-Check unsichtbar
`privacy_gateway/restore.py:13-17`, `leakage.py:15` (`_\d{3}`) vs. `pseudonymize.py:64` (`:03d`, ab 1000 vierstellig). `<IBAN_1000>` bleibt in strict ohne Fehler und in lenient ohne `unknown`-Eintrag stehen; der Unknown-Token-Check sieht es ebenfalls nicht. Lange Proxy-Konversationen erreichen das. Konfidenz: sicher.
Fix: `_\d{3,}` in beiden Regexen.

### 11. `RestoreError` im Proxy ungefangen: strict-Default → 500 bzw. abgerissener Stream
`privacy_gateway_proxy/server.py:155`, `:168`; kein `except RestoreError` im Paket. Jeder String der Form `<[A-Z][A-Z_]*_\d{3}>` in der Modellantwort (zitiert oder halluziniert) reißt die Antwort ab. Reproduziert. Mit `restore.mode: lenient` nicht betroffen. Konfidenz: sicher.
Fix: im Proxy lenient restaurieren oder `RestoreError` fangen und Rohantwort mit Audit-Event durchreichen.

### 12. `min_confidence` ohne Bereichsprüfung schaltet Erkennung und Leak-Check ab
`privacy_gateway/config.py:331-333`. `min_confidence: 1.5` wird akzeptiert; höchste Confidence ist 1.0, Regex 0.9–0.99. Text geht komplett im Klartext raus mit `leakage: ok`. Konfidenz: sicher.
Fix: `0 <= x <= 1` erzwingen, Werte über 0.9 mit Warnung.

## Mittel

13. **Token-Literal im Eingabetext kollidiert mit echtem Token.** `pseudonymize.py:52-64`, `restore.py:41-46`. `Beispiel <IBAN_001> und IBAN DE89…` → beide `<IBAN_001>`, Restore setzt an beiden Stellen die echte IBAN ein. Allein stehend greift der Unknown-Token-Check. Placeholder-Notice fördert das Muster. Reproduziert. Fix: vorhandene Token-Literale aus dem Counter-Raum ausnehmen.
14. **Lenient-Restore matcht klammerlose Bezeichner.** `restore.py:14-17`: `person_female_001`, `report_001`, `user_001` werden ersetzt, wenn die Session ein passendes Token kennt. Reproduziert. Betrifft jede Installation mit `restore.mode: lenient`. Fix: Klammern oder Quotes als Mindestbedingung.
15. **Token-Zähler-Race bei zwei Prozessen auf einer Session.** `api.py:155` lädt Counter einmal in den RAM, `vault.py:207` `INSERT OR REPLACE`: zwei Prozesse vergeben `<PERSON_003>` für verschiedene Werte, der zweite überschreibt still. Konfidenz: wahrscheinlich. Fix: `INSERT` ohne `REPLACE` (Konflikt → Fehler) oder Counter in DB-Transaktion.
16. **Klartext in Rückgabeobjekten.** `DetectionReport.entities[].canonical_norm` trägt den normalisierten Originalwert (`correlation.py:78-82`, `model.py:82`), entgegen README; `VaultEntry.value`/`surface_forms` und `RestoreResult.text` ohne `repr=False` (`model.py:130-137`). Fix: Hash statt Wert, `repr=False`.
17. **Dateirechte.** `vault.db`/`-wal`/`-shm` 0644 (`vault.py:101`), Schutz nur über Elternverzeichnis, das nur bei Neuanlage auf 0700 gesetzt wird; `audit.jsonl` bestehende Rechte werden nicht korrigiert (`audit.py:102`, verifiziert 0644 bleibt); `pgw restore --out` und `--session-file` schreiben 0644 (`cli.py:31`, `:73`); Zwischenverzeichnisse bei `mkdir(parents=True)` umask-offen; Key-Datei folgt Symlinks beim Laden. Fix: `os.chmod` nach Connect, `O_NOFOLLOW`, `mkdir(mode=0o700)`.
18. **Nicht transformierte Blocktypen.** `transform.py:132-159`: `document` (auch `source.type: text`), `image`, `server_tool_use`, `mcp_tool_use`, `search_result` u. a. gehen unverändert raus, ohne Warnung. Bilder/Tools sind dokumentiert, `document` nicht. Fix: `document`-Textquellen aufnehmen, unbekannte Blocktypen mit Textinhalt fail-closed ablehnen.
19. **Metadaten-Leaks im Vault.** `doc_sha256` ungesalzener Hash des ganzen Dokuments in DB und Audit (`api.py:77`, bei kurzen Eingaben wörterbuchangreifbar); Ciphertext-Länge = Wertlänge + 16 (`vault.py:288`); `attributes_json` mit Gender im Klartext (`vault.py:42`); AAD deckt `data_class`/`attributes` nicht. Fix: HMAC mit Vault-Key, Padding auf 32-Byte-Vielfache, Attribute verschlüsseln.
20. **`resolve_overlaps()` verwirft Verlierer ganz und prüft nur `kept[-1]`.** `spans.py:20-38`. Teilüberlappung lässt Teilwerte offen; eine Kette kann ein nicht überlappendes Finding löschen. Mit Default-Config keine natürliche Auslösung gefunden, wird durch User-Regexe scharf. Fix: Verlierer auf Restspans kürzen, gegen alle überlappenden Einträge prüfen.
21. **Teil-Redaktion.** Passwörter mit Leerzeichen: `Passwort: geheim 123` → `<PASSWORD_REDACTED> 123` (`default_config.yaml:459-462`). JSON-`\uXXXX`-Escapes werden nicht dekodiert, obwohl Tool-Results als JSON-Strings durchlaufen. Fix: gequoteten Rest bzw. Zeilenrest nehmen; Escapes mit Offset-Map auflösen.
22. **Tote und stille Schalter.** `DataClass.restore` wird nirgends ausgewertet (`classes.py:87`; funktioniert nur, weil `redact` nichts speichert). Fehlender Vault-Key wird still neu erzeugt (`vault.py:74-91`), alte Sessions dann `decryption failed`. `config_hash` bei Session-Wiederverwendung nicht geprüft (`vault.py:136-148`). Klassennamen-Tippfehler mit `category` erzeugt still eine leere Klasse (`config.py:192`). `enabled: "false"` (String) ist wahr (`config.py:253`). `PGW_AUDIT_LOG=""` schaltet Audit still ab. Fix: Feld entfernen oder auswerten, Key-Erzeugung explizit, Bool-Typ erzwingen, leere Angaben als Fehler.
23. **Proxy-Kleinigkeiten.** `PGW_PROXY_UPSTREAM` akzeptiert `http://` und beliebige Hosts inkl. Auth-Header-Weiterleitung (`settings.py:50-52`); Streaming nutzt `aiter_raw()` ohne Content-Decoding, Non-Streaming `aread()` mit (`server.py:226-232` vs. `:162`); Audit meldet `leakage: ok` bei Upstream-Fehler (`server.py:131`); Body-Größe unbegrenzt; Hop-by-Hop-Liste unvollständig; geschwächte Settings (`transform_system=0`, `min_confidence`, deaktivierte Klassen) erscheinen weder in `status` noch beim Start.

## Test-Lücken

- `tests/unit/test_audit.py::test_only_passed_values_appear_in_the_log` ist tautologisch (prüft nur einen nie übergebenen Sentinel). Kein Test durchsucht das Audit-Log oder `pgw validate`/`--report` nach Originalwerten.
- `tests/integration/test_no_network.py` ist AST-basiert, aber umgehbar: `importlib.import_module`, `__import__`, `subprocess`, `os.system`, `ctypes`, `asyncio` und `from privacy_gateway_proxy import …` werden nicht gefangen. Heute ist das Paket sauber (grep: null Treffer), der Test ist nur schwächer als er wirkt. Die CLAUDE.md-Regel „nichts aus `privacy_gateway_proxy` importieren" ist ungetestet.
- Kein Test, dass ein redigiertes Secret nicht in `vault.db*` liegt; kein Test auf Dateibytes nach `purge()`.
- Golden-Fixtures prüfen nur die Pseudonymisierungs-Richtung; Round-Trip byte-identisch nur für 2 von 5 Fixtures, die anderen gegen `expected_restore()`, das dieselbe Scan-Logik nutzt (zirkulär).
- `-FAILED-original`-Dump ohne Modus-Test; Debug-Verzeichnis-Modus ungetestet.
- Keine Property-/Fuzz-Tests (hypothesis fehlt). Größter Nutzen: Unicode-Round-Trip, Leak-Check-Projektionen, Streaming über beliebige Chunk-Listen.
- `tests/integration/test_cli.py::run` erbt die komplette Shell-Env; ein global gesetztes `PGW_CONFIG`/`PGW_RESTORE_MODE` schlägt durch.
- Holdback `_HOLDBACK` begrenzt `<`-Fragmente auf 48 Zeichen; eine User-Klasse mit über 40 Zeichen Name bricht vermutlich das Streaming.

## Bandit

7 Low-Befunde, 0 Medium/High: 5× „hardcoded password" auf Wörterbuch-Schlüssel wie `"pwd": "PASSWORD"` (Fehlalarme), 2× `subprocess` für `launchctl` (Argumentliste, kein Shell). Nichts davon relevant.

## Geprüft und sauber

- AES-256-GCM korrekt: 12-Byte-Zufalls-Nonce pro Verschlüsselung, 32-Byte-Key aus `secrets`, AAD bindet `session_id|token[|ordinal]`, Vertausch-Test vorhanden.
- Kein Wert-Index in der DB: „gleicher Wert → gleicher Token" entsteht rein im Speicher aus entschlüsselten Einträgen. Kein Wörterbuchangriff über einen Hash-Index.
- Key-Datei: `O_CREAT|O_EXCL` 0600, Ablehnung bei Gruppen-/Welt-Bits und falscher Länge.
- Fail-closed in `api.py`: beide `except`-Zweige purgen/rollen zurück und re-raisen; Result-Cache wird erst nach erfolgreichem Leak-Check befüllt; Rollback stellt Vault, `_entries`, `_known_cache` und Counter wieder her.
- Exception-Messages und Audit-Log enthalten keine Werte; Leak-Antwort des Proxys nur Klassennamen und Anzahl.
- Auth-Header werden nur durchgereicht, Proxy hält keine Credentials; TLS-Verifikation aktiv; keine Redirects; Timeouts gesetzt; alle SQL-Statements parametrisiert; kein Path-Traversal über Session-Key in Debug-Dateinamen.
- `thinking`/`signature`/`tools`/`metadata`/`cache_control` bleiben unangetastet (Tests mit kanonischem Vergleich).
- Streaming-Holdback: kein Token-Bruch über Delta-Grenzen (alle 2670 Byte-Offsets getestet, zusätzlich byteweise und 3-Wege-Splits), kein Verlust am Stream-Ende, `input_json_delta` wird auf der geparsten Struktur restauriert und korrekt escaped.
- `correlate()` entfernt keine Findings und verschiebt keine Spans; Gender nur aus Anrede; Validatoren lassen keine gültigen Werte fallen; Plist-XML-Escaping korrekt, keine Secrets im Plist.

## Empfohlene Reihenfolge

1. Proxy fail-open schließen (1) und Original-Dump entschärfen (8): kleine Änderungen in `server.py`, wirken sofort auf jede laufende Installation.
2. Regex-Fixes mit sofortiger Wirkung: `_\d{3,}` (10), `_ANY_TOKEN` einengen (4), `min_confidence`-Bereich (12), `secure_delete`+`VACUUM` (9), `RestoreError` fangen (11).
3. Normalisierungsstufe mit Offset-Map (2): größter Hebel, betrifft jede Klasse, braucht einen eigenen Plan.
4. Namen: `\s+`, `Nachname, Vorname`, Doppelnamen (5) und Namensteile im Session-Known (6).
5. Secret-Muster nachziehen, beginnend mit `sk-ant-` (7).
6. Proxy-Auth-Token und Origin-Check (3): Designentscheidung, da Claude Code den Header setzen muss (Env `ANTHROPIC_CUSTOM_HEADERS` wäre ein Weg).
7. Test-Lücken schließen, insbesondere Audit-Wertsuche, `test_no_network`, Purge-Bytes, Golden-Restore.

## Bewusst nicht als Befund gewertet

- Bilder, `tools` und `metadata` unverändert: dokumentierte Designentscheidung.
- `PGW_PROXY_TRANSFORM_SYSTEM=0`: bewusst wegen OAuth-429 gesetzt, in der README dokumentiert.
- Restaurierte Werte in `tool_use.input` werden lokal ausgeführt: gewollt, aber ein Prompt-Injection-Risiko (Text in gelesener Datei lässt das Modell `<IBAN_001>` in ein `curl` schreiben, lokal läuft der echte Wert). Gehört in die „Known limits" der README.
