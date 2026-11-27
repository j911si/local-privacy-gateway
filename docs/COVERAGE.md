# Coverage register

What the default rules of version 0.2.0 detect, sorted by how much evidence there is. The
configuration defines 141 entity classes. Most of them are names for things a rule, a label or
your own dictionary can mark; they are not 141 data types the gateway finds reliably.

This register is written by hand for 0.2.0 from the rule set and from a probe with synthetic
example values (2026-11-27). Generating it from recognizer metadata and test results is planned,
see [ROADMAP.md](../ROADMAP.md). No row here is a statement about legal compliance in any
country.

## Languages

All rules run on every text. Nothing is switched off because a text looks like another language.
Labels, salutations, address grammar, context words and the bundled name, city and medical lists
exist in German and English only. The `languages` setting in the configuration is read but has
no effect in 0.2.0.

## 1. Implemented and tested

A format rule plus a validator or a fixed shape, covered by unit tests with positive and negative
cases.

| Data type | Scope | Check |
|---|---|---|
| IBAN | every IBAN country | MOD-97 |
| Payment card number | global | Luhn |
| BIC | global | shape and country code |
| E-mail address | global | structure |
| IPv4, IPv6 | global | `ipaddress`; public and private addresses get separate classes |
| MAC address | global | shape |
| VIN | global | check digit |
| GPS coordinates | global | decimal pair |
| Phone number with country code (`+`, `00`, `(+..)`) | country codes in a built-in table | country code and national length |
| Steuer-ID | Germany | check digit |
| Sozialversicherungsnummer | Germany | check digit |
| Social Security number | United States | shape rules, no registry check |
| Cloud and provider keys (AWS, GitHub, GitLab, Stripe, OpenAI, Anthropic, Slack, Google), JWT, PEM private keys, connection strings | global | fixed prefixes and structure |
| Passwords, PIN, TAN, OTP, API secrets, CSRF tokens behind a label | global formats (`key=value`, JSON, YAML, headers); labels in German and English | label plus value shape; redacted, never stored |
| User name in a home directory path | macOS, Linux, Windows paths | path shape |

## 2. Implemented but not sufficiently validated

Rules exist and have tests, but the checks are weak or the tests cover few real-world variants.
Expect misses and some false positives.

| Data type | Scope | Why it is in this group |
|---|---|---|
| EU VAT number | EU country codes | shape and country code only, no check digit |
| National phone number without country code | German formats | needs a context word such as `Tel.` |
| Postal code | 4 and 5 digits | only behind `PLZ`, `Postleitzahl` or `zip` |
| Street address | German and English street words | grammar rules; `12 Rue de la Paix` is not found |
| Vehicle registration | German format | only behind a label such as `Kennzeichen` |
| Date of birth | German and English markers | only in front of `geboren`, `born`, `Geburtsdatum` and similar, or before a health statement |
| Person names | German and English | with a salutation (`Herr`, `Frau`, `Mr`, `Ms`), behind a person label with a known first name, or as a full name from the bundled lists |
| Health information | German and English term list | 178 terms |
| Organization names | capitalized words in front of a legal form | German, English and a few other forms (`GmbH`, `AG`, `Ltd`, `Inc.`, `S.A.`, `B.V.`, `Oy`, `AB`) |

## 3. Context-only detection

No format check. The value is replaced when it follows a label word from the configuration, in
German or English. An unlabelled value is not found, and a label in another language is not known.

`PASSPORT_ID`, `NATIONAL_ID`, `DRIVER_LICENSE_ID`, `BANK_ACCOUNT`, `CUSTOMER_ID`, `EMPLOYEE_ID`,
`ACCOUNT_ID`, `USER_ID`, `CONTRACT_ID`, `INSURANCE_ID`, `TRANSACTION_ID`, `PAYMENT_REFERENCE`,
`INVOICE_ID`, ticket and case numbers, and infrastructure names (cluster, namespace, pod,
container, tenant, subscription, project, environment, gateway, load balancer, repository, branch).
Example: `Passport: C01X00T47` is replaced, the same number without the label is not.

## 4. Configured entity classes without dedicated detection

These classes exist so that you can fill them with your own dictionary entries or patterns. The
default rules do not produce them: `PERSON_ALIAS`, `TITLE`, `DEBIT_CARD`, `CARDHOLDER`,
`BIOMETRIC_INFORMATION`, `GENETIC_INFORMATION`, `API_URL`, `API_ENDPOINT`.

## 5. Planned coverage

Not implemented. Order and scope are in [ROADMAP.md](../ROADMAP.md): national ID, tax and
social-security numbers of other countries with their check digits, phone validation from
libphonenumber metadata, address and label vocabulary for more languages, and name lists beyond
German and English.

## 6. Unsupported

Probed on 2026-11-27 with published example values; none of these was replaced:

- national identifiers without a matching rule, for example French NIR, Spanish DNI, Italian
  codice fiscale, Dutch BSN, UK National Insurance number, Polish PESEL, Swiss AHV number,
  Brazilian CPF, Indian Aadhaar;
- names after salutations in other languages (`Madame`, `Señor`) and names that are in no list and
  have no salutation or label;
- a date on its own, with or without a year (`14.03.2025`, `14.03.`, `2025-03-14`) when no birth
  marker is near;
- addresses that do not follow German or English street grammar;
- anything in images, PDFs or other binary content.

Everything the rules do not describe is passed through. See
[Known limits](../README.md#known-limits).
