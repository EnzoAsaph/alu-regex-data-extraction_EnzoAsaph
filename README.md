# alu-regex-data-extraction_EnzoAsaph

**Data Extraction & Secure Validation — ALU Hackathon 2026**  
Author: EnzoAsaph  
Language: Python 3.8+

---

## Overview

This program reads a raw text file that simulates a response from a student-services API.  
It extracts six types of structured data using regular expressions, detects and quarantines
hostile or injection-like input, and writes a structured JSON report.

Security is a first-class concern throughout: every line of input is treated as untrusted,
credit card numbers are never written in plain text, and email addresses are partially
redacted in output to limit unnecessary PII exposure.

---

## File Structure

```
alu-regex-data-extraction_EnzoAsaph/
├── input/
│   └── raw-text.txt        # Raw API data (realistic, messy, production-style)
├── src/
│   └── main.py             # All regex patterns, extraction logic, and security checks
├── output/
│   └── sample-output.json  # Generated JSON report (created by running the program)
└── README.md               # This file
```

---

## How to Run

**Requirements:** Python 3.8 or higher. No third-party libraries required.

```bash
# From the project root directory:
python src/main.py
```

The program:
1. Reads `input/raw-text.txt`
2. Prints security warnings to stderr for any quarantined lines
3. Writes `output/sample-output.json`
4. Prints an extraction summary to the console

---

## Data Types Extracted

| # | Type | Pattern highlights |
|---|------|-------------------|
| 1 | **Email addresses** | RFC 5321 local-part + domain; bounded quantifiers |
| 2 | **Credit card numbers** | Visa, Mastercard, Amex, Discover; optional space/hyphen separators |
| 3 | **URLs** | `http`/`https` only; SSRF-risky targets flagged separately |
| 4 | **Phone numbers** | US, East Africa (+250–256), other intl. (+XX), local (0XX…) |
| 5 | **Currency amounts** | Symbol-prefix ($, €, £), code-prefix (RWF, KES, USD…), amount-suffix |
| 6 | **Hashtags** | Must begin with a letter; alphanumeric + underscore body; max 100 chars |

### ALU-Specific Email Validation

The program classifies extracted emails into three ALU categories:

| Category | Domain |
|----------|--------|
| ALU Official | `@alueducation.com` |
| ALU Alumni | `@alumni.alueducation.com` |
| ALU SI | `@si.alueducation.com` |

The subdomain patterns are carefully separated so that `@alumni.alueducation.com`
is **not** counted as an `@alueducation.com` address.

---

## Regex Patterns Explained

### 1. Email — `EMAIL_RE`

```python
r"\b[a-zA-Z0-9](?:[a-zA-Z0-9._%+\-]{0,62}[a-zA-Z0-9])?@"
r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,10}\b"
```

- Local part: must start and end with alphanumeric; middle allows `._%+-`; max 64 chars.
- Domain: one or more labels of up to 63 chars each, plus a 2–10 char TLD.
- **All quantifiers are bounded** (`{0,62}`, `{0,61}`) to prevent ReDoS.

### 2. Credit Card — `CREDIT_CARD_RE`

```
Visa       : 4XXX [-] XXXX [-] XXXX [-] XXXX   (16 digits, prefix 4)
Mastercard : 5[1-5]XX [-] XXXX [-] XXXX [-] XXXX (16 digits, prefix 51–55)
Amex       : 3[47]XX [-] XXXXXX [-] XXXXX        (15 digits, prefix 34/37)
Discover   : 6011/65XX [-] XXXX [-] XXXX [-] XXXX (16 digits)
```

`[-\s]?` between groups allows an optional single space or hyphen as separator.

### 3. URL — `URL_RE`

```python
r"https?://(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}(?::\d{1,5})?(?:/[^\s<>\"']{0,2000})?"
```

- Scheme is restricted to `http`/`https`, which rejects `javascript:` and `data:` URIs.
- Path character class `[^\s<>"']` prevents over-matching into surrounding HTML.
- Path length capped at 2 000 characters.

### 4. Phone — `PHONE_RE`

Three sub-patterns handle distinct format families:

```
US/Canada  : \+?1[-. ]?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}
East Africa: \+?25[0-6][-. ]?\d{3}[-. ]?\d{3}[-. ]?\d{3}
Other intl.: \+[2-9]\d{1,2}[-. ]\d{2,4}[-. ]\d{4,6}
Local (0XX): 0\d{2,3}[-. ]?\d{3}[-. ]?\d{3,4}
```

Requiring a leading `+` for the "other international" branch reduces false positives
against dates and serial numbers.

### 5. Currency — `CURRENCY_RE`

Three surface forms are handled:

```
Code-prefix  : RWF 2,500,000   USD 3,200.00
Symbol-prefix: $5,000.00       €150.00      £99.99
Amount-suffix: 85,000 KES      50,000 RWF
```

Codes: USD, EUR, GBP, RWF, KES, UGX, TZS, NGN, ZAR.

### 6. Hashtag — `HASHTAG_RE`

```python
r"(?<!\w)#([a-zA-Z][a-zA-Z0-9_]{0,99})(?!\w)"
```

- `(?<!\w)` — not preceded by a word character (avoids matching URL fragments).
- First char after `#` must be a **letter** — `#123` is not a valid hashtag.
- Body up to 100 characters (Twitter/X platform limit).

---

## Security Features

### 1. Input Size Gate
Inputs larger than 2 MB are rejected before processing to prevent resource exhaustion.

### 2. Unicode Normalisation (NFC)
Raw text is normalised to NFC form before processing.  This neutralises homoglyph attacks
where visually identical characters from different Unicode blocks are used to spoof domain
names (e.g. Cyrillic `а` in place of Latin `a`).

### 3. Control-Character Stripping
C0/C1 control characters (except tab, newline, carriage return) are removed.  Null bytes
(`\x00`) in particular can truncate strings in C-based backends and bypass content filters.

### 4. Per-Line Length Cap
Lines exceeding 5 000 characters are truncated before extraction.  Pathologically long lines
can trigger catastrophic backtracking in naive regex engines (ReDoS).  All patterns also use
bounded quantifiers as a second line of defence.

### 5. Hostile-Line Quarantine
Before any extraction, every line is tested against six hostile-input patterns:

| Class | Example trigger |
|-------|----------------|
| SQL injection | `DROP TABLE students` / `SELECT * FROM` / `UNION … INTO OUTFILE` |
| XSS — script tags | `<script>alert(1)</script>` |
| XSS — pseudo-protocol | `javascript:void(0)` |
| XSS — event handlers | `onerror=fetch(…)` / `onclick=…` |
| Path traversal | `../../etc/passwd` |
| Null-byte injection | `%00` / `\x00` |

Lines that match are **quarantined**: logged to stderr and excluded from all extraction.
The line number and a 120-character preview are recorded in the JSON output under
`security.quarantined_lines`.

### 6. Credit Card Masking
The raw PAN (Primary Account Number) is passed directly to `mask_card()` and discarded.
Only the masked representation (`**** **** **** XXXX`) is stored or written to output.

### 7. Email Redaction
The local part of every email address is partially redacted in the `all` list
(e.g. `alex.murera@…` → `al*********@…`).  The domain is preserved so that ALU
classification labels remain readable.

### 8. SSRF Detection
After URL extraction, each URL is checked against a private-IP / loopback pattern.
URLs targeting `localhost`, `127.x.x.x`, or RFC-1918 ranges are moved to a
`flagged` list with a `SSRF_RISK` label rather than included in the `safe` list.

---

## Sample Output Structure

```json
{
  "metadata": {
    "processed_at": "2026-05-24T...",
    "input_size_chars": 9595,
    "hostile_lines_quarantined": 7,
    "privacy_note": "Credit card PANs are masked. Email local-parts are partially redacted."
  },
  "security": {
    "quarantined_lines": [
      { "line_number": 162, "preview": "Name: Robert'); DROP TABLE students; --" },
      ...
    ]
  },
  "extracted": {
    "emails": {
      "all": ["al*********@alueducation.com", ...],
      "alu_official": ["alex.murera@alueducation.com", ...],
      "alu_alumni":   ["james.osei@alumni.alueducation.com", ...],
      "alu_si":       ["kwame.asante@si.alueducation.com", ...],
      "count": 22
    },
    "credit_cards": {
      "masked_numbers": ["**** **** **** 9012", ...],
      "count": 10
    },
    "urls":             { "safe": [...], "flagged": [...], "count": 18 },
    "phone_numbers":    ["+250 788 456 789", ...],
    "currency_amounts": ["RWF 2,500,000", "$5,000.00", ...],
    "hashtags":         ["#ALU", "#PaymentIssue", ...]
  }
}
```

---

## Input Design

`input/raw-text.txt` simulates a raw API export from a student services portal.
It contains four sections:

1. **Support Tickets** — student enquiries with realistic contact details and payment info.
2. **Payment Transaction Records** — financial records with card numbers in mixed formats.
3. **Social Media Activity Feed** — unmoderated posts with hashtags and URLs.
4. **Unverified / Flagged Submissions** — raw form entries including hostile payloads
   (SQL injection, XSS, path traversal) mixed with legitimate records.

This structure reflects real production conditions where good and bad data coexist
in the same stream and must be separated by the application rather than by the source.
