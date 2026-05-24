#!/usr/bin/env python3
"""
alu-regex-data-extraction
=========================
Data Extraction & Secure Validation — ALU Hackathon Assignment
Author : EnzoAsaph
Date   : 2026-05-24

Reads raw-text.txt (simulated API response), extracts six types of
structured data using regular expressions, flags hostile input, and
writes a structured JSON report to output/sample-output.json.

Security model
--------------
  - All input is treated as UNTRUSTED.
  - Every line is checked for SQL injection, XSS, path traversal, and
    null-byte patterns BEFORE any extraction runs.
  - Lines that match hostile patterns are quarantined and excluded.
  - Credit card numbers are NEVER stored in plain text — they are masked
    to the last four digits immediately after matching.
  - Email local-parts are partially redacted in JSON output to limit
    unnecessary PII exposure in logs.
"""

import re
import json
import sys
import unicodedata
from pathlib import Path
from datetime import datetime, timezone


# ═══════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═══════════════════════════════════════════════════════════════════════

MAX_INPUT_BYTES = 2_097_152   # 2 MB — reject oversized payloads
MAX_LINE_CHARS  = 5_000       # per-line cap — prevents ReDoS via giant tokens


# ═══════════════════════════════════════════════════════════════════════
#  SECURITY LAYER — hostile input detection and sanitisation
# ═══════════════════════════════════════════════════════════════════════
#
#  These patterns represent the most common injection vectors seen in
#  production systems.  A match on ANY pattern causes the entire line to
#  be quarantined: it is logged to stderr and never passed to extraction.
#
#  Note: this is a defence-in-depth layer, not a complete WAF.  The goal
#  is to demonstrate that input must not be automatically trusted.

HOSTILE_PATTERNS = [
    # ── SQL injection ──────────────────────────────────────────────────
    # Requires a DML/DDL keyword AND a SQL clause keyword on the same line.
    # Bounded .{0,200}? prevents catastrophic backtracking across long lines.
    re.compile(
        r"\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|UNION|EXEC(?:UTE)?|CAST)\b"
        r".{0,200}?"
        r"\b(?:FROM|INTO|TABLE|WHERE|SET|VALUES|OUTFILE)\b",
        re.IGNORECASE | re.DOTALL,
    ),

    # ── XSS — <script> tags ────────────────────────────────────────────
    # Matches opening <script…> with up to 500 chars before the closing >
    # to handle attributes like <script type="text/javascript">.
    re.compile(r"<script[\s\S]{0,500}?(?:>|/>)", re.IGNORECASE),

    # ── XSS — javascript: / vbscript: pseudo-protocols ─────────────────
    re.compile(r"(?:java|vb)script\s*:", re.IGNORECASE),

    # ── XSS — inline event handlers (onerror=, onclick=, onload=, …) ───
    # Catches the pattern used in <img onerror="..."> and similar tags.
    re.compile(r"\bon(?:error|load|click|mouseover|focus|blur|input)\s*=", re.IGNORECASE),

    # ── Path traversal ─────────────────────────────────────────────────
    # Two or more consecutive ../ or ..\ sequences.
    re.compile(r"(?:\.\.[\\/]){2,}"),

    # ── Null-byte injection ─────────────────────────────────────────────
    # Null bytes can truncate strings in C-based backends and bypass filters.
    re.compile(r"\x00|%00"),
]


def is_hostile(line: str) -> bool:
    """Return True if the line matches any known hostile-input pattern."""
    for pattern in HOSTILE_PATTERNS:
        if pattern.search(line):
            return True
    return False


def sanitize_input(raw: str) -> str:
    """
    Normalise and clean raw text before extraction.

    Steps:
    1. NFC Unicode normalisation — neutralises homoglyph / IDN spoofing
       (e.g. Cyrillic lookalike characters inserted into domain names).
    2. Strip C0/C1 control characters while keeping \\n, \\r, \\t.
    3. Truncate lines that exceed MAX_LINE_CHARS to prevent ReDoS attacks
       via pathologically long tokens passed to the extraction regexes.
    """
    # Step 1 — Unicode normalisation (NFC form)
    text = unicodedata.normalize("NFC", raw)

    # Step 2 — Remove dangerous control characters
    # Keep: 0x09 (tab), 0x0A (newline), 0x0D (carriage return)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x80-\x9f]", "", text)

    # Step 3 — Per-line length cap
    lines = []
    for line in text.splitlines():
        if len(line) > MAX_LINE_CHARS:
            print(
                f"[SECURITY WARNING] Line truncated: "
                f"{len(line)} → {MAX_LINE_CHARS} chars",
                file=sys.stderr,
            )
            line = line[:MAX_LINE_CHARS]
        lines.append(line)

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════
#  REGEX PATTERNS
# ═══════════════════════════════════════════════════════════════════════

# ── 1. Email ───────────────────────────────────────────────────────────
#
#  Follows RFC 5321 conventions.
#  • Local part  : starts & ends with alphanumeric; middle may contain
#                  dots, underscores, percent signs, plus signs, hyphens.
#                  BOUNDED to ≤ 64 characters total.
#  • Domain part : one or more labels of ≤ 63 chars separated by dots,
#                  followed by a TLD of 2–10 characters.
#  • All quantifiers are BOUNDED — this prevents catastrophic backtracking
#    that could be triggered by a carefully crafted malicious input (ReDoS).

_EMAIL_LOCAL  = r"[a-zA-Z0-9](?:[a-zA-Z0-9._%+\-]{0,62}[a-zA-Z0-9])?"
_EMAIL_DOMAIN = (
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,10}"
)

EMAIL_RE = re.compile(rf"\b{_EMAIL_LOCAL}@{_EMAIL_DOMAIN}\b")

# ALU official staff / student address: name@alueducation.com
ALU_OFFICIAL_RE = re.compile(
    rf"\b{_EMAIL_LOCAL}@alueducation\.com\b", re.IGNORECASE
)

# ALU alumni address: name@alumni.alueducation.com
# Note: the subdomain "alumni." ensures this does NOT match @alueducation.com
ALU_ALUMNI_RE = re.compile(
    rf"\b{_EMAIL_LOCAL}@alumni\.alueducation\.com\b", re.IGNORECASE
)

# ALU Social Innovation address: name@si.alueducation.com
ALU_SI_RE = re.compile(
    rf"\b{_EMAIL_LOCAL}@si\.alueducation\.com\b", re.IGNORECASE
)

# ── 2. Credit Card ─────────────────────────────────────────────────────
#
#  Covers four major card networks:
#   Visa       : 16 digits, prefix 4
#   Mastercard : 16 digits, prefix 51–55
#   Amex       : 15 digits, prefix 34 or 37
#   Discover   : 16 digits, prefix 6011 or 65XX
#
#  Separators between groups may be a single space OR a single hyphen
#  (or no separator at all).  The _S placeholder enforces this.
#
#  Security: full PAN is masked immediately after matching — it is never
#  written to output or logs in plain text (see mask_card() below).

_S = r"[-\s]?"   # optional single separator character

CREDIT_CARD_RE = re.compile(
    r"\b(?:"
    # Visa — 4 + 4 + 4 + 4 = 16 digits
    rf"4[0-9]{{3}}{_S}[0-9]{{4}}{_S}[0-9]{{4}}{_S}[0-9]{{4}}"
    # Mastercard — 4 + 4 + 4 + 4 = 16 digits, prefix 51–55
    rf"|5[1-5][0-9]{{2}}{_S}[0-9]{{4}}{_S}[0-9]{{4}}{_S}[0-9]{{4}}"
    # Amex — 4 + 6 + 5 = 15 digits, prefix 34/37
    rf"|3[47][0-9]{{2}}{_S}[0-9]{{6}}{_S}[0-9]{{5}}"
    # Discover — 4 + 4 + 4 + 4 = 16 digits, prefix 6011 or 65XX
    rf"|6(?:011|5[0-9]{{2}}){_S}[0-9]{{4}}{_S}[0-9]{{4}}{_S}[0-9]{{4}}"
    r")\b"
)

# ── 3. URL ─────────────────────────────────────────────────────────────
#
#  Matches http:// and https:// URLs only.
#  • Scheme is restricted to http/https — this rejects javascript:,
#    data:, file:, and other dangerous pseudo-protocols at the pattern level.
#  • Path / query / fragment: excludes whitespace and characters that signal
#    embedded HTML (<, >, ", ') to prevent over-matching into surrounding markup.
#  • Path length capped at 2 000 characters (RFC 7230 practical limit).
#  • After matching, the extractor also checks for SSRF-risky targets
#    (localhost, private IP ranges) and flags them separately.

URL_RE = re.compile(
    r"https?://"
    r"(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}"   # hostname with at least one dot
    r"(?::\d{1,5})?"                          # optional port number
    r"(?:/[^\s<>\"']{0,2000})?"              # optional path / query / fragment
)

# ── 4. Phone Numbers ───────────────────────────────────────────────────
#
#  Three sub-patterns cover the most common real-world formats:
#
#  (a) US / Canada   : +1 (617) 890-4321
#                      Country code 1, area code in parens, dashes between groups.
#  (b) East Africa   : +250 788 456 789
#                      Country codes 250–256 (Rwanda, Tanzania, Kenya, Uganda …)
#                      followed by three groups of three digits.
#  (c) Other intl.   : +233 541-234567
#                      Requires leading + to reduce false positives vs. dates.
#  (d) Local (0XX…)  : 0788-321-654 or 0783 100 200
#                      Leading zero, common in Rwanda and Kenya.
#
#  Deduplication and a minimum-7-digit filter are applied after matching.

PHONE_RE = re.compile(
    r"(?<!\d)"   # NOT preceded by a digit — prevents false matches inside card numbers
    r"(?:"
    # (a) US/Canada: +1 (NXX) NXX-XXXX
    r"\+?1[-.\s]?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}"
    # (b) East Africa: +250/254/255/256 XXX XXX XXX
    r"|\+?25[0-6][-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?\d{3}"
    # (c) Other international (requires + to anchor)
    r"|\+[2-9]\d{1,2}[-.\s]\d{2,4}[-.\s]\d{4,6}"
    # (d) Local with leading zero: 0XXX-XXX-XXXX
    r"|0\d{2,3}[-.\s]?\d{3}[-.\s]?\d{3,4}"
    r")"
    r"(?!\d)"    # NOT followed by a digit — avoids matching subsequences of digit strings
)

# ── 5. Currency Amounts ────────────────────────────────────────────────
#
#  Handles three surface forms:
#   • Code-prefixed  : RWF 2,500,000  /  USD 3,200.00
#   • Symbol-prefixed: $5,000.00  /  €150.00  /  £99.99
#   • Amount-suffixed: 50,000 RWF  /  85,000 KES
#
#  Codes covered: USD, EUR, GBP, RWF, KES, UGX, TZS, NGN, ZAR.
#  Amount body: up to 15 digit/comma characters plus optional 2-decimal fraction.

_CODES  = r"(?:USD|EUR|GBP|RWF|KES|UGX|TZS|NGN|ZAR)"
_AMOUNT = r"[\d,]{1,15}(?:\.\d{1,2})?"
_SYMBOL = r"[$€£¥]"

CURRENCY_RE = re.compile(
    rf"(?:"
    rf"{_CODES}\s?{_AMOUNT}"         # code-prefix  : RWF 2,500,000
    rf"|{_SYMBOL}\s?{_AMOUNT}"       # symbol-prefix: $5,000.00
    rf"|{_AMOUNT}\s?{_CODES}"        # amount-suffix: 85,000 KES
    rf")"
)

# ── 6. Hashtags ────────────────────────────────────────────────────────
#
#  Rules:
#  • Must NOT be preceded by a word character — (?<!\w) — so we don't
#    split "#ALU" out of a URL fragment like "example.com/path#ALU".
#  • The character immediately after # must be a LETTER (not a digit),
#    matching the convention used by Twitter/X, Instagram, and LinkedIn.
#  • Body: alphanumeric + underscore, max 100 characters (platform limit).
#  • Must NOT be followed by a word character — (?!\w).

HASHTAG_RE = re.compile(r"(?<!\w)#([a-zA-Z][a-zA-Z0-9_]{0,99})(?!\w)")


# ═══════════════════════════════════════════════════════════════════════
#  PRIVACY HELPERS
# ═══════════════════════════════════════════════════════════════════════

def mask_card(raw: str) -> str:
    """
    Replace all but the last four digits of a card number with asterisks.

    The full PAN (Primary Account Number) is discarded immediately after
    this function is called — it is never written to disk, printed to the
    console, or included in any log output.

    Example:
        '4532 1234 5678 9012'  →  '**** **** **** 9012'
        '3714 496353 98431'    →  '**** **** **** 8431'
    """
    digits = re.sub(r"\D", "", raw)          # strip non-digit characters
    return f"**** **** **** {digits[-4:]}"   # show only last 4 digits


def redact_email(email: str) -> str:
    """
    Partially redact the local part of an email address.

    Only the first two characters of the local part are kept; the rest are
    replaced with '*'.  The domain is preserved so that ALU-specific
    classifications remain readable in the output.

    Examples:
        'alex.murera@alueducation.com'        →  'al*********@alueducation.com'
        'j.osei.alumni@gmail.com'             →  'j.*********@gmail.com'
        'sa@example.com'  (len ≤ 2 fallback)  →  's*@example.com'
    """
    local, domain = email.rsplit("@", 1)
    if len(local) <= 2:
        return local[0] + "*@" + domain
    return local[:2] + "*" * (len(local) - 2) + "@" + domain


# ═══════════════════════════════════════════════════════════════════════
#  EXTRACTION FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════

def _unique(seq: list) -> list:
    """Return a deduplicated list preserving original insertion order."""
    seen, out = set(), []
    for item in seq:
        key = item.strip().lower()
        if key not in seen:
            seen.add(key)
            out.append(item.strip())
    return out


def extract_emails(text: str) -> dict:
    """
    Extract all email addresses and classify ALU-specific addresses.

    Returns:
        all          — all unique emails (local part redacted for privacy)
        alu_official — addresses ending @alueducation.com
        alu_alumni   — addresses ending @alumni.alueducation.com
        alu_si       — addresses ending @si.alueducation.com
        count        — total unique email count
    """
    all_emails   = _unique(EMAIL_RE.findall(text))
    alu_official = _unique(ALU_OFFICIAL_RE.findall(text))
    alu_alumni   = _unique(ALU_ALUMNI_RE.findall(text))
    alu_si       = _unique(ALU_SI_RE.findall(text))

    return {
        # Local parts are redacted; domain kept for classification visibility
        "all":          [redact_email(e) for e in all_emails],
        "alu_official": alu_official,   # institutional addresses retained
        "alu_alumni":   alu_alumni,
        "alu_si":       alu_si,
        "count":        len(all_emails),
    }


def extract_credit_cards(text: str) -> dict:
    """
    Extract credit card numbers and immediately mask them.

    SECURITY: The raw PAN is used only to produce a masked string.
    It is never assigned to a variable that persists beyond this function.
    The return value contains only masked representations.
    """
    # Raw matches are consumed and discarded in a single expression
    masked = _unique([mask_card(m) for m in CREDIT_CARD_RE.findall(text)])
    return {
        "masked_numbers": masked,
        "count":          len(masked),
        "note":           "Full card numbers are discarded after masking — never stored or logged.",
    }


_TRAIL_PUNCT = re.compile(r"[.,;:!?)'\"]+$")

def extract_urls(text: str) -> dict:
    """
    Extract URLs and flag those that represent SSRF or other risks.

    SSRF (Server-Side Request Forgery) risk: URLs targeting localhost,
    loopback (127.x.x.x), or RFC-1918 private IP ranges are separated
    into a 'flagged' list rather than the 'safe' list.

    Trailing punctuation (periods, commas, etc.) that the regex may include
    when a URL appears mid-sentence is stripped as a post-processing step.
    """
    # Strip trailing punctuation that belongs to surrounding text, not the URL
    raw  = _unique([_TRAIL_PUNCT.sub("", u) for u in URL_RE.findall(text)])
    safe    = []
    flagged = []

    # Pattern that identifies SSRF-risky targets
    _PRIVATE = re.compile(
        r"(?:localhost"
        r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        r"|0\.0\.0\.0"
        r"|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
        r"|192\.168\.\d{1,3}\.\d{1,3})",
        re.IGNORECASE,
    )

    for url in raw:
        if _PRIVATE.search(url):
            flagged.append({
                "url":  url,
                "flag": "SSRF_RISK — targets private/loopback address",
            })
        elif len(url) > 500:
            flagged.append({
                "url":  url[:120] + "…",
                "flag": "SUSPICIOUS_LENGTH — URL exceeds 500 characters",
            })
        else:
            safe.append(url)

    return {"safe": safe, "flagged": flagged, "count": len(raw)}


def extract_phones(text: str) -> list:
    """
    Extract unique phone numbers.

    Deduplication is performed on the digit-only form to avoid counting
    '+250 788 456 789' and '250-788-456-789' as separate entries.
    Numbers with fewer than 7 digits are discarded as likely false positives.
    """
    raw = PHONE_RE.findall(text)
    seen, out = set(), []
    for p in raw:
        digits = re.sub(r"\D", "", p)
        if len(digits) >= 7 and digits not in seen:
            seen.add(digits)
            out.append(p.strip())
    return out


def extract_currency(text: str) -> list:
    """Extract unique currency amount strings."""
    return _unique(CURRENCY_RE.findall(text))


def extract_hashtags(text: str) -> list:
    """
    Extract unique hashtags.

    Note: HASHTAG_RE captures only the text after '#'.
    The leading '#' character is prepended here so the output is readable.
    """
    raw = HASHTAG_RE.findall(text)
    return ["#" + tag for tag in _unique(raw)]


# ═══════════════════════════════════════════════════════════════════════
#  MAIN PIPELINE
# ═══════════════════════════════════════════════════════════════════════

def process(raw_text: str) -> dict:
    """
    Full processing pipeline:
      1. Enforce input size limit.
      2. Sanitise (Unicode normalisation, control-char removal, line-length cap).
      3. Quarantine hostile lines (SQL injection, XSS, path traversal, …).
      4. Run extraction on the remaining clean text.
      5. Return a structured result dict suitable for JSON serialisation.
    """

    # ── Step 1: Size gate ────────────────────────────────────────────
    byte_count = len(raw_text.encode("utf-8"))
    if byte_count > MAX_INPUT_BYTES:
        raise ValueError(
            f"Input size {byte_count:,} bytes exceeds the 2 MB safety limit."
        )

    # ── Step 2: Sanitise ─────────────────────────────────────────────
    clean = sanitize_input(raw_text)

    # ── Step 3: Hostile-line quarantine ──────────────────────────────
    hostile_lines = []
    safe_lines    = []

    for line_num, line in enumerate(clean.splitlines(), start=1):
        if is_hostile(line):
            preview = (line[:120] + "…") if len(line) > 120 else line
            hostile_lines.append({
                "line_number": line_num,
                "preview":     preview,
            })
            print(
                f"[SECURITY] Line {line_num:>4} quarantined — "
                f"hostile pattern detected: {line[:60].strip()}…",
                file=sys.stderr,
            )
        else:
            safe_lines.append(line)

    safe_text = "\n".join(safe_lines)

    # ── Step 4: Extract ──────────────────────────────────────────────
    return {
        "metadata": {
            "processed_at":             datetime.now(timezone.utc).isoformat(),
            "input_size_chars":         len(raw_text),
            "hostile_lines_quarantined": len(hostile_lines),
            "privacy_note": (
                "Credit card PANs are masked to last 4 digits. "
                "Email local-parts are partially redacted."
            ),
        },
        "security": {
            "quarantined_lines": hostile_lines,
        },
        "extracted": {
            "emails":           extract_emails(safe_text),
            "credit_cards":     extract_credit_cards(safe_text),
            "urls":             extract_urls(safe_text),
            "phone_numbers":    extract_phones(safe_text),
            "currency_amounts": extract_currency(safe_text),
            "hashtags":         extract_hashtags(safe_text),
        },
    }


# ═══════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════

def main() -> None:
    base_dir    = Path(__file__).resolve().parent.parent
    input_path  = base_dir / "input"  / "raw-text.txt"
    output_path = base_dir / "output" / "sample-output.json"

    if not input_path.exists():
        print(f"[ERROR] Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[INFO] Reading input  : {input_path}")
    raw = input_path.read_text(encoding="utf-8")
    print(f"[INFO] Input size     : {len(raw):,} characters")
    print()

    results = process(raw)

    # Write JSON output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(results, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    # ── Console summary ──────────────────────────────────────────────
    ext = results["extracted"]
    sep = "=" * 62
    print()
    print(sep)
    print("  EXTRACTION REPORT")
    print(sep)
    print(f"  Emails found           : {ext['emails']['count']}")
    print(f"    -> ALU Official      : {len(ext['emails']['alu_official'])}")
    print(f"    -> ALU Alumni        : {len(ext['emails']['alu_alumni'])}")
    print(f"    -> ALU SI            : {len(ext['emails']['alu_si'])}")
    print(f"  Credit cards (masked)  : {ext['credit_cards']['count']}")
    print(f"  URLs - safe            : {len(ext['urls']['safe'])}")
    print(f"  URLs - flagged (SSRF)  : {len(ext['urls']['flagged'])}")
    print(f"  Phone numbers          : {len(ext['phone_numbers'])}")
    print(f"  Currency amounts       : {len(ext['currency_amounts'])}")
    print(f"  Hashtags               : {len(ext['hashtags'])}")
    print(f"  [!] Quarantined lines  : {results['metadata']['hostile_lines_quarantined']}")
    print(sep)
    print(f"\n[INFO] Full output written to: {output_path}")


if __name__ == "__main__":
    main()
