# Password Audit

An educational Python CLI for common-password checks, sequence detection, an illustrative length policy, and optional Have I Been Pwned (HIBP) Pwned Passwords lookup. It does not connect to Active Directory or identify attacker techniques.

## Install and run

```bash
git clone https://github.com/awais1-cybersec/password-audit.git
cd password-audit
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python src/password_audit.py --offline
# Optional online lookup:
python src/password_audit.py
```

Input is hidden and is not included in output. Online mode sends the first five hexadecimal characters of a SHA-1 hash to HIBP, not the plaintext password. Network errors produce `unavailable`, never a clean result. Offline mode produces `not_checked`. Prefer synthetic examples while learning.

Example: assessing `password` offline produces HIGH risk, an exact common-password finding, and `AssessmentComplete: false`. LOW is a local heuristic, not a guarantee of safety. Corpus occurrence counts are not counts of distinct breaches.

## Limits

The entropy figure assumes uniform independent character selection; it does not estimate real cracking time for human-chosen passwords. The 12-character check is an illustrative local policy, not AD/LDAP compliance. Password characteristics alone do not prove credential dumping or input capture, so automatic ATT&CK attribution has been removed.

The common-password list was extracted from the original project; its upstream source is unverified. See [provenance](data/README.md).

## Tests

```bash
python -m unittest discover -s tests -v
```

Tests mock HIBP requests and never submit passwords externally.
