"""Educational password checks; results are heuristics, not attack attribution."""
import argparse
import getpass
import hashlib
import json
import math
from pathlib import Path
import re
import requests

HIBP_API = "https://api.pwnedpasswords.com/range/"
COMMON_PASSWORDS = frozenset((Path(__file__).resolve().parents[1] / "data/common_passwords.txt").read_text().splitlines())
KEYBOARD_PATTERNS = ("qwerty", "asdf", "zxcv", "12345", "54321")

def hibp_check(password):
    digest = hashlib.sha1(password.encode()).hexdigest().upper()
    try:
        response = requests.get(HIBP_API + digest[:5], timeout=10, headers={"Add-Padding": "true"})
        response.raise_for_status()
        matches = []
        for line in response.text.splitlines():
            suffix, count = line.split(":")
            if not re.fullmatch(r"[0-9A-F]{35}", suffix) or not count.isdigit():
                raise ValueError("Invalid range response")
            matches.append((suffix, int(count)))
        if not matches:
            raise ValueError("Empty range response")
        count = next((count for suffix, count in matches if suffix == digest[5:]), 0)
        return {"status": "found" if count else "not_found", "count": count}
    except (requests.RequestException, ValueError):
        return {"status": "unavailable", "count": None}

def calculate_entropy(password):
    charset = sum(size for pattern, size in ((r"[a-z]",26),(r"[A-Z]",26),(r"[0-9]",10),(r"[^a-zA-Z0-9]",32)) if re.search(pattern,password))
    return round(len(password)*math.log2(charset),2) if charset else 0

def brute_force_resistance(entropy):
    return "LOW" if entropy < 40 else "MEDIUM" if entropy < 60 else "HIGH"

def ad_password_policy_check(password):
    # Illustrative local policy, not an Active Directory compliance assessment.
    return ["Below illustrative 12-character minimum"] if len(password) < 12 else []

def soc_password_audit(password, online=True):
    if not password:
        raise ValueError("Password must not be empty")
    findings = ad_password_policy_check(password)
    common = password.casefold() in COMMON_PASSWORDS
    pattern = any(p in password.casefold() or p[::-1] in password.casefold() for p in KEYBOARD_PATTERNS)
    if common: findings.append("Exact common-password match")
    if pattern: findings.append("Keyboard or numeric sequence detected")
    breach = hibp_check(password) if online else {"status":"not_checked", "count":None}
    if breach["status"] == "found": findings.append("Present in Pwned Passwords corpus")
    if breach["status"] == "unavailable": findings.append("Breach check unavailable; exposure unknown")
    entropy = calculate_entropy(password)
    risk = "HIGH" if common or breach["status"] == "found" else "MEDIUM" if findings or pattern or entropy < 60 else "LOW"
    return {"Risk":risk,"EntropyEstimate":entropy,"EstimateAssumption":"Uniform independent character selection; unreliable for human-chosen passwords", "Findings":findings,"BreachCheck":breach,"AssessmentComplete":breach["status"] in ("found","not_found")}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline",action="store_true",help="Do not contact HIBP")
    args=parser.parse_args()
    try:
        result=soc_password_audit(getpass.getpass("Password to assess (hidden): "),online=not args.offline)
    except (ValueError,EOFError,KeyboardInterrupt) as exc:
        parser.exit(2, str(exc)+"\n")
    print(json.dumps(result,indent=2))

if __name__ == "__main__":
    main()
