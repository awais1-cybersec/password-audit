import hashlib
import sys
from pathlib import Path
import unittest
from unittest.mock import Mock, patch
import requests
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"src"))
import password_audit as audit

class AuditTests(unittest.TestCase):
    def test_empty(self):
        with self.assertRaises(ValueError): audit.soc_password_audit("",False)
    def test_common_and_offline(self):
        result=audit.soc_password_audit("password",False)
        self.assertEqual(result["Risk"],"HIGH")
        self.assertFalse(result["AssessmentComplete"])
    def test_no_substring_common_match(self):
        self.assertNotIn("Exact common-password match",audit.soc_password_audit("prefix-password-suffix",False)["Findings"])
    def test_boundaries(self):
        self.assertEqual([audit.brute_force_resistance(x) for x in (39,40,59,60)],["LOW","MEDIUM","MEDIUM","HIGH"])
    @patch.object(audit.requests,"get")
    def test_timeout(self,get):
        get.side_effect=requests.Timeout()
        self.assertEqual(audit.hibp_check("example")["status"],"unavailable")
    @patch.object(audit.requests,"get")
    def test_http_error(self,get):
        get.return_value.raise_for_status.side_effect=requests.HTTPError()
        self.assertEqual(audit.hibp_check("example")["status"],"unavailable")
    @patch.object(audit.requests,"get")
    def test_found_and_hash_prefix(self,get):
        digest=hashlib.sha1(b"example").hexdigest().upper()
        get.return_value=Mock(text=digest[5:]+":8")
        self.assertEqual(audit.hibp_check("example"),{"status":"found","count":8})
        self.assertEqual(get.call_args.args[0],audit.HIBP_API+digest[:5])
        self.assertEqual(get.call_args.kwargs["timeout"],10)
    @patch.object(audit.requests,"get")
    def test_not_found(self,get):
        get.return_value=Mock(text="0"*35+":1")
        self.assertEqual(audit.hibp_check("example")["status"],"not_found")
    @patch.object(audit.requests,"get")
    def test_malformed(self,get):
        get.return_value=Mock(text="unexpected")
        self.assertEqual(audit.hibp_check("example")["status"],"unavailable")

if __name__ == "__main__": unittest.main()
