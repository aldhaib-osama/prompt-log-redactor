import unittest

from prompt_log_redactor import redact_log, redact_text


class RedactTests(unittest.TestCase):
    def test_email_redacted(self):
        out, counts = redact_text("contact me at user@example.com please")
        self.assertIn("[REDACTED:email]", out)
        self.assertNotIn("user@example.com", out)
        self.assertEqual(counts["email"], 1)

    def test_api_key_redacted(self):
        out, _ = redact_text("key is sk-abcdef0123456789abcd ok")
        self.assertIn("[REDACTED:api_key]", out)

    def test_bearer_redacted(self):
        out, _ = redact_text("Authorization: Bearer abcdef0123456789")
        self.assertIn("[REDACTED:bearer]", out)

    def test_jwt_redacted(self):
        jwt = "eyJhbGciOi.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJS"
        out, _ = redact_text("token " + jwt)
        self.assertIn("[REDACTED:jwt]", out)

    def test_phone_redacted(self):
        out, _ = redact_text("call +249 91 234 5678 now")
        self.assertIn("[REDACTED:phone]", out)

    def test_clean_text_untouched(self):
        out, counts = redact_text("the model refused politely")
        self.assertEqual(out, "the model refused politely")
        self.assertEqual(counts, {})

    def test_nested_log_redacted(self):
        doc = {"turns": [{"role": "user", "text": "mail a@b.co"},
                          {"role": "model", "text": "done"}]}
        redacted, counts = redact_log(doc)
        self.assertEqual(counts["email"], 1)
        self.assertIn("[REDACTED:email]", redacted["turns"][0]["text"])

    def test_counts_accumulate(self):
        doc = ["a@b.co", "c@d.co"]
        _, counts = redact_log(doc)
        self.assertEqual(counts["email"], 2)

    def test_non_string_nodes_kept(self):
        doc = {"n": 3, "ok": True, "items": [1, "x@y.zz"]}
        redacted, _ = redact_log(doc)
        self.assertEqual(redacted["n"], 3)
        self.assertEqual(redacted["items"][0], 1)


if __name__ == "__main__":
    unittest.main()
