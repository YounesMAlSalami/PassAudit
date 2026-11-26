import unittest

import password_auditor as app


class PasswordAuditorAssignmentTests(unittest.TestCase):
    def test_strength_categories_exist(self):
        result = app.assess_password_strength("Ab!9xQm2vL#8")
        self.assertIn(result["classification"], {
            "Very Weak", "Weak", "Moderate", "Strong", "Very Strong"
        })
        self.assertGreaterEqual(result["score"], 0)
        self.assertLessEqual(result["score"], 100)
        self.assertIn("Uppercase", result["categories"])
        self.assertIn("Lowercase", result["categories"])
        self.assertIn("Numbers", result["categories"])
        self.assertIn("Special", result["categories"])

    def test_weak_short_password_is_not_strong(self):
        result = app.assess_password_strength("abc")
        self.assertIn(result["classification"], ("Very Weak", "Weak"))

    def test_generator_guarantees_selected_categories(self):
        password, error = app.generate_strong_password(
            20, True, True, True, True
        )
        self.assertEqual(error, "")
        self.assertEqual(len(password), 20)
        self.assertTrue(any(character.isupper() for character in password))
        self.assertTrue(any(character.islower() for character in password))
        self.assertTrue(any(character.isdigit() for character in password))
        self.assertTrue(any(not character.isalnum() for character in password))

    def test_generator_rejects_invalid_configuration(self):
        password, error = app.generate_strong_password(
            2, True, True, True, True
        )
        self.assertIsNone(password)
        self.assertNotEqual(error, "")

        password, error = app.generate_strong_password(
            20, False, False, False, False
        )
        self.assertIsNone(password)
        self.assertNotEqual(error, "")

    def test_common_password_lookup_is_case_insensitive(self):
        wordlist = app.load_wordlist(app.WORDLIST_PATH)
        candidates = app.load_wordlist_candidates(app.WORDLIST_PATH)
        if candidates:
            sample = candidates[0].casefold()
            self.assertTrue(app.is_common_password(sample.upper(), wordlist))

    def test_linux_hash_algorithm_detection(self):
        self.assertEqual(app.detect_linux_hash_algorithm("$6$salt$hash"), "SHA-512")
        self.assertEqual(app.detect_linux_hash_algorithm("$5$salt$hash"), "SHA-256")
        self.assertEqual(app.detect_linux_hash_algorithm("$y$j9T$salt$hash"), "Yescrypt")
        self.assertEqual(app.detect_linux_hash_algorithm("abCDef0123456"), "DES")
        self.assertEqual(app.detect_linux_hash_algorithm("unexpected"), "Unknown")


if __name__ == "__main__":
    unittest.main()
