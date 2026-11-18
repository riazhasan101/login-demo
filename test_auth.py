"""Unit tests for the password helpers and the login check.

Run them from the repository root with::

    python -m unittest -v
"""

from __future__ import annotations

import unittest

import app
import auth


class PasswordHashingTests(unittest.TestCase):
    def test_hash_is_deterministic_for_the_same_salt(self):
        first = auth.hash_password("correct-horse", "salt-a")
        second = auth.hash_password("correct-horse", "salt-a")
        self.assertEqual(first, second)

    def test_hash_changes_when_the_salt_changes(self):
        first = auth.hash_password("correct-horse", "salt-a")
        second = auth.hash_password("correct-horse", "salt-b")
        self.assertNotEqual(first, second)

    def test_hash_is_not_the_plaintext(self):
        self.assertNotEqual(auth.hash_password("correct-horse", "salt-a"), "correct-horse")

    def test_new_salt_is_random_hex(self):
        first = auth.new_salt()
        second = auth.new_salt()
        self.assertEqual(len(first), 16)
        self.assertNotEqual(first, second)
        int(first, 16)  # raises ValueError when it is not hex


class VerifyPasswordTests(unittest.TestCase):
    def setUp(self):
        self.salt = auth.new_salt()
        self.password_hash = auth.hash_password("correct-horse", self.salt)

    def test_correct_password_is_accepted(self):
        self.assertTrue(
            auth.verify_password("correct-horse", self.password_hash, self.salt),
            "verify_password must hash the candidate password with the stored salt "
            "and compare the result with the stored hash",
        )

    def test_wrong_password_is_rejected(self):
        self.assertFalse(auth.verify_password("wrong-horse", self.password_hash, self.salt))

    def test_empty_password_is_rejected(self):
        self.assertFalse(auth.verify_password("", self.password_hash, self.salt))

    def test_missing_stored_hash_is_rejected(self):
        self.assertFalse(auth.verify_password("correct-horse", "", self.salt))

    def test_stored_hash_cannot_be_used_as_a_password(self):
        # The hash itself is not a valid password: the comparison has to happen
        # after hashing the candidate value.
        self.assertFalse(auth.verify_password(self.password_hash, self.password_hash, self.salt))


class CheckLoginTests(unittest.TestCase):
    def test_known_account_can_sign_in(self):
        self.assertTrue(app.check_login("owner", "demo1234"), "the demo account must be able to sign in")

    def test_username_is_case_insensitive(self):
        self.assertTrue(app.check_login("OWNER", "demo1234"))

    def test_wrong_password_is_rejected(self):
        self.assertFalse(app.check_login("owner", "demo1235"))

    def test_unknown_user_is_rejected(self):
        self.assertFalse(app.check_login("nobody", "demo1234"))


if __name__ == "__main__":
    unittest.main()
