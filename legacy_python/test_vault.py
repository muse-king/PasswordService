import base64
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import vault


FAKE_MASTER_PASSWORD = "fake-test-master-password"


class VaultCoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.vault_path = Path(self.temporary_directory.name) / "passwords.enc"

    def _valid_envelope(self) -> dict[str, object]:
        return vault.encrypt_vault(
            FAKE_MASTER_PASSWORD,
            [{"name": "Fake envelope record", "password": "fake-envelope-password"}],
        )

    def _assert_rejected_before_kdf(self, envelope: dict[str, object]) -> None:
        self.vault_path.write_text(json.dumps(envelope), encoding="utf-8")
        before = self.vault_path.read_bytes()
        with mock.patch.object(vault, "_derive_key") as derive_key:
            with self.assertRaisesRegex(
                vault.VaultAuthenticationError,
                "Invalid master password or corrupted vault",
            ):
                vault.load_vault(self.vault_path, FAKE_MASTER_PASSWORD)
        derive_key.assert_not_called()
        self.assertEqual(self.vault_path.read_bytes(), before)

    def test_create_save_close_reopen_round_trip_exact_values(self) -> None:
        records = [{"name": "GitHub", "password": "FakePass-123!"}]
        vault.create_vault(self.vault_path, FAKE_MASTER_PASSWORD, records)
        loaded = vault.load_vault(self.vault_path, FAKE_MASTER_PASSWORD)
        self.assertEqual(loaded, records)

    def test_unicode_name_and_password_are_preserved(self) -> None:
        records = [{"name": "阿里云-测试", "password": "假密码-密码🔐-123"}]
        vault.save_vault(self.vault_path, FAKE_MASTER_PASSWORD, records)
        self.assertEqual(vault.load_vault(self.vault_path, FAKE_MASTER_PASSWORD), records)

    def test_long_and_special_character_password_is_preserved(self) -> None:
        password = ("Fake`~!@#$%^&*()_+-=[]{}|;:'\",.<>/?\\" * 20) + "END"
        records = [{"name": "Special fake record", "password": password}]
        vault.save_vault(self.vault_path, FAKE_MASTER_PASSWORD, records)
        self.assertEqual(vault.load_vault(self.vault_path, FAKE_MASTER_PASSWORD), records)

    def test_multiple_records_and_duplicates_are_preserved(self) -> None:
        records = [
            {"name": "GitHub", "password": "fake-old"},
            {"name": "GitHub Work", "password": "fake-work"},
            {"name": "GitHub", "password": "fake-new"},
        ]
        vault.save_vault(self.vault_path, FAKE_MASTER_PASSWORD, records)
        self.assertEqual(vault.load_vault(self.vault_path, FAKE_MASTER_PASSWORD), records)

    def test_wrong_master_password_fails_and_does_not_modify_file(self) -> None:
        vault.save_vault(self.vault_path, FAKE_MASTER_PASSWORD, [{"name": "Fake", "password": "secret-test"}])
        before = self.vault_path.read_bytes()
        with self.assertRaisesRegex(vault.VaultAuthenticationError, "Invalid master password or corrupted vault"):
            vault.load_vault(self.vault_path, "wrong-fake-master-password")
        self.assertEqual(self.vault_path.read_bytes(), before)

    def test_empty_master_password_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "must not be empty"):
            vault.save_vault(self.vault_path, "", [])
        self.assertFalse(self.vault_path.exists())

    def test_tampered_ciphertext_fails(self) -> None:
        vault.save_vault(self.vault_path, FAKE_MASTER_PASSWORD, [{"name": "Fake", "password": "fake-value"}])
        envelope = json.loads(self.vault_path.read_text(encoding="utf-8"))
        ciphertext = bytearray(base64.b64decode(envelope["ciphertext"]))
        ciphertext[len(ciphertext) // 2] ^= 1
        envelope["ciphertext"] = base64.b64encode(ciphertext).decode("ascii")
        self.vault_path.write_text(json.dumps(envelope), encoding="utf-8")
        with self.assertRaises(vault.VaultAuthenticationError):
            vault.load_vault(self.vault_path, FAKE_MASTER_PASSWORD)

    def test_tampered_authenticated_metadata_fails(self) -> None:
        vault.save_vault(self.vault_path, FAKE_MASTER_PASSWORD, [{"name": "Fake", "password": "fake-value"}])
        envelope = json.loads(self.vault_path.read_text(encoding="utf-8"))
        salt = bytearray(base64.b64decode(envelope["salt"]))
        salt[0] ^= 1
        envelope["salt"] = base64.b64encode(salt).decode("ascii")
        self.vault_path.write_text(json.dumps(envelope), encoding="utf-8")
        with self.assertRaises(vault.VaultAuthenticationError):
            vault.load_vault(self.vault_path, FAKE_MASTER_PASSWORD)

    def test_tampered_nonce_fails(self) -> None:
        vault.save_vault(self.vault_path, FAKE_MASTER_PASSWORD, [{"name": "Fake", "password": "fake-value"}])
        envelope = json.loads(self.vault_path.read_text(encoding="utf-8"))
        nonce = bytearray(base64.b64decode(envelope["nonce"]))
        nonce[-1] ^= 1
        envelope["nonce"] = base64.b64encode(nonce).decode("ascii")
        self.vault_path.write_text(json.dumps(envelope), encoding="utf-8")
        with self.assertRaises(vault.VaultAuthenticationError):
            vault.load_vault(self.vault_path, FAKE_MASTER_PASSWORD)

    def test_repeated_save_reload_and_append_preserve_existing_records(self) -> None:
        first = [{"name": "First fake", "password": "fake-one"}]
        vault.save_vault(self.vault_path, FAKE_MASTER_PASSWORD, first)
        loaded = vault.load_vault(self.vault_path, FAKE_MASTER_PASSWORD)
        loaded.append({"name": "Second fake", "password": "fake-two"})
        vault.save_vault(self.vault_path, FAKE_MASTER_PASSWORD, loaded)
        self.assertEqual(vault.load_vault(self.vault_path, FAKE_MASTER_PASSWORD), loaded)

    def test_plaintext_name_and_password_are_not_in_vault_file(self) -> None:
        name = "UNIQUE_FAKE_RECORD_NAME_9f17"
        password = "UNIQUE_FAKE_PASSWORD_4c82!"
        vault.save_vault(self.vault_path, FAKE_MASTER_PASSWORD, [{"name": name, "password": password}])
        disk_bytes = self.vault_path.read_bytes()
        self.assertNotIn(name.encode("utf-8"), disk_bytes)
        self.assertNotIn(password.encode("utf-8"), disk_bytes)
        self.assertNotIn(FAKE_MASTER_PASSWORD.encode("utf-8"), disk_bytes)

    def test_each_save_uses_new_salt_and_nonce(self) -> None:
        records = [{"name": "Fake", "password": "fake-value"}]
        vault.save_vault(self.vault_path, FAKE_MASTER_PASSWORD, records)
        first = json.loads(self.vault_path.read_text(encoding="utf-8"))
        vault.save_vault(self.vault_path, FAKE_MASTER_PASSWORD, records)
        second = json.loads(self.vault_path.read_text(encoding="utf-8"))
        self.assertNotEqual(first["salt"], second["salt"])
        self.assertNotEqual(first["nonce"], second["nonce"])
        self.assertNotEqual(first["ciphertext"], second["ciphertext"])

    def test_atomic_replace_failure_preserves_previous_valid_vault(self) -> None:
        original = [{"name": "Original fake", "password": "fake-original"}]
        vault.save_vault(self.vault_path, FAKE_MASTER_PASSWORD, original)
        before = self.vault_path.read_bytes()
        with mock.patch.object(vault.os, "replace", side_effect=OSError("simulated replace failure")):
            with self.assertRaises(OSError):
                vault.save_vault(
                    self.vault_path,
                    FAKE_MASTER_PASSWORD,
                    [{"name": "Replacement fake", "password": "fake-replacement"}],
                )
        self.assertEqual(self.vault_path.read_bytes(), before)
        self.assertEqual(vault.load_vault(self.vault_path, FAKE_MASTER_PASSWORD), original)
        self.assertEqual(list(self.vault_path.parent.glob(f".{self.vault_path.name}.*.tmp")), [])

    def test_create_refuses_to_overwrite_existing_vault(self) -> None:
        vault.create_vault(self.vault_path, FAKE_MASTER_PASSWORD)
        before = self.vault_path.read_bytes()
        with self.assertRaises(FileExistsError):
            vault.create_vault(self.vault_path, FAKE_MASTER_PASSWORD)
        self.assertEqual(self.vault_path.read_bytes(), before)

    def test_malformed_envelope_fails_without_returning_records(self) -> None:
        self._assert_rejected_before_kdf({"version": vault.VAULT_VERSION})

    def test_unsupported_version_fails_before_kdf(self) -> None:
        envelope = self._valid_envelope()
        envelope["version"] = vault.VAULT_VERSION + 1
        self._assert_rejected_before_kdf(envelope)

    def test_unsupported_kdf_fails_before_kdf(self) -> None:
        envelope = self._valid_envelope()
        envelope["kdf"]["name"] = "not-argon2id"
        self._assert_rejected_before_kdf(envelope)

    def test_unsupported_cipher_fails_before_kdf(self) -> None:
        envelope = self._valid_envelope()
        envelope["cipher"] = "not-aes-256-gcm"
        self._assert_rejected_before_kdf(envelope)

    def test_absurd_memory_cost_fails_before_kdf(self) -> None:
        envelope = self._valid_envelope()
        envelope["kdf"]["memory_cost_kib"] = vault.MAX_MEMORY_COST_KIB + 1
        self._assert_rejected_before_kdf(envelope)

    def test_absurd_iteration_count_fails_before_kdf(self) -> None:
        envelope = self._valid_envelope()
        envelope["kdf"]["iterations"] = vault.MAX_ITERATIONS + 1
        self._assert_rejected_before_kdf(envelope)

    def test_absurd_lanes_fails_before_kdf(self) -> None:
        envelope = self._valid_envelope()
        envelope["kdf"]["lanes"] = vault.MAX_LANES + 1
        self._assert_rejected_before_kdf(envelope)

    def test_invalid_salt_fails_before_kdf(self) -> None:
        envelope = self._valid_envelope()
        envelope["salt"] = base64.b64encode(b"short-salt").decode("ascii")
        self._assert_rejected_before_kdf(envelope)

    def test_invalid_nonce_fails_before_kdf(self) -> None:
        envelope = self._valid_envelope()
        envelope["nonce"] = base64.b64encode(b"short").decode("ascii")
        self._assert_rejected_before_kdf(envelope)

    def test_truncated_ciphertext_fails_before_kdf(self) -> None:
        envelope = self._valid_envelope()
        envelope["ciphertext"] = base64.b64encode(b"truncated").decode("ascii")
        self._assert_rejected_before_kdf(envelope)


if __name__ == "__main__":
    unittest.main()
