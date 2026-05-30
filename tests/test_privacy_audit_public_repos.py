from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "privacy_audit_public_repos.py"
SPEC = importlib.util.spec_from_file_location("privacy_audit_public_repos", MODULE_PATH)
assert SPEC and SPEC.loader
audit = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = audit
SPEC.loader.exec_module(audit)


class PrivacyAuditTests(unittest.TestCase):
    def test_mask_value_keeps_context(self) -> None:
        value = audit.mask_value("maskable_value_abcdefghijklmnopqrstuvwxyz1234567890")
        self.assertTrue(value.startswith("mask"))
        self.assertIn("*", value)

    def test_allowed_github_url_is_stripped_before_matching(self) -> None:
        line = "homepage = https://github.com/subisle/demo"
        stripped = audit.strip_allowlisted_text(line)
        self.assertNotIn("github.com", stripped)

    def test_github_noreply_email_is_stripped_before_matching(self) -> None:
        line = "author: subisle <123456+subisle@users.noreply.github.com>"
        stripped = audit.strip_allowlisted_text(line)
        self.assertNotIn("@users.noreply.github.com", stripped)

    def test_agent_path_is_review_finding(self) -> None:
        findings = audit.scan_path("subisle/demo", "AGENTS.md", "history-path")
        self.assertTrue(any(item.rule == "agent_instruction_path" for item in findings))

    def test_secret_assignment_is_high_finding(self) -> None:
        findings = audit.scan_text(
            "subisle/demo",
            "config.py",
            "TOKEN = 'abc1234567890abc1234567890'",
            "blob:deadbeef",
        )
        self.assertTrue(
            any(item.rule == "secret_assignment" and item.severity == "high" for item in findings)
        )

    def test_scoped_npm_package_is_not_email(self) -> None:
        findings = audit.scan_text(
            "subisle/demo",
            "pnpm-lock.yaml",
            "'@types/node@20.19.37':",
            "blob:deadbeef",
        )
        self.assertFalse(any(item.rule == "email_address" for item in findings))

    def test_html_meta_name_is_not_contact_label(self) -> None:
        findings = audit.scan_text(
            "subisle/demo",
            "index.html",
            '<meta name="viewport" content="width=device-width">',
            "blob:deadbeef",
        )
        self.assertFalse(any(item.rule == "contact_label" for item in findings))

    def test_camel_case_full_name_variable_is_not_contact_label(self) -> None:
        findings = audit.scan_text(
            "subisle/demo",
            "model.kt",
            "val fullName: String? = null",
            "blob:deadbeef",
        )
        self.assertFalse(any(item.rule == "contact_label" for item in findings))

    def test_password_lookup_is_not_secret_assignment(self) -> None:
        findings = audit.scan_text(
            "subisle/demo",
            "database.py",
            "password = db_config['password']",
            "blob:deadbeef",
        )
        self.assertFalse(any(item.rule == "secret_assignment" for item in findings))

    def test_process_env_password_default_is_not_secret_assignment(self) -> None:
        findings = audit.scan_text(
            "subisle/demo",
            "database.ts",
            "password = process.env.DB_PASSWORD || 'your_password'",
            "blob:deadbeef",
        )
        self.assertFalse(any(item.rule == "secret_assignment" for item in findings))

    def test_known_binary_extension_is_not_scanned(self) -> None:
        self.assertFalse(audit.should_scan_blob("icon.webp", b"fake-binary-content"))

    def test_generated_typescript_build_info_is_not_scanned(self) -> None:
        self.assertFalse(audit.should_scan_blob("tsconfig.node.tsbuildinfo", b"12345678901"))


if __name__ == "__main__":
    unittest.main()
