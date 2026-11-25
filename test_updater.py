# -*- coding: utf-8 -*-
"""
test_updater.py - Unit tests for updater.py
"""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from updater import (
    parse_version_tuple,
    is_newer_version,
    _parse_json_update_info,
    _parse_github_release_info,
    compute_file_sha256,
    UpdateInfo,
)


class TestUpdater(unittest.TestCase):
    def test_parse_version_tuple(self):
        self.assertEqual(parse_version_tuple("2.4"), (2, 4))
        self.assertEqual(parse_version_tuple("v2.4.1"), (2, 4, 1))
        self.assertEqual(parse_version_tuple("3.0-beta"), (3, 0))
        self.assertEqual(parse_version_tuple(""), (0,))

    def test_is_newer_version(self):
        self.assertTrue(is_newer_version("2.4", "2.5"))
        self.assertTrue(is_newer_version("2.4", "2.4.1"))
        self.assertTrue(is_newer_version("v2.4.0", "v2.5.0"))
        self.assertTrue(is_newer_version("2.4", "3.0"))
        
        self.assertFalse(is_newer_version("2.4", "2.4"))
        self.assertFalse(is_newer_version("2.4.0", "2.4"))
        self.assertFalse(is_newer_version("2.5", "2.4"))
        self.assertFalse(is_newer_version("3.0", "2.9.9"))

    def test_parse_json_update_info(self):
        sample_json = {
            "version": "2.5",
            "release_date": "2026-09-01",
            "title": "Bản cập nhật v2.5",
            "changelog": [
                "⚡ Tối ưu ping",
                "🐛 Sửa lỗi kết nối"
            ],
            "download_url": "https://github.com/datpusheen/FreetonVPN/releases/download/v2.5/FreetonVPN.exe",
            "file_size_bytes": 15000000,
            "sha256": "ABCDEF1234567890",
            "mandatory": True,
            "min_supported_version": "2.0"
        }
        info = _parse_json_update_info(sample_json)
        self.assertEqual(info.version, "2.5")
        self.assertEqual(info.title, "Bản cập nhật v2.5")
        self.assertEqual(len(info.changelog), 2)
        self.assertEqual(info.sha256, "abcdef1234567890")
        self.assertTrue(info.mandatory)
        self.assertEqual(info.min_supported_version, "2.0")
        self.assertIn("Tối ưu ping", info.formatted_changelog)

    def test_parse_github_release_info(self):
        sample_gh = {
            "tag_name": "v2.5",
            "name": "Freeton VPN 2.5 Release",
            "published_at": "2026-09-01T12:00:00Z",
            "body": "- Tối ưu kết nối\n- Nâng cấp UI",
            "assets": [
                {
                    "name": "FreetonVPN.exe",
                    "browser_download_url": "https://github.com/datpusheen/FreetonVPN/releases/download/v2.5/FreetonVPN.exe",
                    "size": 18000000
                }
            ]
        }
        info = _parse_github_release_info(sample_gh)
        self.assertEqual(info.version, "2.5")
        self.assertEqual(info.release_date, "2026-09-01")
        self.assertEqual(info.download_url, "https://github.com/datpusheen/FreetonVPN/releases/download/v2.5/FreetonVPN.exe")
        self.assertEqual(info.file_size_bytes, 18000000)
        self.assertEqual(len(info.changelog), 2)

    def test_compute_file_sha256(self):
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"Hello Freeton VPN Updater Test")
            temp_path = Path(tf.name)

        try:
            expected = hashlib.sha256(b"Hello Freeton VPN Updater Test").hexdigest().lower()
            calculated = compute_file_sha256(temp_path)
            self.assertEqual(calculated, expected)
        finally:
            if temp_path.exists():
                temp_path.unlink()


if __name__ == "__main__":
    unittest.main()
