import unittest

from backend.scanners.profiles import resolve_profile


class ScanProfileTests(unittest.TestCase):
    def test_external_comprehensive_profile_contains_full_toolchain(self) -> None:
        self.assertEqual(
            resolve_profile("external_attack_surface", "comprehensive"),
            ("subfinder", "amass", "dnsx", "httpx", "naabu", "nmap", "katana", "arjun", "nuclei"),
        )

    def test_web_modes_scale_from_lightweight_to_full_coverage(self) -> None:
        quick = resolve_profile("web_application_assessment", "quick")
        comprehensive = resolve_profile("web_application_assessment", "comprehensive")
        self.assertLess(len(quick), len(comprehensive))
        self.assertIn("hakrawler", comprehensive)

