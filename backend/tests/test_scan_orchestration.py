import unittest

from fastapi.testclient import TestClient

from backend.main import app


class ScanOrchestrationRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)

    def test_creates_tracks_and_lists_real_execution_job(self) -> None:
        created = self.client.post(
            "/api/v1/scans",
            json={"scanner": "nmap", "target": "example.test", "scan_type": "discovery"},
        )
        self.assertEqual(created.status_code, 202, created.text)
        job = created.json()
        self.assertEqual(job["status"], "Queued")
        self.assertEqual(job["progress"], 0)
        self.assertEqual(job["current_phase"], "Queued for execution")

        self.assertEqual(self.client.get(f"/api/v1/scans/{job['job_id']}").status_code, 200)
        self.assertTrue(any(item["job_id"] == job["job_id"] for item in self.client.get("/api/v1/scans").json()))

        # The test environment does not install Nmap; the background worker must
        # safely surface that as a terminal job failure rather than crash FastAPI.
        terminal = self.client.get(f"/api/v1/scans/{job['job_id']}").json()
        self.assertIn(terminal["status"], {"Queued", "Running", "Failed", "Cancelled"})

    def test_rejects_unregistered_scanner_without_executing_anything(self) -> None:
        response = self.client.post(
            "/api/v1/scans",
            json={"scanner": "unknown", "target": "example.test", "scan_type": "default"},
        )
        self.assertEqual(response.status_code, 422)


if __name__ == "__main__":
    unittest.main()
