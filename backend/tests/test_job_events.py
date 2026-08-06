import asyncio
import unittest

from backend.jobs.manager import ScanJobManager
from backend.jobs.models import CreateScanJobRequest, ScanJobStatus


class ScanJobEventTests(unittest.IsolatedAsyncioTestCase):
    async def test_each_subscriber_receives_its_own_status_updates(self) -> None:
        manager = ScanJobManager()
        job = manager.create(CreateScanJobRequest(scanner="nmap", target="example.test"))
        first = manager.subscribe(job.job_id)
        second = manager.subscribe(job.job_id)

        assert first is not None
        assert second is not None
        _, first_queue = first
        _, second_queue = second

        manager.update(job.job_id, status=ScanJobStatus.RUNNING, progress=10, current_phase="Executing scanners")

        first_update = await asyncio.wait_for(first_queue.get(), timeout=0.1)
        second_update = await asyncio.wait_for(second_queue.get(), timeout=0.1)
        self.assertEqual(first_update.status, ScanJobStatus.RUNNING)
        self.assertEqual(second_update.status, ScanJobStatus.RUNNING)

        manager.unsubscribe(job.job_id, first_queue)
        manager.unsubscribe(job.job_id, second_queue)
