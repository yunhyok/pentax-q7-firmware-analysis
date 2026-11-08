"""A scheduled delivery must still be rejected when queue submission fails."""
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'tools'))
import check_af_completion as af


class QueueDeliveryTests(unittest.TestCase):
    def test_scheduled_delivery_requires_accepted_submission(self):
        name, setup, (action,) = next(c for c in af.CASES if c[0] == 'search-queue-rejected')
        self.assertEqual((name, setup['queue_send_result'], action[3]), ('search-queue-rejected', 0, 1))
        hooks = {}
        af.install(SimpleNamespace(hook=lambda pc, proc: hooks.update({pc:proc})), Mock(),
                   SimpleNamespace(SimProcedure=object))
        delay = hooks[af.DELAY]
        for status in (0, 1):
            delay.state = SimpleNamespace(globals=dict(queue_send_result=status, delivery=action[3], messages=(6,), link_result=1))
            with self.subTest(status=status), patch.object(af, 'make_state', side_effect=RuntimeError('worker entered')) as worker:
                if status == 0:
                    for _ in range(101):
                        self.assertEqual(delay.run(1), 0)
                    self.assertEqual(delay.state.globals['wait_count'], 101)
                    worker.assert_not_called()
                else:
                    with self.assertRaisesRegex(RuntimeError, 'worker entered'):
                        delay.run(1)
                    worker.assert_called_once()


if __name__ == '__main__':
    unittest.main()
