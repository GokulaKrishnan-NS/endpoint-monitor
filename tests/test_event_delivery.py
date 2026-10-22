"""
Tests for the event delivery mechanism, the bounded process-event cache and
the incremental table refresh behaviour (GUI phase).
"""

import os
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

from src.models.event import Event
from src.ui.engine import MonitoringEngine
from src.ui.table_sync import sync_tree_rows


class FakeTree:
    """Minimal stand-in for a ttk.Treeview used by the refresh tests."""

    def __init__(self):
        self.items = {}
        self._counter = 0
        self._selected = []
        self.insert_calls = 0
        self.delete_calls = 0

    # -- ttk.Treeview compatible subset -------------------------------
    def get_children(self):
        return list(self.items.keys())

    def item(self, item_id, option=None, **kwargs):
        if option == "values":
            return self.items.get(item_id, ())
        if "values" in kwargs:
            self.items[item_id] = tuple(kwargs["values"])
            return {"values": self.items[item_id]}
        return {"values": self.items.get(item_id, ())}

    def insert(self, parent, index, values=None):
        self.insert_calls += 1
        item_id = f"item-{self._counter}"
        self._counter += 1
        self.items[item_id] = tuple(values or ())
        return item_id

    def delete(self, *item_ids):
        if len(item_ids) == 1 and isinstance(item_ids[0], (list, tuple)):
            item_ids = item_ids[0]
        for item_id in item_ids:
            self.delete_calls += 1
            self.items.pop(item_id, None)

    def selection(self):
        return list(self._selected)

    def selection_set(self, item_ids):
        self._selected = list(item_ids)

    def yview(self):
        return (0.0, 1.0)

    def yview_moveto(self, fraction):
        return None


class TestEventQueueDelivery(unittest.TestCase):
    """The engine publishes events and the UI consumes them exactly once."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.baseline_path = os.path.join(self.temp_dir.name, "baseline.json")
        self.engine = MonitoringEngine(
            poll_interval=1.0,
            max_events_capacity=50,
            max_queue_size=10,
            baseline_path=self.baseline_path,
        )

    def tearDown(self):
        self.engine.stop(timeout=1.0)
        self.temp_dir.cleanup()

    def test_ingested_event_is_delivered_through_the_queue(self):
        event = Event(event_id="evt-1", severity="HIGH", risk_score=9)
        self.engine._ingest_event(event)

        delivered = self.engine.poll_new_events(max_items=10)
        self.assertEqual(len(delivered), 1)
        self.assertEqual(delivered[0].event_id, "evt-1")

        # The queue is drained exactly once
        self.assertEqual(self.engine.poll_new_events(max_items=10), [])

    def test_event_is_not_duplicated_between_queue_and_snapshot(self):
        event = Event(event_id="evt-2", severity="HIGH", risk_score=9)
        self.engine._ingest_event(event)

        delivered = self.engine.poll_new_events(max_items=10)
        snapshot = self.engine.get_events_snapshot()

        self.assertEqual(len(delivered), 1)
        self.assertEqual(len([e for e in snapshot if e.event_id == "evt-2"]), 1)

    def test_saturated_queue_keeps_the_newest_notification(self):
        engine = MonitoringEngine(
            poll_interval=1.0,
            max_events_capacity=100,
            max_queue_size=3,
            baseline_path=self.baseline_path,
        )
        try:
            for index in range(10):
                engine._ingest_event(
                    Event(event_id=f"evt-{index}", severity="LOW", risk_score=0)
                )

            delivered = engine.poll_new_events(max_items=100)
            ids = [event.event_id for event in delivered]

            # No event is lost from the authoritative bounded history
            history_ids = [event.event_id for event in engine.get_events_snapshot()]
            for index in range(10):
                self.assertIn(f"evt-{index}", history_ids)

            # The newest notifications are kept, the oldest are evicted
            self.assertLessEqual(len(ids), 3)
            self.assertIn("evt-9", ids)
            self.assertNotIn("evt-0", ids)
        finally:
            engine.stop(timeout=1.0)

    def test_alert_history_is_preserved_when_the_queue_drops_notifications(self):
        engine = MonitoringEngine(
            poll_interval=1.0,
            max_events_capacity=100,
            max_alerts_capacity=100,
            max_queue_size=2,
            baseline_path=self.baseline_path,
        )
        try:
            for index in range(5):
                engine._ingest_event(
                    Event(
                        event_id=f"alert-{index}",
                        severity="HIGH",
                        risk_score=9,
                        indicators=["encoded_command"],
                    )
                )
            alerts = engine.get_alerts_snapshot()
            self.assertEqual(len(alerts), 5)
        finally:
            engine.stop(timeout=1.0)


class TestProcessEventCache(unittest.TestCase):
    """The per-process evaluation cache must stay bounded."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.baseline_path = os.path.join(self.temp_dir.name, "baseline.json")

    def tearDown(self):
        self.temp_dir.cleanup()

    def _engine(self, capacity=50):
        return MonitoringEngine(
            poll_interval=1.0,
            max_process_events_capacity=capacity,
            baseline_path=self.baseline_path,
        )

    def test_exited_processes_are_evicted(self):
        engine = self._engine()
        try:
            engine._process_events[10] = Event(pid=10, timestamp=1.0)
            engine._process_events[11] = Event(pid=11, timestamp=2.0)

            engine._prune_process_events({10: {"pid": 10, "create_time": 1.0}})

            self.assertIn(10, engine.get_process_events_snapshot())
            self.assertNotIn(11, engine.get_process_events_snapshot())
        finally:
            engine.stop(timeout=1.0)

    def test_transient_collection_failure_keeps_process_state(self):
        engine = self._engine()
        try:
            engine._process_events[10] = Event(pid=10, timestamp=1.0)

            # An empty snapshot means the collection failed - nothing is evicted
            engine._prune_process_events({})

            self.assertIn(10, engine.get_process_events_snapshot())
        finally:
            engine.stop(timeout=1.0)

    def test_cache_capacity_is_enforced(self):
        engine = self._engine(capacity=10)
        try:
            for pid in range(100):
                engine._process_events[pid] = Event(pid=pid, timestamp=float(pid))

            engine._prune_process_events(
                {pid: {"pid": pid, "create_time": float(pid)} for pid in range(100)}
            )

            self.assertLessEqual(len(engine.get_process_events_snapshot()), 10)
        finally:
            engine.stop(timeout=1.0)


class TestIncrementalTableRefresh(unittest.TestCase):
    """Rows are updated in place instead of being recreated every tick."""

    def test_rows_are_inserted_updated_and_removed(self):
        tree = FakeTree()

        stats = sync_tree_rows(tree, [(1, "a"), (2, "b")])
        self.assertEqual(stats["inserted"], 2)
        self.assertEqual(len(tree.get_children()), 2)

        original_ids = tree.get_children()

        stats = sync_tree_rows(tree, [(1, "a"), (2, "changed"), (3, "c")])
        self.assertEqual(stats["inserted"], 1)
        self.assertEqual(stats["updated"], 1)
        self.assertEqual(stats["removed"], 0)
        self.assertEqual(len(tree.get_children()), 3)

        # The unchanged row keeps its identity
        self.assertEqual(tree.get_children()[0], original_ids[0])

        stats = sync_tree_rows(tree, [(1, "a")])
        self.assertEqual(stats["removed"], 2)
        self.assertEqual(len(tree.get_children()), 1)

    def test_unchanged_rows_are_not_rewritten(self):
        tree = FakeTree()
        sync_tree_rows(tree, [(1, "a"), (2, "b")])
        insert_calls = tree.insert_calls

        stats = sync_tree_rows(tree, [(1, "a"), (2, "b")])
        self.assertEqual(stats["unchanged"], 2)
        self.assertEqual(stats["inserted"], 0)
        self.assertEqual(stats["updated"], 0)
        self.assertEqual(tree.insert_calls, insert_calls)

    def test_selection_is_preserved(self):
        tree = FakeTree()
        sync_tree_rows(tree, [(1, "a"), (2, "b")])
        tree.selection_set([tree.get_children()[1]])

        sync_tree_rows(tree, [(1, "a"), (2, "b"), (3, "c")])

        selected = tree.selection()
        self.assertEqual(len(selected), 1)
        values = tree.item(selected[0], "values")
        self.assertEqual(values[0], 2)

    def test_stale_rows_are_removed_and_selection_cleaned(self):
        tree = FakeTree()
        sync_tree_rows(tree, [(1, "a"), (2, "b")])
        tree.selection_set([tree.get_children()[1]])

        sync_tree_rows(tree, [(1, "a")])

        self.assertEqual(len(tree.get_children()), 1)
        self.assertEqual(tree.selection(), [])


class TestDashboardConsumesQueue(unittest.TestCase):
    """The desktop UI drains the notification queue without duplicating rows."""

    def setUp(self):
        from src.ui.dashboard import is_gui_available

        if not is_gui_available():
            self.skipTest("GUI display environment not available (headless mode).")

        import tkinter as tk

        self.temp_dir = tempfile.TemporaryDirectory()
        self.baseline_path = os.path.join(self.temp_dir.name, "baseline.json")
        self.engine = MonitoringEngine(
            poll_interval=1.0, baseline_path=self.baseline_path
        )
        self.root = tk.Tk()
        self.root.withdraw()

    def tearDown(self):
        try:
            self.root.destroy()
        except Exception:
            pass
        self.engine.stop(timeout=1.0)
        self.temp_dir.cleanup()

    def test_ui_poll_cycle_drains_the_queue(self):
        from src.ui.dashboard import SecurityDashboardApp

        app = SecurityDashboardApp(engine=self.engine, root=self.root, auto_start=False)
        try:
            self.engine._ingest_event(
                Event(
                    event_id="gui-evt-1",
                    event_type="process_start",
                    source="process_monitor",
                    severity="HIGH",
                    risk_score=8,
                    process_name="probe.exe",
                )
            )

            app._ui_poll_cycle()

            # The queue was consumed by the UI
            self.assertEqual(self.engine.poll_new_events(max_items=10), [])
            self.assertGreaterEqual(app._new_event_count, 1)

            # The event is rendered exactly once in the alert table
            app._refresh_alerts_tree()
            children = app.tree_alerts.get_children()
            matching = [
                item
                for item in children
                if app.tree_alerts.item(item, "values")[4].startswith("probe.exe")
            ]
            self.assertEqual(len(matching), 1)
        finally:
            app.on_close()


if __name__ == "__main__":
    unittest.main()
