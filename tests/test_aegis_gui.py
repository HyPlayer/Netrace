from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from tool.aegis_events import FlowStore, copy_value_for_id, flow_events_jsonl
from tool.aegis_gui import NetraceGuiWindow
from tool.aegis_runtime import EmbeddedMitmRunner, prepare_mitm_confdir


def _events() -> list[dict[str, object]]:
    return [
        {
            "ts": 1000.0,
            "flow_id": "flow-1",
            "kind": "request",
            "protocol": "xeapi",
            "operation": "decrypt",
            "method": "POST",
            "url": "https://interface3.music.163.com/eapi/test",
            "path": "/eapi/test",
            "status": "request-decrypted",
            "request_headers": {"content-type": "application/x-www-form-urlencoded"},
            "body": "{\"hello\":\"request\"}",
            "r_plain": "1000000000000|",
        },
        {
            "ts": 1001.0,
            "flow_id": "flow-1",
            "kind": "response",
            "protocol": "xeapi",
            "operation": "decrypt",
            "method": "POST",
            "url": "https://interface3.music.163.com/eapi/test",
            "path": "/eapi/test",
            "http_status": 200,
            "status": "response-decrypted",
            "response_headers": {"content-type": "application/json"},
            "body": "{\"hello\":\"response\"}",
        },
        {
            "ts": 1002.0,
            "flow_id": "flow-1",
            "kind": "session",
            "protocol": "xeapi",
            "status": "session",
            "session_id": "sid",
            "session_key": "secret",
        },
    ]


def _gui_args(tmp: str | Path) -> SimpleNamespace:
    tmp_path = Path(tmp)
    return SimpleNamespace(
        listen_host="0.0.0.0",
        listen_port=8080,
        confdir="",
        ca_pem="",
        upstream_proxy="http://127.0.0.1:9370",
        ssl_insecure=True,
        static_key="hex:00",
        sign_key="b64:AA==",
        proxy_private_key_file=str(tmp_path / "proxy.key"),
        weapi_private_key_file=str(tmp_path / "weapi.key"),
        hkdf_salt="",
        hkdf_info="",
        response_mode="auto",
        force_key_refresh_on_miss=True,
        public_key_ttl_seconds=600,
        event_log=str(tmp_path / "events.jsonl"),
        dump_dir=str(tmp_path / "dumps"),
        no_autostart=True,
    )


class FlowEventTests(unittest.TestCase):
    def test_flow_store_aggregates_events_and_copy_values(self) -> None:
        store = FlowStore()
        for event in _events():
            flow, _is_new = store.apply(event)

        self.assertEqual(flow.flow_id, "flow-1")
        self.assertEqual(flow.display_protocol, "xeapi")
        self.assertEqual(flow.http_status, "200")
        self.assertEqual(flow.display_status, "response-decrypted")
        self.assertEqual(flow.session_key, "secret")
        self.assertIn("request", copy_value_for_id(flow, "request-body"))
        self.assertIn("response", copy_value_for_id(flow, "response-body"))
        self.assertEqual(copy_value_for_id(flow, "session-key"), "secret")

    def test_filtered_export_is_jsonl(self) -> None:
        store = FlowStore()
        for event in _events():
            store.apply(event)

        exported = flow_events_jsonl(store.records())
        lines = exported.splitlines()
        self.assertEqual(len(lines), 3)
        self.assertEqual(json.loads(lines[0])["flow_id"], "flow-1")


class RuntimeTests(unittest.TestCase):
    def test_missing_default_ca_reports_actionable_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _gui_args(tmp)
            args.ca_pem = ""
            args.confdir = str(Path(tmp) / "confdir")
            with patch("tool.aegis_runtime.DEFAULT_CA_PEM", Path(tmp) / "missing-ca.pem"):
                with self.assertRaises(FileNotFoundError) as raised:
                    prepare_mitm_confdir(args)
        message = str(raised.exception)
        self.assertIn("CA PEM not found", message)
        self.assertIn("--ca-pem PATH", message)

    def test_missing_explicit_ca_reports_actionable_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _gui_args(tmp)
            args.ca_pem = str(Path(tmp) / "explicit-missing-ca.pem")
            with self.assertRaises(FileNotFoundError) as raised:
                prepare_mitm_confdir(args)
        message = str(raised.exception)
        self.assertIn("explicit-missing-ca.pem", message)
        self.assertIn("--ca-pem PATH", message)

    def test_runner_start_times_out_when_ready_signal_never_arrives(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _gui_args(tmp)
            runner = EmbeddedMitmRunner(args, None)
            with (
                patch.object(runner, "_run", return_value=None),
                patch.object(runner.started, "wait", return_value=False),
                patch.object(runner, "stop") as stop,
            ):
                with self.assertRaises(TimeoutError):
                    runner.start()
        stop.assert_called_once()


class GuiSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def test_gui_no_autostart_renders_and_filters_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _gui_args(tmp)
            window = NetraceGuiWindow(args)
            self.addCleanup(window.close)

            for event in _events():
                flow = window.model.add_event(event)
            window.render_flow(flow)
            window.proxy.refilter()
            window._update_filter_options()

            self.assertEqual(window.model.rowCount(), 1)
            self.assertEqual(window.proxy.rowCount(), 1)
            self.assertIn("response-decrypted", window.detail_views["overview"].toPlainText())
            self.assertIn("request", window.detail_views["request-body"].toPlainText())

            window.search_edit.setText("response")
            self.assertEqual(window.proxy.rowCount(), 1)
            window.search_edit.setText("not-present")
            self.assertEqual(window.proxy.rowCount(), 0)

            window.search_edit.clear()
            window.protocol_combo.setCurrentText("xeapi")
            self.assertEqual(window.proxy.rowCount(), 1)

    def test_gui_clear_resets_combo_and_proxy_filters(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            window = NetraceGuiWindow(_gui_args(tmp))
            self.addCleanup(window.close)

            for event in _events():
                window.model.add_event(event)
            window._update_filter_options()

            window.protocol_combo.setCurrentText("xeapi")
            window.status_combo.setCurrentText("response-decrypted")
            self.assertEqual(window.proxy.protocol_filter, "xeapi")
            self.assertEqual(window.proxy.status_filter, "response-decrypted")

            window.clear_flows()

            self.assertEqual(window.protocol_combo.currentText(), "All")
            self.assertEqual(window.status_combo.currentText(), "All")
            self.assertEqual(window.proxy.protocol_filter, "All")
            self.assertEqual(window.proxy.status_filter, "All")

    def test_gui_filter_hiding_selection_clears_details_and_copy_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            window = NetraceGuiWindow(_gui_args(tmp))
            self.addCleanup(window.close)

            for event in _events():
                window.model.add_event(event)
            window.proxy.refilter()
            window.table.selectRow(0)
            self.assertIsNotNone(window.selected_flow())

            window.search_edit.setText("not-present")

            self.assertIsNone(window.selected_flow_id)
            self.assertIsNone(window.selected_flow())
            self.assertEqual(window.copy_button.menu().actions()[0].text(), "URL")
            self.assertEqual(window.detail_views["overview"].toPlainText(), "Select a request")


if __name__ == "__main__":
    unittest.main()
