#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from PySide6.QtCore import QItemSelection, QModelIndex, QSortFilterProxyModel, Qt, QTimer
from PySide6.QtGui import QAction, QCloseEvent, QFont
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QStyle,
    QTableView,
    QTabWidget,
    QToolButton,
    QVBoxLayout,
    QWidget,
)
from PySide6.QtCore import QAbstractTableModel

from tool.aegis_events import (
    EventLogTailer,
    FlowRecord,
    FlowStore,
    body_detail_text,
    copy_value_for_id,
    event_detail_text,
    flow_events_jsonl,
    format_ts,
    log_event_text,
    overview_text,
    raw_detail_text,
    session_detail_text,
)
from tool.aegis_runtime import EmbeddedMitmRunner, build_parser as build_runtime_parser, prepare_mitm_confdir


class FlowTableModel(QAbstractTableModel):
    COLUMNS = ("Time", "Method", "HTTP", "Protocol", "State", "Path")

    def __init__(self, store: FlowStore) -> None:
        super().__init__()
        self.store = store

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        if parent.isValid():
            return 0
        return len(self.store.order)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        if parent.isValid():
            return 0
        return len(self.COLUMNS)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        flow = self.flow_at(index.row())
        if flow is None:
            return None
        if role == Qt.ItemDataRole.UserRole:
            return flow.flow_id
        if role not in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole):
            return None
        values = (
            format_ts(flow.last_ts, include_date=False),
            flow.method,
            flow.http_status,
            flow.display_protocol,
            flow.display_status,
            flow.display_path,
        )
        if role == Qt.ItemDataRole.ToolTipRole:
            return flow.url or flow.display_path
        return values[index.column()]

    def headerData(  # noqa: N802
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> Any:
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.COLUMNS[section]
        return None

    def add_event(self, event: dict[str, Any]) -> FlowRecord:
        flow_id = str(event.get("flow_id") or f"event:{event.get('ts', '')}")
        is_new = flow_id not in self.store.flows
        if is_new:
            row = len(self.store.order)
            self.beginInsertRows(QModelIndex(), row, row)
            flow, _ = self.store.apply(event)
            self.endInsertRows()
            return flow

        flow, _ = self.store.apply(event)
        row = self.store.order.index(flow.flow_id)
        top_left = self.index(row, 0)
        bottom_right = self.index(row, self.columnCount() - 1)
        self.dataChanged.emit(top_left, bottom_right, [Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole])
        return flow

    def clear(self) -> None:
        self.beginResetModel()
        self.store.clear()
        self.endResetModel()

    def flow_at(self, row: int) -> FlowRecord | None:
        if row < 0 or row >= len(self.store.order):
            return None
        return self.store.flows.get(self.store.order[row])


class FlowFilterProxyModel(QSortFilterProxyModel):
    def __init__(self) -> None:
        super().__init__()
        self.search_text = ""
        self.protocol_filter = "All"
        self.status_filter = "All"

    def set_search_text(self, text: str) -> None:
        self.search_text = text.strip().lower()
        self.refilter()

    def set_protocol_filter(self, value: str) -> None:
        self.protocol_filter = value
        self.refilter()

    def set_status_filter(self, value: str) -> None:
        self.status_filter = value
        self.refilter()

    def refilter(self) -> None:
        self.beginFilterChange()
        self.endFilterChange(QSortFilterProxyModel.Direction.Rows)

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:  # noqa: N802
        model = self.sourceModel()
        if not isinstance(model, FlowTableModel):
            return True
        flow = model.flow_at(source_row)
        if flow is None:
            return False
        if self.protocol_filter != "All" and flow.display_protocol != self.protocol_filter:
            return False
        if self.status_filter != "All" and flow.display_status != self.status_filter:
            return False
        if self.search_text and self.search_text not in flow.search_text:
            return False
        return True


class NetraceGuiWindow(QMainWindow):
    def __init__(self, args: Any) -> None:
        super().__init__()
        self.args = args
        self.event_log = Path(args.event_log).resolve()
        self.dump_dir = Path(args.dump_dir).resolve()
        self.runner: EmbeddedMitmRunner | None = None
        self.tailer = EventLogTailer(self.event_log)
        self.store = FlowStore()
        self.model = FlowTableModel(self.store)
        self.proxy = FlowFilterProxyModel()
        self.proxy.setSourceModel(self.model)
        self.selected_flow_id: str | None = None
        self._updating_filters = False

        self.setWindowTitle("Netrace")
        self.resize(1280, 820)
        self._build_ui()

        self.poll_timer = QTimer(self)
        self.poll_timer.setInterval(250)
        self.poll_timer.timeout.connect(self.poll_events)
        self.poll_timer.start()

        self.event_log.parent.mkdir(parents=True, exist_ok=True)
        self.dump_dir.mkdir(parents=True, exist_ok=True)
        if not getattr(args, "no_autostart", False):
            self.start_proxy()
        else:
            self.set_status("Ready. Autostart disabled.")

    def _build_ui(self) -> None:
        root = QWidget(self)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(6)
        self.start_button = QPushButton("Start")
        self.start_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPlay))
        self.start_button.clicked.connect(self.start_proxy)
        self.stop_button = QPushButton("Stop")
        self.stop_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaStop))
        self.stop_button.clicked.connect(self.stop_proxy)
        self.clear_button = QPushButton("Clear")
        self.clear_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogResetButton))
        self.clear_button.clicked.connect(self.clear_flows)

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search URL, body, status, protocol...")
        self.search_edit.textChanged.connect(self.on_search_changed)

        self.protocol_combo = QComboBox()
        self.protocol_combo.addItem("All")
        self.protocol_combo.currentTextChanged.connect(self.on_protocol_filter_changed)
        self.status_combo = QComboBox()
        self.status_combo.addItem("All")
        self.status_combo.currentTextChanged.connect(self.on_status_filter_changed)

        self.copy_button = QToolButton()
        self.copy_button.setText("Copy")
        self.copy_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.copy_button.setMenu(self._copy_menu())

        self.export_button = QToolButton()
        self.export_button.setText("Export")
        self.export_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.export_button.setMenu(self._export_menu())

        toolbar.addWidget(self.start_button)
        toolbar.addWidget(self.stop_button)
        toolbar.addWidget(self.clear_button)
        toolbar.addSpacing(8)
        toolbar.addWidget(QLabel("Search"))
        toolbar.addWidget(self.search_edit, 1)
        toolbar.addWidget(QLabel("Protocol"))
        toolbar.addWidget(self.protocol_combo)
        toolbar.addWidget(QLabel("State"))
        toolbar.addWidget(self.status_combo)
        toolbar.addWidget(self.copy_button)
        toolbar.addWidget(self.export_button)
        layout.addLayout(toolbar)

        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setColumnWidth(0, 82)
        self.table.setColumnWidth(1, 72)
        self.table.setColumnWidth(2, 58)
        self.table.setColumnWidth(3, 78)
        self.table.setColumnWidth(4, 190)
        self.table.selectionModel().selectionChanged.connect(self.on_selection_changed)

        self.tabs = QTabWidget()
        self.detail_views: dict[str, QPlainTextEdit] = {}
        for key, title in (
            ("overview", "Overview"),
            ("request", "Request"),
            ("response", "Response"),
            ("request-body", "Request Body"),
            ("response-body", "Response Body"),
            ("raw", "Raw"),
            ("session", "Session"),
        ):
            edit = QPlainTextEdit()
            edit.setReadOnly(True)
            edit.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
            edit.setFont(QFont("Consolas", 10))
            self.detail_views[key] = edit
            self.tabs.addTab(edit, title)

        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        main_splitter.addWidget(self.table)
        main_splitter.addWidget(self.tabs)
        main_splitter.setStretchFactor(0, 3)
        main_splitter.setStretchFactor(1, 4)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(3000)
        self.log_view.setFont(QFont("Consolas", 9))

        vertical_splitter = QSplitter(Qt.Orientation.Vertical)
        vertical_splitter.addWidget(main_splitter)
        vertical_splitter.addWidget(self.log_view)
        vertical_splitter.setStretchFactor(0, 5)
        vertical_splitter.setStretchFactor(1, 1)
        layout.addWidget(vertical_splitter, 1)

        self.setCentralWidget(root)
        self.statusBar().showMessage("Ready")
        self._sync_running_buttons()
        self._render_empty_details()

    def _copy_menu(self) -> QMenu:
        menu = QMenu(self)
        for label, copy_id in (
            ("URL", "url"),
            ("Request Headers", "request-headers"),
            ("Request Body", "request-body"),
            ("Response Headers", "response-headers"),
            ("Response Body", "response-body"),
            ("Raw Events", "raw-events"),
            ("Session", "session-info"),
        ):
            action = QAction(label, self)
            action.triggered.connect(lambda _checked=False, value=copy_id: self.copy_selected(value))
            menu.addAction(action)
        return menu

    def _export_menu(self) -> QMenu:
        menu = QMenu(self)
        for label, export_id in (
            ("Selected Raw Events JSON", "raw-events"),
            ("Selected Request Body", "request-body"),
            ("Selected Response Body", "response-body"),
            ("Filtered Events JSONL", "filtered-events"),
        ):
            action = QAction(label, self)
            action.triggered.connect(lambda _checked=False, value=export_id: self.export_data(value))
            menu.addAction(action)
        return menu

    def start_proxy(self) -> None:
        if self.runner is not None:
            self.set_status("Embedded mitmproxy is already running.")
            return
        try:
            self.event_log.write_text("", encoding="utf-8")
            self.tailer.reset()
            confdir = prepare_mitm_confdir(self.args)
            self.runner = EmbeddedMitmRunner(self.args, confdir)
            self.runner.start()
        except Exception as exc:
            self.runner = None
            self.set_status(f"embedded mitmproxy failed: {exc}")
            QMessageBox.critical(self, "Netrace", f"embedded mitmproxy failed:\n{exc}")
            self._sync_running_buttons()
            return
        self.set_status(
            f"listening on {self.args.listen_host}:{self.args.listen_port} | upstream: {self.args.upstream_proxy}"
        )
        self.append_log(f"event log: {self.event_log}")
        if confdir is not None:
            self.append_log(f"mitm CA confdir: {confdir}")
        self._sync_running_buttons()

    def stop_proxy(self) -> None:
        if self.runner is None:
            self.set_status("Embedded mitmproxy is not running.")
            return
        self.runner.stop()
        self.runner = None
        self.set_status("Embedded mitmproxy stopped.")
        self._sync_running_buttons()

    def clear_flows(self) -> None:
        self.model.clear()
        self.selected_flow_id = None
        self.log_view.clear()
        self._render_empty_details()
        self._update_filter_options()
        self._sync_selection_after_filter()

    def poll_events(self) -> None:
        events = self.tailer.read_new()
        if not events:
            return
        first_new = self.model.rowCount() == 0
        for event in events:
            flow = self.model.add_event(event)
            self.append_log(log_event_text(event))
            if self.selected_flow_id == flow.flow_id:
                self.render_flow(flow)
        self.proxy.refilter()
        self._update_filter_options()
        self._sync_selection_after_filter()
        if first_new and self.proxy.rowCount() > 0:
            self.table.selectRow(0)

    def on_search_changed(self, text: str) -> None:
        self.proxy.set_search_text(text)
        self._sync_selection_after_filter()

    def on_protocol_filter_changed(self, value: str) -> None:
        self.proxy.set_protocol_filter(value)
        self._sync_selection_after_filter()

    def on_status_filter_changed(self, value: str) -> None:
        self.proxy.set_status_filter(value)
        self._sync_selection_after_filter()

    def on_selection_changed(self, selected: QItemSelection, _deselected: QItemSelection) -> None:
        indexes = selected.indexes()
        if not indexes:
            self.selected_flow_id = None
            self._render_empty_details()
            return
        source_index = self.proxy.mapToSource(indexes[0])
        flow = self.model.flow_at(source_index.row())
        if flow is None:
            return
        self.selected_flow_id = flow.flow_id
        self.render_flow(flow)

    def render_flow(self, flow: FlowRecord) -> None:
        response_event = flow.response_event or flow.key_event
        self.detail_views["overview"].setPlainText(overview_text(flow))
        self.detail_views["request"].setPlainText(event_detail_text("Request", flow.request_event))
        self.detail_views["response"].setPlainText(event_detail_text("Response", response_event))
        self.detail_views["request-body"].setPlainText(body_detail_text("Request Body", flow.request_event))
        self.detail_views["response-body"].setPlainText(body_detail_text("Response Body", response_event))
        self.detail_views["raw"].setPlainText(raw_detail_text(flow))
        self.detail_views["session"].setPlainText(session_detail_text(flow))

    def copy_selected(self, copy_id: str) -> None:
        flow = self.selected_flow()
        value = copy_value_for_id(flow, copy_id)
        if not value:
            self.set_status("Nothing to copy for the selected request.")
            return
        QApplication.clipboard().setText(value)
        self.set_status("Copied to clipboard.")

    def export_data(self, export_id: str) -> None:
        if export_id == "filtered-events":
            value = flow_events_jsonl(self.filtered_flows())
            default_name = "netrace-filtered-events.jsonl"
        else:
            flow = self.selected_flow()
            value = copy_value_for_id(flow, export_id)
            default_name = f"netrace-{export_id}.txt"
        if not value:
            self.set_status("Nothing to export.")
            return
        path, _selected_filter = QFileDialog.getSaveFileName(self, "Export", default_name, "All Files (*.*)")
        if not path:
            return
        Path(path).write_text(value, encoding="utf-8")
        self.set_status(f"Exported {path}")

    def selected_flow(self) -> FlowRecord | None:
        return self.store.get(self.selected_flow_id)

    def filtered_flows(self) -> list[FlowRecord]:
        flows: list[FlowRecord] = []
        for row in range(self.proxy.rowCount()):
            source_index = self.proxy.mapToSource(self.proxy.index(row, 0))
            flow = self.model.flow_at(source_index.row())
            if flow is not None:
                flows.append(flow)
        return flows

    def append_log(self, text: str) -> None:
        self.log_view.appendPlainText(text)

    def set_status(self, text: str) -> None:
        self.statusBar().showMessage(text)

    def _render_empty_details(self) -> None:
        for view in self.detail_views.values():
            view.setPlainText("Select a request")

    def _update_filter_options(self) -> None:
        if self._updating_filters:
            return
        self._updating_filters = True
        try:
            current_protocol = self.protocol_combo.currentText()
            current_status = self.status_combo.currentText()
            protocols = sorted({flow.display_protocol for flow in self.store.records() if flow.display_protocol != "-"})
            statuses = sorted({flow.display_status for flow in self.store.records() if flow.display_status})
            protocol = self._replace_combo_items(self.protocol_combo, ["All", *protocols], current_protocol)
            status = self._replace_combo_items(self.status_combo, ["All", *statuses], current_status)
            if self.proxy.protocol_filter != protocol:
                self.proxy.set_protocol_filter(protocol)
            if self.proxy.status_filter != status:
                self.proxy.set_status_filter(status)
        finally:
            self._updating_filters = False

    @staticmethod
    def _replace_combo_items(combo: QComboBox, values: list[str], current: str) -> str:
        final_value = current if current in values else "All"
        combo.blockSignals(True)
        combo.clear()
        combo.addItems(values)
        combo.setCurrentText(final_value)
        combo.blockSignals(False)
        return final_value

    def _sync_selection_after_filter(self) -> None:
        if self.selected_flow_id is None:
            return
        for row in range(self.proxy.rowCount()):
            source_index = self.proxy.mapToSource(self.proxy.index(row, 0))
            flow = self.model.flow_at(source_index.row())
            if flow is not None and flow.flow_id == self.selected_flow_id:
                return
        self.selected_flow_id = None
        self.table.clearSelection()
        self._render_empty_details()

    def _sync_running_buttons(self) -> None:
        running = self.runner is not None
        self.start_button.setEnabled(not running)
        self.stop_button.setEnabled(running)

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802
        self.poll_timer.stop()
        if self.runner is not None:
            self.runner.stop()
            self.runner = None
        event.accept()


def build_parser() -> Any:
    return build_runtime_parser(
        description="Netrace GUI for encrypted /xeapi and /eapi traffic",
        include_gui_options=True,
    )


def main() -> None:
    args = build_parser().parse_args()
    app = QApplication.instance()
    owns_app = app is None
    if app is None:
        app = QApplication(sys.argv)
    window = NetraceGuiWindow(args)
    window.show()
    if owns_app:
        raise SystemExit(app.exec())


if __name__ == "__main__":
    main()
