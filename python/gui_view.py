from PySide6.QtCore import (Qt, QEvent, QObject, QRunnable, QThreadPool, Signal, Slot)
from PySide6.QtWidgets import (QApplication, QFrame, QLabel, QMainWindow, QPushButton, QHBoxLayout, QVBoxLayout, QWidget)

from BIRD import BIRD

import asyncio
from datetime import datetime
import signal
import sys

# Async worker thread
class AsyncWorker(QRunnable, QObject):
    def __init__(self):
        QRunnable.__init__(self)
        QObject.__init__(self)

    exception_signal = Signal(Exception)

    @Slot()
    def run(self):
        self.loop = asyncio.new_event_loop()
        self.loop.run_forever()

    def stop(self):
        asyncio.run_coroutine_threadsafe(self._stop_internal(), self.loop)

    async def _stop_internal(self):
        self.loop.stop()

    async def dispatch_and_check_exception(coro):
        try:
            await coro
        except Exception as e:
            AsyncWorker.worker.exception_signal.emit(e)

    def dispatch(coro):
        asyncio.run_coroutine_threadsafe(AsyncWorker.dispatch_and_check_exception(coro), AsyncWorker.worker.loop)

if not hasattr(AsyncWorker, "worker"):
    AsyncWorker.worker = AsyncWorker()


class InitialLayout(QWidget):
    connected_signal = Signal(BIRD)

    def __init__(self):
        super().__init__()

        self.layout = QVBoxLayout(self)

        self.text = QLabel("No connection to BIRD.")
        self.layout.addWidget(self.text, alignment=Qt.AlignmentFlag.AlignCenter)

        async_trigger = QPushButton(text="Connect")
        async_trigger.clicked.connect(self.connect_slot)
        self.layout.addWidget(async_trigger, alignment=Qt.AlignmentFlag.AlignCenter)

    @Slot()
    def connect_slot(self):
        self.bird = BIRD("/run/bird/bird.ctl")

        async def f():
            async with self.bird as b:
                await b.version.update()
                await b.status.update()

            self.connected_signal.emit(self.bird)

        AsyncWorker.dispatch(f())

class ProtocolView(QFrame):
    update_signal = Signal()

    def __init__(self, bp):
        super().__init__()
        self.bp = bp
        self.setFrameShape(QFrame.Box)

        self.layout = QHBoxLayout(self)

        self.name_label = QLabel(self.bp.name)
        self.name_label.setStyleSheet("font-weight: bold;")
        self.layout.addWidget(self.name_label)

        self.state_label = QLabel(self.bp.state)
        self.layout.addWidget(self.state_label)

        self.disable_button = QPushButton("■")
        self.disable_button.clicked.connect(self.disable_slot)
        self.layout.addWidget(self.disable_button)

        self.enable_button = QPushButton("▶")
        self.enable_button.clicked.connect(self.enable_slot)
        self.layout.addWidget(self.enable_button)

        self.update_signal.connect(self.update_slot)
        self.update_signal.emit()

    def state_color(self):
        return {
                "down": "#ff8888",
                "up": "#88ff88",
                "start": "#cccc88",
                }[self.bp.state]

    @Slot()
    def update_slot(self):
        self.disable_button.setEnabled(self.bp.state != "down")
        self.enable_button.setEnabled(self.bp.state not in ( "up", "start"))
        self.state_label.setText(self.bp.state)
        self.state_label.setStyleSheet(f"background: {self.state_color()}; padding: 0.5em;")

    @Slot()
    def disable_slot(self):
        AsyncWorker.dispatch(self.disable_async())

    async def disable_async(self):
        async with self.bp.bird:
            await self.bp.disable()
        self.update_signal.emit()

    @Slot()
    def enable_slot(self):
        AsyncWorker.dispatch(self.enable_async())

    async def enable_async(self):
        async with self.bp.bird:
            await self.bp.enable()
        self.update_signal.emit()

class ProtocolListView(QWidget):
    def __init__(self):
        super().__init__()
        self.protocols = []
        self.layout = QVBoxLayout(self)

    def update_data(self, protocols):
        for p in self.protocols:
            self.layout.removeWidget(p)
            p.deleteLater()

        self.protocols = [ ProtocolView(p) for p in protocols.data.values() ]
        for p in self.protocols:
            self.layout.addWidget(p)

class ConnectedLayout(QWidget):
    redraw_signal = Signal(dict)

    def __init__(self, bird):
        super().__init__()
        self.bird = bird

        self.layout = QVBoxLayout(self)

        self.main_info = QLabel(f"Connected to {bird.version.name} {bird.version.version}")
        self.layout.addWidget(self.main_info)

        self.status = QLabel(f"Status: {bird.status.status}")
        self.layout.addWidget(self.status)

        self.protocols = ProtocolListView()
        self.layout.addWidget(self.protocols)

        self.last_update = QLabel(f"Last update: {datetime.now()}")
        self.layout.addWidget(self.last_update)

        self.redraw_signal.connect(self.redraw_slot)
        AsyncWorker.dispatch(self.updater())

    async def reload_state(self):
        async with self.bird as b:
            await b.version.update()
            await b.status.update()
            await b.protocols.update()

            self.redraw_signal.emit({
                "version": b.version,
                "status": b.status,
                "protocols": b.protocols,
                })

    async def updater(self):
        async with self.bird as b:
            await b.protocols.update()

            self.redraw_signal.emit({
                "version": b.version,
                "status": b.status,
                "protocols": b.protocols,
                })

        while True:
            await asyncio.sleep(0.3)
            await self.reload_state()

    @Slot(dict)
    def redraw_slot(self, data):
        self.status.setText(f"Status: {data['status'].status}")
        self.main_info.setText(f"Connected to {data['version'].name} {data['version'].version}")
        self.protocols.update_data(data['protocols'])
        self.last_update.setText(f"Last update: {datetime.now()}")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        AsyncWorker.worker.exception_signal.connect(self.exception_slot)

        self.set_layout(InitialLayout())
        self.layout.connected_signal.connect(self.connected_slot)

    def set_layout(self, layout):
        self.setCentralWidget(layout)
        self.layout = layout

    @Slot(Exception)
    def exception_slot(self, e):
        print("Exception in async thread")
        raise e

    @Slot(BIRD)
    def connected_slot(self, bird):
        self.set_layout(ConnectedLayout(bird))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    threadpool = QThreadPool()
    threadpool.start(AsyncWorker.worker)

    mainwindow = MainWindow()
    mainwindow.show()

    signal.signal(signal.SIGINT, signal.SIG_DFL)
    app.exec()
    AsyncWorker.worker.stop()
