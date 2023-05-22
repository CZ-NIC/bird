from PySide6.QtCore import (Qt, QEvent, QObject, QRunnable, QThreadPool, Signal, Slot)
from PySide6.QtWidgets import (QApplication, QLabel, QMainWindow, QPushButton, QHBoxLayout, QVBoxLayout, QWidget)

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
            AsyncWorker.worker.exception_happened.emit(e)

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

                self.connected_signal.emit(b)

        AsyncWorker.dispatch(f())

class ProtocolView(QWidget):
    def __init__(self, bp):
        super().__init__()
        self.bp = bp

        self.layout = QHBoxLayout(self)
        self.name_label = QLabel(self.bp.name)
        self.name_label.setStyleSheet("font-weight: bold")
        self.layout.addWidget(self.name_label)

class ProtocolListView(QWidget):
    def __init__(self, bird):
        super().__init__()
        self.bird = bird

        self.layout = QVBoxLayout(self)
        self.protocols = []

    @Slot(object)
    def redraw(self, protocols):
        for p in self.protocols:
            self.layout.removeWidget(p)

        self.protocols = [ ProtocolView(p) for p in protocols.data.values() ]
        for p in self.protocols:
            self.layout.addWidget(p)

class ConnectedLayout(QWidget):
    redraw_signal = Signal()

    def __init__(self, bird):
        super().__init__()
        self.bird = bird

        self.layout = QVBoxLayout(self)

        self.main_info = QLabel(f"Connected to {bird.version.name} {bird.version.version}")
        self.layout.addWidget(self.main_info)

        self.status = QLabel(f"Status: {bird.status.status}")
        self.layout.addWidget(self.status)

        self.protocols = ProtocolListView(self.bird)
        self.layout.addWidget(self.protocols)

        self.last_update = QLabel(f"Last update: {datetime.now()}")
        self.layout.addWidget(self.last_update)

        self.redraw_signal.connect(self.redraw_slot)
        AsyncWorker.dispatch(self.updater())

    async def updater(self):
        async with self.bird as b:
            await b.protocols.update()
        self.redraw_signal.emit()

        while True:
            await asyncio.sleep(5)
            async with self.bird as b:
                await b.version.update()
                await b.status.update()
                await b.protocols.update()
            self.redraw_signal.emit()

    @Slot()
    def redraw_slot(self):
        self.status.setText(f"Status: {self.bird.status.status}")
        self.main_info.setText(f"Connected to {self.bird.version.name} {self.bird.version.version}")
        self.protocols.redraw(self.bird.protocols)
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
        print("got exception")
        raise Exception() from e

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
