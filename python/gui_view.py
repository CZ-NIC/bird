from PySide6.QtCore import (Qt, QEvent, QObject, QRunnable, QThreadPool, Signal, Slot)
from PySide6.QtWidgets import (QApplication, QLabel, QMainWindow, QPushButton, QVBoxLayout, QWidget)

from BIRD import BIRD

import asyncio
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


class ConnectedLayout(QWidget):
    def __init__(self, bird):
        super().__init__()
        self.bird = bird

        self.layout = QVBoxLayout(self)

        self.main_info = QLabel(f"Connected to {bird.version.name} {bird.version.version}")
        self.layout.addWidget(self.main_info)

        self.status = QLabel(f"Status: {bird.status.status}")
        self.layout.addWidget(self.status)

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
