from PySide6.QtCore import (Qt, QEvent, QObject, QRunnable, QThreadPool, Signal, Slot)
from PySide6.QtWidgets import (QApplication, QLabel, QMainWindow, QPushButton, QVBoxLayout, QWidget)

from BIRD import BIRD

import asyncio
import signal
import sys

# Async worker thread
class AsyncWorker(QRunnable):
    @Slot()
    def run(self):
        self.loop = asyncio.new_event_loop()
        self.loop.run_forever()

    def stop(self):
        asyncio.run_coroutine_threadsafe(self._stop_internal(), self.loop)

    async def _stop_internal(self):
        self.loop.stop()

    def dispatch(coro):
        asyncio.run_coroutine_threadsafe(coro, AsyncWorker.worker.loop)

if not hasattr(AsyncWorker, "worker"):
    AsyncWorker.worker = AsyncWorker()


class MainWindow(QMainWindow):

    start_signal = Signal()
    done_signal = Signal()

    def __init__(self):
        super().__init__()

        self.bird = BIRD("/run/bird/bird.ctl")
        self.initial_layout()

    def initial_layout(self):
        widget = QWidget()
        self.setCentralWidget(widget)

        layout = QVBoxLayout(widget)

        self.text = QLabel("No connection to BIRD.")
        layout.addWidget(self.text, alignment=Qt.AlignmentFlag.AlignCenter)

        async_trigger = QPushButton(text="Connect")
        async_trigger.clicked.connect(self.connect)
        layout.addWidget(async_trigger, alignment=Qt.AlignmentFlag.AlignCenter)

    @Slot()
    def connect(self):
        async def f():
            async with self.bird as b:
                await b.version.update()
                await b.status.update()

                self.text.setText(f"Connected to {b.version.name} {b.version.version}")

        AsyncWorker.dispatch(f())

if __name__ == "__main__":
    app = QApplication(sys.argv)
    threadpool = QThreadPool()
    threadpool.start(AsyncWorker.worker)

    mainwindow = MainWindow()
    mainwindow.show()

    signal.signal(signal.SIGINT, signal.SIG_DFL)
    app.exec()
    AsyncWorker.worker.stop()
