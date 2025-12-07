"""
Debug timer widget for Binary Ninja status bar.
"""
from PySide6 import QtWidgets, QtCore
from PySide6.QtCore import QTimer

try:
    from .log import logger
except ImportError:
    from log import logger


class DebugTimerWidget(QtWidgets.QWidget):
    """A status bar widget that displays and counts up the time spent debugging."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.total_seconds = 0
        self.running = True

        self.label = QtWidgets.QLabel("Time Wasted Debugging: 00:00:00:00", self)
        self.label.setToolTip("Days:Hours:Minutes:Seconds")

        layout = QtWidgets.QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.label)
        self.setLayout(layout)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_time)
        self.timer.start(100)

        self.setMaximumWidth(300)

    def update_time(self):
        """Update the timer display."""
        if self.running:
            self.total_seconds += 0.1

        total_seconds = int(self.total_seconds)

        days = total_seconds // 86400
        hours = (total_seconds % 86400) // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60

        time_str = f"Time Wasted Debugging: {days:02d}:{hours:02d}:{minutes:02d}:{seconds:02d}"
        self.label.setText(time_str)

    def toggle_timer(self):
        """Toggle the timer between running and paused states."""
        self.running = not self.running
        return self.running

    def reset_timer(self):
        """Reset the timer to zero."""
        self.total_seconds = 0
        self.update_time()

    def mouseReleaseEvent(self, event):
        """Handle mouse click events to toggle the timer."""
        super().mouseReleaseEvent(event)
        if event.button() == QtCore.Qt.MouseButton.RightButton:
            self.show_context_menu(event.pos())

    def show_context_menu(self, pos):
        """Show a context menu with timer options."""
        menu = QtWidgets.QMenu(self)

        toggle_action = menu.addAction("Start Timer" if not self.running else "Pause Timer")
        toggle_action.triggered.connect(self.toggle_timer)

        reset_action = menu.addAction("Reset Timer")
        reset_action.triggered.connect(self.reset_timer)

        menu.exec(self.mapToGlobal(pos))


def init_debug_timer(settings, core_ui_enabled):
    """Initialize the debug timer if UI is enabled and the setting is turned on

    Args:
        settings: Binary Ninja Settings object
        core_ui_enabled: Function to check if core UI is enabled

    Returns:
        DebugTimerWidget: The created widget, or None if not created
    """
    debug_timer_widget = None
    if core_ui_enabled() and settings.get_bool("bnwrap.show_debug_timer"):
        try:
            from binaryninjaui import UIContext

            def add_debug_timer_to_status_bar():
                nonlocal debug_timer_widget

                contexts = UIContext.allContexts()
                if not contexts:
                    QTimer.singleShot(1000, add_debug_timer_to_status_bar)
                    return

                window = contexts[0].mainWindow()
                if window:
                    status_bar = window.statusBar()
                    debug_timer_widget = DebugTimerWidget()
                    status_bar.addPermanentWidget(debug_timer_widget)
                    logger.log_info("Debug timer widget added to status bar")

            # Start the process to add the widget when UI is ready
            QTimer.singleShot(1000, add_debug_timer_to_status_bar)

        except ImportError:
            logger.log_error("Failed to import UI modules for debug timer")

    return debug_timer_widget
