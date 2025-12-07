"""
Debug timer widget for Binary Ninja status bar.
"""
from PySide6 import QtWidgets, QtCore
from PySide6.QtCore import QTimer
from binaryninja.log import log as bnlog
from binaryninja.log import LogLevel


class DebugTimerWidget(QtWidgets.QWidget):
    """A status bar widget that displays and counts up the time spent debugging."""

    def __init__(self, parent=None):
        super(DebugTimerWidget, self).__init__(parent)
        self.total_seconds = 0
        self.running = True  # Start the timer by default

        # Create the label with the initial text
        self.label = QtWidgets.QLabel("Time Wasted Debugging: 00:00:00:00", self)
        self.label.setToolTip("Days:Hours:Minutes:Seconds")

        # Set up layout
        layout = QtWidgets.QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.label)
        self.setLayout(layout)

        # Create a timer to update every 100ms (1/10th of a second)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_time)
        self.timer.start(100)  # Update every 100ms

        # Make sure the widget doesn't take up too much space but move it left more
        self.setMaximumWidth(300)

    def update_time(self):
        """Update the timer display."""
        if self.running:
            self.total_seconds += 0.1  # 100ms = 0.1s

        # Calculate days, hours, minutes, seconds
        total_seconds = int(self.total_seconds)

        days = total_seconds // 86400
        hours = (total_seconds % 86400) // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60

        # Format time string with days:hours:minutes:seconds
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
            # Show context menu on right click
            self.show_context_menu(event.pos())

    def show_context_menu(self, pos):
        """Show a context menu with timer options."""
        menu = QtWidgets.QMenu(self)

        # Add timer control actions
        toggle_action = menu.addAction("Start Timer" if not self.running else "Pause Timer")
        toggle_action.triggered.connect(self.toggle_timer)

        reset_action = menu.addAction("Reset Timer")
        reset_action.triggered.connect(self.reset_timer)

        # Execute the menu
        menu.exec_(self.mapToGlobal(pos))


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
        # We need to import these modules only when UI is enabled
        try:
            from binaryninjaui import UIContext

            # Create a function to add the widget to the status bar
            def add_debug_timer_to_status_bar():
                nonlocal debug_timer_widget

                # Get all UI contexts
                contexts = UIContext.allContexts()
                if not contexts:
                    # No contexts available yet, try again later
                    QTimer.singleShot(1000, add_debug_timer_to_status_bar)
                    return

                # Add widget to the first context's status bar
                window = contexts[0].mainWindow()
                if window:
                    status_bar = window.statusBar()
                    debug_timer_widget = DebugTimerWidget()
                    status_bar.addPermanentWidget(debug_timer_widget)
                    bnlog(LogLevel.InfoLog, "Debug timer widget added to status bar")

            # Start the process to add the widget when UI is ready
            QTimer.singleShot(1000, add_debug_timer_to_status_bar)

        except ImportError:
            bnlog(LogLevel.ErrorLog, "Failed to import UI modules for debug timer")

    return debug_timer_widget
