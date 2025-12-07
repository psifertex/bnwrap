import os
from binaryninja import Settings, core_ui_enabled
from PySide6 import QtWidgets, QtCore

from .widget import BNWrappedWidget
from .uiutils import create_splash_image
from .debug_timer import init_debug_timer

widget = None
debug_timer_widget = None

# Register settings
settings = Settings()
settings.register_group("bnwrap", "Binary Ninja Wrapped")
settings.register_setting("bnwrap.show_debug_timer", """{
    "title": "Show Debug Timer",
    "description": "Show a timer in the status bar counting up the time you've spent debugging",
    "type": "boolean",
    "default": false,
    "requiresRestart": true
    }""")

# Initialize debug timer
debug_timer_widget = init_debug_timer(settings, core_ui_enabled)


def launchBNWrapped(context):
    """Launch the Binary Ninja Wrapped widget"""
    # Get the actual recent files from settings
    global widget
    recent_files = QtCore.QSettings().value("ui/recentFiles", [], type=list)

    # Create a splash screen while loading
    splash_pixmap = create_splash_image()
    splash = QtWidgets.QSplashScreen(splash_pixmap)
    splash.setStyleSheet("""
        font-size: 18px;
        font-weight: bold;
    """)
    splash.showMessage(
        "Initializing Binary Ninja Wrapped...",
        QtCore.Qt.AlignmentFlag.AlignBottom | QtCore.Qt.AlignmentFlag.AlignCenter,
        QtCore.Qt.GlobalColor.white
    )
    splash.show()
    QtWidgets.QApplication.processEvents()

    # Create widget but don't close splash yet - we'll enforce a minimum display time
    widget = BNWrappedWidget(recent_files, splash)
    widget.resize(1000, 800)
    widget.show()

    # Enforce a minimum splash screen display time of 3 seconds
    # This will be handled in the BNWrappedWidget's initialization


# Only register UI actions if not in testing mode
if not os.environ.get('BNWRAP_TESTING'):
    try:
        from binaryninjaui import UIAction, UIActionHandler, Menu

        # Register the UIAction
        UIAction.registerAction("Binja Wrapped", "Generate a Spotify-wrapped style summary of recent files")
        UIActionHandler.globalActions().bindAction("Binja Wrapped", UIAction(launchBNWrapped))

        # Add to the Plugin Menu
        Menu.mainMenu("Plugins").addAction("Binja Wrapped", "Plugins")
    except ImportError:
        # Running in headless mode or tests
        pass
