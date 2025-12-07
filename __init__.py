import os
import io
import json
import random
import operator
import datetime
import getpass
import platform
import tempfile
import urllib.parse
import hashlib
from binaryninja import load, SymbolType, user_directory, Settings, core_ui_enabled
from binaryninja.log import LogLevel

# Import shared logger
from .log import logger
from PySide6 import QtWidgets, QtGui, QtCore
from PySide6.QtCore import QResource, QTimer
import matplotlib.pyplot as plt
import matplotlib as mpl

# Import refactored modules
from .utils import get_user_name, get_file_hash
from .file_analyzer import FileAnalyzer
from .debug_timer import DebugTimerWidget, init_debug_timer
from . import quotes
from . import template_loader

widget = None
debug_timer_widget = None

# Register our settings
settings = Settings()
settings.register_group("bnwrap", "Binary Ninja Wrapped")
settings.register_setting("bnwrap.show_debug_timer", """{
    "title": "Show Debug Timer",
    "description": "Show a timer in the status bar counting up the time you've spent debugging",
    "type": "boolean",
    "default": false,
    "requiresRestart": true
    }""")

# Initialize the debug timer on plugin load
debug_timer_widget = init_debug_timer(settings, core_ui_enabled)

class BNWrappedWidget(QtWidgets.QWidget):
    def __init__(self, recent_files, splash=None, parent=None):
        super().__init__(parent)
        self.recent_files = QtCore.QSettings().value("ui/recentFiles", [], type=list)
        self.count = 0
        self.file_formats = {}
        self.cpu_archs = {}
        self.binary_stats = {'avg': 0, 'min': 0, 'max': 0}
        self.static_binaries_count = {'static': 0, 'dynamic': 0}
        self.biggest_binary = {"path": "", "size": 0, "format": "", "arch": ""}
        self.splash = splash  # Store the splash screen reference
        self.splash_start_time = datetime.datetime.now()  # Track when the splash was shown
        self.user_name = get_user_name()  # Get the user's name
        self.current_tab_index = 0  # Track the current tab for custom quotes
        self.year = datetime.datetime.now().year  # Current year for display

        # Initialize the file analyzer
        self.file_analyzer = FileAnalyzer()
        
        # Initialize UI with placeholder content
        self.initUI(True)
        
        # Bind ESC key to close the dialog for easier interaction
        self.escapeShortcut = QtGui.QShortcut(QtGui.QKeySequence(QtCore.Qt.Key.Key_Escape), self)
        self.escapeShortcut.activated.connect(self.close)
        
        # Start stats computation in a small delay to allow UI to render first
        QtCore.QTimer.singleShot(100, self.showProgressDialog)

    def showProgressDialog(self):
        """Show a progress dialog while computing stats"""
        # Only close splash screen if it's been displayed for at least 3 seconds
        if hasattr(self, 'splash') and self.splash:
            elapsed_time = (datetime.datetime.now() - self.splash_start_time).total_seconds()
            if elapsed_time < 3.0:
                # Wait until 3 seconds have passed
                remaining_time = int((3.0 - elapsed_time) * 1000)
                QtCore.QTimer.singleShot(remaining_time, self.closeSplash)
            else:
                # Already been 3 seconds, close it now
                self.closeSplash()
            
        # Make sure any existing overlay doesn't catch Escape key
        # by ensuring it doesn't have focus
        if hasattr(self, 'overlay'):
            self.overlay.setFocusPolicy(QtCore.Qt.FocusPolicy.NoFocus)
            
    def closeSplash(self):
        """Close the splash screen after ensuring minimum display time"""
        if hasattr(self, 'splash') and self.splash:
            self.splash.close()
            self.splash = None
            
        if not self.recent_files:
            # If no files, keep the placeholder data
            self.updateUI()
            return
            
        # Create progress dialog
        dialog = QtWidgets.QProgressDialog(
            f"Analyzing your binary files, {self.user_name}...", 
            "Cancel", 
            0, 
            len(self.recent_files), 
            self
        )
        dialog.setWindowTitle("Binary Ninja Wrapped")
        dialog.setWindowModality(QtCore.Qt.WindowModality.WindowModal)
        dialog.setAutoClose(True)
        dialog.setMinimumDuration(0)  # Show immediately
        
        # Create and set a cancel button that will properly handle the ESC key
        cancel_button = QtWidgets.QPushButton("Cancel", dialog)
        cancel_button.setAutoDefault(True)
        dialog.setCancelButton(cancel_button)
        
        # Connect ESC key explicitly to ensure it works
        shortcut = QtGui.QShortcut(QtGui.QKeySequence(QtCore.Qt.Key.Key_Escape), dialog)
        shortcut.activated.connect(dialog.cancel)
        
        dialog.setStyleSheet("""
            QPushButton {
                background-color: #1DB954;
                color: white;
                border-radius: 4px;
                padding: 5px 15px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1ED760;
            }
            QLabel {
                font-size: 14px;
            }
        """)
        
        # Create a stylish progress bar
        progress_bar = QtWidgets.QProgressBar(dialog)
        progress_bar.setTextVisible(True)
        progress_bar.setFormat("%v/%m files analyzed - %p%")
        progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid grey;
                border-radius: 5px;
                text-align: center;
                background-color: #191414;
                color: white;
                min-height: 20px;
            }
            
            QProgressBar::chunk {
                background-color: #1DB954;
                width: 20px;
            }
        """)
        dialog.setBar(progress_bar)
        
        # Set a reasonable size
        dialog.resize(400, dialog.height())
        
        # Make sure dialog is on top, but below any overlay
        dialog.setWindowFlags(dialog.windowFlags() | QtCore.Qt.WindowType.WindowStaysOnTopHint)
        dialog.show()
        
        # If we have an overlay, make sure it stays above the progress dialog
        if hasattr(self, 'overlay'):
            self.overlay.raise_()
        
        # Give UI time to refresh
        QtWidgets.QApplication.processEvents()
        
        # Compute the stats with progress updates
        self.computeStats(dialog)
        
        # Update UI with real data after computation
        dialog.close()
        self.updateUI()

    def computeStats(self, progress_dialog=None):
        """Compute statistics with optional progress dialog"""
        # Initialize stats
        self.count = 0
        self.file_formats = {}
        self.cpu_archs = {}
        self.binary_stats = {'avg': 0, 'min': float('inf'), 'max': 0}
        self.static_binaries_count = {'static': 0, 'dynamic': 0}
        self.biggest_binary = {"path": "", "size": 0, "format": "", "arch": ""}
        total_size = 0
        
        # Process each file
        for i, f in enumerate(self.recent_files):
            if progress_dialog and progress_dialog.wasCanceled():
                break
                
            # Update progress
            if progress_dialog:
                progress_dialog.setValue(i)
                progress_dialog.setLabelText(f"Analyzing: {os.path.basename(f)}")
                QtWidgets.QApplication.processEvents()
            
            # Process the file
            result = self.file_analyzer.skim_file(f)
            if 'file_formats' not in result or 'arch' not in result or 'size' not in result:
                continue
                
            # Update stats
            self.count += 1
            # Count file format and architecture (file_analyzer guarantees these are never empty)
            self.file_formats[result['file_formats']] = self.file_formats.get(result['file_formats'], 0) + 1
            self.cpu_archs[result['arch']] = self.cpu_archs.get(result['arch'], 0) + 1

            # Only include non-empty files in size calculations
            if result['size'] > 0:
                total_size += result['size']
                self.binary_stats['min'] = min(self.binary_stats['min'], result['size'])
                self.binary_stats['max'] = max(self.binary_stats['max'], result['size'])
            
            # Update static/dynamic binaries count
            if 'is_static' in result and result['is_static']:
                self.static_binaries_count['static'] += 1
            else:
                self.static_binaries_count['dynamic'] += 1
            
            # Track biggest binary
            if result['size'] > self.biggest_binary["size"]:
                self.biggest_binary = {
                    "path": f,
                    "size": result['size'],
                    "format": result['file_formats'],
                    "arch": result['arch']
                }
        
        # Calculate average
        if self.count > 0:
            self.binary_stats['avg'] = total_size / self.count
        else:
            self.binary_stats['min'] = 0
            
        # If we have no results, use some dummy data
        if not self.file_formats:
            self.file_formats = {'PE': 10, 'ELF': 5, 'Mach-O': 3}
            self.cpu_archs = {'x86': 12, 'ARM': 3, 'MIPS': 1}
            self.binary_stats = {'avg': 1024, 'min': 512, 'max': 2048}
            self.static_binaries_count = {'static': 8, 'dynamic': 10}
            self.biggest_binary = {"path": "example.exe", "size": 2048, "format": "PE", "arch": "x86"}
        
        # Final progress update
        if progress_dialog:
            progress_dialog.setValue(len(self.recent_files))  

    def initUI(self, use_placeholder=False):
        """Initialize the UI, optionally with placeholder content"""
        self.setWindowTitle("Binary Ninja Wrapped")
        layout = QtWidgets.QVBoxLayout(self)

        # Use placeholder data for initial rendering
        if use_placeholder and not self.file_formats:
            self.file_formats = {'PE': 10, 'ELF': 5, 'Mach-O': 3}
            self.cpu_archs = {'x86': 12, 'ARM': 3, 'MIPS': 1}
            self.binary_stats = {'avg': 1024, 'min': 512, 'max': 2048}
            self.static_binaries_count = {'static': 8, 'dynamic': 10}
            
        # Create tabs widget
        self.tabs = QtWidgets.QTabWidget(self)
        # Connect tab change signal to update quote
        self.tabs.currentChanged.connect(self.onTabChanged)
        layout.addWidget(self.tabs)

        # Create tab content
        self.statsTextTab = self.createStatsTextTab()
        self.fileFormatTab = self.createStatTab("File Format Breakdown", self.generateFileFormatImage)
        self.cpuArchTab = self.createStatTab("CPU Architectures", self.generateCPUArchImage)
        self.binaryStatsTab = self.createStatTab("Binary Statistics", self.generateBinaryStatsImage)
        self.staticBinariesTab = self.createStatTab("Static Binaries", self.generateStaticBinariesImage)

        # Add tabs
        self.tabs.addTab(self.statsTextTab, "Stats Summary")
        self.tabs.addTab(self.fileFormatTab, "File Formats")
        self.tabs.addTab(self.cpuArchTab, "CPU Arch")
        self.tabs.addTab(self.binaryStatsTab, "Statistics")
        self.tabs.addTab(self.staticBinariesTab, "Static Binaries")
        
        # Add overlay for placeholder mode
        if use_placeholder:
            self.overlay = QtWidgets.QLabel("Loading stats...", self)
            self.overlay.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
            self.overlay.setStyleSheet("""
                background-color: rgba(25, 20, 20, 0.7);
                color: white;
                font-size: 18px;
                font-weight: bold;
                border: 2px solid #1DB954;
                border-radius: 10px;
            """)
            self.overlay.move(10, 40)
            self.overlay.resize(self.width() - 20, self.height() - 60)
            self.overlay.setFocusPolicy(QtCore.Qt.FocusPolicy.NoFocus)  # Ensure it doesn't capture escape key
            self.overlay.show()
            self.overlay.raise_()  # Ensure overlay stays on top
            
            # The resizeEvent method will handle keeping the overlay properly sized
        
        # Add button container at the bottom
        buttonLayout = QtWidgets.QHBoxLayout()
        socialButtonLayout = QtWidgets.QHBoxLayout()
        
        # Style for all buttons
        buttonStyle = """
            QPushButton {
                background-color: #191414;
                color: white;
                border-radius: 4px;
                padding: 8px 15px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #333333;
            }
        """
        
        # Style for social media buttons
        socialButtonStyle = """
            QPushButton {
                background-color: #1DA1F2;
                color: white;
                border-radius: 4px;
                padding: 8px 15px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #0c85d0;
            }
            QPushButton#mastodon {
                background-color: #6364FF;
            }
            QPushButton#mastodon:hover {
                background-color: #5253ee;
            }
            QPushButton#linkedin {
                background-color: #0077B5;
            }
            QPushButton#linkedin:hover {
                background-color: #006396;
            }
        """
        
        # Add export combined button
        self.exportButton = QtWidgets.QPushButton("Export Combined Image", self)
        self.exportButton.clicked.connect(self.exportCombinedImage)
        self.exportButton.setStyleSheet(buttonStyle)
        buttonLayout.addWidget(self.exportButton)
        
        # Add export all button (images + HTML)
        self.exportAllButton = QtWidgets.QPushButton("Export All", self)
        self.exportAllButton.clicked.connect(self.exportImages)
        self.exportAllButton.setStyleSheet(buttonStyle)
        buttonLayout.addWidget(self.exportAllButton)
        
        # Add social media share buttons
        self.shareTwitterButton = QtWidgets.QPushButton("Share to Twitter", self)
        self.shareTwitterButton.clicked.connect(self.shareToTwitter)
        self.shareTwitterButton.setStyleSheet(socialButtonStyle)
        socialButtonLayout.addWidget(self.shareTwitterButton)
        
        self.shareMastodonButton = QtWidgets.QPushButton("Share to Mastodon", self)
        self.shareMastodonButton.setObjectName("mastodon")
        self.shareMastodonButton.clicked.connect(self.shareToMastodon)
        self.shareMastodonButton.setStyleSheet(socialButtonStyle)
        socialButtonLayout.addWidget(self.shareMastodonButton)
        
        self.shareLinkedInButton = QtWidgets.QPushButton("Share to LinkedIn", self)
        self.shareLinkedInButton.setObjectName("linkedin")
        self.shareLinkedInButton.clicked.connect(self.shareToLinkedIn)
        self.shareLinkedInButton.setStyleSheet(socialButtonStyle)
        socialButtonLayout.addWidget(self.shareLinkedInButton)
        
        # Add refresh button
        self.refreshButton = QtWidgets.QPushButton("Flush Stats Cache", self)
        self.refreshButton.clicked.connect(self.refreshStats)
        self.refreshButton.setStyleSheet(buttonStyle)
        buttonLayout.addWidget(self.refreshButton)
        
        # Add both button layouts to the main layout
        layout.addLayout(socialButtonLayout)
        layout.addLayout(buttonLayout)
        
    def resizeEvent(self, event):
        """Handle resize events to keep the overlay properly sized"""
        if hasattr(self, 'overlay'):
            self.overlay.resize(self.width() - 20, self.height() - 60)
        # Call the original resize event handler
        super().resizeEvent(event)
        
    def onTabChanged(self, index):
        """Handle tab change event"""
        self.current_tab_index = index
        
    # Quote functionality has been moved to individual tabs

    def refreshStats(self):
        """Refresh statistics by clearing cache and recomputing"""
        # Clear the file analyzer cache in memory
        self.file_analyzer.cache = {}

        # Show progress dialog
        dialog = QtWidgets.QProgressDialog(
            f"Re-analyzing your binary files, {self.user_name}...",
            "Cancel",
            0,
            len(self.recent_files),
            self
        )
        dialog.setWindowTitle("Binary Ninja Wrapped - Refresh")
        dialog.setWindowModality(QtCore.Qt.WindowModality.WindowModal)
        dialog.setAutoClose(True)
        dialog.setMinimumDuration(0)
        dialog.show()
        QtWidgets.QApplication.processEvents()

        # Recompute stats
        self.computeStats(dialog)

        # Close progress dialog
        dialog.close()

        # Save the updated cache to disk (to default location, no prompt)
        self.file_analyzer.save_cache()

        # Update UI with new data
        self.updateUI()

    def updateUI(self):
        """Update the UI with the latest data after computations are done"""
        # Update the tabs with real data
        index = self.tabs.currentIndex()
        
        # Recreate tabs with real data
        self.tabs.removeTab(0)  # Stats Summary
        self.tabs.removeTab(0)  # File Formats
        self.tabs.removeTab(0)  # CPU Arch
        self.tabs.removeTab(0)  # Statistics
        self.tabs.removeTab(0)  # Static Binaries
        
        self.statsTextTab = self.createStatsTextTab()
        self.fileFormatTab = self.createStatTab("File Format Breakdown", self.generateFileFormatImage)
        self.cpuArchTab = self.createStatTab("CPU Architectures", self.generateCPUArchImage)
        self.binaryStatsTab = self.createStatTab("Binary Statistics", self.generateBinaryStatsImage)
        self.staticBinariesTab = self.createStatTab("Static Binaries", self.generateStaticBinariesImage)
        
        self.tabs.addTab(self.statsTextTab, "Stats Summary")
        self.tabs.addTab(self.fileFormatTab, "File Formats")
        self.tabs.addTab(self.cpuArchTab, "CPU Arch")
        self.tabs.addTab(self.binaryStatsTab, "Statistics")
        self.tabs.addTab(self.staticBinariesTab, "Static Binaries")
        
        # Restore the previously selected tab
        self.tabs.setCurrentIndex(index)
        
        # Now remove the overlay if it exists (after all updates are done)
        if hasattr(self, 'overlay'):
            self.overlay.hide()
            self.overlay.deleteLater()
            delattr(self, 'overlay')

    def createStatTab(self, title, imageGenFunc):
        widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(widget)
        
        # Add the image
        imageLabel = QtWidgets.QLabel(widget)
        imageLabel.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(imageLabel)
        pixmap = imageGenFunc()
        if pixmap:
            imageLabel.setPixmap(pixmap)
            
        # Add a quote below the chart based on which chart this is
        quoteLabel = QtWidgets.QLabel(widget)
        quoteLabel.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        quoteLabel.setWordWrap(True)
        quoteLabel.setSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Maximum)
        
        # Use theme-appropriate color for the quote background
        bg_color = ""
        if "File Format" in title:
            bg_color = self.get_spotify_colors(tab_index=1)[0]
        elif "CPU" in title:
            bg_color = self.get_spotify_colors(tab_index=2)[0]
        elif "Binary Statistics" in title:
            bg_color = self.get_spotify_colors(tab_index=3)[0]
        elif "Static Binaries" in title:
            bg_color = self.get_spotify_colors(tab_index=4)[0]
        else:
            bg_color = "#1DB954"  # Default Spotify green
            
        # Determine if background is light or dark
        if bg_color.startswith('#'):
            r = int(bg_color[1:3], 16)
            g = int(bg_color[3:5], 16)
            b = int(bg_color[5:7], 16)
            brightness = (0.299*r + 0.587*g + 0.114*b) / 255
            text_color = 'black' if brightness > 0.5 else 'white'
        else:
            text_color = 'white'  # Default to white text
            
        quoteLabel.setStyleSheet(f"""
            background-color: {bg_color};
            color: {text_color};
            padding: 10px;
            border-radius: 5px;
            font-style: italic;
            font-size: 14px;
            margin: 10px;
        """)
        
        # Get the appropriate quote based on the title
        if "File Format" in title:
            quote = self.getJokeForFileFormats()
        elif "CPU" in title:
            quote = self.getJokeForArchitectures()
        elif "Binary Statistics" in title:
            quote = self.getJokeForBinaryStats()
        elif "Static Binaries" in title:
            quote = self.getQuoteForStaticBinaries()
        else:
            quote = self.getJokeForStats()
            
        quoteLabel.setText(quote)
        layout.addWidget(quoteLabel)
        
        return widget

    def createStatsTextTab(self):
        widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(widget)
        
        # Create a colorful background
        palette = widget.palette()
        palette.setColor(QtGui.QPalette.Window, QtGui.QColor("#1DB954"))
        widget.setAutoFillBackground(True)
        widget.setPalette(palette)
        
        # Create styled text for stats
        text = QtWidgets.QTextEdit()
        text.setReadOnly(True)
        
        # Build stats text with HTML formatting, escaping CSS curly braces
        # Build HTML components
        file_formats_html = ''
        sorted_formats = sorted(self.file_formats.items(), key=operator.itemgetter(1), reverse=True)
        for fmt, count in sorted_formats:
            file_formats_html += f'<div class="stat">{fmt}: {count}</div>'

        cpu_archs_html = ''
        sorted_archs = sorted(self.cpu_archs.items(), key=operator.itemgetter(1), reverse=True)
        for arch, count in sorted_archs:
            cpu_archs_html += f'<div class="stat">{arch}: {count}</div>'

        binary_stats_html = ''
        for stat, value in self.binary_stats.items():
            binary_stats_html += f'<div class="stat">{stat.capitalize()}: {value:.2f} KB</div>'

        biggest_binary_html = ''
        if self.biggest_binary["path"]:
            arch_display = self.biggest_binary["arch"] if self.biggest_binary["arch"] else "Unknown"
            biggest_binary_html = f'''
<h2>Biggest Binary</h2>
<div class="stat">Path: {os.path.basename(self.biggest_binary["path"])}</div>
<div class="stat">Size: {self.biggest_binary["size"]:.2f} KB</div>
<div class="stat">Format: {self.biggest_binary["format"]}</div>
<div class="stat">Architecture: {arch_display}</div>
'''

        current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Render template
        html = template_loader.render_stats_tab(
            user_name=self.user_name,
            stats_quote=self.getJokeForStats(),
            file_formats_html=file_formats_html,
            formats_quote=self.getJokeForFileFormats(),
            cpu_archs_html=cpu_archs_html,
            archs_quote=self.getJokeForArchitectures(),
            binary_stats_html=binary_stats_html,
            biggest_binary_html=biggest_binary_html,
            static_count=self.static_binaries_count["static"],
            dynamic_count=self.static_binaries_count["dynamic"],
            static_quote=self.getQuoteForStaticBinaries(),
            timestamp=current_time
        )

        text.setHtml(html)
        
        layout.addWidget(text)
        
        # Add generation timestamp
        timestamp_layout = QtWidgets.QHBoxLayout()
        
        # Add timestamp label
        timestamp_label = QtWidgets.QLabel(widget)
        current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        timestamp_label.setText(f"Generated: {current_time}")
        timestamp_label.setStyleSheet("color: #333333; font-style: italic;")
            
        timestamp_layout.addWidget(timestamp_label)
        layout.addLayout(timestamp_layout)
        
        return widget

    def get_spotify_colors(self, tab_index=None):
        # Define all available colors
        all_colors = [
            "#1DB954",  # Spotify green
            "#FF9CE0",  # Pink
            "#2E77D0",  # Blue
            "#FF7900",  # Orange
            "#FFFF64",  # Yellow
            "#B49BC8",  # Purple
            "#FFB9B9",  # Salmon
            "#30A2FF",  # Light blue
            "#E13300",  # Bright red
            "#00C5CD",  # Turquoise
            "#ADFF2F",  # Green yellow
            "#FF6EB4",  # Hot pink
            "#9370DB",  # Medium purple
            "#20B2AA",  # Light sea green
            "#FF4500",  # Orange red
            "#00BFFF",  # Deep sky blue
        ]
        
        # Store random color schemes for consistent use within a session
        if not hasattr(self, 'random_color_schemes'):
            self.random_color_schemes = {}
            
            # Initialize with random schemes for each tab
            for i in range(5):  # 0-4 for the 5 tabs
                # Shuffle colors and pick the first 8
                import random
                shuffled = all_colors.copy()
                random.shuffle(shuffled)
                self.random_color_schemes[i] = shuffled[:8]
        
        # Return the stored random scheme for the requested tab
        if tab_index is not None and tab_index in self.random_color_schemes:
            return self.random_color_schemes[tab_index]
        
        # Default palette (used when no tab is specified)
        return self.random_color_schemes.get(0, all_colors[:8])

    def generateFileFormatImage(self):
        formats = self.file_formats
        # Sort by value in descending order
        sorted_formats = dict(sorted(formats.items(), key=operator.itemgetter(1), reverse=True))
        
        # Use a random dark background color for the chart
        if not hasattr(self, 'background_colors'):
            self.background_colors = self.generate_random_backgrounds()
            
        background_color = self.background_colors[1]  # Use the color for tab 1

        fig, ax = plt.subplots(figsize=(6, 6), facecolor=background_color)
        
        colors = self.get_spotify_colors(tab_index=1)  # Use File Formats tab-specific colors
        # Choose text color based on background brightness
        text_color = 'black' if hasattr(self, 'background_is_light') and self.background_is_light.get(1, False) else 'white'
        
        # Increase font sizes for better readability
        plt.rcParams['font.size'] = 14  # Increase base font size
        
        wedges, texts, autotexts = ax.pie(
            sorted_formats.values(), 
            labels=sorted_formats.keys(), 
            autopct='%1.1f%%', 
            colors=colors,
            textprops={'color': text_color, 'fontsize': 14}  # Explicit font size for labels
        )
        # Make percentage text bold with appropriate color and larger font based on wedge color
        for i, autotext in enumerate(autotexts):
            # Get the wedge this text corresponds to
            if i < len(wedges):
                wedge = wedges[i]
                # Get the wedge color as RGBA
                wedge_color = wedge.get_facecolor()
                # Convert RGBA to RGB 0-255
                r, g, b = [int(c * 255) for c in wedge_color[:3]]
                # Calculate brightness
                wedge_brightness = (0.299*r + 0.587*g + 0.114*b) / 255
                # Set appropriate text color based on wedge brightness
                wedge_text_color = 'black' if wedge_brightness > 0.5 else 'white'
                autotext.set_color(wedge_text_color)
            else:
                autotext.set_color(text_color)
                
            autotext.set_fontweight('bold')
            autotext.set_fontsize(16)  # Larger font for percentages
            
        # Also update the label colors and sizes - always use chart background color for these
        for text in texts:
            text.set_color(text_color)
            text.set_fontsize(14)  # Consistent font size for labels

        ax.set_title("File Format Breakdown", color=text_color, fontweight='bold', fontsize=20)
        return self.figureToPixmap(fig)

    def generate_random_backgrounds(self):
        """Generate random backgrounds for each tab with varying brightness"""
        import random
        
        # Define both dark and light base colors for variety
        base_colors = [
            # Dark colors
            "#1A1A1A",  # Almost black
            "#121212",  # Spotify dark
            "#242424",  # Dark gray
            "#0D1117",  # GitHub dark
            "#2D2D2D",  # Darker gray
            # Medium brightness colors
            "#3D3D3D",  # Medium gray
            "#444444",  # Medium gray
            "#555555",  # Medium gray
            # Light colors (for variety, less likely to be chosen)
            "#DDDDDD",  # Light gray
            "#EEEEEE",  # Lighter gray
        ]
        
        # Generate a set of random backgrounds
        backgrounds = {}
        background_is_light = {}  # Track if each background is light
        
        for i in range(5):  # 0-4 for the 5 tabs
            # Choose a random base color with preference for darker colors
            # Use weighted random selection to favor dark backgrounds
            weights = [5, 5, 5, 5, 5, 3, 3, 3, 1, 1]  # Higher weights for darker colors
            base = random.choices(base_colors, weights=weights, k=1)[0]
            
            # Convert hex to RGB, modify, and convert back
            r = int(base[1:3], 16)
            g = int(base[3:5], 16)
            b = int(base[5:7], 16)
            
            # Add a slight tint of a random color to make it more interesting
            r_mod = random.randint(-20, 40)
            g_mod = random.randint(-20, 40)
            b_mod = random.randint(-20, 40)
            
            r = max(0, min(255, r + r_mod))
            g = max(0, min(255, g + g_mod))
            b = max(0, min(255, b + b_mod))
            
            # Convert back to hex
            bg_color = f"#{r:02x}{g:02x}{b:02x}"
            backgrounds[i] = bg_color
            
            # Calculate brightness using the formula:
            # (0.299*R + 0.587*G + 0.114*B) / 255
            # Values > 0.5 are considered light backgrounds
            brightness = (0.299*r + 0.587*g + 0.114*b) / 255
            background_is_light[i] = brightness > 0.5
            
        # Store the light/dark information for easy access
        self.background_is_light = background_is_light
        return backgrounds
    
    def generateCPUArchImage(self):
        archs = self.cpu_archs
        # Sort by value in descending order
        sorted_archs = dict(sorted(archs.items(), key=operator.itemgetter(1), reverse=True))
        
        # Use a random dark background color for the chart
        if not hasattr(self, 'background_colors'):
            self.background_colors = self.generate_random_backgrounds()
            
        background_color = self.background_colors[2]  # Use the color for tab 2

        fig, ax = plt.subplots(figsize=(6, 6), facecolor=background_color)
        
        colors = self.get_spotify_colors(tab_index=2)  # Use CPU Architecture tab-specific colors
        bars = ax.bar(
            sorted_archs.keys(), 
            sorted_archs.values(),
            color=colors[:len(sorted_archs)]
        )
        
        # Choose text color based on background brightness
        text_color = 'black' if hasattr(self, 'background_is_light') and self.background_is_light.get(2, False) else 'white'
        
        # Increase font sizes for better readability
        plt.rcParams['font.size'] = 14  # Increase base font size
        
        # Add value labels on top of bars with font size based on number of bars
        # If more than 3 bars, use smaller font size
        label_fontsize = 16 if len(sorted_archs) <= 3 else 10
        
        for bar in bars:
            height = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width()/2., 
                height + 0.1,
                f'{int(height)}',
                ha='center', 
                va='bottom', 
                color=text_color, 
                fontweight='bold',
                fontsize=label_fontsize
            )

        ax.set_title("CPU Architectures", color=text_color, fontweight='bold', fontsize=20)
        ax.set_facecolor(background_color)  # Use the selected background color
        
        ax.tick_params(axis='x', labelsize=label_fontsize)
        ax.tick_params(axis='y', labelsize=label_fontsize)
        
        # Update spine colors based on background brightness
        ax.spines['bottom'].set_color(text_color)
        ax.spines['top'].set_color(text_color)
        ax.spines['left'].set_color(text_color)
        ax.spines['right'].set_color(text_color)
        ax.tick_params(axis='x', colors=text_color)
        ax.tick_params(axis='y', colors=text_color)
        return self.figureToPixmap(fig)

    def generateBinaryStatsImage(self):
        stats = self.binary_stats
        # Sort by value in descending order
        sorted_stats = dict(sorted(stats.items(), key=operator.itemgetter(1), reverse=True))
        
        # Use a random dark background color for the chart
        if not hasattr(self, 'background_colors'):
            self.background_colors = self.generate_random_backgrounds()
            
        background_color = self.background_colors[3]  # Use the color for tab 3

        fig, ax = plt.subplots(figsize=(6, 6), facecolor=background_color)
        
        colors = self.get_spotify_colors(tab_index=3)  # Use Binary Statistics tab-specific colors
        bars = ax.bar(
            sorted_stats.keys(), 
            sorted_stats.values(),
            color=colors[:len(sorted_stats)]
        )
        
        # Choose text color based on background brightness
        text_color = 'black' if hasattr(self, 'background_is_light') and self.background_is_light.get(3, False) else 'white'
        
        # Increase font sizes for better readability
        plt.rcParams['font.size'] = 14  # Increase base font size
        
        # Add value labels on top of bars with font size based on number of bars
        # If more than 3 bars, use smaller font size
        label_fontsize = 16 if len(sorted_stats) <= 3 else 10
        
        for bar in bars:
            height = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width()/2., 
                height + 0.1,
                f'{int(height)}',
                ha='center', 
                va='bottom', 
                color=text_color, 
                fontweight='bold',
                fontsize=label_fontsize
            )

        ax.set_title("Binary Statistics", color=text_color, fontweight='bold', fontsize=20)
        ax.set_ylabel("Size (KB)", color=text_color, fontsize=16)
        ax.set_facecolor(background_color)  # Use the selected background color
        
        # Make the tick labels larger
        ax.tick_params(axis='x', labelsize=label_fontsize)
        ax.tick_params(axis='y', labelsize=label_fontsize)
        
        # Update spine colors based on background brightness
        ax.spines['bottom'].set_color(text_color)
        ax.spines['top'].set_color(text_color)
        ax.spines['left'].set_color(text_color)
        ax.spines['right'].set_color(text_color)
        ax.tick_params(axis='x', colors=text_color)
        ax.tick_params(axis='y', colors=text_color)
        return self.figureToPixmap(fig)
    def generateStaticBinariesImage(self):
        static_count = self.static_binaries_count['static']
        dynamic_count = self.static_binaries_count['dynamic']
        total = static_count + dynamic_count
        
        # Calculate percentages for display
        static_percentage = (static_count / total * 100) if total > 0 else 0
        dynamic_percentage = (dynamic_count / total * 100) if total > 0 else 0
        
        # Use a random dark background color for the chart
        if not hasattr(self, 'background_colors'):
            self.background_colors = self.generate_random_backgrounds()
            
        background_color = self.background_colors[4]  # Use the color for tab 4

        fig, ax = plt.subplots(figsize=(6, 6), facecolor=background_color)
        
        colors = self.get_spotify_colors(tab_index=4)  # Use Static Binaries tab-specific colors
        bars = ax.bar(
            ['Static', 'Dynamic'], 
            [static_count, dynamic_count],
            color=[colors[0], colors[1]]
        )
        
        # Choose text color based on background brightness
        text_color = 'black' if hasattr(self, 'background_is_light') and self.background_is_light.get(4, False) else 'white'
        
        # Increase font sizes for better readability
        plt.rcParams['font.size'] = 14  # Increase base font size
        
        # Determine number of bars (always 2 for static vs dynamic, but for consistency)
        num_bars = 2  # ['Static', 'Dynamic']
        # Font size based on number of bars (consistent with other charts)
        label_fontsize = 16 if num_bars <= 3 else 12
        
        # Add value labels on top of bars with appropriate font size
        for bar in bars:
            height = bar.get_height()
            percentage = (height / total * 100) if total > 0 else 0
            ax.text(
                bar.get_x() + bar.get_width()/2., 
                height + 0.1,
                f'{int(height)} ({percentage:.1f}%)',
                ha='center', 
                va='bottom', 
                color=text_color, 
                fontweight='bold',
                fontsize=label_fontsize
            )

        ax.set_title("Static vs Dynamic Binaries", color=text_color, fontweight='bold', fontsize=20)
        ax.set_ylabel("Count", color=text_color, fontsize=16)
        ax.set_facecolor(background_color)  # Use the selected background color
        
        # Make the tick labels larger
        ax.tick_params(axis='x', labelsize=14)
        ax.tick_params(axis='y', labelsize=14)
        
        # Update spine colors based on background brightness
        ax.spines['bottom'].set_color(text_color)
        ax.spines['top'].set_color(text_color)
        ax.spines['left'].set_color(text_color)
        ax.spines['right'].set_color(text_color)
        ax.tick_params(axis='x', colors=text_color)
        ax.tick_params(axis='y', colors=text_color)
        return self.figureToPixmap(fig)

    def figureToPixmap(self, fig):
        buf = io.BytesIO()
        # Use tight_layout to prevent label overflow and bbox_inches to ensure nothing is clipped
        fig.tight_layout()
        fig.savefig(buf, format='png', bbox_inches='tight')
        plt.close(fig)
        buf.seek(0)
        img = QtGui.QImage()
        img.loadFromData(buf.getvalue(), "PNG")
        return QtGui.QPixmap.fromImage(img)

    def exportCombinedImage(self):
        """Export a single combined image with all charts and stats in a grid layout"""
        file_path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Save Combined Image", "", "PNG Files (*.png)"
        )
        
        if not file_path:
            return
            
        # Add .png extension if not present
        if not file_path.lower().endswith('.png'):
            file_path += '.png'
            
        # Generate all the chart images
        chart_pixmaps = [
            self.generateFileFormatImage(),
            self.generateCPUArchImage(),
            self.generateBinaryStatsImage(),
            self.generateStaticBinariesImage()
        ]
        
        titles = [
            "File Format Breakdown",
            "CPU Architectures",
            "Binary Statistics",
            "Static Binaries"
        ]
        
        # Grid layout configuration
        columns = 2  # Number of columns in the grid
        rows = (len(chart_pixmaps) + columns - 1) // columns  # Ceiling division to get number of rows
        
        # Get typical dimensions of the charts
        chart_width = max(pixmap.width() for pixmap in chart_pixmaps)
        chart_height = max(pixmap.height() for pixmap in chart_pixmaps)
        
        # Grid spacing
        horizontal_spacing = 40
        vertical_spacing = 40
        
        # Size of the quotes
        quote_height = 60

        # Check if wordmark exists to adjust header height
        wordmark = QtGui.QPixmap(":/icons/images/logo-wordmark-dark.png")

        # Calculate total dimensions for the grid layout
        header_height = 180 if not wordmark.isNull() else 150  # Space for wordmark, title and timestamp
        footer_height = 40   # Extra space at the bottom

        # Total width: margin + (chart_width + spacing) * columns - spacing (no spacing after last column) + margin
        total_width = 60 + (chart_width + horizontal_spacing) * columns - horizontal_spacing + 60

        # Total height: header + (chart_height + quote_height + spacing) * rows - spacing (no spacing after last row) + footer
        total_height = header_height + (chart_height + quote_height + vertical_spacing) * rows - vertical_spacing + footer_height

        # Create a new image with the right dimensions
        combined = QtGui.QPixmap(total_width, total_height)
        combined.fill(QtGui.QColor("#2D2D2D"))  # Lighter background to make BN logo pop

        # Paint everything onto the combined image
        painter = QtGui.QPainter(combined)

        # Use the wordmark at the top
        wordmark = QtGui.QPixmap(":/icons/images/logo-wordmark-dark.png")
        if not wordmark.isNull():
            # Scale the wordmark to fit nicely
            wordmark_width = min(300, total_width * 0.6)  # Target width in pixels, not more than 60% of total width
            wordmark = wordmark.scaledToWidth(int(wordmark_width), QtCore.Qt.TransformationMode.SmoothTransformation)
            
            # Position the wordmark, centered horizontally
            wordmark_x = (total_width - wordmark.width()) // 2
            wordmark_y = 20
            painter.drawPixmap(wordmark_x, wordmark_y, wordmark)
        
        # Draw title below wordmark
        title_font = QtGui.QFont()
        title_font.setPointSize(24)
        title_font.setBold(True)
        painter.setFont(title_font)
        painter.setPen(QtCore.Qt.GlobalColor.white)

        # Adjust title position depending on whether wordmark was drawn
        title_y = 80 if not wordmark.isNull() else 40

        painter.drawText(
            QtCore.QRect(0, title_y, total_width, 40),
            QtCore.Qt.AlignmentFlag.AlignCenter,
            f"{self.user_name}'s Wrapped {self.year}"
        )
        
        # Draw generation timestamp
        current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        timestamp_font = QtGui.QFont()
        timestamp_font.setPointSize(10)
        timestamp_font.setItalic(True)
        painter.setFont(timestamp_font)
        painter.setPen(QtGui.QColor("#1DB954"))  # Spotify green
        
        # Adjust the timestamp position - it should be below the title
        timestamp_y = 120 if not wordmark.isNull() else 80
        
        painter.drawText(
            QtCore.QRect(0, timestamp_y, total_width, 20),
            QtCore.Qt.AlignmentFlag.AlignCenter,
            f"Generated: {current_time}"
        )
        
        # Generate quotes for each chart
        quotes = []
        for i, title in enumerate(titles):
            if "File Format" in title:
                quotes.append(self.getJokeForFileFormats())
            elif "CPU" in title:
                quotes.append(self.getJokeForArchitectures())
            elif "Binary Statistics" in title:
                quotes.append(self.getJokeForBinaryStats())
            elif "Static Binaries" in title:
                quotes.append(self.getQuoteForStaticBinaries())
            else:
                quotes.append(self.getJokeForStats())
        
        # Draw charts and quotes in a grid layout
        for i, pixmap in enumerate(chart_pixmaps):
            # Calculate grid position
            row = i // columns
            col = i % columns
            
            # Calculate position for this chart
            x_pos = 60 + col * (chart_width + horizontal_spacing) + (chart_width - pixmap.width()) // 2
            y_pos = header_height + row * (chart_height + quote_height + vertical_spacing)
            
            # Draw the chart (title is already included in the chart from matplotlib)
            painter.drawPixmap(x_pos, y_pos, pixmap)

            # Draw the quote below this chart
            quote = quotes[i]
            quote_font = QtGui.QFont()
            quote_font.setPointSize(10)
            quote_font.setItalic(True)
            painter.setFont(quote_font)

            # Position for the quote is right below the chart, centered over the actual chart image
            quote_x = x_pos
            quote_y = y_pos + pixmap.height() + 10

            # Draw colorful box for the quote - use the tab's color scheme
            tab_colors = self.get_spotify_colors(tab_index=i+1)
            quote_rect = QtCore.QRect(quote_x + 10, quote_y, pixmap.width() - 20, quote_height - 10)
            bg_color = QtGui.QColor(tab_colors[0])
            painter.fillRect(quote_rect, bg_color)

            # Calculate text color based on background brightness
            r, g, b = bg_color.red(), bg_color.green(), bg_color.blue()
            brightness = (0.299 * r + 0.587 * g + 0.114 * b) / 255
            text_color = QtCore.Qt.GlobalColor.black if brightness > 0.5 else QtCore.Qt.GlobalColor.white
            painter.setPen(text_color)
            
            # Calculate the optimal font size for this quote
            # Start with a large font size and decrease until it fits
            optimal_font_size = 16  # Start with this size
            quote_font.setPointSize(optimal_font_size)
            
            # Create a QFontMetrics to measure text
            font_metrics = QtGui.QFontMetrics(quote_font)
            
            # Calculate available width and height
            available_width = quote_rect.width() - 20  # Subtract some padding
            available_height = quote_rect.height() - 10  # Subtract some padding
            
            # Check if the text fits at current font size
            text_rect = font_metrics.boundingRect(
                QtCore.QRect(0, 0, available_width, 1000),  # Tall rectangle for word wrapping
                QtCore.Qt.TextFlag.TextWordWrap,
                quote
            )
            
            # Decrease font size until text fits
            while (text_rect.width() > available_width or text_rect.height() > available_height) and optimal_font_size > 8:
                optimal_font_size -= 1
                quote_font.setPointSize(optimal_font_size)
                font_metrics = QtGui.QFontMetrics(quote_font)
                text_rect = font_metrics.boundingRect(
                    QtCore.QRect(0, 0, available_width, 1000),
                    QtCore.Qt.TextFlag.TextWordWrap,
                    quote
                )
            
            # Set the optimized font size
            painter.setFont(quote_font)
            
            # Draw the quote text with optimized font size
            painter.drawText(
                quote_rect,
                QtCore.Qt.AlignmentFlag.AlignCenter | QtCore.Qt.TextFlag.TextWordWrap,
                quote
            )
        
        painter.end()
        
        # Save the combined image
        combined.save(file_path, "PNG")
        QtWidgets.QMessageBox.information(self, "Export", "Combined image exported successfully!")
            
    def exportImages(self):
        """Export individual chart images with quotes and HTML summary"""
        directory = QtWidgets.QFileDialog.getExistingDirectory(self, "Select Export Directory")
        if directory:
            # Define the charts and their associated quotes
            charts_with_quotes = [
                {
                    "filename": "file_format_breakdown.png",
                    "title": "File Format Breakdown",
                    "image_func": self.generateFileFormatImage,
                    "quote_func": self.getJokeForFileFormats
                },
                {
                    "filename": "cpu_architectures.png",
                    "title": "CPU Architectures",
                    "image_func": self.generateCPUArchImage,
                    "quote_func": self.getJokeForArchitectures
                },
                {
                    "filename": "binary_statistics.png", 
                    "title": "Binary Statistics",
                    "image_func": self.generateBinaryStatsImage,
                    "quote_func": self.getJokeForBinaryStats
                },
                {
                    "filename": "static_binaries.png",
                    "title": "Static vs Dynamic Binaries",
                    "image_func": self.generateStaticBinariesImage,
                    "quote_func": self.getQuoteForStaticBinaries
                }
            ]
            
            successfully_saved = 0
            
            # Export each image with its quote
            for chart in charts_with_quotes:
                # Get the chart image
                chart_pixmap = chart["image_func"]()
                if not chart_pixmap:
                    continue
                    
                # Get the quote
                quote = chart["quote_func"]()
                
                # Create a new image with space for the quote
                quote_height = 80  # Space for the quote
                padding = 20  # Padding around the image
                
                # Create a new pixmap with extra height for the quote
                final_width = chart_pixmap.width() + (2 * padding)
                final_height = chart_pixmap.height() + quote_height + (2 * padding)
                
                final_pixmap = QtGui.QPixmap(final_width, final_height)
                
                # Get background color based on the chart type
                if "File Format" in chart["title"]:
                    bg_color = self.background_colors.get(1, "#122F1C")
                elif "CPU" in chart["title"]:
                    bg_color = self.background_colors.get(2, "#192A3D")
                elif "Binary Statistics" in chart["title"]:
                    bg_color = self.background_colors.get(3, "#2D1A36")
                elif "Static" in chart["title"]:
                    bg_color = self.background_colors.get(4, "#3A1923")
                else:
                    bg_color = "#191414"
                    
                final_pixmap.fill(QtGui.QColor(bg_color))
                
                # Create a painter to draw on the final image
                painter = QtGui.QPainter(final_pixmap)
                
                # Draw the chart
                painter.drawPixmap(padding, padding, chart_pixmap)
                
                # Draw the title
                title_font = QtGui.QFont()
                title_font.setPointSize(16)
                title_font.setBold(True)
                painter.setFont(title_font)
                
                # Choose text color based on background brightness
                # Calculate background brightness
                r = int(bg_color[1:3], 16)
                g = int(bg_color[3:5], 16)
                b = int(bg_color[5:7], 16)
                brightness = (0.299*r + 0.587*g + 0.114*b) / 255
                text_color = 'black' if brightness > 0.5 else 'white'
                
                painter.setPen(QtGui.QColor(text_color))
                
                # Draw the quote in a box at the bottom
                quote_rect = QtCore.QRect(
                    padding, 
                    padding + chart_pixmap.height() + 10, 
                    final_width - (2 * padding),
                    quote_height - 10
                )
                
                # Use theme-appropriate color for quote background
                # Get a color from the chart's color palette
                if "File Format" in chart["title"]:
                    quote_bg_color = self.get_spotify_colors(tab_index=1)[0]
                elif "CPU" in chart["title"]:
                    quote_bg_color = self.get_spotify_colors(tab_index=2)[0]
                elif "Binary Statistics" in chart["title"]:
                    quote_bg_color = self.get_spotify_colors(tab_index=3)[0]
                elif "Static" in chart["title"]:
                    quote_bg_color = self.get_spotify_colors(tab_index=4)[0]
                else:
                    quote_bg_color = "#1DB954"  # Default Spotify green
                
                painter.fillRect(quote_rect, QtGui.QColor(quote_bg_color))
                
                # Calculate optimal font size for the quote
                # Start with a large font size and scale down if needed
                quote_font = QtGui.QFont()
                quote_font.setItalic(True)
                
                # Choose initial font size based on quote length
                quote_length = len(quote)
                if quote_length < 100:
                    initial_font_size = 14
                elif quote_length < 200:
                    initial_font_size = 12
                else:
                    initial_font_size = 10
                
                # Set initial font size
                quote_font.setPointSize(initial_font_size)
                painter.setFont(quote_font)
                
                # Calculate if the text fits
                font_metrics = QtGui.QFontMetrics(quote_font)
                text_rect = font_metrics.boundingRect(
                    QtCore.QRect(0, 0, quote_rect.width() - 20, 1000),
                    QtCore.Qt.TextFlag.TextWordWrap,
                    quote
                )
                
                # Scale down font if needed until the text fits
                current_font_size = initial_font_size
                while (text_rect.height() > quote_rect.height() - 10) and current_font_size > 8:
                    current_font_size -= 1
                    quote_font.setPointSize(current_font_size)
                    painter.setFont(quote_font)
                    font_metrics = QtGui.QFontMetrics(quote_font)
                    text_rect = font_metrics.boundingRect(
                        QtCore.QRect(0, 0, quote_rect.width() - 20, 1000),
                        QtCore.Qt.TextFlag.TextWordWrap,
                        quote
                    )
                
                # Determine text color based on background brightness
                # Calculate quote background brightness
                qr = int(quote_bg_color[1:3], 16) if quote_bg_color.startswith('#') else 0
                qg = int(quote_bg_color[3:5], 16) if quote_bg_color.startswith('#') else 0
                qb = int(quote_bg_color[5:7], 16) if quote_bg_color.startswith('#') else 0
                qbrightness = (0.299*qr + 0.587*qg + 0.114*qb) / 255
                quote_text_color = 'black' if qbrightness > 0.5 else 'white'
                
                painter.setPen(QtGui.QColor(quote_text_color))
                
                # Draw the quote with word wrapping
                painter.drawText(
                    quote_rect,
                    QtCore.Qt.AlignmentFlag.AlignCenter | QtCore.Qt.TextFlag.TextWordWrap,
                    quote
                )
                
                # End painting
                painter.end()
                
                # Save the final image
                full_path = os.path.join(directory, chart["filename"])
                if final_pixmap.save(full_path, "PNG"):
                    successfully_saved += 1
            
            # Generate and save HTML summary with stats
            html_path = os.path.join(directory, "binary_ninja_wrapped.html")
            
            # Get current date for the header
            current_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Load CSS
            css = template_loader.load_export_css()

            # Build HTML components
            file_formats_html = ''
            sorted_formats = sorted(self.file_formats.items(), key=operator.itemgetter(1), reverse=True)
            for fmt, count in sorted_formats:
                file_formats_html += f'<div class="stat-item">{fmt}: <span class="stat-value">{count}</span></div>\n'

            cpu_archs_html = ''
            sorted_archs = sorted(self.cpu_archs.items(), key=operator.itemgetter(1), reverse=True)
            for arch, count in sorted_archs:
                cpu_archs_html += f'<div class="stat-item">{arch}: <span class="stat-value">{count}</span></div>\n'

            binary_stats_html = ''
            for stat, value in self.binary_stats.items():
                binary_stats_html += f'<div class="stat-item">{stat.capitalize()}: <span class="stat-value">{value:.2f} KB</span></div>\n'

            biggest_binary_html = ''
            if self.biggest_binary["path"]:
                binary_name = os.path.basename(self.biggest_binary["path"])
                binary_size = self.biggest_binary["size"]
                binary_format = self.biggest_binary["format"]
                binary_arch = self.biggest_binary["arch"] if self.biggest_binary["arch"] else "Unknown"
                biggest_binary_html = f'''
                        <h3>Biggest Binary</h3>
                        <div class="stat-item">Path: <span class="stat-value">{binary_name}</span></div>
                        <div class="stat-item">Size: <span class="stat-value">{binary_size:.2f} KB</span></div>
                        <div class="stat-item">Format: <span class="stat-value">{binary_format}</span></div>
                        <div class="stat-item">Architecture: <span class="stat-value">{binary_arch}</span></div>
                '''

            # Render template
            html = template_loader.render_export_html(
                css=css,
                date=current_date,
                overall_quote=self.getJokeForStats(),
                binary_count=self.count,
                formats_quote=self.getJokeForFileFormats(),
                file_formats_html=file_formats_html,
                archs_quote=self.getJokeForArchitectures(),
                cpu_archs_html=cpu_archs_html,
                binary_stats_quote=self.getJokeForBinaryStats(),
                binary_stats_html=binary_stats_html,
                biggest_binary_html=biggest_binary_html,
                static_quote=self.getQuoteForStaticBinaries(),
                static_count=self.static_binaries_count["static"],
                dynamic_count=self.static_binaries_count["dynamic"],
                user_name=self.user_name
            )

            # Write the HTML file
            try:
                with open(html_path, 'w') as f:
                    f.write(html)
                html_saved = True
            except Exception as e:
                logger.log_error(f"Error saving HTML: {str(e)}")
                html_saved = False
            
            # Show completion message
            if html_saved:
                message = f"Successfully exported {successfully_saved} images and HTML summary to:\n{directory}"
            else:
                message = f"Successfully exported {successfully_saved} images to:\n{directory}\nFailed to save HTML summary."
                
            QtWidgets.QMessageBox.information(self, "Export Complete", message)
            
    def shareToTwitter(self):
        """Share stats and image to Twitter"""
        # First, save the combined image to a temporary location
        temp_dir = tempfile.gettempdir()
        temp_file = os.path.join(temp_dir, "bn_wrapped_share.png")
        
        # Generate combined image
        chart_pixmaps = [
            self.generateFileFormatImage(),
            self.generateCPUArchImage(),
            self.generateBinaryStatsImage(),
            self.generateStaticBinariesImage()
        ]
        
        # Create a combined image with lighter background
        combined = self.createCombinedImage(chart_pixmaps, background_color="#2D2D2D")
        
        # Save the image for sharing
        if combined and combined.save(temp_file, "PNG"):
            # Get a quote to share
            quote = self.getQuote()
            
            # Encode the text for URL
            encoded_text = urllib.parse.quote(f"My Binary Ninja Wrapped stats: {quote} #BinaryNinjaWrapped")
            
            # Show dialog to let user know what's happening
            msg = QtWidgets.QMessageBox(self)
            msg.setWindowTitle("Share to Twitter")
            msg.setText("The combined image has been saved and will open in your browser.<br><br>You can attach the image from:<br>" + temp_file)
            msg.setStandardButtons(QtWidgets.QMessageBox.StandardButton.Ok | QtWidgets.QMessageBox.StandardButton.Cancel)
            
            if msg.exec() == QtWidgets.QMessageBox.StandardButton.Ok:
                # Open Twitter with pre-filled text
                twitter_url = f"https://twitter.com/intent/tweet?text={encoded_text}"
                QtGui.QDesktopServices.openUrl(QtCore.QUrl(twitter_url))
    
    def shareToMastodon(self):
        """Share stats and image to Mastodon"""
        # First, save the combined image to a temporary location
        temp_dir = tempfile.gettempdir()
        temp_file = os.path.join(temp_dir, "bn_wrapped_share.png")
        
        # Generate combined image
        chart_pixmaps = [
            self.generateFileFormatImage(),
            self.generateCPUArchImage(),
            self.generateBinaryStatsImage(),
            self.generateStaticBinariesImage()
        ]
        
        # Create a combined image with lighter background
        combined = self.createCombinedImage(chart_pixmaps, background_color="#2D2D2D")
        
        # Save the image for sharing
        if combined and combined.save(temp_file, "PNG"):
            # Get a quote to share
            quote = self.getQuote()
            
            # Prompt user for their Mastodon instance
            instance, ok = QtWidgets.QInputDialog.getText(
                self, "Mastodon Instance", 
                "Enter your Mastodon instance URL (e.g., mastodon.social):"
            )
            
            if ok and instance:
                # Encode the text for URL
                encoded_text = urllib.parse.quote(f"My Binary Ninja Wrapped stats: {quote} #BinaryNinjaWrapped")
                
                # Show dialog to let user know what's happening
                msg = QtWidgets.QMessageBox(self)
                msg.setWindowTitle("Share to Mastodon")
                msg.setText("The combined image has been saved and will open in your browser.<br><br>You can attach the image from:<br>" + temp_file)
                msg.setStandardButtons(QtWidgets.QMessageBox.StandardButton.Ok | QtWidgets.QMessageBox.StandardButton.Cancel)
                
                if msg.exec() == QtWidgets.QMessageBox.StandardButton.Ok:
                    # Open Mastodon compose page with pre-filled text
                    mastodon_url = f"https://{instance}/share?text={encoded_text}"
                    QtGui.QDesktopServices.openUrl(QtCore.QUrl(mastodon_url))
    
    def shareToLinkedIn(self):
        """Share stats and image to LinkedIn"""
        # First, save the combined image to a temporary location
        temp_dir = tempfile.gettempdir()
        temp_file = os.path.join(temp_dir, "bn_wrapped_share.png")
        
        # Generate combined image
        chart_pixmaps = [
            self.generateFileFormatImage(),
            self.generateCPUArchImage(),
            self.generateBinaryStatsImage(),
            self.generateStaticBinariesImage()
        ]
        
        # Create a combined image with lighter background
        combined = self.createCombinedImage(chart_pixmaps, background_color="#2D2D2D")
        
        # Save the image for sharing
        if combined and combined.save(temp_file, "PNG"):
            # Get a quote to share
            quote = self.getQuote()
            
            # Prepare text to share
            share_text = f"My Binary Ninja Wrapped stats: {quote} #BinaryNinjaWrapped"
            
            # Show dialog to let user know what's happening
            msg = QtWidgets.QMessageBox(self)
            msg.setWindowTitle("Share to LinkedIn")
            msg.setText("The combined image has been saved and will open in your browser.<br><br>You can attach the image from:<br>" + temp_file)
            msg.setStandardButtons(QtWidgets.QMessageBox.StandardButton.Ok | QtWidgets.QMessageBox.StandardButton.Cancel)
            
            if msg.exec() == QtWidgets.QMessageBox.StandardButton.Ok:
                # LinkedIn only supports the URL parameter for share-offsite
                # The user will need to manually add the text
                
                # Simple URL format for LinkedIn
                linkedin_url = "https://www.linkedin.com/sharing/share-offsite/?url=https://binary.ninja"
                
                # Open LinkedIn sharing dialog
                QtGui.QDesktopServices.openUrl(QtCore.QUrl(linkedin_url))
    
    def createCombinedImage(self, chart_pixmaps, background_color="#2D2D2D"):
        """Helper method to create a combined image for social media sharing"""
        if not chart_pixmaps:
            return None
            
        titles = [
            "File Format Breakdown",
            "CPU Architectures",
            "Binary Statistics",
            "Static Binaries"
        ]
        
        # Grid layout configuration
        columns = 2  # Number of columns in the grid
        rows = (len(chart_pixmaps) + columns - 1) // columns  # Ceiling division to get number of rows
        
        # Get typical dimensions of the charts
        chart_width = max(pixmap.width() for pixmap in chart_pixmaps)
        chart_height = max(pixmap.height() for pixmap in chart_pixmaps)
        
        # Grid spacing
        horizontal_spacing = 40
        vertical_spacing = 40
        
        # Size of the quotes
        quote_height = 60

        # Check if wordmark exists to adjust header height
        wordmark = QtGui.QPixmap(":/icons/images/logo-wordmark-dark.png")

        # Calculate total dimensions for the grid layout
        header_height = 180 if not wordmark.isNull() else 150  # Space for wordmark, title and timestamp
        footer_height = 40   # Extra space at the bottom

        # Total width: margin + (chart_width + spacing) * columns - spacing (no spacing after last column) + margin
        total_width = 60 + (chart_width + horizontal_spacing) * columns - horizontal_spacing + 60

        # Total height: header + (chart_height + quote_height + spacing) * rows - spacing (no spacing after last row) + footer
        total_height = header_height + (chart_height + quote_height + vertical_spacing) * rows - vertical_spacing + footer_height

        # Create a new image with the right dimensions
        combined = QtGui.QPixmap(total_width, total_height)
        combined.fill(QtGui.QColor(background_color))  # Lighter background to make BN logo pop
        
        # Paint everything onto the combined image
        painter = QtGui.QPainter(combined)
        
        # Add the same content as in exportCombinedImage
        # Use the wordmark at the top
        if not wordmark.isNull():
            logo_x = (total_width - wordmark.width()) // 2
            painter.drawPixmap(logo_x, 20, wordmark)
        
        # Add a title
        title_font = QtGui.QFont()
        title_font.setPointSize(24)
        title_font.setBold(True)
        painter.setFont(title_font)
        painter.setPen(QtGui.QColor("#1DB954"))  # Spotify green
        
        title_y = 45 if wordmark.isNull() else 20 + wordmark.height() + 10
        
        painter.drawText(
            QtCore.QRect(0, title_y, total_width, 30),
            QtCore.Qt.AlignmentFlag.AlignCenter,
            f"{self.user_name}'s Wrapped {self.year}"
        )
        
        # Add timestamp
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        timestamp_font = QtGui.QFont()
        timestamp_font.setPointSize(12)
        timestamp_font.setItalic(True)
        painter.setFont(timestamp_font)
        painter.setPen(QtGui.QColor("#1DB954"))  # Spotify green
        
        # Adjust the timestamp position - it should be below the title
        timestamp_y = 120 if not wordmark.isNull() else 80
        
        painter.drawText(
            QtCore.QRect(0, timestamp_y, total_width, 20),
            QtCore.Qt.AlignmentFlag.AlignCenter,
            f"Generated: {current_time}"
        )
        
        # Draw each chart in a grid layout
        for i, pixmap in enumerate(chart_pixmaps):
            if not pixmap:
                continue
                
            # Calculate grid position
            col = i % columns
            row = i // columns
            
            # Calculate pixel position for this chart
            x = 60 + col * (chart_width + horizontal_spacing)
            y = header_height + row * (chart_height + quote_height + vertical_spacing)
            
            # Draw the chart
            painter.drawPixmap(x, y, pixmap)
            
            # Add a quote below the chart
            quote = ""
            if "File Format" in titles[i]:
                quote = self.getJokeForFileFormats()
            elif "CPU" in titles[i]:
                quote = self.getJokeForArchitectures()
            elif "Binary Statistics" in titles[i]:
                quote = self.getJokeForBinaryStats()
            elif "Static" in titles[i]:
                quote = self.getQuoteForStaticBinaries()
            
            # Set up the font for the quote
            quote_font = QtGui.QFont()
            quote_font.setPointSize(10)
            quote_font.setItalic(True)
            painter.setFont(quote_font)
            
            # Determine the color - use a color from the chart to make it look nice
            if i < len(self.get_spotify_colors()):
                quote_color = self.get_spotify_colors()[i]
            else:
                quote_color = "#1DB954"  # Default to Spotify green
                
            painter.setPen(QtGui.QColor(quote_color))
            
            # The quote rectangle position
            quote_x = x
            quote_y = y + chart_height + 10
            quote_width = chart_width
            
            # Draw the quote with word wrapping
            painter.drawText(
                QtCore.QRect(quote_x, quote_y, quote_width, quote_height),
                QtCore.Qt.AlignmentFlag.AlignCenter | QtCore.Qt.TextFlag.TextWordWrap,
                quote
            )
        
        # End painting
        painter.end()
        
        return combined

    def getJokeForStats(self):
        """Get a quote about overall statistics"""
        return quotes.get_stats_quote(self.count, self.user_name, self.binary_stats)
        
    def getJokeForFileFormats(self):
        """Get a quote about file format variety"""
        return quotes.get_file_formats_quote(self.file_formats)

    def getJokeForArchitectures(self):
        """Get a quote about CPU architecture variety"""
        return quotes.get_architectures_quote(self.cpu_archs)

    def getJokeForBinaryStats(self):
        """Get a quote about binary statistics"""
        return quotes.get_binary_stats_quote(self.binary_stats)

    def getQuoteForStaticBinaries(self):
        """Get a quote about static vs dynamic binaries"""
        return quotes.get_static_binaries_quote(self.static_binaries_count)
    
    def getQuote(self):
        """Get a random quote from all categories"""
        quotes = [
            self.getJokeForStats(),
            self.getJokeForFileFormats(),
            self.getJokeForArchitectures(),
            self.getJokeForBinaryStats(),
            self.getQuoteForStaticBinaries(),
        ]
        return random.choice(quotes)


def launchBNWrapped(context):
    # Get the actual recent files from settings
    global widget
    recent_files = QtCore.QSettings().value("ui/recentFiles", [], type=list)
    
    # Create a splash screen while loading
    splash_pixmap = createSplashImage()
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
    
def createSplashImage():
    """Create a stylish splash screen image with the Binary Ninja wordmark logo"""
    # Create a pixmap for the splash screen - make it larger
    pixmap = QtGui.QPixmap(700, 400)
    pixmap.fill(QtGui.QColor("#191414"))  # Dark background
    
    # Create a painter to draw on the pixmap
    painter = QtGui.QPainter(pixmap)
    
    # Draw colorful gradient boxes - use random colors for visual interest
    import random
    
    # Define a larger set of possible colors for more variety
    color_options = [
        QtGui.QColor("#1DB954"),  # Spotify green
        QtGui.QColor("#FF9CE0"),  # Pink
        QtGui.QColor("#2E77D0"),  # Blue
        QtGui.QColor("#FF7900"),  # Orange
        QtGui.QColor("#FFFF64"),  # Yellow
        QtGui.QColor("#B49BC8"),  # Purple
        QtGui.QColor("#FFB9B9"),  # Salmon
        QtGui.QColor("#30A2FF"),  # Light blue
        QtGui.QColor("#E13300"),  # Bright red
        QtGui.QColor("#00C5CD"),  # Turquoise
        QtGui.QColor("#ADFF2F"),  # Green yellow
        QtGui.QColor("#FF6EB4"),  # Hot pink
    ]
    
    # Randomly select 5 colors
    random.shuffle(color_options)
    colors = color_options[:5]
    
    box_size = 80
    box_margin = 25  # Increased margin for better spacing
    box_start_x = (pixmap.width() - (box_size * 3 + box_margin * 2)) // 2
    box_start_y = 60  # Move boxes down to avoid overlap with wordmark
    
    for i in range(5):
        row = i // 3
        col = i % 3
        x = box_start_x + col * (box_size + box_margin)
        y = box_start_y + row * (box_size + box_margin)
        
        # Create a gradient for each box
        gradient = QtGui.QLinearGradient(x, y, x + box_size, y + box_size)
        gradient.setColorAt(0, colors[i])
        gradient.setColorAt(1, colors[i].darker(120))
        
        painter.setBrush(QtGui.QBrush(gradient))
        painter.setPen(QtCore.Qt.PenStyle.NoPen)
        painter.drawRoundedRect(x, y, box_size, box_size, 10, 10)
    
    # Add the Binary Ninja wordmark logo
    # For dark background, use the dark wordmark as requested
    wordmark = QtGui.QPixmap(":/icons/images/logo-wordmark-dark.png")
    if not wordmark.isNull():
        # Scale the wordmark to fit nicely 
        wordmark_width = 350  # Target width in pixels, increased for better visibility
        wordmark = wordmark.scaledToWidth(wordmark_width, QtCore.Qt.TransformationMode.SmoothTransformation)
        
        # Position the wordmark at the top, centered horizontally
        wordmark_x = (pixmap.width() - wordmark.width()) // 2
        wordmark_y = 280  # Position below the boxes to avoid overlap
        painter.drawPixmap(wordmark_x, wordmark_y, wordmark)
    
    # Finish painting
    painter.end()
    
    return pixmap

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