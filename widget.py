import os
import operator
import datetime
from PySide6 import QtWidgets, QtGui, QtCore

from .utils import get_user_name, get_contrasting_text_color
from .file_analyzer import FileAnalyzer
from .chart_generator import ChartGenerator
from .exporter import BNWrappedExporter
from . import quotes
from . import template_loader
from .log import logger


class BNWrappedWidget(QtWidgets.QWidget):
    """Main widget for Binary Ninja Wrapped - displays stats about recently analyzed files"""

    def __init__(self, recent_files, splash=None, parent=None):
        super().__init__(parent)
        self.recent_files = QtCore.QSettings().value("ui/recentFiles", [], type=list)
        self.count = 0
        self.file_formats = {}
        self.cpu_archs = {}
        self.binary_stats = {'avg size': 0, 'min size': 0, 'max size': 0, 'projects': 0}
        self.static_binaries_count = {'static': 0, 'dynamic': 0}
        self.biggest_binary = {"path": "", "size": 0, "format": "", "arch": ""}
        self.project_count = 0
        self.splash = splash  # Store the splash screen reference
        self.splash_start_time = datetime.datetime.now()  # Track when the splash was shown
        self.user_name = get_user_name()  # Get the user's name
        self.current_tab_index = 0  # Track the current tab for custom quotes
        self.year = datetime.datetime.now().year

        self.file_analyzer = FileAnalyzer()
        self.chart_generator = ChartGenerator()
        self.exporter = BNWrappedExporter(self)

        self.initUI(True)

        self.escapeShortcut = QtGui.QShortcut(QtGui.QKeySequence(QtCore.Qt.Key.Key_Escape), self)
        self.escapeShortcut.activated.connect(self.close)

    def _apply_placeholder_data(self):
        """Apply placeholder data for demo/loading purposes"""
        self.file_formats = {'PE': 10, 'ELF': 5, 'Mach-O': 3}
        self.cpu_archs = {'x86': 12, 'ARM': 3, 'MIPS': 1}
        self.binary_stats = {'avg size': 1024, 'min size': 512, 'max size': 2048, 'projects': 3}
        self.static_binaries_count = {'static': 8, 'dynamic': 10}
        self.biggest_binary = {"path": "example.exe", "size": 2048, "format": "PE", "arch": "x86"}

        QtCore.QTimer.singleShot(100, self.showProgressDialog)

    def showProgressDialog(self):
        """Show a progress dialog while computing stats"""
        if hasattr(self, 'splash') and self.splash:
            elapsed_time = (datetime.datetime.now() - self.splash_start_time).total_seconds()
            if elapsed_time < 3.0:
                # Wait until 3 seconds have passed
                remaining_time = int((3.0 - elapsed_time) * 1000)
                QtCore.QTimer.singleShot(remaining_time, self.closeSplash)
            else:
                # Already been 3 seconds, close it now
                self.closeSplash()

        if hasattr(self, 'overlay'):
            self.overlay.setFocusPolicy(QtCore.Qt.FocusPolicy.NoFocus)

    def closeSplash(self):
        """Close the splash screen after ensuring minimum display time"""
        if hasattr(self, 'splash') and self.splash:
            self.splash.close()
            self.splash = None

        if not self.recent_files:
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
        dialog.setMinimumDuration(0)

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

        dialog.resize(400, dialog.height())

        dialog.setWindowFlags(dialog.windowFlags() | QtCore.Qt.WindowType.WindowStaysOnTopHint)
        dialog.show()

        if hasattr(self, 'overlay'):
            self.overlay.raise_()

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
        self.binary_stats = {'avg size': 0, 'min size': float('inf'), 'max size': 0, 'projects': 0}
        self.static_binaries_count = {'static': 0, 'dynamic': 0}
        self.biggest_binary = {"path": "", "size": 0, "format": "", "arch": ""}
        self.project_count = 0
        total_size = 0

        # Process each file
        for i, f in enumerate(self.recent_files):
            if progress_dialog and progress_dialog.wasCanceled():
                break

            if os.path.isdir(f):
                self.project_count += 1
                logger.log_debug(f"Counting project/directory: {f}")
                continue

            if not os.path.exists(f):
                logger.log_debug(f"Skipping non-existent file: {f}")
                continue

            if progress_dialog:
                progress_dialog.setValue(i)
                progress_dialog.setLabelText(f"Analyzing: {os.path.basename(f)}")
                QtWidgets.QApplication.processEvents()

            result = self.file_analyzer.skim_file(f)
            if 'file_formats' not in result or 'arch' not in result or 'size' not in result:
                continue

            self.count += 1
            file_format = result['file_formats']
            arch = result['arch']

            if not file_format or file_format == '':
                logger.log_warn(f"Empty file_format detected for {f}, result: {result}")
                file_format = 'Raw'
            if not arch or arch == '':
                logger.log_warn(f"Empty arch detected for {f}, result: {result}")
                arch = 'Raw'

            self.file_formats[file_format] = self.file_formats.get(file_format, 0) + 1
            self.cpu_archs[arch] = self.cpu_archs.get(arch, 0) + 1

            if result['size'] > 0:
                total_size += result['size']
                self.binary_stats['min size'] = min(self.binary_stats['min size'], result['size'])
                self.binary_stats['max size'] = max(self.binary_stats['max size'], result['size'])

            if 'is_static' in result and result['is_static']:
                self.static_binaries_count['static'] += 1
            else:
                self.static_binaries_count['dynamic'] += 1

            if result['size'] > self.biggest_binary["size"]:
                self.biggest_binary = {
                    "path": f,
                    "size": result['size'],
                    "format": result['file_formats'],
                    "arch": result['arch']
                }

        if self.count > 0:
            self.binary_stats['avg size'] = total_size / self.count
        else:
            self.binary_stats['min size'] = 0

        self.binary_stats['projects'] = self.project_count

        if not self.file_formats:
            self._apply_placeholder_data()

        if progress_dialog:
            progress_dialog.setValue(len(self.recent_files))

    def initUI(self, use_placeholder=False):
        """Initialize the UI, optionally with placeholder content"""
        self.setWindowTitle("Binary Ninja Wrapped")
        layout = QtWidgets.QVBoxLayout(self)

        if use_placeholder and not self.file_formats:
            self._apply_placeholder_data()

        self.tabs = QtWidgets.QTabWidget(self)
        self.tabs.currentChanged.connect(self.onTabChanged)
        layout.addWidget(self.tabs)

        self.statsTextTab = self.createStatsTextTab()
        self.fileFormatTab = self.createStatTab("File Format Breakdown", self.generateFileFormatImage)
        self.cpuArchTab = self.createStatTab("CPU Architectures", self.generateCPUArchImage)
        self.binaryStatsTab = self.createStatTab("Statistics", self.generateBinaryStatsImage)
        self.staticBinariesTab = self.createStatTab("Static Binaries", self.generateStaticBinariesImage)

        self.tabs.addTab(self.statsTextTab, "Stats Summary")
        self.tabs.addTab(self.fileFormatTab, "File Formats")
        self.tabs.addTab(self.cpuArchTab, "CPU Arch")
        self.tabs.addTab(self.binaryStatsTab, "Statistics")
        self.tabs.addTab(self.staticBinariesTab, "Static Binaries")

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
            self.overlay.raise_()

        buttonLayout = QtWidgets.QHBoxLayout()
        socialButtonLayout = QtWidgets.QHBoxLayout()

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

        self.exportButton = QtWidgets.QPushButton("Export Combined Image", self)
        self.exportButton.clicked.connect(self.exporter.export_combined_image)
        self.exportButton.setStyleSheet(buttonStyle)
        buttonLayout.addWidget(self.exportButton)

        self.exportAllButton = QtWidgets.QPushButton("Export All", self)
        self.exportAllButton.clicked.connect(self.exporter.export_images)
        self.exportAllButton.setStyleSheet(buttonStyle)
        buttonLayout.addWidget(self.exportAllButton)

        self.shareTwitterButton = QtWidgets.QPushButton("Share to Twitter", self)
        self.shareTwitterButton.clicked.connect(self.exporter.share_to_twitter)
        self.shareTwitterButton.setStyleSheet(socialButtonStyle)
        socialButtonLayout.addWidget(self.shareTwitterButton)

        self.shareMastodonButton = QtWidgets.QPushButton("Share to Mastodon", self)
        self.shareMastodonButton.setObjectName("mastodon")
        self.shareMastodonButton.clicked.connect(self.exporter.share_to_mastodon)
        self.shareMastodonButton.setStyleSheet(socialButtonStyle)
        socialButtonLayout.addWidget(self.shareMastodonButton)

        self.shareLinkedInButton = QtWidgets.QPushButton("Share to LinkedIn", self)
        self.shareLinkedInButton.setObjectName("linkedin")
        self.shareLinkedInButton.clicked.connect(self.exporter.share_to_linkedin)
        self.shareLinkedInButton.setStyleSheet(socialButtonStyle)
        socialButtonLayout.addWidget(self.shareLinkedInButton)

        self.refreshButton = QtWidgets.QPushButton("Flush Stats Cache", self)
        self.refreshButton.clicked.connect(self.refreshStats)
        self.refreshButton.setStyleSheet(buttonStyle)
        buttonLayout.addWidget(self.refreshButton)

        layout.addLayout(socialButtonLayout)
        layout.addLayout(buttonLayout)

    def resizeEvent(self, event):
        """Handle resize events to keep the overlay properly sized"""
        if hasattr(self, 'overlay'):
            self.overlay.resize(self.width() - 20, self.height() - 60)
        super().resizeEvent(event)

    def onTabChanged(self, index):
        """Handle tab change event"""
        self.current_tab_index = index

    def refreshStats(self):
        """Refresh statistics by clearing cache and recomputing"""
        self.file_analyzer.cache = {}

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

        self.computeStats(dialog)

        dialog.close()

        self.file_analyzer.save_cache()

        self.updateUI()

    def updateUI(self):
        """Update the UI with the latest data after computations are done"""
        index = self.tabs.currentIndex()

        self.tabs.removeTab(0)
        self.tabs.removeTab(0)
        self.tabs.removeTab(0)
        self.tabs.removeTab(0)
        self.tabs.removeTab(0)

        self.statsTextTab = self.createStatsTextTab()
        self.fileFormatTab = self.createStatTab("File Format Breakdown", self.generateFileFormatImage)
        self.cpuArchTab = self.createStatTab("CPU Architectures", self.generateCPUArchImage)
        self.binaryStatsTab = self.createStatTab("Statistics", self.generateBinaryStatsImage)
        self.staticBinariesTab = self.createStatTab("Static Binaries", self.generateStaticBinariesImage)

        self.tabs.addTab(self.statsTextTab, "Stats Summary")
        self.tabs.addTab(self.fileFormatTab, "File Formats")
        self.tabs.addTab(self.cpuArchTab, "CPU Arch")
        self.tabs.addTab(self.binaryStatsTab, "Statistics")
        self.tabs.addTab(self.staticBinariesTab, "Static Binaries")

        self.tabs.setCurrentIndex(index)

        if hasattr(self, 'overlay'):
            self.overlay.hide()
            self.overlay.deleteLater()
            delattr(self, 'overlay')

    def createStatTab(self, title, imageGenFunc):
        """Create a statistics tab with chart and quote"""
        widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(widget)

        imageLabel = QtWidgets.QLabel(widget)
        imageLabel.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(imageLabel)
        pixmap = imageGenFunc()
        if pixmap:
            imageLabel.setPixmap(pixmap)

        quoteLabel = QtWidgets.QLabel(widget)
        quoteLabel.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        quoteLabel.setWordWrap(True)
        quoteLabel.setSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Maximum)

        bg_color = ""
        if "File Format" in title:
            bg_color = self.get_spotify_colors(tab_index=1)[0]
        elif "CPU" in title:
            bg_color = self.get_spotify_colors(tab_index=2)[0]
        elif "Statistics" in title:
            bg_color = self.get_spotify_colors(tab_index=3)[0]
        elif "Static Binaries" in title:
            bg_color = self.get_spotify_colors(tab_index=4)[0]
        else:
            bg_color = "#1DB954"

        text_color = get_contrasting_text_color(bg_color) if bg_color.startswith('#') else 'white'

        quoteLabel.setStyleSheet(f"""
            background-color: {bg_color};
            color: {text_color};
            padding: 10px;
            border-radius: 5px;
            font-style: italic;
            font-size: 14px;
            margin: 10px;
        """)

        if "File Format" in title:
            quote = quotes.get_file_formats_quote(self.file_formats)
        elif "CPU" in title:
            quote = quotes.get_architectures_quote(self.cpu_archs)
        elif "Statistics" in title:
            quote = quotes.get_binary_stats_quote(self.binary_stats)
        elif "Static Binaries" in title:
            quote = quotes.get_static_binaries_quote(self.static_binaries_count)
        else:
            quote = quotes.get_stats_quote(self.count, self.user_name, self.binary_stats)

        quoteLabel.setText(quote)
        layout.addWidget(quoteLabel)

        return widget

    def createStatsTextTab(self):
        """Create the stats summary text tab"""
        widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(widget)

        # Create a colorful background
        palette = widget.palette()
        palette.setColor(QtGui.QPalette.Window, QtGui.QColor("#1DB954"))
        widget.setAutoFillBackground(True)
        widget.setPalette(palette)

        text = QtWidgets.QTextEdit()
        text.setReadOnly(True)

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

        html = template_loader.render_stats_tab(
            user_name=self.user_name,
            stats_quote=quotes.get_stats_quote(self.count, self.user_name, self.binary_stats),
            file_formats_html=file_formats_html,
            formats_quote=quotes.get_file_formats_quote(self.file_formats),
            cpu_archs_html=cpu_archs_html,
            archs_quote=quotes.get_architectures_quote(self.cpu_archs),
            binary_stats_html=binary_stats_html,
            biggest_binary_html=biggest_binary_html,
            static_count=self.static_binaries_count["static"],
            dynamic_count=self.static_binaries_count["dynamic"],
            static_quote=quotes.get_static_binaries_quote(self.static_binaries_count),
            project_count=self.project_count,
            projects_quote=quotes.get_projects_quote(self.project_count),
            timestamp=current_time
        )

        text.setHtml(html)

        layout.addWidget(text)

        timestamp_layout = QtWidgets.QHBoxLayout()

        timestamp_label = QtWidgets.QLabel(widget)
        current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        timestamp_label.setText(f"Generated: {current_time}")
        timestamp_label.setStyleSheet("color: #333333; font-style: italic;")

        timestamp_layout.addWidget(timestamp_label)
        layout.addLayout(timestamp_layout)

        return widget

    def get_spotify_colors(self, tab_index=None):
        """Delegate to chart generator for color palette"""
        return self.chart_generator.get_color_palette(tab_index)

    def generateFileFormatImage(self):
        """Delegate to chart generator for file format chart"""
        return self.chart_generator.generate_file_format_chart(self.file_formats, tab_index=1)

    def generateCPUArchImage(self):
        """Delegate to chart generator for CPU architecture chart"""
        return self.chart_generator.generate_cpu_arch_chart(self.cpu_archs, tab_index=2)

    def generateBinaryStatsImage(self):
        """Delegate to chart generator for binary stats chart"""
        return self.chart_generator.generate_binary_stats_chart(self.binary_stats, tab_index=3)

    def generateStaticBinariesImage(self):
        """Delegate to chart generator for static binaries chart"""
        return self.chart_generator.generate_static_binaries_chart(
            self.static_binaries_count['static'],
            self.static_binaries_count['dynamic'],
            tab_index=4
        )
