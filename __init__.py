import os
import io
import json
import random
import operator
import datetime
import getpass
import platform
import pwd
from binaryninja import PluginCommand, load, SymbolType, user_directory
from binaryninja.log import log as bnlog
from binaryninja.log import LogLevel
from PySide6 import QtWidgets, QtGui, QtCore
import matplotlib.pyplot as plt
import matplotlib as mpl

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
        self.cache_path = os.path.join(user_directory(), "wrapped_cache.json")
        self.timestamp = 0  # When the data was last updated
        self.user_name = self.get_user_name()  # Get the user's name
        
        # Initialize UI with placeholder content
        self.initUI(True)
        
        # Try to load cached data first
        cache_loaded = self.load_cached_data()
        
        # Check if cache is older than a week
        cache_age = (datetime.datetime.now() - 
                    datetime.datetime.fromtimestamp(self.timestamp)).total_seconds()
        cache_too_old = cache_age > 604800  # 7 days in seconds
        
        if cache_loaded and not cache_too_old:
            # Update UI with loaded data
            QtCore.QTimer.singleShot(100, self.updateUI)
        else:
            # Start stats computation in a small delay to allow UI to render first
            QtCore.QTimer.singleShot(100, self.showProgressDialog)
            
    def get_user_name(self):
        """Get the user's name in a cross-platform way"""
        try:
            # Try to get the full name
            if platform.system() == "Windows":
                # Windows-specific approach
                import ctypes
                GetUserNameEx = ctypes.windll.secur32.GetUserNameExW
                NameDisplay = 3  # EXTENDED_NAME_FORMAT value for display name
                
                size = ctypes.pointer(ctypes.c_ulong(0))
                GetUserNameEx(NameDisplay, None, size)
                
                nameBuffer = ctypes.create_unicode_buffer(size.contents.value)
                GetUserNameEx(NameDisplay, nameBuffer, size)
                return nameBuffer.value
            else:
                # Unix-like systems (macOS, Linux)
                try:
                    # Try to get the full name from the passwd database
                    return pwd.getpwuid(os.getuid())[4].split(',')[0]
                except (KeyError, IndexError):
                    pass
            
            # Fallback to just username
            return getpass.getuser()
        except:
            # Final fallback
            return "Binary Ninja User"

    def skimFile(self, file_path):
        # Stub: skim the file for relevant information
        result = {}
        # skip files that don't exist or are directories:
        if not os.path.exists(file_path) or os.path.isdir(file_path):
            return result
        bnlog(LogLevel.InfoLog, "Scanning file: " + file_path)
        with load(file_path, update_analysis=False) as bv:
            bv.set_analysis_hold(True)
            result['file_formats'] = bv.view_type
            result['arch'] = bv.arch.name
            result['size'] = os.path.getsize(file_path) / 1024
            # TODO: Handle fat MachO files
            num_imports = len(bv.get_symbols_of_type(SymbolType.ImportAddressSymbol))
            result['num_imports'] = num_imports
            # Determine if binary is statically compiled based on import count
            result['is_static'] = num_imports <= 5
            bnlog(LogLevel.InfoLog, f"File: {file_path}, Format: {result['file_formats']}, Arch: {result['arch']}, Size: {result['size']} KB, Imports: {num_imports}")
        return result

    def showProgressDialog(self):
        """Show a progress dialog while computing stats"""
        # Close splash screen if it exists
        if hasattr(self, 'splash') and self.splash:
            self.splash.close()
            
        # Make sure any existing overlay doesn't catch Escape key
        # by ensuring it doesn't have focus
        if hasattr(self, 'overlay'):
            self.overlay.setFocusPolicy(QtCore.Qt.FocusPolicy.NoFocus)
            
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
            QProgressDialog {
                background-color: #191414;
                color: white;
                border: 2px solid #1DB954;
                border-radius: 10px;
            }
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
                color: white;
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
    
    def load_cached_data(self):
        """Load stats from cached JSON file"""
        try:
            if os.path.exists(self.cache_path):
                with open(self.cache_path, 'r') as f:
                    data = json.load(f)
                
                # Store the timestamp
                self.timestamp = data.get('timestamp', 0)
                
                # Load cached data
                self.count = data.get('count', 0)
                self.file_formats = data.get('file_formats', {})
                self.cpu_archs = data.get('cpu_archs', {})
                self.binary_stats = data.get('binary_stats', {'avg': 0, 'min': 0, 'max': 0})
                self.static_binaries_count = data.get('static_binaries_count', {'static': 0, 'dynamic': 0})
                self.biggest_binary = data.get('biggest_binary', {"path": "", "size": 0, "format": "", "arch": ""})
                
                # Close splash screen if it exists
                if hasattr(self, 'splash') and self.splash:
                    self.splash.close()
                
                return True
        except Exception as e:
            bnlog(LogLevel.ErrorLog, f"Error loading cache: {str(e)}")
        return False
    
    def save_cached_data(self):
        """Save stats to a cached JSON file"""
        try:
            # Create .binaryninja dir if it doesn't exist
            os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
            
            # Update timestamp
            self.timestamp = datetime.datetime.now().timestamp()
            
            data = {
                'timestamp': self.timestamp,
                'count': self.count,
                'file_formats': self.file_formats,
                'cpu_archs': self.cpu_archs,
                'binary_stats': self.binary_stats,
                'static_binaries_count': self.static_binaries_count,
                'biggest_binary': self.biggest_binary
            }
            
            with open(self.cache_path, 'w') as f:
                json.dump(data, f)
                
        except Exception as e:
            bnlog(LogLevel.ErrorLog, f"Error saving cache: {str(e)}")
    
    def refresh_stats(self):
        """Force a refresh of the statistics"""
        self.initUI(True)
            
        # Start new computation
        QtCore.QTimer.singleShot(100, self.showProgressDialog)
    
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
            result = self.skimFile(f)
            if 'file_formats' not in result or 'arch' not in result or 'size' not in result:
                continue
                
            # Update stats
            self.count += 1
            self.file_formats[result['file_formats']] = self.file_formats.get(result['file_formats'], 0) + 1
            self.cpu_archs[result['arch']] = self.cpu_archs.get(result['arch'], 0) + 1
            total_size += result['size']
            self.binary_stats['min'] = min(self.binary_stats['min'], result['size'])
            self.binary_stats['max'] = max(self.binary_stats['max'], result['size'])
            
            # Update static/dynamic binaries count
            if 'is_static' in result and result['is_static']:
                bnlog(LogLevel.InfoLog, f"Static binary: {result['is_static']}")
                if result['is_static']:
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
        
        # Save the data to cache
        self.save_cached_data()
        
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
            
            # Resize event handler to keep overlay properly sized
            self.resizeEvent = self.handleResize

        # Add quote label
        self.quoteLabel = QtWidgets.QLabel("Quote of the day: " + self.getQuote(), self)
        layout.addWidget(self.quoteLabel)
        
        # Add button container at the bottom
        buttonLayout = QtWidgets.QHBoxLayout()
        
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
        
        # Add export button
        self.exportButton = QtWidgets.QPushButton("Export Combined Image", self)
        self.exportButton.clicked.connect(self.exportCombinedImage)
        self.exportButton.setStyleSheet(buttonStyle)
        buttonLayout.addWidget(self.exportButton)
        
        # Add refresh button
        self.refreshButton = QtWidgets.QPushButton("Refresh Stats", self)
        self.refreshButton.clicked.connect(self.refresh_stats)
        self.refreshButton.setStyleSheet(buttonStyle)
        buttonLayout.addWidget(self.refreshButton)
        
        # Add close button
        self.closeButton = QtWidgets.QPushButton("Close", self)
        self.closeButton.clicked.connect(self.close)
        self.closeButton.setStyleSheet(buttonStyle)
        buttonLayout.addWidget(self.closeButton)
        
        layout.addLayout(buttonLayout)
        
    def handleResize(self, event):
        """Handle resize events to keep the overlay properly sized"""
        if hasattr(self, 'overlay'):
            self.overlay.resize(self.width() - 20, self.height() - 60)
        # Call the original resize event
        QtWidgets.QWidget.resizeEvent(self, event)
        
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
        
        # Update the quote
        self.quoteLabel.setText("Quote of the day: " + self.getQuote())
        
        # Now remove the overlay if it exists (after all updates are done)
        if hasattr(self, 'overlay'):
            self.overlay.hide()
            self.overlay.deleteLater()
            delattr(self, 'overlay')
            # Restore normal resize handling
            self.resizeEvent = QtWidgets.QWidget.resizeEvent

    def createStatTab(self, title, imageGenFunc):
        widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(widget)
        label = QtWidgets.QLabel(widget)
        label.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(label)
        pixmap = imageGenFunc()
        if pixmap:
            label.setPixmap(pixmap)
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
        html = """
        <html>
        <head>
        <style>
            body {{ 
                font-family: Arial, sans-serif; 
                color: white; 
                background-color: #1DB954;
                padding: 20px;
            }}
            h1 {{ 
                font-size: 24px; 
                text-align: center;
                margin-bottom: 20px;
            }}
            h2 {{ 
                font-size: 20px; 
                color: #191414;
                margin-top: 15px;
            }}
            .stat {{
                font-size: 18px;
                margin: 10px 0;
            }}
            .quote {{
                font-style: italic;
                background-color: #191414;
                color: white;
                padding: 10px;
                border-radius: 5px;
                margin-top: 15px;
                margin-bottom: 15px;
            }}
            .timestamp {{
                font-size: 12px;
                color: #191414;
                text-align: right;
                margin-top: 5px;
                font-style: italic;
            }}
        </style>
        </head>
        <body>
        <h1>Hey {} Here's Your Binary Ninja Wrapped</h1>
        """.format(self.user_name)
        
        # Add quote about general stats
        html += f'<div class="quote">{self.getJokeForStats()}</div>'
        
        html += '<h2>File Formats</h2>'
        # Sort and add file formats
        sorted_formats = sorted(self.file_formats.items(), key=operator.itemgetter(1), reverse=True)
        for fmt, count in sorted_formats:
            html += f'<div class="stat">{fmt}: {count}</div>'
        
        # Add quote about file formats
        html += f'<div class="quote">{self.getJokeForFileFormats()}</div>'
        
        html += '<h2>CPU Architectures</h2>'
        sorted_archs = sorted(self.cpu_archs.items(), key=operator.itemgetter(1), reverse=True)
        for arch, count in sorted_archs:
            html += f'<div class="stat">{arch}: {count}</div>'
        
        # Add quote about CPU architectures
        html += f'<div class="quote">{self.getJokeForArchitectures()}</div>'
        
        html += '<h2>Binary Statistics</h2>'
        for stat, value in self.binary_stats.items():
            html += f'<div class="stat">{stat.capitalize()}: {value:.2f} KB</div>'
        
        # Add biggest binary information
        if self.biggest_binary["path"]:
            html += '<h2>Biggest Binary</h2>'
            html += f'<div class="stat">Path: {os.path.basename(self.biggest_binary["path"])}</div>'
            html += f'<div class="stat">Size: {self.biggest_binary["size"]:.2f} KB</div>'
            html += f'<div class="stat">Format: {self.biggest_binary["format"]}</div>'
            html += f'<div class="stat">Architecture: {self.biggest_binary["arch"]}</div>'
        
        html += f'<h2>Static Binaries</h2>'
        html += f'<div class="stat">Static: {self.static_binaries_count["static"]}</div>'
        html += f'<div class="stat">Dynamic: {self.static_binaries_count["dynamic"]}</div>'
        
        # Add quote about static binaries
        html += f'<div class="quote">{self.getQuoteForStaticBinaries()}</div>'
        
        # Add timestamp at the bottom
        if self.timestamp > 0:
            timestamp_str = datetime.datetime.fromtimestamp(self.timestamp).strftime('%Y-%m-%d %H:%M:%S')
            html += f'<div class="timestamp">Stats last updated: {timestamp_str}</div>'
        
        html += '</body></html>'
        text.setHtml(html)
        
        layout.addWidget(text)
        
        # Add timestamp at the bottom
        timestamp_layout = QtWidgets.QHBoxLayout()
        
        # Add timestamp label
        timestamp_label = QtWidgets.QLabel(widget)
        if self.timestamp > 0:
            timestamp_str = datetime.datetime.fromtimestamp(self.timestamp).strftime('%Y-%m-%d %H:%M:%S')
            timestamp_label.setText(f"Last updated: {timestamp_str}")
            
            # Check if it's been more than a week
            timestamp_age = (datetime.datetime.now() - 
                           datetime.datetime.fromtimestamp(self.timestamp)).total_seconds() / 86400  # Days
            if timestamp_age > 7:
                timestamp_label.setStyleSheet("color: #FF0000; font-style: italic;")  # Red color for outdated stats
            else:
                timestamp_label.setStyleSheet("color: #333333; font-style: italic;")
        else:
            timestamp_label.setText("Just generated")
            timestamp_label.setStyleSheet("color: #333333; font-style: italic;")
            
        timestamp_layout.addWidget(timestamp_label)
        layout.addLayout(timestamp_layout)
        
        return widget

    def get_spotify_colors(self):
        # Spotify-like color palette
        return [
            "#1DB954",  # Spotify green
            "#FF9CE0",  # Pink
            "#2E77D0",  # Blue
            "#FF7900",  # Orange
            "#FFFF64",  # Yellow
            "#B49BC8",  # Purple
            "#FFB9B9",  # Salmon
            "#30A2FF",  # Light blue
        ]

    def generateFileFormatImage(self):
        formats = self.file_formats
        # Sort by value in descending order
        sorted_formats = dict(sorted(formats.items(), key=operator.itemgetter(1), reverse=True))
        
        fig, ax = plt.subplots(facecolor="#191414")  # Dark background like Spotify
        
        colors = self.get_spotify_colors()
        wedges, texts, autotexts = ax.pie(
            sorted_formats.values(), 
            labels=sorted_formats.keys(), 
            autopct='%1.1f%%', 
            colors=colors,
            textprops={'color': 'white'}
        )
        # Make percentage text white and bold
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontweight('bold')
            
        ax.set_title("File Format Breakdown", color='white', fontweight='bold')
        return self.figureToPixmap(fig)

    def generateCPUArchImage(self):
        archs = self.cpu_archs
        # Sort by value in descending order
        sorted_archs = dict(sorted(archs.items(), key=operator.itemgetter(1), reverse=True))
        
        fig, ax = plt.subplots(facecolor="#191414")  # Dark background
        
        colors = self.get_spotify_colors()
        bars = ax.bar(
            sorted_archs.keys(), 
            sorted_archs.values(),
            color=colors[:len(sorted_archs)]
        )
        
        # Add value labels on top of bars
        for bar in bars:
            height = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width()/2., 
                height + 0.1,
                f'{int(height)}',
                ha='center', 
                va='bottom', 
                color='white', 
                fontweight='bold'
            )
            
        ax.set_title("CPU Architectures", color='white', fontweight='bold')
        ax.set_facecolor("#191414")  # Dark background
        ax.spines['bottom'].set_color('white')
        ax.spines['top'].set_color('white')
        ax.spines['left'].set_color('white')
        ax.spines['right'].set_color('white')
        ax.tick_params(axis='x', colors='white')
        ax.tick_params(axis='y', colors='white')
        return self.figureToPixmap(fig)

    def generateBinaryStatsImage(self):
        stats = self.binary_stats
        # Sort by value in descending order
        sorted_stats = dict(sorted(stats.items(), key=operator.itemgetter(1), reverse=True))
        
        fig, ax = plt.subplots(facecolor="#191414")  # Dark background
        
        colors = self.get_spotify_colors()
        bars = ax.bar(
            sorted_stats.keys(), 
            sorted_stats.values(),
            color=colors[:len(sorted_stats)]
        )
        
        # Add value labels on top of bars
        for bar in bars:
            height = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width()/2., 
                height + 0.1,
                f'{int(height)}',
                ha='center', 
                va='bottom', 
                color='white', 
                fontweight='bold'
            )
            
        ax.set_title("Binary Statistics", color='white', fontweight='bold')
        ax.set_ylabel("Size (KB)", color='white')
        ax.set_facecolor("#191414")  # Dark background
        ax.spines['bottom'].set_color('white')
        ax.spines['top'].set_color('white')
        ax.spines['left'].set_color('white')
        ax.spines['right'].set_color('white')
        ax.tick_params(axis='x', colors='white')
        ax.tick_params(axis='y', colors='white')
        return self.figureToPixmap(fig)

    def generateStaticBinariesImage(self):
        static_count = self.static_binaries_count['static']
        dynamic_count = self.static_binaries_count['dynamic']
        total = static_count + dynamic_count
        
        # Calculate percentages for display
        static_percentage = (static_count / total * 100) if total > 0 else 0
        dynamic_percentage = (dynamic_count / total * 100) if total > 0 else 0
        
        fig, ax = plt.subplots(facecolor="#191414")  # Dark background
        
        colors = self.get_spotify_colors()
        bars = ax.bar(
            ['Static', 'Dynamic'], 
            [static_count, dynamic_count],
            color=[colors[0], colors[1]]
        )
        
        # Add value labels on top of bars
        for bar in bars:
            height = bar.get_height()
            percentage = (height / total * 100) if total > 0 else 0
            ax.text(
                bar.get_x() + bar.get_width()/2., 
                height + 0.1,
                f'{int(height)} ({percentage:.1f}%)',
                ha='center', 
                va='bottom', 
                color='white', 
                fontweight='bold'
            )
            
        ax.set_title("Static vs Dynamic Binaries", color='white', fontweight='bold')
        ax.set_ylabel("Count", color='white')
        ax.set_facecolor("#191414")  # Dark background
        ax.spines['bottom'].set_color('white')
        ax.spines['top'].set_color('white')
        ax.spines['left'].set_color('white')
        ax.spines['right'].set_color('white')
        ax.tick_params(axis='x', colors='white')
        ax.tick_params(axis='y', colors='white')
        return self.figureToPixmap(fig)

    def figureToPixmap(self, fig):
        buf = io.BytesIO()
        fig.savefig(buf, format='png')
        plt.close(fig)
        buf.seek(0)
        img = QtGui.QImage()
        img.loadFromData(buf.getvalue(), "PNG")
        return QtGui.QPixmap.fromImage(img)

    def exportCombinedImage(self):
        """Export a single combined image with all charts and stats"""
        file_path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Save Combined Image", "", "PNG Files (*.png)"
        )
        
        if not file_path:
            return
            
        # Add .png extension if not present
        if not file_path.lower().endswith('.png'):
            file_path += '.png'
            
        # Generate all the chart images
        charts = [
            ("File Format Breakdown", self.generateFileFormatImage()),
            ("CPU Architectures", self.generateCPUArchImage()),
            ("Binary Statistics", self.generateBinaryStatsImage()),
            ("Static Binaries", self.generateStaticBinariesImage())
        ]
        
        # Get the total height needed
        header_height = 140  # Space for title and timestamp
        footer_height = 60   # Space for quote
        chart_height = sum(chart[1].height() for _, chart in charts)
        spacing = 20 * (len(charts) - 1)  # Space between charts
        
        total_height = header_height + chart_height + spacing + footer_height
        max_width = max(chart.width() for _, chart in charts)
        
        # Create a new image with the right dimensions
        combined = QtGui.QPixmap(max_width, total_height)
        combined.fill(QtGui.QColor("#191414"))  # Dark background
        
        # Paint everything onto the combined image
        painter = QtGui.QPainter(combined)
        
        # Draw title
        title_font = QtGui.QFont()
        title_font.setPointSize(24)
        title_font.setBold(True)
        painter.setFont(title_font)
        painter.setPen(QtCore.Qt.GlobalColor.white)
        painter.drawText(
            QtCore.QRect(0, 20, max_width, 40),
            QtCore.Qt.AlignmentFlag.AlignCenter,
            f"{self.user_name}'s Binary Ninja Wrapped"
        )
        
        # Draw timestamp
        if self.timestamp > 0:
            timestamp_str = datetime.datetime.fromtimestamp(self.timestamp).strftime('%Y-%m-%d %H:%M:%S')
            timestamp_font = QtGui.QFont()
            timestamp_font.setPointSize(10)
            timestamp_font.setItalic(True)
            painter.setFont(timestamp_font)
            painter.setPen(QtGui.QColor("#1DB954"))  # Spotify green
            painter.drawText(
                QtCore.QRect(0, 70, max_width, 20),
                QtCore.Qt.AlignmentFlag.AlignCenter,
                f"Stats generated: {timestamp_str}"
            )
        
        # Draw each chart
        y_pos = header_height
        for title, chart in charts:
            # Center the chart horizontally
            x_pos = (max_width - chart.width()) // 2
            
            # Draw the chart
            painter.drawPixmap(x_pos, y_pos, chart)
            
            # Move down for the next chart
            y_pos += chart.height() + 20
        
        # Draw a quote at the bottom
        quote = self.getJoke()
        quote_font = QtGui.QFont()
        quote_font.setPointSize(12)
        quote_font.setItalic(True)
        painter.setFont(quote_font)
        painter.setPen(QtCore.Qt.GlobalColor.white)
        
        # Draw green box for the quote
        quote_rect = QtCore.QRect(20, total_height - footer_height, max_width - 40, footer_height - 10)
        painter.fillRect(quote_rect, QtGui.QColor("#1DB954"))
        
        # Draw the quote text
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
        """Export individual images and HTML summary (kept for compatibility)"""
        directory = QtWidgets.QFileDialog.getExistingDirectory(self, "Select Export Directory")
        if directory:
            # Create an HTML file for the stats first
            html_path = os.path.join(directory, "stats_summary.html")
            
            # Build stats text with HTML formatting
            html = """
            <html>
            <head>
            <style>
                body {{ 
                    font-family: Arial, sans-serif; 
                    color: white; 
                    background-color: #1DB954;
                    padding: 20px;
                }}
                h1 {{ 
                    font-size: 24px; 
                    text-align: center;
                    margin-bottom: 20px;
                }}
                h2 {{ 
                    font-size: 20px; 
                    color: #191414;
                    margin-top: 15px;
                }}
                .stat {{
                    font-size: 18px;
                    margin: 10px 0;
                }}
                .quote {{
                    font-style: italic;
                    background-color: #191414;
                    color: white;
                    padding: 10px;
                    border-radius: 5px;
                    margin-top: 15px;
                    margin-bottom: 15px;
                }}
            </style>
            </head>
            <body>
            <h1>Your Binary Ninja Wrapped</h1>
            
            <div class="quote">{}</div>
            
            <h2>File Formats</h2>
            """.format(self.getJokeForStats())
            
            # Sort and add file formats
            sorted_formats = sorted(self.file_formats.items(), key=operator.itemgetter(1), reverse=True)
            for fmt, count in sorted_formats:
                html += f'<div class="stat">{fmt}: {count}</div>'
            
            # Add quote about file formats
            html += f'<div class="quote">{self.getJokeForFileFormats()}</div>'
            
            html += '<h2>CPU Architectures</h2>'
            sorted_archs = sorted(self.cpu_archs.items(), key=operator.itemgetter(1), reverse=True)
            for arch, count in sorted_archs:
                html += f'<div class="stat">{arch}: {count}</div>'
            
            # Add quote about CPU architectures
            html += f'<div class="quote">{self.getJokeForArchitectures()}</div>'
            
            html += '<h2>Binary Statistics</h2>'
            for stat, value in self.binary_stats.items():
                html += f'<div class="stat">{stat.capitalize()}: {value:.2f} KB</div>'
            
            # Add biggest binary information
            if self.biggest_binary["path"]:
                html += '<h2>Biggest Binary</h2>'
                html += f'<div class="stat">Path: {os.path.basename(self.biggest_binary["path"])}</div>'
                html += f'<div class="stat">Size: {self.biggest_binary["size"]:.2f} KB</div>'
                html += f'<div class="stat">Format: {self.biggest_binary["format"]}</div>'
                html += f'<div class="stat">Architecture: {self.biggest_binary["arch"]}</div>'
                
                # Add quote about binary stats
                html += f'<div class="quote">{self.getJokeForBinaryStats()}</div>'
            
            html += f'<h2>Static Binaries</h2>'
            html += f'<div class="stat">Static: {self.static_binaries_count["static"]}</div>'
            html += f'<div class="stat">Dynamic: {self.static_binaries_count["dynamic"]}</div>'
            
            # Add quote about static binaries
            html += f'<div class="quote">{self.getQuoteForStaticBinaries()}</div>'
            
            html += '</body></html>'
            
            with open(html_path, 'w') as f:
                f.write(html)
            
            # Export the images
            images = [
                ("file_format_breakdown.png", self.generateFileFormatImage),
                ("cpu_architectures.png", self.generateCPUArchImage),
                ("binary_statistics.png", self.generateBinaryStatsImage),
                ("static_binaries.png", self.generateStaticBinariesImage)
            ]
            for filename, imageFunc in images:
                pixmap = imageFunc()
                if pixmap:
                    full_path = os.path.join(directory, filename)
                    pixmap.save(full_path, "PNG")
            QtWidgets.QMessageBox.information(self, "Export", "Images and stats summary exported successfully!")

    def getJokeForStats(self):
        """Get a quote about overall statistics"""
        quotes = [
            f"You've analyzed {self.count} binaries. That's more than most people analyze in a lifetime!",
            f"Your Binary Ninja has munched through {self.count} files. It's basically a digital gourmand.",
            f"If each binary was a step, you'd have walked {self.count} steps into the land of reverse engineering.",
            f"Your binaries collectively take up {sum(self.binary_stats.values())/3:.2f} KB. That's like... a small picture of a cat.",
            f"Hey {self.user_name}, if reverse engineering were an Olympic sport, you'd be a contender with those {self.count} binaries!",
            f"Binary analysis level: {self.count}. Keep going {self.user_name}, you're doing great!",
        ]
        return random.choice(quotes)
        
    def getJokeForFileFormats(self):
        """Get a quote about file format variety"""
        num_formats = len(self.file_formats)
        
        if num_formats == 0:
            return "No file formats detected? Your binaries are playing hide and seek!"
        elif num_formats == 1:
            format_name = next(iter(self.file_formats.keys()))
            return f"Just {format_name}? I see you're a person of focus, commitment, and sheer will."
        elif num_formats == 2:
            return "Two file formats - it's a binary situation in your binary analysis!"
        elif num_formats >= 3:
            return f"Variety is the spice of life! With {num_formats} different file formats, your binaries are having a format party."
        else:
            return "Your file formats are as diverse as a box of artisanal chocolates!"

    def getJokeForArchitectures(self):
        """Get a quote about CPU architecture variety"""
        num_archs = len(self.cpu_archs)
        
        if num_archs == 0:
            return "No architectures detected? Your binaries must be quantum - existing in all states at once!"
        elif num_archs == 1:
            arch_name = next(iter(self.cpu_archs.keys()))
            return f"100% loyal to {arch_name}! When you find something you like, you stick with it."
        elif num_archs == 2:
            return "Two architectures - keeping one foot in each world. Perfectly balanced, as all things should be."
        elif num_archs >= 3:
            return f"With {num_archs} different architectures, you're basically the United Nations of binary analysis!"
        else:
            return "Your CPU architectures are like your taste in music - eclectic and sophisticated."

    def getJokeForBinaryStats(self):
        """Get a quote about binary statistics"""
        if self.binary_stats['min'] == self.binary_stats['max']:
            return "All your binaries are exactly the same size? That's more suspicious than identical twins with the same outfit."
        
        size_ratio = self.binary_stats['max'] / max(1, self.binary_stats['min'])
        
        if size_ratio > 100:
            return f"Your largest binary is {size_ratio:.1f}x bigger than your smallest. That's like comparing a house cat to a tiger!"
        elif size_ratio > 10:
            return f"From {self.binary_stats['min']:.1f}KB to {self.binary_stats['max']:.1f}KB - you've got quite the range there!"
        else:
            return "Your binaries are surprisingly consistent in size. Marie Kondo would be proud of your tidy code."

    def getQuoteForStaticBinaries(self):
        """Get a quote about static vs dynamic binaries"""
        static_count = self.static_binaries_count['static']
        dynamic_count = self.static_binaries_count['dynamic']
        total = static_count + dynamic_count
        
        if total == 0:
            return "No binaries analyzed yet? The static vs dynamic debate awaits you!"
        
        static_percentage = (static_count / total * 100) if total > 0 else 0
        
        if static_percentage > 80:
            return "You're a static linking enthusiast! Your binaries are self-contained universes."
        elif static_percentage > 50:
            return "You prefer independence - most of your binaries are statically linked."
        elif static_percentage > 20:
            return "A healthy mix of static and dynamic binaries - flexibility is your forte."
        else:
            return "You're all about those dynamic dependencies. Sharing is caring!"
    
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

def launchBNWrapped(bv):
    # Get the actual recent files from settings
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
    
    # Create widget but don't show splash.finish yet
    widget = BNWrappedWidget(recent_files, splash)
    widget.resize(800, 600)
    widget.show()
    bv.user_data = widget
    
def createSplashImage():
    """Create a stylish splash screen image"""
    # Create a pixmap for the splash screen
    pixmap = QtGui.QPixmap(500, 300)
    pixmap.fill(QtGui.QColor("#191414"))  # Dark background
    
    # Create a painter to draw on the pixmap
    painter = QtGui.QPainter(pixmap)
    
    # Draw colorful gradient boxes
    colors = [
        QtGui.QColor("#1DB954"),
        QtGui.QColor("#FF9CE0"),
        QtGui.QColor("#2E77D0"),
        QtGui.QColor("#FF7900"),
        QtGui.QColor("#FFFF64"),
    ]
    
    box_size = 80
    box_margin = 15
    box_start_x = (pixmap.width() - (box_size * 3 + box_margin * 2)) // 2
    box_start_y = 50
    
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
    
    # Draw text
    font = QtGui.QFont()
    font.setPointSize(24)
    font.setBold(True)
    painter.setFont(font)
    painter.setPen(QtCore.Qt.GlobalColor.white)
    painter.drawText(
        QtCore.QRect(0, 220, pixmap.width(), 40),
        QtCore.Qt.AlignmentFlag.AlignCenter,
        "Binary Ninja Wrapped"
    )
    
    # Finish painting
    painter.end()
    
    return pixmap

PluginCommand.register("Binja Wrapped", "Generate a Spotify-wrapped style summary of recent files", launchBNWrapped)






