import os
import io
import random
from binaryninja import PluginCommand
from PySide6 import QtWidgets, QtGui, QtCore
import matplotlib.pyplot as plt

class SpotifyWrappedWidget(QtWidgets.QWidget):
    def __init__(self, recent_files, parent=None):
        super().__init__(parent)
        self.recent_files = recent_files
        self.computeStats()  # Stub: compute stats from recent_files
        self.initUI()

    def computeStats(self):
        # Stub: replace these with real computations using self.recent_files
        self.file_formats = {'PE': 10, 'ELF': 5, 'Mach-O': 3}  
        self.cpu_archs = {'x86': 12, 'ARM': 3, 'MIPS': 1}  
        self.binary_stats = {'avg': 1024, 'min': 512, 'max': 2048}  
        self.imported_apis_percentage = 35  

    def initUI(self):
        self.setWindowTitle("Binary Ninja Wrapped")
        layout = QtWidgets.QVBoxLayout(self)

        self.tabs = QtWidgets.QTabWidget(self)
        layout.addWidget(self.tabs)

        self.fileFormatTab = self.createStatTab("File Format Breakdown", self.generateFileFormatImage)
        self.cpuArchTab = self.createStatTab("CPU Architectures", self.generateCPUArchImage)
        self.binaryStatsTab = self.createStatTab("Binary Statistics", self.generateBinaryStatsImage)
        self.importedAPIsTab = self.createStatTab("Imported APIs", self.generateImportedAPIsImage)

        self.tabs.addTab(self.fileFormatTab, "File Formats")
        self.tabs.addTab(self.cpuArchTab, "CPU Arch")
        self.tabs.addTab(self.binaryStatsTab, "Statistics")
        self.tabs.addTab(self.importedAPIsTab, "Imported APIs")

        self.jokeLabel = QtWidgets.QLabel("Joke of the day: " + self.getJoke(), self)
        layout.addWidget(self.jokeLabel)

        self.exportButton = QtWidgets.QPushButton("Export All Images", self)
        self.exportButton.clicked.connect(self.exportImages)
        layout.addWidget(self.exportButton)

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

    def generateFileFormatImage(self):
        formats = self.file_formats
        fig, ax = plt.subplots()
        ax.pie(formats.values(), labels=formats.keys(), autopct='%1.1f%%')
        ax.set_title("File Format Breakdown")
        return self.figureToPixmap(fig)

    def generateCPUArchImage(self):
        archs = self.cpu_archs
        fig, ax = plt.subplots()
        ax.bar(archs.keys(), archs.values())
        ax.set_title("CPU Architectures")
        return self.figureToPixmap(fig)

    def generateBinaryStatsImage(self):
        stats = self.binary_stats
        fig, ax = plt.subplots()
        ax.bar(stats.keys(), stats.values())
        ax.set_title("Binary Statistics")
        ax.set_ylabel("Size (KB)")
        return self.figureToPixmap(fig)

    def generateImportedAPIsImage(self):
        percentage = self.imported_apis_percentage
        fig, ax = plt.subplots()
        ax.bar(['Imported APIs'], [percentage])
        ax.set_title("Imported APIs Percentage")
        ax.set_ylabel("Percentage (%)")
        return self.figureToPixmap(fig)

    def figureToPixmap(self, fig):
        buf = io.BytesIO()
        fig.savefig(buf, format='png')
        plt.close(fig)
        buf.seek(0)
        img = QtGui.QImage()
        img.loadFromData(buf.getvalue(), "PNG")
        return QtGui.QPixmap.fromImage(img)

    def exportImages(self):
        directory = QtWidgets.QFileDialog.getExistingDirectory(self, "Select Export Directory")
        if directory:
            images = [
                ("file_format_breakdown.png", self.generateFileFormatImage),
                ("cpu_architectures.png", self.generateCPUArchImage),
                ("binary_statistics.png", self.generateBinaryStatsImage),
                ("imported_apis.png", self.generateImportedAPIsImage)
            ]
            for filename, imageFunc in images:
                pixmap = imageFunc()
                if pixmap:
                    full_path = os.path.join(directory, filename)
                    pixmap.save(full_path, "PNG")
            QtWidgets.QMessageBox.information(self, "Export", "Images exported successfully!")

    def getJoke(self):
        jokes = []
        # Joke based on file format variety
        if len(self.file_formats) < 2:
            jokes.append("Only one file format? Your binaries are as predictable as a broken record.")
        else:
            jokes.append("A diverse file format lineup! Your binaries are like a box of assorted chocolates.")

        # Joke based on CPU architecture variety
        if len(self.cpu_archs) < 2:
            jokes.append("Stuck on one CPU architecture? Your binaries have commitment issues!")
        else:
            jokes.append("Multiple CPU architectures! Your binaries are international jet-setters.")

        # Joke based on binary statistics variation
        if self.binary_stats['min'] == self.binary_stats['max']:
            jokes.append("Uniform binary sizes? Even your files are copy-pasting!")
        else:
            jokes.append("Binaries of all sizes – it's a digital potluck in there!")

        # Joke based on imported APIs percentage
        if self.imported_apis_percentage < 50:
            jokes.append("Low API imports: Your binaries are lone wolves, doing it all on their own.")
        else:
            jokes.append("High API imports: Your binaries sure know how to make friends!")

        return random.choice(jokes)

def launchSpotifyWrapped(bv):
    recent_files = ["file1", "file2", "file3"]  # Replace with actual recent files if available
    widget = SpotifyWrappedWidget(recent_files)
    widget.resize(800, 600)
    widget.show()
    bv.user_data = widget

PluginCommand.register("Spotify Wrapped", "Generate a Spotify Wrapped style summary of recent files", launchSpotifyWrapped)






