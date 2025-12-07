"""
UI utility functions for Binary Ninja Wrapped plugin.
"""
import io
import random
from PySide6 import QtGui, QtCore
import matplotlib.pyplot as plt


def fit_text_to_rect(text, font, available_width, available_height, initial_size, min_size=8):
    """Reduce font size until text fits within specified dimensions.

    Args:
        text: The text to fit
        font: QFont object to adjust
        available_width: Maximum width in pixels
        available_height: Maximum height in pixels
        initial_size: Starting font size
        min_size: Minimum allowed font size (default 8)

    Returns:
        The optimized font size that fits the text
    """
    font.setPointSize(initial_size)
    font_metrics = QtGui.QFontMetrics(font)
    text_rect = font_metrics.boundingRect(
        QtCore.QRect(0, 0, available_width, 1000),
        QtCore.Qt.TextFlag.TextWordWrap,
        text
    )

    current_size = initial_size
    while (text_rect.width() > available_width or text_rect.height() > available_height) and current_size > min_size:
        current_size -= 1
        font.setPointSize(current_size)
        font_metrics = QtGui.QFontMetrics(font)
        text_rect = font_metrics.boundingRect(
            QtCore.QRect(0, 0, available_width, 1000),
            QtCore.Qt.TextFlag.TextWordWrap,
            text
        )

    return current_size


def figure_to_pixmap(fig):
    """Convert a matplotlib figure to a QPixmap.

    Args:
        fig: Matplotlib figure object

    Returns:
        QPixmap: The figure converted to a pixmap
    """
    buf = io.BytesIO()
    fig.tight_layout()
    fig.savefig(buf, format='png', bbox_inches='tight')
    plt.close(fig)
    buf.seek(0)
    img = QtGui.QImage()
    img.loadFromData(buf.getvalue(), "PNG")
    return QtGui.QPixmap.fromImage(img)


def create_splash_image():
    """Create a stylish splash screen image with the Binary Ninja wordmark logo.

    Returns:
        QPixmap: The splash screen image
    """
    pixmap = QtGui.QPixmap(700, 400)
    pixmap.fill(QtGui.QColor("#191414"))

    painter = QtGui.QPainter(pixmap)

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
    box_margin = 25
    box_start_x = (pixmap.width() - (box_size * 3 + box_margin * 2)) // 2
    box_start_y = 60

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
    wordmark = QtGui.QPixmap(":/icons/images/logo-wordmark-dark.png")
    if not wordmark.isNull():
        wordmark_width = 350
        wordmark = wordmark.scaledToWidth(wordmark_width, QtCore.Qt.TransformationMode.SmoothTransformation)

        wordmark_x = (pixmap.width() - wordmark.width()) // 2
        wordmark_y = 280
        painter.drawPixmap(wordmark_x, wordmark_y, wordmark)

    painter.end()

    return pixmap
