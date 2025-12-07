"""
UI utility functions for Binary Ninja Wrapped plugin.
"""
import io
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
