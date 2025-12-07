import os
import operator
import datetime
import tempfile
import urllib.parse
from PySide6 import QtWidgets, QtGui, QtCore

from .utils import get_contrasting_text_color, calculate_brightness_rgb
from .uiutils import fit_text_to_rect
from . import template_loader
from . import quotes
from .log import logger


class BNWrappedExporter:
    """Handles all export and social media sharing functionality for BNWrapped"""

    def __init__(self, parent_widget):
        """Initialize the exporter

        Args:
            parent_widget: The BNWrappedWidget instance that owns this exporter
        """
        self.parent = parent_widget
        self.user_name = parent_widget.user_name
        self.year = parent_widget.year

    def export_combined_image(self):
        """Export a single combined image with all charts and stats in a grid layout"""
        file_path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self.parent, "Save Combined Image", "", "PNG Files (*.png)"
        )

        if not file_path:
            return

        # Add .png extension if not present
        if not file_path.lower().endswith('.png'):
            file_path += '.png'

        # Generate all the chart images
        chart_pixmaps = [
            self.parent.generateFileFormatImage(),
            self.parent.generateCPUArchImage(),
            self.parent.generateBinaryStatsImage(),
            self.parent.generateStaticBinariesImage()
        ]

        titles = [
            "File Format Breakdown",
            "CPU Architectures",
            "Statistics",
            "Static Binaries"
        ]

        # Grid layout configuration
        columns = 2
        rows = (len(chart_pixmaps) + columns - 1) // columns

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
        header_height = 180 if not wordmark.isNull() else 150
        footer_height = 40

        # Total width and height
        total_width = 60 + (chart_width + horizontal_spacing) * columns - horizontal_spacing + 60
        total_height = header_height + (chart_height + quote_height + vertical_spacing) * rows - vertical_spacing + footer_height

        # Create a new image with the right dimensions
        combined = QtGui.QPixmap(total_width, total_height)
        combined.fill(QtGui.QColor("#2D2D2D"))

        # Paint everything onto the combined image
        painter = QtGui.QPainter(combined)

        if not wordmark.isNull():
            # Scale the wordmark to fit nicely
            wordmark_width = min(300, total_width * 0.6)
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
        painter.setPen(QtGui.QColor("#1DB954"))

        # Adjust the timestamp position
        timestamp_y = 120 if not wordmark.isNull() else 80

        painter.drawText(
            QtCore.QRect(0, timestamp_y, total_width, 20),
            QtCore.Qt.AlignmentFlag.AlignCenter,
            f"Generated: {current_time}"
        )

        # Draw charts and quotes in grid layout
        self._draw_grid(
            chart_pixmaps, painter, total_width, header_height,
            chart_width, chart_height, horizontal_spacing, vertical_spacing,
            quote_height, columns, draw_quote_boxes=True
        )

        painter.end()

        # Save the combined image
        combined.save(file_path, "PNG")
        QtWidgets.QMessageBox.information(self.parent, "Export", "Combined image exported successfully!")

    def _draw_grid(self, chart_pixmaps, painter, total_width, header_height, chart_width, chart_height,
                   horizontal_spacing, vertical_spacing, quote_height, columns, draw_quote_boxes=True):
        """Draw charts and quotes in a grid layout on the given painter"""
        titles = [
            "File Format Breakdown",
            "CPU Architectures",
            "Statistics",
            "Static Binaries"
        ]

        # Generate quotes for each chart
        quotes_list = []
        for title in titles:
            if "File Format" in title:
                quotes_list.append(quotes.get_file_formats_quote(self.parent.file_formats))
            elif "CPU" in title:
                quotes_list.append(quotes.get_architectures_quote(self.parent.cpu_archs))
            elif "Statistics" in title:
                quotes_list.append(quotes.get_binary_stats_quote(self.parent.binary_stats))
            elif "Static Binaries" in title:
                quotes_list.append(quotes.get_static_binaries_quote(self.parent.static_binaries_count))
            else:
                quotes_list.append(quotes.get_stats_quote(self.parent.count, self.parent.user_name, self.parent.binary_stats))

        # Draw charts and quotes in grid
        for i, pixmap in enumerate(chart_pixmaps):
            if not pixmap:
                continue

            # Calculate grid position
            row = i // columns
            col = i % columns

            # Calculate position for this chart
            x_pos = 60 + col * (chart_width + horizontal_spacing) + (chart_width - pixmap.width()) // 2
            y_pos = header_height + row * (chart_height + quote_height + vertical_spacing)

            # Draw the chart
            painter.drawPixmap(x_pos, y_pos, pixmap)

            # Draw the quote below this chart
            quote = quotes_list[i]
            quote_font = QtGui.QFont()
            quote_font.setPointSize(10)
            quote_font.setItalic(True)

            # Position for the quote
            quote_x = x_pos
            quote_y = y_pos + pixmap.height() + 10

            if draw_quote_boxes:
                # Draw colorful box for the quote
                tab_colors = self.parent.chart_generator.get_color_palette(tab_index=i+1)
                quote_rect = QtCore.QRect(quote_x + 10, quote_y, pixmap.width() - 20, quote_height - 10)
                bg_color = QtGui.QColor(tab_colors[0])
                painter.fillRect(quote_rect, bg_color)

                # Calculate text color based on background brightness
                r, g, b = bg_color.red(), bg_color.green(), bg_color.blue()
                brightness = calculate_brightness_rgb(r, g, b)
                text_color = QtCore.Qt.GlobalColor.black if brightness > 0.5 else QtCore.Qt.GlobalColor.white
                painter.setPen(text_color)

                # Fit text to available space
                available_width = quote_rect.width() - 20
                available_height = quote_rect.height() - 10
                fit_text_to_rect(quote, quote_font, available_width, available_height, 16)
                painter.setFont(quote_font)

                # Draw the quote text
                painter.drawText(
                    quote_rect,
                    QtCore.Qt.AlignmentFlag.AlignCenter | QtCore.Qt.TextFlag.TextWordWrap,
                    quote
                )
            else:
                # Simple colored text without boxes
                tab_colors = self.parent.chart_generator.get_color_palette()
                quote_color = tab_colors[i] if i < len(tab_colors) else "#1DB954"
                painter.setPen(QtGui.QColor(quote_color))
                painter.setFont(quote_font)

                # Draw the quote
                painter.drawText(
                    QtCore.QRect(quote_x, quote_y, pixmap.width(), quote_height),
                    QtCore.Qt.AlignmentFlag.AlignCenter | QtCore.Qt.TextFlag.TextWordWrap,
                    quote
                )

    def export_images(self):
        """Export individual chart images with quotes and HTML summary"""
        directory = QtWidgets.QFileDialog.getExistingDirectory(self.parent, "Select Export Directory")
        if directory:
            # Define the charts and their associated quotes
            charts_with_quotes = [
                {
                    "filename": "file_format_breakdown.png",
                    "title": "File Format Breakdown",
                    "image_func": self.parent.generateFileFormatImage,
                    "quote_func": lambda: quotes.get_file_formats_quote(self.parent.file_formats)
                },
                {
                    "filename": "cpu_architectures.png",
                    "title": "CPU Architectures",
                    "image_func": self.parent.generateCPUArchImage,
                    "quote_func": lambda: quotes.get_architectures_quote(self.parent.cpu_archs)
                },
                {
                    "filename": "binary_statistics.png",
                    "title": "Statistics",
                    "image_func": self.parent.generateBinaryStatsImage,
                    "quote_func": lambda: quotes.get_binary_stats_quote(self.parent.binary_stats)
                },
                {
                    "filename": "static_binaries.png",
                    "title": "Static vs Dynamic Binaries",
                    "image_func": self.parent.generateStaticBinariesImage,
                    "quote_func": lambda: quotes.get_static_binaries_quote(self.parent.static_binaries_count)
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
                quote_height = 80
                padding = 20

                # Create a new pixmap with extra height for the quote
                final_width = chart_pixmap.width() + (2 * padding)
                final_height = chart_pixmap.height() + quote_height + (2 * padding)

                final_pixmap = QtGui.QPixmap(final_width, final_height)

                # Get background color based on the chart type
                if "File Format" in chart["title"]:
                    bg_color = self.parent.chart_generator.background_colors.get(1, "#122F1C")
                elif "CPU" in chart["title"]:
                    bg_color = self.parent.chart_generator.background_colors.get(2, "#192A3D")
                elif "Statistics" in chart["title"]:
                    bg_color = self.parent.chart_generator.background_colors.get(3, "#2D1A36")
                elif "Static" in chart["title"]:
                    bg_color = self.parent.chart_generator.background_colors.get(4, "#3A1923")
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
                text_color = get_contrasting_text_color(bg_color)
                painter.setPen(QtGui.QColor(text_color))

                # Draw the quote in a box at the bottom
                quote_rect = QtCore.QRect(
                    padding,
                    padding + chart_pixmap.height() + 10,
                    final_width - (2 * padding),
                    quote_height - 10
                )

                # Use theme-appropriate color for quote background
                if "File Format" in chart["title"]:
                    quote_bg_color = self.parent.chart_generator.get_color_palette(tab_index=1)[0]
                elif "CPU" in chart["title"]:
                    quote_bg_color = self.parent.chart_generator.get_color_palette(tab_index=2)[0]
                elif "Statistics" in chart["title"]:
                    quote_bg_color = self.parent.chart_generator.get_color_palette(tab_index=3)[0]
                elif "Static" in chart["title"]:
                    quote_bg_color = self.parent.chart_generator.get_color_palette(tab_index=4)[0]
                else:
                    quote_bg_color = "#1DB954"

                painter.fillRect(quote_rect, QtGui.QColor(quote_bg_color))

                # Fit text to available space
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

                available_width = quote_rect.width() - 20
                available_height = quote_rect.height() - 10
                fit_text_to_rect(quote, quote_font, available_width, available_height, initial_font_size)
                painter.setFont(quote_font)

                # Determine text color based on background brightness
                quote_text_color = get_contrasting_text_color(quote_bg_color)
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
            sorted_formats = sorted(self.parent.file_formats.items(), key=operator.itemgetter(1), reverse=True)
            for fmt, count in sorted_formats:
                file_formats_html += f'<div class="stat-item">{fmt}: <span class="stat-value">{count}</span></div>\n'

            cpu_archs_html = ''
            sorted_archs = sorted(self.parent.cpu_archs.items(), key=operator.itemgetter(1), reverse=True)
            for arch, count in sorted_archs:
                cpu_archs_html += f'<div class="stat-item">{arch}: <span class="stat-value">{count}</span></div>\n'

            binary_stats_html = ''
            for stat, value in self.parent.binary_stats.items():
                binary_stats_html += f'<div class="stat-item">{stat.capitalize()}: <span class="stat-value">{value:.2f} KB</span></div>\n'

            biggest_binary_html = ''
            if self.parent.biggest_binary["path"]:
                binary_name = os.path.basename(self.parent.biggest_binary["path"])
                binary_size = self.parent.biggest_binary["size"]
                binary_format = self.parent.biggest_binary["format"]
                binary_arch = self.parent.biggest_binary["arch"] if self.parent.biggest_binary["arch"] else "Unknown"
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
                overall_quote=quotes.get_stats_quote(self.parent.count, self.parent.user_name, self.parent.binary_stats),
                binary_count=self.parent.count,
                formats_quote=quotes.get_file_formats_quote(self.parent.file_formats),
                file_formats_html=file_formats_html,
                archs_quote=quotes.get_architectures_quote(self.parent.cpu_archs),
                cpu_archs_html=cpu_archs_html,
                binary_stats_quote=quotes.get_binary_stats_quote(self.parent.binary_stats),
                binary_stats_html=binary_stats_html,
                biggest_binary_html=biggest_binary_html,
                static_quote=quotes.get_static_binaries_quote(self.parent.static_binaries_count),
                static_count=self.parent.static_binaries_count["static"],
                dynamic_count=self.parent.static_binaries_count["dynamic"],
                user_name=self.user_name,
                year=self.year
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

            QtWidgets.QMessageBox.information(self.parent, "Export Complete", message)

    def share_to_twitter(self):
        """Share stats and image to Twitter"""
        # First, save the combined image to a temporary location
        temp_dir = tempfile.gettempdir()
        temp_file = os.path.join(temp_dir, "bn_wrapped_share.png")

        # Generate combined image
        chart_pixmaps = [
            self.parent.generateFileFormatImage(),
            self.parent.generateCPUArchImage(),
            self.parent.generateBinaryStatsImage(),
            self.parent.generateStaticBinariesImage()
        ]

        # Create a combined image with lighter background
        combined = self._create_combined_image(chart_pixmaps, background_color="#2D2D2D")

        # Save the image for sharing
        if combined and combined.save(temp_file, "PNG"):
            # Get a quote to share
            quote = self._get_random_quote()

            # Encode the text for URL
            encoded_text = urllib.parse.quote(f"My Binary Ninja Wrapped stats: {quote} #BinaryNinjaWrapped")

            # Show dialog to let user know what's happening
            msg = QtWidgets.QMessageBox(self.parent)
            msg.setWindowTitle("Share to Twitter")
            msg.setText("The combined image has been saved and will open in your browser.<br><br>You can attach the image from:<br>" + temp_file)
            msg.setStandardButtons(QtWidgets.QMessageBox.StandardButton.Ok | QtWidgets.QMessageBox.StandardButton.Cancel)

            if msg.exec() == QtWidgets.QMessageBox.StandardButton.Ok:
                # Open Twitter with pre-filled text
                twitter_url = f"https://twitter.com/intent/tweet?text={encoded_text}"
                QtGui.QDesktopServices.openUrl(QtCore.QUrl(twitter_url))

    def share_to_mastodon(self):
        """Share stats and image to Mastodon"""
        # First, save the combined image to a temporary location
        temp_dir = tempfile.gettempdir()
        temp_file = os.path.join(temp_dir, "bn_wrapped_share.png")

        # Generate combined image
        chart_pixmaps = [
            self.parent.generateFileFormatImage(),
            self.parent.generateCPUArchImage(),
            self.parent.generateBinaryStatsImage(),
            self.parent.generateStaticBinariesImage()
        ]

        # Create a combined image with lighter background
        combined = self._create_combined_image(chart_pixmaps, background_color="#2D2D2D")

        # Save the image for sharing
        if combined and combined.save(temp_file, "PNG"):
            # Get a quote to share
            quote = self._get_random_quote()

            # Prompt user for their Mastodon instance
            instance, ok = QtWidgets.QInputDialog.getText(
                self.parent, "Mastodon Instance",
                "Enter your Mastodon instance URL (e.g., mastodon.social):"
            )

            if ok and instance:
                # Encode the text for URL
                encoded_text = urllib.parse.quote(f"My Binary Ninja Wrapped stats: {quote} #BinaryNinjaWrapped")

                # Show dialog to let user know what's happening
                msg = QtWidgets.QMessageBox(self.parent)
                msg.setWindowTitle("Share to Mastodon")
                msg.setText("The combined image has been saved and will open in your browser.<br><br>You can attach the image from:<br>" + temp_file)
                msg.setStandardButtons(QtWidgets.QMessageBox.StandardButton.Ok | QtWidgets.QMessageBox.StandardButton.Cancel)

                if msg.exec() == QtWidgets.QMessageBox.StandardButton.Ok:
                    # Open Mastodon compose page with pre-filled text
                    mastodon_url = f"https://{instance}/share?text={encoded_text}"
                    QtGui.QDesktopServices.openUrl(QtCore.QUrl(mastodon_url))

    def share_to_linkedin(self):
        """Share stats and image to LinkedIn"""
        # First, save the combined image to a temporary location
        temp_dir = tempfile.gettempdir()
        temp_file = os.path.join(temp_dir, "bn_wrapped_share.png")

        # Generate combined image
        chart_pixmaps = [
            self.parent.generateFileFormatImage(),
            self.parent.generateCPUArchImage(),
            self.parent.generateBinaryStatsImage(),
            self.parent.generateStaticBinariesImage()
        ]

        # Create a combined image with lighter background
        combined = self._create_combined_image(chart_pixmaps, background_color="#2D2D2D")

        # Save the image for sharing
        if combined and combined.save(temp_file, "PNG"):
            # Get a quote to share
            quote = self._get_random_quote()

            # Prepare text to share
            share_text = f"My Binary Ninja Wrapped stats: {quote} #BinaryNinjaWrapped"

            # Show dialog to let user know what's happening
            msg = QtWidgets.QMessageBox(self.parent)
            msg.setWindowTitle("Share to LinkedIn")
            msg.setText("The combined image has been saved and will open in your browser.<br><br>You can attach the image from:<br>" + temp_file)
            msg.setStandardButtons(QtWidgets.QMessageBox.StandardButton.Ok | QtWidgets.QMessageBox.StandardButton.Cancel)

            if msg.exec() == QtWidgets.QMessageBox.StandardButton.Ok:
                # LinkedIn only supports the URL parameter for share-offsite
                linkedin_url = "https://www.linkedin.com/sharing/share-offsite/?url=https://binary.ninja"
                QtGui.QDesktopServices.openUrl(QtCore.QUrl(linkedin_url))

    def _create_combined_image(self, chart_pixmaps, background_color="#2D2D2D"):
        """Helper method to create a combined image for social media sharing"""
        if not chart_pixmaps:
            return None

        titles = [
            "File Format Breakdown",
            "CPU Architectures",
            "Statistics",
            "Static Binaries"
        ]

        # Grid layout configuration
        columns = 2
        rows = (len(chart_pixmaps) + columns - 1) // columns

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
        header_height = 180 if not wordmark.isNull() else 150
        footer_height = 40

        # Total width and height
        total_width = 60 + (chart_width + horizontal_spacing) * columns - horizontal_spacing + 60
        total_height = header_height + (chart_height + quote_height + vertical_spacing) * rows - vertical_spacing + footer_height

        # Create a new image with the right dimensions
        combined = QtGui.QPixmap(total_width, total_height)
        combined.fill(QtGui.QColor(background_color))

        # Paint everything onto the combined image
        painter = QtGui.QPainter(combined)

        # Use the wordmark at the top
        if not wordmark.isNull():
            logo_x = (total_width - wordmark.width()) // 2
            painter.drawPixmap(logo_x, 20, wordmark)

        # Add a title
        title_font = QtGui.QFont()
        title_font.setPointSize(24)
        title_font.setBold(True)
        painter.setFont(title_font)
        painter.setPen(QtGui.QColor("#1DB954"))

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
        painter.setPen(QtGui.QColor("#1DB954"))

        # Adjust the timestamp position
        timestamp_y = 120 if not wordmark.isNull() else 80

        painter.drawText(
            QtCore.QRect(0, timestamp_y, total_width, 20),
            QtCore.Qt.AlignmentFlag.AlignCenter,
            f"Generated: {current_time}"
        )

        # Draw charts and quotes in grid layout
        self._draw_grid(
            chart_pixmaps, painter, total_width, header_height,
            chart_width, chart_height, horizontal_spacing, vertical_spacing,
            quote_height, columns, draw_quote_boxes=False
        )

        painter.end()

        return combined

    def _get_random_quote(self):
        """Get a random quote from all categories"""
        import random
        quotes_list = [
            quotes.get_stats_quote(self.parent.count, self.parent.user_name, self.parent.binary_stats),
            quotes.get_file_formats_quote(self.parent.file_formats),
            quotes.get_architectures_quote(self.parent.cpu_archs),
            quotes.get_binary_stats_quote(self.parent.binary_stats),
            quotes.get_static_binaries_quote(self.parent.static_binaries_count),
        ]
        return random.choice(quotes_list)
