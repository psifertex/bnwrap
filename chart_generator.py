import random
import operator
import matplotlib.pyplot as plt
from .utils import calculate_brightness_rgb
from .uiutils import figure_to_pixmap


class ChartGenerator:
    """Handles all chart generation and visualization for BNWrapped"""

    def __init__(self):
        self.background_colors = {}
        self.background_is_light = {}
        self.color_schemes = {}
        self._initialize_colors()

    def _initialize_colors(self):
        """Initialize color schemes and backgrounds"""
        self.background_colors = self._generate_backgrounds()
        self.color_schemes = self._generate_color_schemes()

    def _generate_color_schemes(self):
        """Generate random color schemes for each tab"""
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

        schemes = {}
        # Initialize with random schemes for each tab (0-4)
        for i in range(5):
            shuffled = all_colors.copy()
            random.shuffle(shuffled)
            schemes[i] = shuffled[:8]

        return schemes

    def _generate_backgrounds(self):
        """Generate random backgrounds for each tab with varying brightness"""
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

        backgrounds = {}
        background_is_light = {}

        for i in range(5):  # 0-4 for the 5 tabs
            # Choose a random base color with preference for darker colors
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

            brightness = calculate_brightness_rgb(r, g, b)
            background_is_light[i] = brightness > 0.5

        # Store the light/dark information for easy access
        self.background_is_light = background_is_light
        return backgrounds

    def get_color_palette(self, tab_index=None):
        """Get color palette for a specific tab

        Args:
            tab_index: Index of the tab (0-4), or None for default palette

        Returns:
            List of color hex strings
        """
        if tab_index is not None and tab_index in self.color_schemes:
            return self.color_schemes[tab_index]

        # Default palette (used when no tab is specified)
        return self.color_schemes.get(0, [
            "#1DB954", "#FF9CE0", "#2E77D0", "#FF7900",
            "#FFFF64", "#B49BC8", "#FFB9B9", "#30A2FF"
        ])

    def generate_file_format_chart(self, formats_dict, tab_index=1):
        """Generate a pie chart for file formats

        Args:
            formats_dict: Dictionary of file formats and their counts
            tab_index: Tab index for color scheme selection

        Returns:
            QPixmap of the generated chart
        """
        # Sort by value in descending order
        sorted_formats = dict(sorted(formats_dict.items(), key=operator.itemgetter(1), reverse=True))

        background_color = self.background_colors[tab_index]
        fig, ax = plt.subplots(figsize=(6, 6), facecolor=background_color)

        colors = self.get_color_palette(tab_index=tab_index)
        text_color = 'black' if self.background_is_light.get(tab_index, False) else 'white'

        # Increase font sizes for better readability
        plt.rcParams['font.size'] = 14

        wedges, texts, autotexts = ax.pie(
            sorted_formats.values(),
            labels=sorted_formats.keys(),
            autopct='%1.1f%%',
            colors=colors,
            textprops={'color': text_color, 'fontsize': 14}
        )

        # Make percentage text bold with appropriate color based on wedge color
        for i, autotext in enumerate(autotexts):
            if i < len(wedges):
                wedge = wedges[i]
                wedge_color = wedge.get_facecolor()
                r, g, b = [int(c * 255) for c in wedge_color[:3]]
                wedge_brightness = calculate_brightness_rgb(r, g, b)
                wedge_text_color = 'black' if wedge_brightness > 0.5 else 'white'
                autotext.set_color(wedge_text_color)
            else:
                autotext.set_color(text_color)

            autotext.set_fontweight('bold')
            autotext.set_fontsize(16)

        # Update label colors and sizes
        for text in texts:
            text.set_color(text_color)
            text.set_fontsize(14)

        ax.set_title("File Format Breakdown", color=text_color, fontweight='bold', fontsize=20)
        return figure_to_pixmap(fig)

    def generate_cpu_arch_chart(self, archs_dict, tab_index=2):
        """Generate a bar chart for CPU architectures

        Args:
            archs_dict: Dictionary of CPU architectures and their counts
            tab_index: Tab index for color scheme selection

        Returns:
            QPixmap of the generated chart
        """
        # Sort by value in descending order
        sorted_archs = dict(sorted(archs_dict.items(), key=operator.itemgetter(1), reverse=True))

        # Check if any architectures are predicted (have asterisk)
        has_predicted = any('*' in arch for arch in sorted_archs.keys())

        background_color = self.background_colors[tab_index]
        fig, ax = plt.subplots(figsize=(6, 6), facecolor=background_color)

        colors = self.get_color_palette(tab_index=tab_index)
        bars = ax.bar(
            sorted_archs.keys(),
            sorted_archs.values(),
            color=colors[:len(sorted_archs)]
        )

        text_color = 'black' if self.background_is_light.get(tab_index, False) else 'white'

        # Increase font sizes for better readability
        plt.rcParams['font.size'] = 14

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
        ax.set_facecolor(background_color)

        ax.tick_params(axis='x', labelsize=label_fontsize)
        ax.tick_params(axis='y', labelsize=label_fontsize)

        # Update spine colors based on background brightness
        ax.spines['bottom'].set_color(text_color)
        ax.spines['top'].set_color(text_color)
        ax.spines['left'].set_color(text_color)
        ax.spines['right'].set_color(text_color)
        ax.tick_params(axis='x', colors=text_color)
        ax.tick_params(axis='y', colors=text_color)

        # Add footnote if there are predicted architectures
        if has_predicted:
            fig.text(0.5, 0.02, '* Predicted architecture', ha='center',
                    fontsize=9, color=text_color, style='italic')

        return figure_to_pixmap(fig)

    def generate_binary_stats_chart(self, stats_dict, tab_index=3):
        """Generate a bar chart for binary statistics

        Args:
            stats_dict: Dictionary of binary statistics
            tab_index: Tab index for color scheme selection

        Returns:
            QPixmap of the generated chart
        """
        # Use fixed order: max, avg, min, projects
        desired_order = ['max', 'avg', 'min', 'projects']
        sorted_stats = {key: stats_dict[key] for key in desired_order if key in stats_dict}

        background_color = self.background_colors[tab_index]
        fig, ax = plt.subplots(figsize=(6, 6), facecolor=background_color)

        colors = self.get_color_palette(tab_index=tab_index)
        bars = ax.bar(
            sorted_stats.keys(),
            sorted_stats.values(),
            color=colors[:len(sorted_stats)]
        )

        # Use logarithmic scale for better visualization
        ax.set_yscale('log')

        text_color = 'black' if self.background_is_light.get(tab_index, False) else 'white'

        # Increase font sizes for better readability
        plt.rcParams['font.size'] = 14

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

        ax.set_title("Statistics", color=text_color, fontweight='bold', fontsize=20)
        ax.set_ylabel("Value (log scale)", color=text_color, fontsize=16)
        ax.set_facecolor(background_color)

        ax.tick_params(axis='x', labelsize=label_fontsize)
        ax.tick_params(axis='y', labelsize=label_fontsize)

        # Update spine colors based on background brightness
        ax.spines['bottom'].set_color(text_color)
        ax.spines['top'].set_color(text_color)
        ax.spines['left'].set_color(text_color)
        ax.spines['right'].set_color(text_color)
        ax.tick_params(axis='x', colors=text_color)
        ax.tick_params(axis='y', colors=text_color)

        return figure_to_pixmap(fig)

    def generate_static_binaries_chart(self, static_count, dynamic_count, tab_index=4):
        """Generate a bar chart for static vs dynamic binaries

        Args:
            static_count: Count of static binaries
            dynamic_count: Count of dynamic binaries
            tab_index: Tab index for color scheme selection

        Returns:
            QPixmap of the generated chart
        """
        total = static_count + dynamic_count

        background_color = self.background_colors[tab_index]
        fig, ax = plt.subplots(figsize=(6, 6), facecolor=background_color)

        colors = self.get_color_palette(tab_index=tab_index)
        bars = ax.bar(
            ['Static', 'Dynamic'],
            [static_count, dynamic_count],
            color=[colors[0], colors[1]]
        )

        text_color = 'black' if self.background_is_light.get(tab_index, False) else 'white'

        # Increase font sizes for better readability
        plt.rcParams['font.size'] = 14

        label_fontsize = 16

        # Add value labels on top of bars with percentages
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
        ax.set_facecolor(background_color)

        ax.tick_params(axis='x', labelsize=14)
        ax.tick_params(axis='y', labelsize=14)

        # Update spine colors based on background brightness
        ax.spines['bottom'].set_color(text_color)
        ax.spines['top'].set_color(text_color)
        ax.spines['left'].set_color(text_color)
        ax.spines['right'].set_color(text_color)
        ax.tick_params(axis='x', colors=text_color)
        ax.tick_params(axis='y', colors=text_color)

        return figure_to_pixmap(fig)
