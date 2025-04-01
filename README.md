# Binary Ninja Wrapped (v1.00)

A fun "Spotify Wrapped" style visualization tool for your Binary Ninja usage.

![Binary Ninja Wrapped Screenshot](./wrapped.png)

## Overview

Binary Ninja Wrapped provides a stylish visualization of your reverse engineering habits in Binary Ninja. Inspired by Spotify's annual "Wrapped" feature, it analyzes your recently opened files and generates personalized stats and charts about:

- File format distribution (PE, ELF, Mach-O, etc.)
- CPU architecture preferences
- Binary size statistics
- Static vs. dynamic linking patterns

Each chart comes with personalized, sometimes humorous commentary on your binary analysis habits.

## Frequently Asked Questions

**Q: Is this a joke?**

**A:** Well, yes. I mean, it's intended to be a non-serious, funny plugin.

**Q: So it doesn't actually work?**

**A:** Oh no, it's very much a real plugin that will really do what it says and involves several thousand lines of vibe coding.

**Q: But why was it released on April 1 if it's a prank?**

**A:** You got the part where it was supposed to be non-serious and funny, right?

## Features

- **Interactive UI**: Browse different stats through an intuitive tabbed interface
- **Dynamic Visualizations**: Colorful charts and graphs display your binary analysis patterns
- **Personalized Quotes**: Each section features unique, context-aware commentary
- **Exportable Results**: Save a beautiful collage of all your charts in a grid layout

## Installation

1. Install via the Plugin Manager! 
1. Alternatively, clone this repository into your Binary Ninja plugins directory:
   ```
   cd ~/.binaryninja/plugins/                       # Linux
   cd ~/Library/Application\ Support/Binary\ Ninja/ # macOS
   cd %APPDATA%\Binary Ninja\plugins                # Windows
   git clone https://github.com/vector35/bnwrap.git
   ```

1. Restart Binary Ninja.

## Usage

1. Open Binary Ninja
2. Go to the **Plugins** menu
3. Select **Binja Wrapped**
4. Browse through the tabs to explore different aspects of your binary analysis habits
5. Use the **Export Combined Image** button to save a shareable collage

## Example

![example image](./example.png)

## Requirements

- Binary Ninja (recent version)
- PySide6 (included with Binary Ninja)

## Contributing

Contributions are welcome! Feel free to submit pull requests or open issues for bugs or feature requests.

## License

This project is released under the MIT License. See the LICENSE file for details.
