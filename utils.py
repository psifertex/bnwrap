"""
Utility functions for Binary Ninja Wrapped plugin.
"""
import os
import getpass
import platform
import hashlib

try:
    from .log import logger
except ImportError:
    from log import logger


def get_user_name():
    """Get the user's name in a cross-platform way

    Returns:
        str: The user's full name if available, otherwise username,
             or "Binary Ninja User" as fallback
    """
    try:
        if platform.system() == "Windows":
            import ctypes
            GetUserNameEx = ctypes.windll.secur32.GetUserNameExW
            NameDisplay = 3  # EXTENDED_NAME_FORMAT value for display name

            size = ctypes.pointer(ctypes.c_ulong(0))
            GetUserNameEx(NameDisplay, None, size)

            nameBuffer = ctypes.create_unicode_buffer(size.contents.value)
            GetUserNameEx(NameDisplay, nameBuffer, size)
            return nameBuffer.value
        else:
            try:
                import pwd
                return pwd.getpwuid(os.getuid())[4].split(',')[0]
            except (KeyError, IndexError, ImportError):
                pass

        return getpass.getuser()
    except Exception:
        return "Binary Ninja User"


def get_file_hash(file_path):
    """Compute SHA256 hash of a file

    Args:
        file_path (str): Path to the file to hash

    Returns:
        str: SHA256 hash as hexadecimal string, or None if computation fails
    """
    try:
        if not os.path.exists(file_path) or os.path.isdir(file_path):
            return None

        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            # Read in chunks to handle large files efficiently
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        logger.log_warn(f"Failed to compute hash for {file_path}")
        return None


def calculate_brightness_hex(hex_color):
    """Calculate brightness of a hex color (0-1 scale)

    Args:
        hex_color (str): Hex color string like '#RRGGBB'

    Returns:
        float: Brightness value from 0 (dark) to 1 (light)
    """
    if not hex_color.startswith('#') or len(hex_color) != 7:
        return 0.5

    r = int(hex_color[1:3], 16)
    g = int(hex_color[3:5], 16)
    b = int(hex_color[5:7], 16)
    return calculate_brightness_rgb(r, g, b)


def calculate_brightness_rgb(r, g, b):
    """Calculate brightness from RGB values (0-1 scale)

    Uses the standard luminance formula for perceived brightness.

    Args:
        r, g, b (int): RGB values 0-255

    Returns:
        float: Brightness value from 0 (dark) to 1 (light)
    """
    return (0.299*r + 0.587*g + 0.114*b) / 255


def get_contrasting_text_color(bg_hex_color):
    """Get black or white text color for optimal contrast

    Args:
        bg_hex_color (str): Background hex color

    Returns:
        str: 'black' or 'white'
    """
    brightness = calculate_brightness_hex(bg_hex_color)
    return 'black' if brightness > 0.5 else 'white'
