"""
Utility functions for Binary Ninja Wrapped plugin.
"""
import os
import getpass
import platform
import hashlib
from binaryninja.log import log as bnlog
from binaryninja.log import LogLevel


def get_user_name():
    """Get the user's name in a cross-platform way

    Returns:
        str: The user's full name if available, otherwise username,
             or "Binary Ninja User" as fallback
    """
    try:
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
                import pwd
                return pwd.getpwuid(os.getuid())[4].split(',')[0]
            except (KeyError, IndexError, ImportError):
                pass

        return getpass.getuser()
    except:
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
    except:
        bnlog(LogLevel.WarningLog, f"Failed to compute hash for {file_path}")
        return None
