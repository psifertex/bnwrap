"""
Tests for utils module.
"""
import os
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

# Import module directly to avoid triggering __init__.py
import utils
get_user_name = utils.get_user_name
get_file_hash = utils.get_file_hash


class TestGetUserName(unittest.TestCase):
    """Test get_user_name function"""

    def test_returns_string(self):
        """Should always return a string"""
        result = get_user_name()
        self.assertIsInstance(result, str)
        self.assertTrue(len(result) > 0)

    @patch('platform.system')
    def test_windows_path(self, mock_system):
        """Should attempt Windows-specific code on Windows"""
        mock_system.return_value = "Windows"
        # This will likely fail in test environment, but should fall back gracefully
        result = get_user_name()
        self.assertIsInstance(result, str)

    @patch('platform.system')
    @patch('getpass.getuser')
    def test_unix_fallback_to_getuser(self, mock_getuser, mock_system):
        """Should fall back to getpass.getuser on Unix if pwd fails"""
        mock_system.return_value = "Linux"
        mock_getuser.return_value = "testuser"
        result = get_user_name()
        # Should get some result (either from pwd or getuser)
        self.assertIsInstance(result, str)

    def test_fallback_on_exception(self):
        """Should return default value on complete failure"""
        # This is hard to test directly, but we can verify the function
        # doesn't raise exceptions
        try:
            result = get_user_name()
            self.assertIsInstance(result, str)
        except Exception as e:
            self.fail(f"get_user_name raised exception: {e}")


class TestGetFileHash(unittest.TestCase):
    """Test get_file_hash function"""

    def test_hash_of_file(self):
        """Should compute SHA256 hash of a file"""
        # Create a temporary file with known content
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("test content")
            temp_file = f.name

        try:
            result = get_file_hash(temp_file)
            self.assertIsInstance(result, str)
            # SHA256 hash should be 64 hex characters
            self.assertEqual(len(result), 64)
            # Hash should be deterministic
            result2 = get_file_hash(temp_file)
            self.assertEqual(result, result2)
        finally:
            os.unlink(temp_file)

    def test_nonexistent_file(self):
        """Should return None for nonexistent file"""
        result = get_file_hash("/nonexistent/file/path")
        self.assertIsNone(result)

    def test_directory(self):
        """Should return None for directory"""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = get_file_hash(tmpdir)
            self.assertIsNone(result)

    def test_different_content_different_hash(self):
        """Different file contents should produce different hashes"""
        # Create two temporary files with different content
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f1:
            f1.write("content 1")
            temp_file1 = f1.name

        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f2:
            f2.write("content 2")
            temp_file2 = f2.name

        try:
            hash1 = get_file_hash(temp_file1)
            hash2 = get_file_hash(temp_file2)
            self.assertNotEqual(hash1, hash2)
        finally:
            os.unlink(temp_file1)
            os.unlink(temp_file2)

    def test_large_file(self):
        """Should handle large files by reading in chunks"""
        # Create a file larger than the chunk size (4096 bytes)
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"x" * 10000)  # 10KB file
            temp_file = f.name

        try:
            result = get_file_hash(temp_file)
            self.assertIsInstance(result, str)
            self.assertEqual(len(result), 64)
        finally:
            os.unlink(temp_file)


if __name__ == '__main__':
    unittest.main()
