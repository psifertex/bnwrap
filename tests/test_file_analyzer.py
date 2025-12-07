"""
Tests for file_analyzer module.
"""
import os
import tempfile
import shutil
import unittest
from unittest.mock import patch, MagicMock, mock_open

# Import module directly to avoid triggering __init__.py
import file_analyzer
FileAnalyzer = file_analyzer.FileAnalyzer


class TestFileAnalyzer(unittest.TestCase):
    """Test FileAnalyzer class"""

    def setUp(self):
        """Set up test fixtures"""
        # Create a temporary directory for cache
        self.temp_dir = tempfile.mkdtemp()
        self.cache_dir = os.path.join(self.temp_dir, "bnwrapped_cache")

    def tearDown(self):
        """Clean up test fixtures"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    @patch('file_analyzer.user_directory')
    def test_initialization(self, mock_user_dir):
        """Should initialize with empty cache"""
        mock_user_dir.return_value = self.temp_dir
        analyzer = FileAnalyzer()

        self.assertIsInstance(analyzer.cache, dict)
        self.assertEqual(len(analyzer.cache), 0)
        # Should create cache directory
        self.assertTrue(os.path.exists(self.cache_dir))

    @patch('file_analyzer.user_directory')
    def test_save_and_load_cache(self, mock_user_dir):
        """Should save and load cache from disk"""
        mock_user_dir.return_value = self.temp_dir

        # Create analyzer and add cache entry
        analyzer1 = FileAnalyzer()
        analyzer1.cache['/test/file'] = {
            'hash': 'abc123',
            'result': {'file_formats': 'ELF', 'arch': 'x86_64'},
            'timestamp': '2025-01-01T00:00:00'
        }
        analyzer1.save_cache()

        # Create new analyzer instance - should load from disk
        analyzer2 = FileAnalyzer()
        self.assertIn('/test/file', analyzer2.cache)
        self.assertEqual(analyzer2.cache['/test/file']['hash'], 'abc123')

    @patch('file_analyzer.user_directory')
    def test_skim_file_nonexistent(self, mock_user_dir):
        """Should return empty result for nonexistent file"""
        mock_user_dir.return_value = self.temp_dir
        analyzer = FileAnalyzer()

        result = analyzer.skim_file('/nonexistent/file')
        self.assertEqual(result['file_formats'], '')
        self.assertEqual(result['arch'], '')
        self.assertEqual(result['size'], 0)

    @patch('file_analyzer.user_directory')
    def test_skim_file_directory(self, mock_user_dir):
        """Should return empty result for directory"""
        mock_user_dir.return_value = self.temp_dir
        analyzer = FileAnalyzer()

        result = analyzer.skim_file(self.temp_dir)
        self.assertEqual(result['file_formats'], '')
        self.assertEqual(result['arch'], '')

    @patch('file_analyzer.user_directory')
    @patch('file_analyzer.get_file_hash')
    @patch('file_analyzer.load')
    def test_skim_file_with_analysis(self, mock_load, mock_hash, mock_user_dir):
        """Should analyze file when not in cache"""
        mock_user_dir.return_value = self.temp_dir
        mock_hash.return_value = 'abc123'

        # Create a temporary file to analyze
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test binary content")
            temp_file = f.name

        try:
            # Mock the Binary Ninja load function
            mock_bv = MagicMock()
            mock_bv.view_type = 'ELF'
            mock_bv.arch.name = 'x86_64'
            mock_bv.get_symbols_of_type.return_value = [1, 2, 3]  # 3 imports
            mock_load.return_value.__enter__.return_value = mock_bv

            analyzer = FileAnalyzer()
            result = analyzer.skim_file(temp_file)

            # Should have analyzed the file
            self.assertEqual(result['file_formats'], 'ELF')
            self.assertEqual(result['arch'], 'x86_64')
            self.assertGreater(result['size'], 0)
            self.assertEqual(result['num_imports'], 3)
            self.assertTrue(result['is_static'])  # <= 5 imports

            # Should be cached now
            self.assertIn(temp_file, analyzer.cache)
        finally:
            os.unlink(temp_file)

    @patch('file_analyzer.user_directory')
    @patch('file_analyzer.get_file_hash')
    def test_skim_file_uses_cache(self, mock_hash, mock_user_dir):
        """Should use cached result when hash matches"""
        mock_user_dir.return_value = self.temp_dir
        mock_hash.return_value = 'abc123'

        # Create a temporary file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test")
            temp_file = f.name

        try:
            analyzer = FileAnalyzer()

            # Pre-populate cache
            analyzer.cache[temp_file] = {
                'hash': 'abc123',
                'result': {
                    'file_formats': 'CACHED',
                    'arch': 'CACHED_ARCH',
                    'size': 999,
                    'num_imports': 10
                },
                'timestamp': '2025-01-01T00:00:00'
            }

            result = analyzer.skim_file(temp_file)

            # Should return cached result
            self.assertEqual(result['file_formats'], 'CACHED')
            self.assertEqual(result['arch'], 'CACHED_ARCH')
            self.assertEqual(result['size'], 999)
        finally:
            os.unlink(temp_file)

    @patch('file_analyzer.user_directory')
    @patch('file_analyzer.get_file_hash')
    @patch('file_analyzer.load')
    def test_static_detection(self, mock_load, mock_hash, mock_user_dir):
        """Should correctly detect static vs dynamic binaries"""
        mock_user_dir.return_value = self.temp_dir
        mock_hash.return_value = 'test_hash'

        # Create a temp file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test")
            temp_file = f.name

        try:
            # Test with few imports (static)
            mock_bv = MagicMock()
            mock_bv.view_type = 'ELF'
            mock_bv.arch.name = 'x86_64'
            mock_bv.get_symbols_of_type.return_value = [1, 2]  # 2 imports
            mock_load.return_value.__enter__.return_value = mock_bv

            analyzer = FileAnalyzer()
            result = analyzer._analyze_file(temp_file)
            self.assertTrue(result['is_static'])

            # Test with many imports (dynamic)
            mock_bv.get_symbols_of_type.return_value = [1, 2, 3, 4, 5, 6, 7]  # 7 imports
            result = analyzer._analyze_file(temp_file)
            self.assertFalse(result['is_static'])
        finally:
            os.unlink(temp_file)

    @patch('file_analyzer.user_directory')
    @patch('file_analyzer.load')
    def test_analysis_error_handling(self, mock_load, mock_user_dir):
        """Should handle analysis errors gracefully"""
        mock_user_dir.return_value = self.temp_dir
        mock_load.side_effect = Exception("Analysis failed")

        # Create a temp file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test")
            temp_file = f.name

        try:
            analyzer = FileAnalyzer()
            result = analyzer._analyze_file(temp_file)

            # Should return empty result on error
            self.assertEqual(result['file_formats'], '')
            self.assertEqual(result['arch'], '')
            self.assertEqual(result['num_imports'], 0)
        finally:
            os.unlink(temp_file)

    @patch('file_analyzer.user_directory')
    @patch('file_analyzer.get_file_hash')
    @patch('file_analyzer.load')
    def test_unknown_format_becomes_unknown(self, mock_load, mock_hash, mock_user_dir):
        """Should convert empty view_type to 'Unknown'"""
        mock_user_dir.return_value = self.temp_dir
        mock_hash.return_value = 'test_hash'

        # Create a temp file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"unknown binary content")
            temp_file = f.name

        try:
            # Mock Binary Ninja returning empty view_type for unknown format
            mock_bv = MagicMock()
            mock_bv.view_type = ''  # Empty string for unknown format
            mock_bv.arch.name = 'x86_64'
            mock_bv.get_symbols_of_type.return_value = []
            mock_load.return_value.__enter__.return_value = mock_bv

            analyzer = FileAnalyzer()
            result = analyzer.skim_file(temp_file)

            # Should convert empty view_type to 'Unknown'
            self.assertEqual(result['file_formats'], 'Unknown')
            self.assertEqual(result['arch'], 'x86_64')
        finally:
            os.unlink(temp_file)


if __name__ == '__main__':
    unittest.main()
