"""
Tests to verify statistics totals match across different categories.
"""
import unittest
from unittest.mock import patch, MagicMock
import tempfile
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Check if we're in testing mode
if os.environ.get('BNWRAP_TESTING') != '1':
    print("Tests must be run with BNWRAP_TESTING=1 environment variable")
    sys.exit(1)


class TestStatsTotals(unittest.TestCase):
    """Test that statistics totals are consistent"""

    @patch('file_analyzer.user_directory')
    @patch('file_analyzer.get_file_hash')
    @patch('file_analyzer.load')
    def test_file_format_totals_match_count(self, mock_load, mock_hash, mock_user_dir):
        """Sum of file format counts should equal total binary count"""
        from file_analyzer import FileAnalyzer

        # Setup
        temp_dir = tempfile.mkdtemp()
        mock_user_dir.return_value = temp_dir

        try:
            analyzer = FileAnalyzer()

            # Create some test files and mock results
            test_files = []
            mock_results = [
                {'file_formats': 'ELF', 'arch': 'x86_64', 'size': 100, 'num_imports': 10, 'is_static': False},
                {'file_formats': 'PE', 'arch': 'x86', 'size': 200, 'num_imports': 5, 'is_static': True},
                {'file_formats': 'Raw', 'arch': 'ARM', 'size': 150, 'num_imports': 3, 'is_static': True},
                {'file_formats': 'ELF', 'arch': 'x86_64', 'size': 175, 'num_imports': 20, 'is_static': False},
                {'file_formats': 'Raw', 'arch': '', 'size': 50, 'num_imports': 0, 'is_static': True},
            ]

            for i, mock_result in enumerate(mock_results):
                # Create temp file
                with tempfile.NamedTemporaryFile(delete=False) as f:
                    f.write(b"test content")
                    test_files.append(f.name)

            # Now analyze each file with proper mocking
            for i, mock_result in enumerate(mock_results):
                # Mock the hash and analysis for this specific file
                def get_hash_side_effect(path):
                    # Return unique hash for each file
                    for idx, f in enumerate(test_files):
                        if f == path:
                            return f'hash_{idx}'
                    return 'unknown_hash'

                mock_hash.side_effect = get_hash_side_effect

                # Set up mock for this file
                mock_bv = MagicMock()
                mock_bv.view_type = mock_result['file_formats'] if mock_result['file_formats'] != 'Raw' else ''
                mock_bv.arch.name = mock_result['arch']
                mock_bv.get_symbols_of_type.return_value = range(mock_result['num_imports'])
                mock_load.return_value.__enter__.return_value = mock_bv

                # Analyze the file
                result = analyzer.skim_file(test_files[i])

            # Now simulate the stats computation
            file_formats = {}
            total_count = 0

            for test_file in test_files:
                result = analyzer.skim_file(test_file)
                if 'file_formats' in result:
                    total_count += 1
                    file_formats[result['file_formats']] = file_formats.get(result['file_formats'], 0) + 1

            # Verify totals match
            format_sum = sum(file_formats.values())
            self.assertEqual(total_count, format_sum,
                           f"Total count ({total_count}) should equal sum of format counts ({format_sum}). Formats: {file_formats}")

            # Verify we have the expected counts
            self.assertEqual(total_count, 5, "Should have analyzed 5 files")
            self.assertEqual(file_formats.get('ELF', 0), 2, "Should have 2 ELF files")
            self.assertEqual(file_formats.get('PE', 0), 1, "Should have 1 PE file")
            self.assertEqual(file_formats.get('Raw', 0), 2, "Should have 2 Raw files")

        finally:
            # Cleanup
            for f in test_files:
                if os.path.exists(f):
                    os.unlink(f)
            if os.path.exists(temp_dir):
                import shutil
                shutil.rmtree(temp_dir)

    @patch('file_analyzer.user_directory')
    @patch('file_analyzer.get_file_hash')
    @patch('file_analyzer.load')
    def test_architecture_totals_match_count(self, mock_load, mock_hash, mock_user_dir):
        """Sum of architecture counts should equal total binary count"""
        from file_analyzer import FileAnalyzer

        # Setup
        temp_dir = tempfile.mkdtemp()
        mock_user_dir.return_value = temp_dir

        try:
            analyzer = FileAnalyzer()

            # Create some test files and mock results
            test_files = []
            mock_results = [
                {'file_formats': 'ELF', 'arch': 'x86_64', 'size': 100, 'num_imports': 10},
                {'file_formats': 'PE', 'arch': 'x86', 'size': 200, 'num_imports': 5},
                {'file_formats': 'Mach-O', 'arch': 'aarch64', 'size': 150, 'num_imports': 3},
                {'file_formats': 'ELF', 'arch': 'x86_64', 'size': 175, 'num_imports': 20},
                {'file_formats': 'Raw', 'arch': '', 'size': 50, 'num_imports': 0},
            ]

            for i, mock_result in enumerate(mock_results):
                # Create temp file
                with tempfile.NamedTemporaryFile(delete=False) as f:
                    f.write(b"test content")
                    test_files.append(f.name)

            # Now analyze each file with proper mocking
            for i, mock_result in enumerate(mock_results):
                # Mock the hash and analysis for this specific file
                def get_hash_side_effect(path):
                    # Return unique hash for each file
                    for idx, f in enumerate(test_files):
                        if f == path:
                            return f'hash_{idx}'
                    return 'unknown_hash'

                mock_hash.side_effect = get_hash_side_effect

                # Set up mock for this file
                mock_bv = MagicMock()
                mock_bv.view_type = mock_result['file_formats'] if mock_result['file_formats'] != 'Raw' else ''
                mock_bv.arch = MagicMock() if mock_result['arch'] else None
                if mock_result['arch']:
                    mock_bv.arch.name = mock_result['arch']
                mock_bv.get_symbols_of_type.return_value = range(mock_result['num_imports'])
                mock_load.return_value.__enter__.return_value = mock_bv

                # Analyze the file
                result = analyzer.skim_file(test_files[i])

            # Now simulate the stats computation
            cpu_archs = {}
            total_count = 0

            for test_file in test_files:
                result = analyzer.skim_file(test_file)
                if 'arch' in result:
                    total_count += 1
                    cpu_archs[result['arch']] = cpu_archs.get(result['arch'], 0) + 1

            # Verify totals match
            arch_sum = sum(cpu_archs.values())
            self.assertEqual(total_count, arch_sum,
                           f"Total count ({total_count}) should equal sum of architecture counts ({arch_sum}). Archs: {cpu_archs}")

            # Verify we have the expected counts
            self.assertEqual(total_count, 5, "Should have analyzed 5 files")
            self.assertEqual(cpu_archs.get('x86_64', 0), 2, "Should have 2 x86_64 files")
            self.assertEqual(cpu_archs.get('x86', 0), 1, "Should have 1 x86 file")
            self.assertEqual(cpu_archs.get('aarch64', 0), 1, "Should have 1 aarch64 file")
            self.assertEqual(cpu_archs.get('Raw', 0), 1, "Should have 1 Raw arch file")

        finally:
            # Cleanup
            for f in test_files:
                if os.path.exists(f):
                    os.unlink(f)
            if os.path.exists(temp_dir):
                import shutil
                shutil.rmtree(temp_dir)

    @patch('file_analyzer.user_directory')
    @patch('file_analyzer.get_file_hash')
    @patch('file_analyzer.load')
    def test_error_cases_use_raw(self, mock_load, mock_hash, mock_user_dir):
        """Files that error during analysis should use 'Raw' format"""
        from file_analyzer import FileAnalyzer

        temp_dir = tempfile.mkdtemp()
        mock_user_dir.return_value = temp_dir

        try:
            analyzer = FileAnalyzer()

            # Create a temp file
            with tempfile.NamedTemporaryFile(delete=False) as f:
                f.write(b"test")
                temp_file = f.name

            # Mock the load to raise an exception
            mock_hash.return_value = 'test_hash'
            mock_load.side_effect = Exception("Analysis failed")

            # Analyze the file
            result = analyzer._analyze_file(temp_file)

            self.assertEqual(result['file_formats'], 'Raw',
                           "Error cases should return 'Raw' format")

            # Cleanup
            os.unlink(temp_file)

        finally:
            if os.path.exists(temp_dir):
                import shutil
                shutil.rmtree(temp_dir)


if __name__ == '__main__':
    unittest.main()
