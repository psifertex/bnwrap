"""
Tests for quotes module.
"""
import unittest

# Import module directly to avoid triggering __init__.py
import quotes
get_stats_quote = quotes.get_stats_quote
get_file_formats_quote = quotes.get_file_formats_quote
get_architectures_quote = quotes.get_architectures_quote
get_binary_stats_quote = quotes.get_binary_stats_quote
get_static_binaries_quote = quotes.get_static_binaries_quote


class TestGetStatsQuote(unittest.TestCase):
    """Test get_stats_quote function"""

    def test_returns_string(self):
        """Should return a string"""
        result = get_stats_quote(10, "TestUser", {'avg': 100, 'min': 50, 'max': 200})
        self.assertIsInstance(result, str)
        self.assertTrue(len(result) > 0)

    def test_includes_count(self):
        """Quote should reference the count"""
        count = 42
        result = get_stats_quote(count, "TestUser", {'avg': 100, 'min': 50, 'max': 200})
        self.assertIn(str(count), result)

    def test_zero_binaries(self):
        """Should handle zero binaries"""
        result = get_stats_quote(0, "TestUser", {'avg': 0, 'min': 0, 'max': 0})
        self.assertIsInstance(result, str)


class TestGetFileFormatsQuote(unittest.TestCase):
    """Test get_file_formats_quote function"""

    def test_no_formats(self):
        """Should handle no file formats"""
        result = get_file_formats_quote({})
        self.assertIsInstance(result, str)
        self.assertIn("No file formats", result)

    def test_single_format(self):
        """Should handle single format"""
        result = get_file_formats_quote({'ELF': 10})
        self.assertIsInstance(result, str)
        self.assertIn('ELF', result)

    def test_two_formats(self):
        """Should handle two formats"""
        result = get_file_formats_quote({'ELF': 5, 'PE': 3})
        self.assertIsInstance(result, str)
        # Should mention it's two formats
        self.assertTrue(len(result) > 0)

    def test_many_formats(self):
        """Should handle many formats"""
        formats = {'ELF': 10, 'PE': 8, 'Mach-O': 6, 'Raw': 2}
        result = get_file_formats_quote(formats)
        self.assertIsInstance(result, str)
        self.assertTrue(len(result) > 0)


class TestGetArchitecturesQuote(unittest.TestCase):
    """Test get_architectures_quote function"""

    def test_no_architectures(self):
        """Should handle no architectures"""
        result = get_architectures_quote({})
        self.assertIsInstance(result, str)
        self.assertIn("No architectures", result)

    def test_single_architecture(self):
        """Should handle single architecture"""
        result = get_architectures_quote({'x86_64': 10})
        self.assertIsInstance(result, str)
        self.assertIn('x86_64', result)

    def test_two_architectures(self):
        """Should handle two architectures"""
        result = get_architectures_quote({'x86_64': 5, 'arm64': 3})
        self.assertIsInstance(result, str)

    def test_many_architectures(self):
        """Should handle many architectures"""
        archs = {'x86_64': 10, 'arm64': 8, 'mips': 6, 'armv7': 2}
        result = get_architectures_quote(archs)
        self.assertIsInstance(result, str)


class TestGetBinaryStatsQuote(unittest.TestCase):
    """Test get_binary_stats_quote function"""

    def test_same_size_binaries(self):
        """Should detect when all binaries are same size"""
        stats = {'min size': 100.0, 'max size': 100.0, 'avg size': 100.0}
        result = get_binary_stats_quote(stats)
        self.assertIsInstance(result, str)
        self.assertTrue(len(result) > 0)

    def test_large_size_ratio(self):
        """Should handle large size differences"""
        stats = {'min size': 10.0, 'max size': 10000.0, 'avg size': 5000.0}
        result = get_binary_stats_quote(stats)
        self.assertIsInstance(result, str)

    def test_medium_size_ratio(self):
        """Should handle medium size differences"""
        stats = {'min size': 100.0, 'max size': 1500.0, 'avg size': 800.0}
        result = get_binary_stats_quote(stats)
        self.assertIsInstance(result, str)

    def test_small_size_ratio(self):
        """Should handle small size differences"""
        stats = {'min size': 100.0, 'max size': 150.0, 'avg size': 125.0}
        result = get_binary_stats_quote(stats)
        self.assertIsInstance(result, str)


class TestGetStaticBinariesQuote(unittest.TestCase):
    """Test get_static_binaries_quote function"""

    def test_no_binaries(self):
        """Should handle no binaries"""
        counts = {'static': 0, 'dynamic': 0}
        result = get_static_binaries_quote(counts)
        self.assertIsInstance(result, str)

    def test_all_static(self):
        """Should handle 100% static binaries"""
        counts = {'static': 10, 'dynamic': 0}
        result = get_static_binaries_quote(counts)
        self.assertIsInstance(result, str)
        # Should mention static preference

    def test_all_dynamic(self):
        """Should handle 100% dynamic binaries"""
        counts = {'static': 0, 'dynamic': 10}
        result = get_static_binaries_quote(counts)
        self.assertIsInstance(result, str)
        # Should mention dynamic preference

    def test_mostly_static(self):
        """Should handle mostly static (>80%)"""
        counts = {'static': 9, 'dynamic': 1}
        result = get_static_binaries_quote(counts)
        self.assertIsInstance(result, str)

    def test_slightly_more_static(self):
        """Should handle slightly more static (50-80%)"""
        counts = {'static': 6, 'dynamic': 4}
        result = get_static_binaries_quote(counts)
        self.assertIsInstance(result, str)

    def test_balanced(self):
        """Should handle balanced distribution (20-50%)"""
        counts = {'static': 3, 'dynamic': 7}
        result = get_static_binaries_quote(counts)
        self.assertIsInstance(result, str)

    def test_mostly_dynamic(self):
        """Should handle mostly dynamic (<20%)"""
        counts = {'static': 1, 'dynamic': 9}
        result = get_static_binaries_quote(counts)
        self.assertIsInstance(result, str)


if __name__ == '__main__':
    unittest.main()
