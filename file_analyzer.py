"""
File analysis and caching for Binary Ninja Wrapped plugin.
"""
import os
import json
import datetime
from binaryninja import load, SymbolType, user_directory
from binaryninja.log import log as bnlog
from binaryninja.log import LogLevel

# Support both package and direct module imports
try:
    from .utils import get_file_hash
except ImportError:
    from utils import get_file_hash


class FileAnalyzer:
    """Handles file analysis with caching support"""

    def __init__(self):
        """Initialize the file analyzer and cache system"""
        self.cache_dir = os.path.join(user_directory(), "bnwrapped_cache")
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)
        self.cache = {}

        # Load cache from disk if it exists
        cache_file = os.path.join(self.cache_dir, "analysis_cache.json")
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    self.cache = json.load(f)
            except:
                bnlog(LogLevel.WarningLog, "Failed to load cache file, creating new cache")
                self.cache = {}

    def save_cache(self):
        """Save the analysis cache to disk"""
        cache_file = os.path.join(self.cache_dir, "analysis_cache.json")
        try:
            with open(cache_file, 'w') as f:
                json.dump(self.cache, f)
        except:
            bnlog(LogLevel.WarningLog, "Failed to save cache file")

    def skim_file(self, file_path):
        """Analyze a file, using cache if the SHA256 hash matches

        Args:
            file_path (str): Path to the file to analyze

        Returns:
            dict: Analysis results with keys:
                - file_formats (str): File format/view type
                - arch (str): Architecture name
                - size (float): File size in KB
                - num_imports (int): Number of import symbols
                - is_static (bool): True if statically linked
        """
        # Initialize result structure
        result = {}
        result['file_formats'] = ''
        result['arch'] = ''
        result['size'] = 0
        result['num_imports'] = 0

        # Skip files that don't exist or are directories
        if not os.path.exists(file_path) or os.path.isdir(file_path):
            return result

        # Compute file hash for cache lookup
        file_hash = get_file_hash(file_path)
        if not file_hash:
            # If we can't compute the hash, just analyze the file directly
            return self._analyze_file(file_path)

        # Check if we have a cached result with matching hash
        if file_path in self.cache and self.cache[file_path].get('hash') == file_hash:
            bnlog(LogLevel.InfoLog, f"Using cached analysis for: {file_path}")
            return self.cache[file_path]['result']

        # If not cached or hash doesn't match, analyze the file
        bnlog(LogLevel.InfoLog, f"Analyzing file: {file_path}")
        result = self._analyze_file(file_path)

        # Cache the result with the hash
        self.cache[file_path] = {
            'hash': file_hash,
            'result': result,
            'timestamp': datetime.datetime.now().isoformat()
        }

        # Save the updated cache
        self.save_cache()

        return result

    def _analyze_file(self, file_path):
        """Perform actual file analysis (no caching)

        Args:
            file_path (str): Path to the file to analyze

        Returns:
            dict: Analysis results (same format as skim_file)
        """
        result = {}
        result['file_formats'] = ''
        result['arch'] = ''
        result['size'] = 0
        result['num_imports'] = 0

        try:
            with load(file_path, update_analysis=False) as bv:
                bv.set_analysis_hold(True)
                result['file_formats'] = bv.view_type if bv.view_type else 'Unknown'
                result['arch'] = bv.arch.name
                result['size'] = os.path.getsize(file_path) / 1024
                # TODO: Handle fat MachO files better here
                num_imports = len(bv.get_symbols_of_type(SymbolType.ImportAddressSymbol))
                result['num_imports'] = num_imports
                # Determine if binary is statically compiled based on import count
                result['is_static'] = num_imports <= 5
                bnlog(LogLevel.DebugLog, f"File: {file_path}, Format: {result['file_formats']}, Arch: {result['arch']}, Size: {result['size']} KB, Imports: {num_imports}")
        except Exception as e:
            bnlog(LogLevel.ErrorLog, f"Error analyzing {file_path}: {str(e)}")

        return result
