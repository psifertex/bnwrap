"""
File analysis and caching for Binary Ninja Wrapped plugin.
"""
import os
import json
import datetime
from binaryninja import load, SymbolType, user_directory, BinaryViewType, BinaryView, Platform

# Try to import project support
try:
    from binaryninja.project import Project
    HAS_PROJECT_SUPPORT = True
except ImportError:
    HAS_PROJECT_SUPPORT = False

# Import the plugin's logger instance and utilities
try:
    from .log import logger
    from .utils import get_file_hash
except ImportError:
    from log import logger
    from utils import get_file_hash


def _find_project_for_file(file_path):
    """Find if a file is inside a project directory and return display name

    Args:
        file_path (str): Path to the file

    Returns:
        str: Display name in format [ProjectName]/path if in project, otherwise None
    """
    if not HAS_PROJECT_SUPPORT:
        return None

    # Walk up the directory tree looking for a .bnpr directory
    current_dir = os.path.dirname(os.path.abspath(file_path))

    while current_dir and current_dir != os.path.dirname(current_dir):  # Stop at root
        if current_dir.endswith('.bnpr'):
            try:
                # Open the project
                project = Project.open_project(current_dir)
                if not project:
                    return None

                try:
                    # Calculate the project file ID (directory name + filename)
                    # The file should be under data/XX/filename where XX is first 2 chars of ID
                    relative_path = os.path.relpath(file_path, current_dir)
                    parts = relative_path.split(os.sep)

                    # Format should be: data/<first_2_chars>/<rest_of_id>
                    if len(parts) >= 3 and parts[0] == 'data':
                        project_file_id = parts[1] + parts[2]  # Combine directory name and filename

                        # Try to get the project file
                        project_file = project.get_file_by_id(project_file_id)
                        if project_file:
                            # Extract the display name while project is open
                            display_name = f"[{project.name}]{project_file.get_path_in_project()}"
                            return display_name
                finally:
                    # Always close the project when we're done
                    project.close()

            except Exception as e:
                logger.log_warn(f"Failed to open project at {current_dir}: {e}")
                return None

        current_dir = os.path.dirname(current_dir)

    return None


def _predict_architecture(file_path, view_type_name=None):
    """Try to predict the architecture using load settings

    Args:
        file_path (str): Path to the file to analyze
        view_type_name (str): Optional view type name from initial analysis

    Returns:
        str: Predicted architecture name or None if prediction failed
    """
    try:
        # Open the raw file
        raw_view = BinaryView.open(file_path)
        if not raw_view:
            return None

        # Check all available view types for predictions
        for view_type in BinaryViewType:
            try:
                if view_type.is_valid_for_data(raw_view):
                    # Get load settings - this is where prediction happens
                    load_settings = view_type.get_load_settings_for_data(raw_view)

                    if load_settings and load_settings.contains("loader.platform"):
                        platform_name = load_settings.get_string("loader.platform", raw_view)
                        if platform_name:
                            # Get the platform object and extract architecture
                            try:
                                platform = Platform[platform_name]
                                if platform and platform.arch:
                                    arch_name = platform.arch.name
                                    logger.log_info(f"Predicted architecture for {file_path}: {arch_name} (from {view_type.name})")
                                    return arch_name
                            except:
                                pass
            except:
                # Skip view types that throw errors
                continue

    except Exception as e:
        logger.log_debug(f"Failed to predict architecture for {file_path}: {e}")

    return None


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
                logger.log_warn("Failed to load cache file, creating new cache")
                self.cache = {}

    def save_cache(self):
        """Save the analysis cache to disk"""
        cache_file = os.path.join(self.cache_dir, "analysis_cache.json")
        try:
            with open(cache_file, 'w') as f:
                json.dump(self.cache, f)
        except:
            logger.log_warn("Failed to save cache file")

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

        # Check if this file is part of a project to get better display name
        display_name = _find_project_for_file(file_path)
        if not display_name:
            display_name = file_path

        # Compute file hash for cache lookup
        file_hash = get_file_hash(file_path)
        if not file_hash:
            # If we can't compute the hash, just analyze the file directly
            return self._analyze_file(file_path, display_name)

        # Check if we have a cached result with matching hash
        if file_path in self.cache and self.cache[file_path].get('hash') == file_hash:
            logger.log_info(f"Using cached analysis for: {display_name}")
            cached_result = self.cache[file_path]['result']
            # Fix old cached entries with empty file_formats or arch
            if 'file_formats' in cached_result and not cached_result['file_formats']:
                cached_result['file_formats'] = 'Raw'
            if 'arch' in cached_result and not cached_result['arch']:
                cached_result['arch'] = 'Raw'
            return cached_result

        # If not cached or hash doesn't match, analyze the file
        logger.log_info(f"Analyzing file: {display_name}")
        result = self._analyze_file(file_path, display_name)

        # Cache the result with the hash
        self.cache[file_path] = {
            'hash': file_hash,
            'result': result,
            'timestamp': datetime.datetime.now().isoformat()
        }

        # Save the updated cache
        self.save_cache()

        return result

    def _analyze_file(self, file_path, display_name=None):
        """Perform actual file analysis (no caching)

        Args:
            file_path (str): Path to the file to analyze
            display_name (str): Optional pre-computed display name for logging

        Returns:
            dict: Analysis results (same format as skim_file)
        """
        result = {}
        result['file_formats'] = ''
        result['arch'] = ''
        result['size'] = 0
        result['num_imports'] = 0

        try:
            # Use provided display name or get it from project detection
            if not display_name:
                display_name = _find_project_for_file(file_path)
                if not display_name:
                    display_name = file_path

            logger.log_debug(f"Starting analysis of: {display_name}")

            with load(file_path, update_analysis=False) as bv:
                bv.set_analysis_hold(True)

                result['file_formats'] = bv.view_type if bv.view_type else 'Raw'
                result['arch'] = bv.arch.name if bv.arch and bv.arch.name else 'Raw'
                result['size'] = os.path.getsize(file_path) / 1024
                # TODO: Handle fat MachO files better here
                num_imports = len(bv.get_symbols_of_type(SymbolType.ImportAddressSymbol))
                result['num_imports'] = num_imports
                # Determine if binary is statically compiled based on import count
                result['is_static'] = num_imports <= 5
                logger.log_debug(f"Completed analysis of: {display_name} - Format: {result['file_formats']}, Arch: {result['arch']}, Size: {result['size']} KB, Imports: {num_imports}")
        except Exception as e:
            logger.log_error(f"Error analyzing {file_path}: {str(e)}")

        # Ensure file_formats and arch are never empty
        if not result['file_formats']:
            result['file_formats'] = 'Raw'

        # If architecture is unknown, try to predict it
        if not result['arch'] or result['arch'] == 'Raw':
            # Pass the view type name as a hint for prediction
            view_type_hint = result.get('file_formats', None)
            predicted_arch = _predict_architecture(file_path, view_type_hint)
            if predicted_arch:
                result['arch'] = f"{predicted_arch}*"
                logger.log_info(f"Using predicted architecture: {result['arch']}")
            else:
                result['arch'] = 'Raw'

        return result
