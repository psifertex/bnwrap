"""
pytest configuration and fixtures for Binary Ninja Wrapped tests.

This file sets up the test environment to allow testing individual modules
without triggering the full plugin initialization.
"""
import sys
import os
from unittest.mock import MagicMock

# Set testing environment variable to prevent UI initialization
os.environ['BNWRAP_TESTING'] = '1'

# Mock Binary Ninja modules BEFORE any other imports
mock_bn = MagicMock()
mock_bn_log = MagicMock()
mock_bn_log.log = MagicMock()
mock_bn_log.LogLevel = MagicMock()

sys.modules['binaryninja'] = mock_bn
sys.modules['binaryninja.log'] = mock_bn_log

# Add parent directory to path so we can import modules directly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
