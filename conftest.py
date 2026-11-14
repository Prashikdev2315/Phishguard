"""
conftest.py — pytest configuration for PhishGuard.
Adds the phishguard root to sys.path so all test modules can import
from ml/, tools/, etc. without installation.
"""
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
