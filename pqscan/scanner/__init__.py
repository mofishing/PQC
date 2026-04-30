"""
pqscan/scanner/__init__.py – public API for the scanner sub-package.

Exposes:
    scan_folder  – bulk scan of a directory tree
    FolderScanReport – result dataclass
    FileScanResult   – per-file result dataclass
"""

from pqscan.scanner.folder_scan import (
    scan_folder,
    FolderScanReport,
    FileScanResult,
    EXTENSION_TO_LANG,
)

__all__ = [
    "scan_folder",
    "FolderScanReport",
    "FileScanResult",
    "EXTENSION_TO_LANG",
]
