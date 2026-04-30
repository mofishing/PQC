#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
PQScan Analysis Module
=====================

提供后量子密码学扫描和分析功能
"""

def __getattr__(name):
    if name in ('PQScanner', 'scan_file', 'scan_directory'):
        from .scanner import PQScanner, scan_file, scan_directory
        globals().update({
            'PQScanner': PQScanner,
            'scan_file': scan_file,
            'scan_directory': scan_directory,
        })
        return globals()[name]
    raise AttributeError(f"module 'pqscan.analysis' has no attribute {name!r}")

__all__ = [
    'PQScanner',
    'scan_file',
    'scan_directory',
]
