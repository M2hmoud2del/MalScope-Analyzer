"""
MalScope Dynamic Analysis Module
==================================
Performs behavioral analysis on suspicious files through:
- Static behavioral prediction (safe mode)
- Cloud sandbox submission (Hybrid Analysis)
- Behavioral data parsing and scoring

Usage:
    from analysis.dynamic.dynamic_analyzer import run_dynamic_analysis
    result = run_dynamic_analysis("C:\\samples\\suspicious_file.exe")
"""

from .dynamic_analyzer import run_dynamic_analysis

__all__ = ["run_dynamic_analysis"]
