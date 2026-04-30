from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence

from pqscan.analysis.base import infer_profile_reason

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

#: File-extension → language string recognised by run_two_phase_pipeline
EXTENSION_TO_LANG: Dict[str, str] = {
    ".c":    "c",
    ".h":    "c",
    ".cpp":  "c",
    ".cc":   "c",
    ".cxx":  "c",
    ".hpp":  "c",
    ".java": "java",
    ".py":   "python",
    ".go":   "go",
}

#: Skip files larger than this (bytes) to avoid OOM on minified / generated files
MAX_FILE_BYTES: int = 5 * 1024 * 1024  # 5 MB


# ─────────────────────────────────────────────────────────────────────────────
# Dataclasses
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class FindingSummary:
    """Compact, JSON-serialisable snapshot of a single finding."""
    line: int
    symbol: str
    profile_id: Optional[str]
    severity: str
    key_bits: Optional[int]
    recommendation: str = ""
    wrapper_chain: List[str] = field(default_factory=list)
    profile_reason: Optional[str] = None


@dataclass
class FileScanResult:
    """Result for a single scanned file."""
    file_path: str
    language: str
    status: str                          # "ok" | "error" | "skipped"
    error: Optional[str] = None
    scan_duration_ms: float = 0.0
    findings: List[FindingSummary] = field(default_factory=list)

    # ── convenience counts ──────────────────────────────────────────────────
    @staticmethod
    def _severity_value(severity: str) -> str:
        return str(severity or "").strip().lower()

    @property
    def total(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if self._severity_value(f.severity) == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if self._severity_value(f.severity) == "high")

    @property
    def unknown_count(self) -> int:
        return sum(1 for f in self.findings if self._severity_value(f.severity) == "unknown")

    @property
    def unknown_reason_breakdown(self) -> Dict[str, int]:
        from collections import Counter

        counter = Counter()
        for f in self.findings:
            if f.profile_id:
                continue
            counter[f.profile_reason or "unknown"] += 1
        return dict(counter)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["total"] = self.total
        d["critical_count"] = self.critical_count
        d["high_count"] = self.high_count
        d["unknown_count"] = self.unknown_count
        d["unknown_reason_breakdown"] = self.unknown_reason_breakdown
        return d


@dataclass
class FolderScanReport:
    """Aggregated result for an entire folder scan."""
    folder_path: str
    recursive: bool
    langs_filter: Optional[List[str]]
    total_files_found: int
    total_files_scanned: int
    total_files_skipped: int
    total_files_errored: int
    scan_duration_ms: float
    file_results: List[FileScanResult] = field(default_factory=list)

    # ── aggregate statistics across all files ────────────────────────────────
    @property
    def total_findings(self) -> int:
        return sum(r.total for r in self.file_results)

    @property
    def total_critical(self) -> int:
        return sum(r.critical_count for r in self.file_results)

    @property
    def total_high(self) -> int:
        return sum(r.high_count for r in self.file_results)

    @property
    def total_unknown(self) -> int:
        return sum(r.unknown_count for r in self.file_results)

    @property
    def unknown_reason_breakdown(self) -> Dict[str, int]:
        from collections import Counter

        counter = Counter()
        for result in self.file_results:
            for reason, count in result.unknown_reason_breakdown.items():
                counter[reason] += count
        return dict(counter)

    @property
    def files_with_findings(self) -> List[FileScanResult]:
        return [r for r in self.file_results if r.total > 0]

    def summary_dict(self) -> dict:
        """Compact JSON-ready summary (no per-file detail)."""
        return {
            "folder_path": self.folder_path,
            "recursive": self.recursive,
            "langs_filter": self.langs_filter,
            "total_files_found": self.total_files_found,
            "total_files_scanned": self.total_files_scanned,
            "total_files_skipped": self.total_files_skipped,
            "total_files_errored": self.total_files_errored,
            "scan_duration_ms": round(self.scan_duration_ms, 1),
            "total_findings": self.total_findings,
            "total_critical": self.total_critical,
            "total_high": self.total_high,
            "total_unknown": self.total_unknown,
            "unknown_reason_breakdown": self.unknown_reason_breakdown,
            "files_with_findings": len(self.files_with_findings),
        }

    def to_dict(self) -> dict:
        """Full JSON-serialisable representation (includes per-file detail)."""
        d = self.summary_dict()
        d["file_results"] = [r.to_dict() for r in self.file_results]
        return d


# ─────────────────────────────────────────────────────────────────────────────
# Core scan logic
# ─────────────────────────────────────────────────────────────────────────────

def _detect_language(path: Path) -> Optional[str]:
    """Return language string for *path*, or None if not supported."""
    return EXTENSION_TO_LANG.get(path.suffix.lower())


def _collect_files(
    folder: Path,
    recursive: bool,
    langs: Optional[Sequence[str]],
) -> List[tuple[Path, str]]:
    """Return (path, lang) pairs for all scannable files under *folder*."""
    pattern = "**/*" if recursive else "*"
    results: List[tuple[Path, str]] = []
    for candidate in folder.glob(pattern):
        if not candidate.is_file():
            continue
        lang = _detect_language(candidate)
        if lang is None:
            continue
        if langs and lang not in langs:
            continue
        results.append((candidate, lang))
    return results


def _scan_single_file(file_path: Path, lang: str) -> FileScanResult:
    """
    Run the two-phase pipeline on one file.
    Returns FileScanResult with status "ok", "error", or "skipped".
    """
    from pqscan.analysis.pipeline_v2 import run_two_phase_pipeline

    start = time.monotonic()

    # Size guard
    try:
        size = file_path.stat().st_size
    except OSError as exc:
        return FileScanResult(
            file_path=str(file_path),
            language=lang,
            status="error",
            error=f"stat failed: {exc}",
        )

    if size > MAX_FILE_BYTES:
        return FileScanResult(
            file_path=str(file_path),
            language=lang,
            status="skipped",
            error=f"file too large ({size} bytes > {MAX_FILE_BYTES})",
        )

    # Read
    try:
        code = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return FileScanResult(
            file_path=str(file_path),
            language=lang,
            status="error",
            error=f"read error: {exc}",
        )

    # Scan
    try:
        import sys as _sys
        _orig_stdout = _sys.stdout
        _sys.stdout = _sys.stderr          # redirect pipeline log output to stderr
        try:
            report = run_two_phase_pipeline(str(file_path), code, lang)
        finally:
            _sys.stdout = _orig_stdout     # always restore
    except Exception as exc:
        import traceback
        return FileScanResult(
            file_path=str(file_path),
            language=lang,
            status="error",
            error=f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}",
            scan_duration_ms=(time.monotonic() - start) * 1000,
        )

    # Convert findings
    summaries: List[FindingSummary] = []
    for f in report.findings:
        key_bits: Optional[int] = None
        if hasattr(f, "evidence") and isinstance(f.evidence, dict):
            key_bits = f.evidence.get("key_bits")
            if key_bits is None:
                details = f.evidence.get("details", {})
                if isinstance(details, dict):
                    key_bits = details.get("key_bits")

        chain = getattr(f, "wrapper_chain", []) or []
        profile_reason = getattr(f, "profile_reason", None)
        if not profile_reason:
            profile_reason = infer_profile_reason(getattr(f, "evidence", None), getattr(f, "profile_id", None))
        summaries.append(FindingSummary(
            line=f.line,
            symbol=getattr(f, "symbol", "") or "",
            profile_id=getattr(f, "profile_id", None),
            profile_reason=profile_reason,
            severity=getattr(f, "severity", "UNKNOWN") or "UNKNOWN",
            key_bits=key_bits,
            recommendation=getattr(f, "recommendation", "") or "",
            wrapper_chain=list(chain),
        ))

    elapsed_ms = (time.monotonic() - start) * 1000
    return FileScanResult(
        file_path=str(file_path),
        language=lang,
        status="ok",
        scan_duration_ms=elapsed_ms,
        findings=summaries,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────

def scan_folder(
    folder_path: "str | Path",
    recursive: bool = True,
    langs: Optional[List[str]] = None,
    max_workers: int = 4,
    on_progress: Optional[Callable[[int, int, str], None]] = None,
) -> FolderScanReport:
    """
    Scan all supported source files under *folder_path*.

    Parameters
    ----------
    folder_path:
        Root directory to scan.
    recursive:
        If True (default) walk into subdirectories.
    langs:
        Restrict to these language strings (e.g. ``["java", "python"]``).
        ``None`` means scan all supported languages.
    max_workers:
        Number of parallel worker threads (default 4).
        Set to 1 for single-threaded (easier debugging).
    on_progress:
        Optional callback ``(current: int, total: int, file_path: str) -> None``
        called on the main thread† after each file finishes.
        † Actually called from whichever thread submits to the pool; safe for
        simple counters / progress bars but not for GUI updates needing the
        main thread.

    Returns
    -------
    FolderScanReport
        Aggregated results. Use ``.to_dict()`` to serialise to JSON.

    Examples
    --------
    >>> from pqscan.scanner import scan_folder
    >>> report = scan_folder("/path/to/project", langs=["java", "python"])
    >>> print(report.summary_dict())
    """
    folder = Path(folder_path).resolve()
    if not folder.is_dir():
        raise ValueError(f"Not a directory: {folder}")

    batch_start = time.monotonic()

    # Collect candidate files
    all_files = _collect_files(folder, recursive, langs)
    total = len(all_files)

    file_results: List[FileScanResult] = []
    done_count = 0
    errored = 0
    skipped = 0

    if max_workers <= 1 or total <= 1:
        # Single-threaded path (simpler, better for unit tests / CI)
        for fp, lang in all_files:
            result = _scan_single_file(fp, lang)
            file_results.append(result)
            done_count += 1
            if result.status == "error":
                errored += 1
            elif result.status == "skipped":
                skipped += 1
            if on_progress:
                on_progress(done_count, total, str(fp))
    else:
        # Multi-threaded path
        future_to_path: dict = {}
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            for fp, lang in all_files:
                fut = pool.submit(_scan_single_file, fp, lang)
                future_to_path[fut] = (fp, lang)

            for fut in as_completed(future_to_path):
                result = fut.result()
                file_results.append(result)
                done_count += 1
                if result.status == "error":
                    errored += 1
                elif result.status == "skipped":
                    skipped += 1
                if on_progress:
                    on_progress(done_count, total, result.file_path)

    # Sort by file path for deterministic output
    file_results.sort(key=lambda r: r.file_path)

    batch_elapsed_ms = (time.monotonic() - batch_start) * 1000
    scanned = total - skipped - errored   # files that completed pipeline

    return FolderScanReport(
        folder_path=str(folder),
        recursive=recursive,
        langs_filter=list(langs) if langs else None,
        total_files_found=total,
        total_files_scanned=scanned,
        total_files_skipped=skipped,
        total_files_errored=errored,
        scan_duration_ms=batch_elapsed_ms,
        file_results=file_results,
    )
