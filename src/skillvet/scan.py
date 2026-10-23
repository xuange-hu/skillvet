"""Scan orchestration — discover targets, run both rule sets, build a report.

Third takeaway that shaped the API: the report must be usable without looking at
the terminal output, so everything is plain data with `to_dict()`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .discover import DiscoveryStats, discover
from .mcprules import check_manifest
from .model import CAPABILITIES, Finding, Severity, Target
from .rules import scan_text

DEFAULT_MAX_BYTES = 512 * 1024


@dataclass
class Report:
    root: str
    targets: list[Target] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)
    stats: DiscoveryStats = field(default_factory=DiscoveryStats)

    # ---- derived views ----------------------------------------------------
    def counts(self) -> dict[str, int]:
        out = {level: 0 for level in Severity.ORDER}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def filtered(self, min_severity: str = Severity.INFO) -> list[Finding]:
        keep = set(Severity.at_least(min_severity))
        return sorted(
            (f for f in self.findings if f.severity in keep),
            key=Finding.sort_key,
        )

    def capabilities(self) -> dict[str, list[Finding]]:
        """Group findings by what the artifact would be able to *do*."""
        out: dict[str, list[Finding]] = {}
        for f in self.findings:
            key = f.capability or f.category
            out.setdefault(key, []).append(f)
        return dict(sorted(out.items(), key=lambda kv: (-len(kv[1]), kv[0])))

    def risk_score(self) -> int:
        """0-100. Every hit contributes; the score saturates, it never wraps."""
        total = sum(Severity.WEIGHT.get(f.severity, 0) for f in self.findings)
        return min(100, total)

    def grade(self) -> str:
        """Worst severity decides the floor; the aggregate score can raise it.

        A single MEDIUM must not be reported as "LOW" just because 8 points is
        below the aggregate threshold — the band names have to mean something.
        """
        counts = self.counts()
        if counts[Severity.CRITICAL]:
            return "CRITICAL"
        if counts[Severity.HIGH] or self.risk_score() >= 45:
            return "HIGH"
        if counts[Severity.MEDIUM] or self.risk_score() >= 15:
            return "MEDIUM"
        if self.risk_score() > 0:
            return "LOW"
        return "CLEAN"

    def files_scanned(self) -> int:
        return len(self.targets)

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "summary": {
                "files_scanned": self.files_scanned(),
                "risk_score": self.risk_score(),
                "grade": self.grade(),
                "counts": self.counts(),
                "capabilities": {
                    cap: len(items) for cap, items in self.capabilities().items()
                },
            },
            "targets": [
                {"file": t.display, "ecosystem": t.ecosystem, "kind": t.kind}
                for t in self.targets
            ],
            "findings": [f.to_dict() for f in self.filtered()],
            "errors": [{"file": a, "error": b} for a, b in self.errors],
            "stats": {
                "files_walked": self.stats.files_walked,
                "pruned_dirs": self.stats.pruned_dirs,
                "truncated": self.stats.truncated,
            },
        }


def read_text(path: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> str:
    data = path.read_bytes()
    if len(data) > max_bytes:
        # Never silently review only the head of something oversized.
        raise ValueError(f"file exceeds --max-bytes ({len(data)} > {max_bytes})")
    return data.decode("utf-8", errors="replace")


def scan_target(target: Target, max_bytes: int = DEFAULT_MAX_BYTES) -> tuple[list[Finding], str | None]:
    text = read_text(target.path, max_bytes)
    if target.kind == "mcp-config":
        return check_manifest(text, target), None
    return scan_text(text, target), None


def scan_targets(targets: list[Target], root: str = ".", max_bytes: int = DEFAULT_MAX_BYTES) -> Report:
    report = Report(root=root, targets=list(targets))
    for target in targets:
        try:
            findings, _ = scan_target(target, max_bytes)
        except ValueError as exc:
            report.errors.append((target.display, str(exc)))
            continue
        except OSError as exc:
            report.errors.append((target.display, f"{exc.__class__.__name__}: {exc}"))
            continue
        report.findings.extend(findings)
    return report


def scan_path(root: str | Path, max_bytes: int = DEFAULT_MAX_BYTES) -> Report:
    """Discover and scan everything under *root*."""
    root_path = Path(root)
    targets, stats = discover(root_path)
    report = scan_targets(targets, root=str(root_path), max_bytes=max_bytes)
    report.stats = stats
    return report


def describe_capability(key: str) -> str:
    return CAPABILITIES.get(key, key.replace("-", " "))
