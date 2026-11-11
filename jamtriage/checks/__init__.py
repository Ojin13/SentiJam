"""Local static checks. None of them execute a submission."""
from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from ..config import Config
from ..proc import MemoryLimitExceeded, run_group
from ..models import FileRecord, Finding, Severity
from ..tools import ToolStatus


class ToolError(Exception):
    pass


MAX_TOOL_MEMORY_MB = 8192      # default ceiling per tool run; [tools] max_tool_memory_mb


def set_tool_memory_limit(mb: int | None) -> None:
    global MAX_TOOL_MEMORY_MB
    MAX_TOOL_MEMORY_MB = int(mb) if mb else None


def run_tool(cmd: list[str], timeout: int, cwd: Path | None = None,
             max_mb: int | None = -1) -> subprocess.CompletedProcess:
    """Run an analysis tool (never a submission) with a timeout and a memory ceiling. The tool's child
    processes are stopped with it. Raises ToolError on failure to run, timeout or too much memory."""
    try:
        return run_group(cmd, timeout=timeout, cwd=cwd, max_mb=MAX_TOOL_MEMORY_MB if max_mb == -1 else max_mb)
    except MemoryLimitExceeded as exc:
        raise ToolError(f"{Path(cmd[0]).name} stopped: needed more than {exc.max_mb} MB of memory") from exc
    except subprocess.TimeoutExpired as exc:
        raise ToolError(f"{Path(cmd[0]).name} timed out after {timeout}s") from exc
    except OSError as exc:
        raise ToolError(f"{Path(cmd[0]).name} could not start: {exc}") from exc


def trusted_runtime(rec: FileRecord) -> bool:
    """Set by the pe check: an engine runtime file that is verifiably the vendor's (see rules/custom.yaml)."""
    return "trusted-runtime" in rec.tags


@dataclass
class EntryContext:
    cfg: Config
    slug: str
    builds_root: Path
    tools: dict[str, ToolStatus]
    files: list[FileRecord] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    checks: dict[str, str] = field(default_factory=dict)   # check -> ok | not run (...) | error (...)
    info: dict = field(default_factory=dict)               # engine, diec, capa, yara, av, signatures, ...

    @property
    def unpacked_root(self) -> Path:
        return self.cfg.unpacked_dir / self.slug

    @property
    def unwrapped_root(self) -> Path:
        return self.cfg.unwrapped_dir / self.slug

    def abspath(self, rec: FileRecord | str) -> Path:
        rel = rec.path if isinstance(rec, FileRecord) else rec
        area, _, rest = rel.partition("/")
        base = {"builds": self.builds_root, "unpacked": self.unpacked_root,
                "unwrapped": self.unwrapped_root}[area]
        return base / rest

    def relpath(self, p: Path) -> str:
        for area, base in (("unwrapped", self.unwrapped_root), ("unpacked", self.unpacked_root),
                           ("builds", self.builds_root)):
            try:
                return f"{area}/{p.resolve().relative_to(base.resolve()).as_posix()}"
            except ValueError:
                continue
        return str(p)

    def tool(self, key: str) -> str | None:
        st = self.tools.get(key)
        return st.path if st and st.status == "available" else None

    def not_run(self, check: str, why: str) -> None:
        self.checks[check] = f"not run ({why})"

    def error(self, check: str, why: str, file: str = "") -> None:
        self.checks[check] = f"error ({why[:160]})"
        self.add(Finding(rule="analysis.error", severity=Severity.MEDIUM,
                         title=f"Could not analyse: {check} failed", file=file, detail=why[:300], source=check))

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def records(self, *kinds: str, origin: str | None = None) -> list[FileRecord]:
        return [r for r in self.files if (not kinds or r.kind in kinds) and (origin is None or r.origin == origin)]
