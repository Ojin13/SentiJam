"""Loading and compiling the YAML rule files in rules/."""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from .models import Severity


def load_yaml(path: Path) -> dict:
    if not path.is_file():
        return {}
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


@dataclass
class StringRule:
    id: str
    severity: Severity
    title: str
    patterns: list[str]


@dataclass
class CustomRules:
    string_rules: list[StringRule]
    runtime_names: set[str]
    runtime_globs: list[str]
    helper_exes: set[str]
    sideload_names: set[str]
    trusted_signers: list[str]
    chromium_unsigned: set[str]

    def is_runtime_glob(self, relpath: str) -> bool:
        low = relpath.lower()
        return any(fnmatch.fnmatch(low, g) for g in self.runtime_globs)

    def is_engine_runtime(self, relpath: str) -> bool:
        name = relpath.rsplit("/", 1)[-1].lower()
        if name in self.runtime_names:
            return True
        low = relpath.lower()
        return any(fnmatch.fnmatch(low, g) for g in self.runtime_globs)

    def is_helper_exe(self, name: str) -> bool:
        return name.lower() in self.helper_exes


@lru_cache(maxsize=8)
def custom_rules(rules_dir: Path) -> CustomRules:
    data = load_yaml(rules_dir / "custom.yaml")
    srules = [StringRule(r["id"], Severity.parse(r.get("severity", "medium")), r.get("title", r["id"]),
                         [str(p) for p in r.get("patterns", [])]) for r in data.get("string_rules", [])]
    return CustomRules(
        string_rules=srules,
        runtime_names={n.lower() for n in data.get("engine_runtime_files", [])},
        runtime_globs=[g.lower() for g in data.get("engine_runtime_globs", [])],
        helper_exes={n.lower() for n in data.get("helper_executables", [])},
        sideload_names={n.lower() for n in data.get("sideload_dll_names", [])},
        trusted_signers=[str(s).lower() for s in data.get("trusted_runtime_signers", [])],
        chromium_unsigned={n.lower() for n in data.get("unsigned_chromium_runtime", [])},
    )


@dataclass
class CodeRule:
    id: str
    severity: Severity
    title: str
    regex: re.Pattern
    pyc_regex: re.Pattern | None = None
    shared: bool = False
    noisy: bool = False


@dataclass
class CodeRules:
    languages: dict[str, list[CodeRule]]
    shared: list[CodeRule]
    third_party_dirs: list[str]
    third_party_max: Severity

    def is_third_party(self, relpath: str) -> bool:
        """Match whole path segments ("node_modules" must be a folder, not part of "my_node_modules_x")."""
        low = "/" + relpath.lower().replace("\\", "/") + "/"
        for d in self.third_party_dirs:
            needle = "/" + d.strip("/").rstrip("*")
            if not d.endswith(("-", "*")):
                needle += "/"
            if needle in low:
                return True
        return False


def _compile_code_rule(r: dict, shared: bool = False) -> CodeRule:
    flags = re.IGNORECASE if r.get("ignore_case") else 0
    pyc = re.compile(r["pyc_pattern"], flags | re.MULTILINE) if r.get("pyc_pattern") else None
    return CodeRule(r["id"], Severity.parse(r.get("severity", "medium")), r.get("title", r["id"]),
                    re.compile(r["pattern"], flags), pyc, shared, bool(r.get("noisy")))


@lru_cache(maxsize=8)
def code_rules(rules_dir: Path) -> CodeRules:
    data = load_yaml(rules_dir / "code.yaml")
    langs = {lang: [_compile_code_rule(r) for r in rules] for lang, rules in (data.get("languages") or {}).items()}
    return CodeRules(
        languages=langs,
        shared=[_compile_code_rule(r, shared=True) for r in data.get("shared", [])],
        third_party_dirs=[d.lower() for d in data.get("third_party_dirs", [])],
        third_party_max=Severity.parse(data.get("third_party_max_severity", "low")),
    )


@dataclass
class WebRule:
    id: str
    severity: Severity
    title: str
    applies: set[str]
    regex: re.Pattern
    external_only: bool = False


@dataclass
class WebRules:
    rules: list[WebRule]
    external_code: re.Pattern
    itch_domains: list[str]
    cdn_domains: list[str]
    known_services: list[str]
    loader_globs: list[str]
    max_scan_bytes: int

    @staticmethod
    def _match_domain(domain: str, suffixes: list[str]) -> bool:
        d = domain.lower().rstrip(".")
        return any(d == s or d.endswith("." + s) for s in suffixes)

    def domain_class(self, domain: str) -> str:
        if self._match_domain(domain, self.itch_domains):
            return "itch"
        if self._match_domain(domain, self.known_services):
            return "service"
        if self._match_domain(domain, self.cdn_domains):
            return "cdn"
        return "unknown"

    def is_loader(self, relpath: str) -> bool:
        low = relpath.lower()
        name = low.rsplit("/", 1)[-1]
        return any(fnmatch.fnmatch(name, g) or fnmatch.fnmatch(low, "*" + g) for g in self.loader_globs)


@lru_cache(maxsize=8)
def web_rules(rules_dir: Path) -> WebRules:
    data = load_yaml(rules_dir / "web.yaml")
    rules = [WebRule(r["id"], Severity.parse(r.get("severity", "medium")), r.get("title", r["id"]),
                     set(r.get("applies", ["html", "js"])), re.compile(r["pattern"], re.IGNORECASE),
                     bool(r.get("external_only"))) for r in data.get("rules", [])]
    return WebRules(
        rules=rules,
        external_code=re.compile(data.get("external_code_pattern", r"(?!x)x"), re.IGNORECASE),
        itch_domains=[d.lower() for d in data.get("itch_domains", [])],
        cdn_domains=[d.lower() for d in data.get("cdn_domains", [])],
        known_services=[d.lower() for d in data.get("known_services", [])],
        loader_globs=[g.lower() for g in data.get("engine_loader_globs", [])],
        max_scan_bytes=int(data.get("max_scan_bytes", 3_000_000)),
    )
