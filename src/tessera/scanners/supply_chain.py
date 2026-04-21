"""tessera.scanners.supply_chain

Scan tool arguments for supply-chain risks in package install commands
and lock files:

* **Typosquatting** - edit distance vs. a popularity corpus.
* **Confusables** - homoglyphs, invisible characters, non-ASCII in names.
* **Shadow names** - ``python-dateutil`` vs ``python3-dateutil``,
  ``<pkg>-dev`` / ``<pkg>-test`` variants shadowing real packages.
* **Known-bad install patterns** - ``curl ... | sh``, ``--index-url`` to
  a non-default host, ``pip install git+https://...`` from unknown hosts,
  ``--trusted-host`` overrides, ``npm --registry`` overrides.
* **Lock file tampering** (via :func:`SupplyChainScanner.scan_lockfile_content`) -
  http:// entries, non-registry resolved URLs, missing integrity hashes.

The popularity corpus bundled here is a representative top-N slice;
override in production by passing ``popular_pypi=`` / ``popular_npm=``
to :class:`SupplyChainScanner` or by calling ``register_popular``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from tessera.scanners import ScanFinding, ScanResult, Severity, severity_rank


# ---------------------------------------------------------------------------
# Popularity corpora (replace in prod via constructor args)
# ---------------------------------------------------------------------------

_POPULAR_PYPI: frozenset[str] = frozenset(
    {
        "requests", "urllib3", "setuptools", "pip", "certifi", "idna",
        "charset-normalizer", "six", "wheel", "python-dateutil", "pytz",
        "numpy", "pandas", "boto3", "botocore", "s3transfer", "jmespath",
        "cryptography", "cffi", "pyyaml", "typing-extensions", "packaging",
        "attrs", "pluggy", "pyparsing", "pytest", "tomli", "exceptiongroup",
        "iniconfig", "click", "django", "flask", "werkzeug", "jinja2",
        "markupsafe", "itsdangerous", "aiohttp", "async-timeout", "multidict",
        "yarl", "aiosignal", "frozenlist", "sqlalchemy", "psycopg2", "redis",
        "celery", "kombu", "vine", "tensorflow", "torch", "transformers",
        "huggingface-hub", "tokenizers", "tqdm", "regex", "scipy",
        "scikit-learn", "matplotlib", "pillow", "beautifulsoup4", "lxml",
        "rsa", "pyasn1", "pyjwt", "bcrypt", "passlib", "httpx", "httpcore",
        "sniffio", "anyio", "uvicorn", "fastapi", "pydantic", "starlette",
        "gunicorn", "typer", "rich", "black", "isort", "mypy", "ruff",
        "pre-commit", "sphinx", "docutils", "openai", "anthropic",
        "langchain", "tiktoken", "google-auth", "google-cloud-storage",
        "firebase-admin", "stripe", "twilio", "pymongo", "pymysql", "psycopg",
        "asyncpg", "supabase", "azure-identity", "azure-core",
        "azure-storage-blob", "pytest-asyncio", "pytest-cov", "coverage",
        "hypothesis", "tomlkit", "poetry-core", "filelock", "cachetools",
        "pyopenssl", "requests-toolbelt", "lockfile", "pygments",
    }
)

_POPULAR_NPM: frozenset[str] = frozenset(
    {
        "react", "react-dom", "lodash", "axios", "express", "webpack",
        "typescript", "vue", "next", "eslint", "prettier", "jest", "mocha",
        "chai", "sinon", "chalk", "commander", "debug", "ms", "dotenv",
        "cors", "body-parser", "cookie-parser", "morgan", "helmet",
        "passport", "jsonwebtoken", "bcrypt", "bcryptjs", "mongoose",
        "sequelize", "pg", "mysql2", "redis", "ioredis", "socket.io", "ws",
        "three", "d3", "moment", "dayjs", "date-fns", "uuid", "nanoid",
        "classnames", "clsx", "styled-components", "tailwindcss", "postcss",
        "autoprefixer", "sass", "rollup", "parcel", "vite", "esbuild",
        "terser", "uglify-js", "fs-extra", "glob", "rimraf", "mkdirp",
        "fastify", "koa", "hapi", "nest", "tsx", "ts-node", "nodemon",
        "pm2", "winston", "bunyan", "pino", "yarn", "pnpm", "rxjs",
        "graphql", "apollo-server", "prisma", "drizzle", "zod", "joi", "yup",
        "formik", "react-hook-form", "swr", "react-query", "redux",
        "zustand", "jotai", "mobx", "leaflet", "cheerio", "playwright",
        "puppeteer", "cypress", "minimist", "yargs", "qs", "cookie",
        "form-data", "tough-cookie", "mime", "semver", "tar", "archiver",
        "bluebird", "core-js", "regenerator-runtime",
    }
)


# ---------------------------------------------------------------------------
# Install-command recognition
# ---------------------------------------------------------------------------

_INSTALL_CMD_RE = re.compile(
    r"""(?ix)
    (?P<manager>
        pip3? | python3?\s+-m\s+pip | pipx |
        npm | yarn | pnpm |
        gem | cargo | go
    )
    \s+
    (?P<verb>install|add|i\b|get)
    \s+
    (?P<rest>[^|&;\n]+)
    """
)

_FLAG_RE = re.compile(r"^-{1,2}[\w-]+(?:=\S*)?$")
_VERSION_SPEC_RE = re.compile(r"[<>=!~^].*$")
_SCOPE_NPM_RE = re.compile(r"^@[\w.-]+/[\w.-]+$")

_INVISIBLE_CHARS = frozenset(
    {
        "\u200b", "\u200c", "\u200d", "\u200e", "\u200f",
        "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
        "\u2060", "\u2061", "\u2062", "\u2063", "\u2064", "\ufeff",
    }
)

# Homoglyph map - tight subset sufficient to flag common cases.
_HOMOGLYPHS: dict[str, str] = {
    # Cyrillic
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0445": "x", "\u0443": "y", "\u0456": "i",
    # Greek
    "\u03bf": "o", "\u03b1": "a", "\u03c1": "p",
    # Fullwidth
    "\uff41": "a", "\uff42": "b", "\uff43": "c",
}


# Known-bad installer patterns (applied to the whole command, not per-package).
_BAD_INSTALL_PATTERNS: tuple[tuple[str, re.Pattern, Severity, str], ...] = (
    (
        "sc.curl_pipe_sh",
        re.compile(
            r"(?ix)(?:curl|wget)\s+[^|&;]*\s*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python3?|node)\b"
        ),
        "high",
        "remote script piped to shell interpreter",
    ),
    (
        "sc.pip_index_override",
        re.compile(r"(?i)pip3?\s+install[^|&;]*\s(?:--index-url|-i)\s+(?!https?://pypi\.org)"),
        "high",
        "pip install with non-default --index-url",
    ),
    (
        "sc.pip_trusted_host",
        re.compile(r"(?i)pip3?\s+install[^|&;]*\s--trusted-host\s+"),
        "medium",
        "pip install with --trusted-host override",
    ),
    (
        "sc.pip_git_url",
        re.compile(
            r"(?i)pip3?\s+install[^|&;]*\sgit\+https?://(?!github\.com/|gitlab\.com/|bitbucket\.org/)"
        ),
        "medium",
        "pip install from a non-major git host",
    ),
    (
        "sc.npm_registry_override",
        re.compile(
            r"(?i)(?:npm|yarn|pnpm)\s+(?:install|add|i)\b[^|&;]*\s--registry\s+"
            r"(?!https?://registry\.(?:npmjs|yarnpkg)\.(?:org|com))"
        ),
        "high",
        "npm/yarn/pnpm install with non-default --registry",
    ),
)


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _ParsedPackage:
    manager: str   # "pypi" | "npm" | "rubygems" | "cargo" | "go" | "unknown"
    name: str
    raw_token: str


class SupplyChainScanner:
    """Scanner for supply-chain risks in package install commands and lock files.

    Implements the :class:`tessera.scanners.Scanner` protocol.

    Args:
        popular_pypi: Override the default PyPI popularity corpus.
        popular_npm: Override the default npm popularity corpus.
        typosquat_max_distance: Edit distance ceiling (1 -> critical, 2 -> high).
        typosquat_min_len: Minimum name length to run edit-distance on.
        block_severity: Minimum severity that causes ``allowed=False``.
    """

    name = "tessera.scanners.supply_chain"

    def __init__(
        self,
        popular_pypi: Iterable[str] | None = None,
        popular_npm: Iterable[str] | None = None,
        typosquat_max_distance: int = 2,
        typosquat_min_len: int = 4,
        block_severity: Severity = "high",
    ) -> None:
        self._pypi = frozenset(popular_pypi) if popular_pypi is not None else _POPULAR_PYPI
        self._npm = frozenset(popular_npm) if popular_npm is not None else _POPULAR_NPM
        self._max_dist = typosquat_max_distance
        self._min_len = typosquat_min_len
        self._block_severity = block_severity

    def scan(
        self,
        *,
        tool_name: str,
        args: Any,
        trajectory_id: str = "",
    ) -> ScanResult:
        findings: list[ScanFinding] = []
        for path, text in _flatten_strings(args):
            findings.extend(self._scan_command_text(text, path))
        return self._build_result(findings)

    def scan_lockfile_content(
        self,
        *,
        filename: str,
        content: str,
    ) -> ScanResult:
        """Analyze lock file content directly.

        Call this when the agent is reading or writing a lock file
        rather than running an installer.
        """
        findings: list[ScanFinding] = []
        kind = _lockfile_kind(filename)
        if kind == "package-lock":
            findings.extend(_scan_package_lock_json(content, filename))
        elif kind == "yarn-lock":
            findings.extend(_scan_yarn_lock(content, filename))
        elif kind in ("poetry-lock", "pipfile-lock"):
            findings.extend(_scan_python_lock(content, filename, kind))
        return self._build_result(findings)

    def _build_result(self, findings: list[ScanFinding]) -> ScanResult:
        block_rank = severity_rank(self._block_severity)
        allowed = all(severity_rank(f.severity) < block_rank for f in findings)
        return ScanResult(scanner=self.name, allowed=allowed, findings=tuple(findings))

    def _scan_command_text(self, text: str, arg_path: str) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        for rid, pattern, sev, msg in _BAD_INSTALL_PATTERNS:
            m = pattern.search(text)
            if m:
                findings.append(
                    ScanFinding(
                        rule_id=rid,
                        severity=sev,
                        message=msg,
                        arg_path=arg_path,
                        evidence=m.group(0)[:200],
                    )
                )

        for pkg in _extract_packages(text):
            findings.extend(self._check_package(pkg, arg_path))

        return findings

    def _check_package(self, pkg: _ParsedPackage, arg_path: str) -> list[ScanFinding]:
        out: list[ScanFinding] = []
        name = pkg.name

        if any(c in _INVISIBLE_CHARS for c in name):
            out.append(
                ScanFinding(
                    rule_id="sc.invisible_char",
                    severity="critical",
                    message=f"package name contains invisible character: {pkg.raw_token!r}",
                    arg_path=arg_path,
                    evidence=pkg.raw_token,
                    metadata={"manager": pkg.manager},
                )
            )
            return out

        if any(c in _HOMOGLYPHS for c in name):
            out.append(
                ScanFinding(
                    rule_id="sc.homoglyph",
                    severity="critical",
                    message=f"package name contains homoglyph character: {pkg.raw_token!r}",
                    arg_path=arg_path,
                    evidence=pkg.raw_token,
                    metadata={"manager": pkg.manager},
                )
            )
            return out

        if any(ord(c) > 127 for c in name):
            out.append(
                ScanFinding(
                    rule_id="sc.nonascii_name",
                    severity="high",
                    message=f"package name contains non-ASCII characters: {pkg.raw_token!r}",
                    arg_path=arg_path,
                    evidence=pkg.raw_token,
                    metadata={"manager": pkg.manager},
                )
            )
            return out

        corpus = self._corpus_for(pkg.manager)
        if corpus is None:
            return out

        normalized = _normalize_name(name, pkg.manager)
        if normalized in corpus:
            return out

        # Separator-shadow: python3-dateutil vs python-dateutil
        loose = _loose_key(normalized)
        loose_corpus = {_loose_key(n): n for n in corpus}
        if loose in loose_corpus and loose_corpus[loose] != normalized:
            out.append(
                ScanFinding(
                    rule_id="sc.separator_shadow",
                    severity="high",
                    message=(
                        f"package {normalized!r} shadows {loose_corpus[loose]!r} via "
                        "separator variation"
                    ),
                    arg_path=arg_path,
                    evidence=pkg.raw_token,
                    metadata={"manager": pkg.manager, "shadowed": loose_corpus[loose]},
                )
            )
            return out

        # Suffix-shadow: <pkg>-dev, <pkg>-test, etc.
        for suffix in ("-dev", "-test", "-tests", "-utils", "-helper", "-helpers"):
            if normalized.endswith(suffix):
                base = normalized[: -len(suffix)]
                if base in corpus:
                    out.append(
                        ScanFinding(
                            rule_id="sc.suffix_shadow",
                            severity="medium",
                            message=(
                                f"package {normalized!r} uses {suffix!r} suffix "
                                f"shadowing {base!r}"
                            ),
                            arg_path=arg_path,
                            evidence=pkg.raw_token,
                            metadata={"manager": pkg.manager, "shadowed": base},
                        )
                    )
                    return out

        # Typosquat: edit distance to nearest corpus entry
        if len(normalized) >= self._min_len:
            nearest, dist = _nearest(normalized, corpus)
            if nearest is not None and 0 < dist <= self._max_dist:
                sev: Severity = "critical" if dist == 1 else "high"
                out.append(
                    ScanFinding(
                        rule_id="sc.typosquat",
                        severity=sev,
                        message=(
                            f"package {normalized!r} is {dist} edit(s) from {nearest!r}"
                        ),
                        arg_path=arg_path,
                        evidence=pkg.raw_token,
                        metadata={
                            "manager": pkg.manager,
                            "nearest": nearest,
                            "distance": dist,
                        },
                    )
                )

        return out

    def _corpus_for(self, manager: str) -> frozenset[str] | None:
        if manager == "pypi":
            return self._pypi
        if manager == "npm":
            return self._npm
        return None


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


_MANAGER_ALIASES = {
    "pip": "pypi", "pip3": "pypi", "pipx": "pypi",
    "python -m pip": "pypi", "python3 -m pip": "pypi",
    "npm": "npm", "yarn": "npm", "pnpm": "npm",
    "gem": "rubygems",
    "cargo": "cargo",
    "go": "go",
}


def _manager_key(raw: str) -> str:
    r = re.sub(r"\s+", " ", raw.strip().lower())
    return _MANAGER_ALIASES.get(r, "unknown")


def _extract_packages(text: str) -> list[_ParsedPackage]:
    out: list[_ParsedPackage] = []
    for m in _INSTALL_CMD_RE.finditer(text):
        manager = _manager_key(m.group("manager"))
        rest = m.group("rest")
        for token in rest.split():
            if _FLAG_RE.match(token):
                continue
            if token.startswith(("http://", "https://", "git+", "file:", "./", "../", "/")):
                continue
            if token.endswith((".whl", ".tar.gz", ".zip")):
                continue
            name = _strip_version_spec(token, manager)
            if not name:
                continue
            out.append(_ParsedPackage(manager=manager, name=name, raw_token=token))
    return out


def _strip_version_spec(token: str, manager: str) -> str:
    if manager == "npm":
        if _SCOPE_NPM_RE.match(token):
            return token
        if token.startswith("@"):
            parts = token.rsplit("@", 1)
            return parts[0] if len(parts) == 2 else token
        return token.split("@", 1)[0]
    name = _VERSION_SPEC_RE.sub("", token)
    name = name.split("[", 1)[0]
    return name.strip()


def _normalize_name(name: str, manager: str) -> str:
    if manager == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    if manager == "npm":
        return name.lower()
    return name.lower()


def _loose_key(name: str) -> str:
    return re.sub(r"[-_.0-9]+", "", name.lower())


def _levenshtein(a: str, b: str, cap: int) -> int:
    """Edit distance capped at ``cap`` (returns cap+1 if it exceeds)."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        row_min = cur[0]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if cur[j] < row_min:
                row_min = cur[j]
        if row_min > cap:
            return cap + 1
        prev = cur
    return prev[-1]


def _nearest(name: str, corpus: frozenset[str]) -> tuple[str | None, int]:
    best_name: str | None = None
    best_dist = 10**9
    for c in corpus:
        d = _levenshtein(name, c, cap=3)
        if d < best_dist:
            best_dist = d
            best_name = c
            if d == 0:
                break
    return best_name, best_dist


def _flatten_strings(args: Any, prefix: str = "") -> Iterable[tuple[str, str]]:
    if args is None:
        return
    if isinstance(args, str):
        yield (prefix or "$", args)
        return
    if isinstance(args, (bytes, bytearray)):
        try:
            yield (prefix or "$", bytes(args).decode("utf-8", errors="replace"))
        except Exception:
            return
        return
    if isinstance(args, Mapping):
        for k, v in args.items():
            child = f"{prefix}.{k}" if prefix else str(k)
            yield from _flatten_strings(v, child)
        return
    if isinstance(args, (list, tuple)):
        for i, v in enumerate(args):
            child = f"{prefix}[{i}]" if prefix else f"[{i}]"
            yield from _flatten_strings(v, child)


# ---------------------------------------------------------------------------
# Lock file analysis
# ---------------------------------------------------------------------------


def _lockfile_kind(filename: str) -> str:
    f = filename.lower().rsplit("/", 1)[-1]
    if f == "package-lock.json" or f == "npm-shrinkwrap.json":
        return "package-lock"
    if f == "yarn.lock":
        return "yarn-lock"
    if f == "poetry.lock":
        return "poetry-lock"
    if f == "pipfile.lock":
        return "pipfile-lock"
    return "unknown"


_TRUSTED_REGISTRY_HOSTS: tuple[str, ...] = (
    "registry.npmjs.org", "registry.yarnpkg.com",
    "files.pythonhosted.org", "pypi.org",
)


def _is_trusted_registry_url(url: str) -> bool:
    if not url.startswith("https://"):
        return False
    host = url[len("https://"):].split("/", 1)[0]
    return host in _TRUSTED_REGISTRY_HOSTS


def _scan_package_lock_json(content: str, filename: str) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    try:
        data = json.loads(content)
    except Exception as e:
        return [
            ScanFinding(
                rule_id="sc.lock.parse_error",
                severity="low",
                message=f"could not parse {filename}: {e}",
                arg_path=filename,
            )
        ]

    packages = data.get("packages") or {}
    for key, entry in packages.items():
        if not isinstance(entry, dict) or not key:
            continue
        resolved = entry.get("resolved") or ""
        integrity = entry.get("integrity") or ""
        if resolved.startswith("http://"):
            findings.append(
                ScanFinding(
                    rule_id="sc.lock.http_resolved",
                    severity="high",
                    message=f"{key}: resolved URL uses http://",
                    arg_path=f"{filename}:packages.{key}",
                    evidence=resolved[:200],
                )
            )
        elif resolved and not _is_trusted_registry_url(resolved):
            findings.append(
                ScanFinding(
                    rule_id="sc.lock.offregistry_resolved",
                    severity="medium",
                    message=f"{key}: resolved from non-default registry host",
                    arg_path=f"{filename}:packages.{key}",
                    evidence=resolved[:200],
                )
            )
        if key and not integrity and resolved:
            findings.append(
                ScanFinding(
                    rule_id="sc.lock.missing_integrity",
                    severity="medium",
                    message=f"{key}: entry missing integrity hash",
                    arg_path=f"{filename}:packages.{key}",
                )
            )
    return findings


_YARN_ENTRY_RE = re.compile(
    r'^(?:"[^"\n]+"|\S+)[ \S]*?:\n'
    r'(?:  [^\n]*\n)+',
    re.MULTILINE,
)
_YARN_RESOLVED_RE = re.compile(r'^\s*resolved\s+"([^"]+)"', re.MULTILINE)
_YARN_INTEGRITY_RE = re.compile(r'^\s*integrity\s+(\S+)', re.MULTILINE)


def _scan_yarn_lock(content: str, filename: str) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    for block_match in _YARN_ENTRY_RE.finditer(content):
        block = block_match.group(0)
        resolved_m = _YARN_RESOLVED_RE.search(block)
        integrity_m = _YARN_INTEGRITY_RE.search(block)
        header = block.split(":", 1)[0].strip().strip('"')
        if resolved_m:
            url = resolved_m.group(1)
            if url.startswith("http://"):
                findings.append(
                    ScanFinding(
                        rule_id="sc.lock.http_resolved",
                        severity="high",
                        message=f"{header}: resolved URL uses http://",
                        arg_path=filename,
                        evidence=url[:200],
                    )
                )
            elif not _is_trusted_registry_url(url):
                findings.append(
                    ScanFinding(
                        rule_id="sc.lock.offregistry_resolved",
                        severity="medium",
                        message=f"{header}: resolved from non-default registry host",
                        arg_path=filename,
                        evidence=url[:200],
                    )
                )
        if resolved_m and not integrity_m:
            findings.append(
                ScanFinding(
                    rule_id="sc.lock.missing_integrity",
                    severity="medium",
                    message=f"{header}: entry missing integrity hash",
                    arg_path=filename,
                )
            )
    return findings


def _scan_python_lock(content: str, filename: str, kind: str) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    if kind == "pipfile-lock":
        try:
            data = json.loads(content)
        except Exception:
            return findings
        for section in ("default", "develop"):
            for pkg, entry in (data.get(section) or {}).items():
                if not isinstance(entry, dict):
                    continue
                hashes = entry.get("hashes") or []
                if not hashes:
                    findings.append(
                        ScanFinding(
                            rule_id="sc.lock.missing_integrity",
                            severity="medium",
                            message=f"{pkg}: entry missing hashes",
                            arg_path=f"{filename}:{section}.{pkg}",
                        )
                    )
        return findings
    # poetry.lock - look for url = "http://" lines
    for m in re.finditer(r'url\s*=\s*"(http://[^"]+)"', content):
        findings.append(
            ScanFinding(
                rule_id="sc.lock.http_resolved",
                severity="high",
                message="poetry.lock entry uses http://",
                arg_path=filename,
                evidence=m.group(1)[:200],
            )
        )
    return findings


__all__ = ["SupplyChainScanner"]
