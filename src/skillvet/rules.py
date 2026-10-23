"""Instruction-file rules.

Every rule is plain, reviewed Python — not a model call. The engine walks the
file line by line and hands each rule the full line list, so a rule can look at
a small context window (real payloads are frequently split across lines).
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Callable, Iterable

from .model import Finding, Severity, Target

HIDDEN_UNICODE = (
    "\u200b\u200c\u200d\u200e\u200f"  # zero-width space/joiner and LRM/RLM
    "\u202a\u202b\u202c\u202d\u202e"  # bidi embedding / override
    "\u2060\u2061\u2062\u2063\u2064"  # invisible operators
    "\ufeff"  # BOM / zero-width no-break space
)
_HIDDEN_SET = frozenset(HIDDEN_UNICODE)


def window_text(lines: list[str], index0: int, radius: int = 2) -> str:
    """Lower-cased text of the +/- radius window around lines[index0]. O(1)."""
    lo = max(0, index0 - radius)
    hi = min(len(lines), index0 + radius + 1)
    return "\n".join(lines[lo:hi]).lower()


@dataclasses.dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    category: str
    why: str
    capability: str = ""
    check: Callable[[list[str], Target], Iterable[Finding]] | None = None


@dataclasses.dataclass(frozen=True)
class RegexRule(Rule):
    """Hit when `pattern` matches, and — optionally — `needs_context` matches
    in the surrounding window. Cross-line detection without a real parser."""

    pattern: str = ""
    needs_context: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "_rx", re.compile(self.pattern, re.IGNORECASE))
        object.__setattr__(
            self,
            "_ctx",
            re.compile(self.needs_context, re.IGNORECASE) if self.needs_context else None,
        )

    def run(self, lines: list[str], target: Target) -> Iterable[Finding]:
        rx = self._rx
        ctx = self._ctx
        for i, raw in enumerate(lines, start=1):
            if not rx.search(raw):
                continue
            if ctx is not None and not ctx.search(window_text(lines, i - 1)):
                continue
            yield Finding(
                rule_id=self.id,
                title=self.title,
                severity=self.severity,
                category=self.category,
                file=target.display,
                line=i,
                snippet=raw.strip()[:300],
                why=self.why,
                capability=self.capability,
            )


def func_rule(**kwargs) -> Callable:
    """Turn `def (lines, target) -> Iterable[Finding]` into a Rule."""

    def deco(fn: Callable[[list[str], Target], Iterable[Finding]]) -> Rule:
        return Rule(check=fn, **kwargs)

    return deco


@dataclasses.dataclass(frozen=True)
class Frontmatter:
    """Minimum YAML frontmatter understanding — enough for permissions.

    Supports `key: value` and `key:` followed by `- item` lines. No quoting,
    anchors or flow collections: we only need this shape, and shipping a real
    YAML parser would break the zero-dependency guarantee.
    """

    data: dict

    @classmethod
    def parse(cls, text: str) -> Frontmatter | None:
        lines = text.splitlines()
        if not lines or lines[0].strip() != "---":
            return None
        end = None
        for i in range(1, len(lines)):
            if lines[i].strip() == "---":
                end = i
                break
        if end is None:
            return None
        data: dict = {}
        key = None
        for raw in lines[1:end]:
            line = raw.rstrip()
            if not line.strip():
                continue
            indented = line[:1].isspace()
            if indented:
                if key is not None and line.strip().startswith("- "):
                    data.setdefault(key, [])
                    if isinstance(data[key], list):
                        data[key].append(_scalar(line.strip()[2:]))
                continue
            if ":" not in line:
                continue
            k, _, v = line.partition(":")
            key = k.strip()
            v = v.strip()
            data[key] = [] if v == "" else _scalar(v)
        return cls(data)

    def get(self, name: str):
        return self.data.get(name)


def _scalar(value: str):
    v = value.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    if v.startswith("[") and v.endswith("]"):
        return [p.strip().strip("\"'") for p in v[1:-1].split(",") if p.strip()]
    return v


def run_rules(lines: list[str], target: Target, rules: Iterable[Rule]) -> list[Finding]:
    out: list[Finding] = []
    for rule in rules:
        if rule.check is not None:
            out.extend(rule.check(lines, target))
        elif isinstance(rule, RegexRule):
            out.extend(rule.run(lines, target))
        else:  # pragma: no cover - guards against a Rule subclass without either
            raise TypeError(f"rule {rule.id} has neither check nor pattern")
    return out


# ---------------------------------------------------------------------------
# custom checks — things a single regex cannot express
# ---------------------------------------------------------------------------


@func_rule(
    id="SKV010",
    title="Hidden Unicode control characters (Trojan Source style)",
    severity=Severity.HIGH,
    category="hidden-text",
    capability="hidden-text",
    why=(
        "Zero-width and bidi-override characters render as nothing, so the text a "
        "human reviews is not the text the model reads. It is the cheapest way to "
        "smuggle a second payload past review — and most scanners miss it."
    ),
)
def _hidden_unicode(lines: list[str], target: Target) -> Iterable[Finding]:
    for i, raw in enumerate(lines, start=1):
        hits = sorted({ch for ch in raw if ch in _HIDDEN_SET})
        if not hits:
            continue
        yield Finding(
            rule_id="SKV010",
            title="Hidden Unicode control characters (Trojan Source style)",
            severity=Severity.HIGH,
            category="hidden-text",
            file=target.display,
            line=i,
            snippet=raw.strip()[:300],
            why=(
                "Invisible control chars at "
                + ", ".join(f"U+{ord(c):04X}" for c in hits)
                + "; the rendered line differs from what the agent parses."
            ),
            capability="hidden-text",
        )


@func_rule(
    id="SKV011",
    title="Broad tool permissions in frontmatter",
    severity=Severity.LOW,
    category="scope",
    capability="scope",
    why=(
        "A wildcard (or unscoped Bash/Write) grant silently widens the blast radius "
        "of every later instruction. Prefer an explicit allowlist."
    ),
)
def _broad_permissions(lines: list[str], target: Target) -> Iterable[Finding]:
    fm = Frontmatter.parse("\n".join(lines))
    if fm is None:
        return []
    tools = fm.get("allowed-tools")
    if tools is None:
        return []
    entries = tools if isinstance(tools, list) else [t.strip() for t in str(tools).split(",")]
    for entry in entries:
        text = str(entry).strip()
        lowered = text.lower()
        if text in {"*", "all"} or lowered.startswith("bash") and lowered in {"bash", "bash(*)", "shell"}:
            idx = next(
                (i for i, raw in enumerate(lines, start=1) if lowered and raw.strip().lower() == lowered),
                1,
            )
            yield Finding(
                rule_id="SKV011",
                title="Broad tool permissions in frontmatter",
                severity=Severity.LOW,
                category="scope",
                file=target.display,
                line=idx,
                snippet=f"allowed-tools: {text}",
                why=f"'{text}' grants unrestricted tool access rather than an allowlist.",
                capability="scope",
            )


# ---------------------------------------------------------------------------
# the rule set
# ---------------------------------------------------------------------------

RULES: tuple[Rule, ...] = (
    _hidden_unicode,
    _broad_permissions,
    RegexRule(
        id="SKV001",
        title="Egress with a secret or credential in the same block",
        severity=Severity.CRITICAL,
        category="network-egress",
        capability="network-egress",
        pattern=r"\b(curl|wget|iwr|Invoke-WebRequest|Invoke-RestMethod|requests\.(post|put)|urllib\.request\.urlopen|fetch\(|nc |Net\.WebClient)\b",
        needs_context=r"(\$\{?[A-Z_]*(TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL)[A-Z_]*\}?|\.env\b|id_rsa|authorized_keys|credentials|\.aws/|Login Data|logins\.json|keychain|\.npmrc|\.netrc|\.git-credentials|Bearer\s)",
        why=(
            "Upload trajectory plus a credential in the same block is the whole attack: "
            "there is no benign reason for an instruction to mail your secrets out."
        ),
    ),
    RegexRule(
        id="SKV002",
        title="Outbound network call",
        severity=Severity.MEDIUM,
        category="network-egress",
        capability="network-egress",
        pattern=r"\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|requests\.(get|post)|urllib\.request|fetch\(|scp |rsync |ssh )\b|https?://[a-z0-9.-]+\.[a-z]{2,}",
        why="Network egress from a skill needs an explicit justification; most do not need it.",
    ),
    RegexRule(
        id="SKV003",
        title="Reads credentials or local secret stores",
        severity=Severity.HIGH,
        category="credential-read",
        capability="credential-read",
        pattern=r"(~|\$HOME|%USERPROFILE%)?/?\.?((ssh/id_rsa|ssh/id_ed25519|aws/credentials|azure/|docker/config\.json|kube/config|npmrc|netrc|git-credentials)|\.env\b)|(Login Data|Local State|logins\.json|keychain|Keychains|credential manager|Sam\.hive|SAM\b|ntds\.dit|lsass)",
        why="Reading a secret store is the prerequisite for credential theft; a code task rarely needs it.",
    ),
    RegexRule(
        id="SKV004",
        title="Decode-then-execute pipeline",
        severity=Severity.HIGH,
        category="obfuscation",
        capability="obfuscation",
        pattern=r"(base64\s+(-d|--decode|-D)|certutil\s+-decode|FromBase64String|\bgunzip\b.+\|\s*(ba)?sh|expand\s+.+\|(ba)?sh)",
        needs_context=r"(\|\s*(ba)?sh|\|\s*bash|iex|\beval\b|\bexec\b|Invoke-Expression|-\s*c\s)",
        why="Encoding plus a pipe into an interpreter exists to defeat review and signature-based detection.",
    ),
    RegexRule(
        id="SKV005",
        title="Fetch-and-run third-party code",
        severity=Severity.HIGH,
        category="supply-chain",
        capability="supply-chain",
        pattern=r"(curl|wget)[^|\n]*\|\s*(sudo\s+)?(ba)?sh\b|(pip|pip3|uv pip|poetry)\s+install\s+[^\s]*(https?://|git\+)|(npm|pnpm|yarn)\s+(i|install)\s+https?://|(bash|sh)\s+-c\s+[\"']?\$\(curl|[\"']?(preinstall|postinstall|install)[\"']?\s*[:=]",
        why="Unpinned remote code executed at install time is the standard supply-chain entry point.",
    ),
    RegexRule(
        id="SKV006",
        title="Irreversibly destructive command",
        severity=Severity.CRITICAL,
        category="destructive",
        capability="destructive",
        # Two shapes: rooted deletes (`rm -rf /`, `rm -rf ~`) and deletes aimed at
        # system paths (`rm -rf /tmp/*`), which is not the apocalypse but is still
        # outside anything a skill should touch.
        pattern=r"rm\s+-[a-z]*r[a-z]*f?\s+(\/|\$|~)(\s|$|:)|rm\s+-[a-z]*r[a-z]*f\s+/(tmp|var|etc|home|usr|opt|boot|Users|Windows|System)\b|rm\s+-rf\s+\*|mkfs(\.[a-z0-9]+)?\b|dd\s+if=|:\(\)\s*\{\s*:\|:\s*&\s*\}\s*;|shred\s+-|vssadmin\s+delete\s+shadows|diskpart\s+clean|del\s+/[a-z]*[fs][a-z]*\s+(c|C):\\|cipher\s+/w|wipefs\b|format\s+[a-z]:",
        why="One line here can destroy the machine running the agent; no code helper needs it.",
    ),
    RegexRule(
        id="SKV007",
        title="Persistence or lateral foothold",
        severity=Severity.CRITICAL,
        category="persistence",
        capability="persistence",
        pattern=r"\bcrontab\b|systemctl\s+(enable|daemon-reload)|launchctl\s+load|\.bashrc|\.zshrc|\.profile|authorized_keys|/etc/sudoers|schtasks\s+/create|HKEY_[A-Z_]+\\.*\\Run|Startup\\|Enable-PSRemoting|Set-ItemProperty\s+.*\\Run",
        why="Persisting past the task, or planting keys, turns a one-shot review miss into lasting access.",
    ),
    RegexRule(
        id="SKV008",
        title="Turns off auditing or hides its tracks",
        severity=Severity.HIGH,
        category="obfuscation",
        capability="obfuscation",
        pattern=r"HISTFILE=/dev/null|unset\s+HISTFILE|history\s+-c\b|kill\s+-9\s+\$\$?|Remove-EventLog|wevtutil\s+(cl|clear-log)|--no-verify|GIT_CONFIG_COUNT|Set-MpPreference\s+-DisableRealtimeMonitoring|DisableWindowsOptionalFeature|2>\s*/dev/null\s+&&\s*rm\b",
        why="Nothing benign needs the audit trail off; this is how post-hoc review is defeated.",
    ),
    RegexRule(
        id="SKV009",
        title="Instruction-override or concealment language",
        severity=Severity.CRITICAL,
        category="prompt-injection",
        capability="prompt-injection",
        # Parenthesised alternatives are non-capturing so confusing two of them
        # cannot silently change the hit count.
        pattern=r"(?:(?:ignore|disregard|forget)\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts|rules))"
        r"|(?:do\s+not\s+(?:tell|inform|mention|surface|report)\s+(?:the\s+)?(?:user|human|it|these))"
        r"|(?:never\s+(?:tell|mention|surface|ask|confirm)\b)"
        r"|(?:don'?t\s+(?:ask|confirm|prompt|tell)\b)"
        r"|(?:without\s+(?:asking|telling|confirmation|approval))"
        r"|(?:no\s+(?:confirmation|approval)\s+(?:needed|required))"
        r"|(?:bypass\s+(?:your\s+)?(?:safety|guardrail|restriction))"
        r"|developer\s+mode|\bDAN\b|jailbreak",
        why="This text targets the model rather than the task: it tries to remove the operator from the loop.",
    ),
    RegexRule(
        id="SKV012",
        title="Arbitrary shell execution primitive",
        severity=Severity.MEDIUM,
        category="shell-exec",
        capability="shell-exec",
        pattern=r"\bos\.system\(|subprocess\.(run|Popen|call|check_output)\([^)]*shell\s*=\s*True|subprocess\.(run|Popen)\(\[[^\]]*\b(sudo|su)\b|Invoke-Expression|\biex\b|\beval\s*\(|Runtime\.getRuntime\(\)\.exec|child_process\.exec\(",
        why="Worth listing explicitly: everything a later rule reports becomes reachable through it.",
    ),
    RegexRule(
        id="SKV013",
        title="Writes or reads outside the project directory",
        severity=Severity.MEDIUM,
        category="scope",
        capability="scope",
        pattern=r"(\.\./){2,}|~\/[^s]|%USERPROFILE%\\|/etc/|/usr/|/var/|C:\\\\?(Windows|Users|ProgramData)|/Library/|/System/",
        why="Escaping the working directory breaks the containment assumption the reviewer is relying on.",
    ),
    RegexRule(
        id="SKV014",
        title="Unverifiable authority claim",
        severity=Severity.INFO,
        category="supply-chain",
        capability="supply-chain",
        pattern=r"\b(officially?\s+(verified|certified|approved|published)|verified\s+by\s+(Anthropic|OpenAI|Google|Microsoft)|from\s+the\s+official\s+(team|repo))\b",
        why="Unbacked authority claims are the social half of slopsquatting; check the source yourself.",
    ),
)

RULES_BY_ID = {r.id: r for r in RULES}


def get_rule(rule_id: str) -> Rule:
    return RULES_BY_ID[rule_id.upper()]


def scan_text(text: str, target: Target) -> list[Finding]:
    """Apply the instruction-file rule set to one document."""
    lines = text.splitlines()
    return run_rules(lines, target, RULES)
