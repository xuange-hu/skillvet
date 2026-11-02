# Security policy

## Scope

**skillvet** — Agent skill package and MCP configuration audit — is a static analysis tool: it reads **skill directories (`SKILL.md`, scripts) and MCP client configuration files** and prints a report.
The security questions that apply to it are the ones that apply to any tool
that parses untrusted input.

Supported: the current release.

## What this tool does with your files

Nothing leaves your machine. There is no network client in the scanning path:
the tool opens the files you point it at, parses them, and writes a report.
It never writes to the files it reads.

## Reporting a vulnerability in skillvet

Use [GitHub private vulnerability reporting](https://github.com/xuange-hu/skillvet/security/advisories)
on the Security tab. If private reporting is unavailable to you, open an issue
marked `security`.

Include:

1. the version (`skillvet --version`);
2. the input that triggers it — the actual file is preferred over a description;
3. what you expected and what happened.

For a parse failure, the smallest input that reproduces it is the whole report.

## What counts as a vulnerability here

- **A Unicode attack that is not detected.** Trojan Source (bidi overrides) and zero-width characters in a `SKILL.md` are the reason this tool exists; a gap here is a real gap in the user's defences.
- **A dangerous capability that reads as safe.** A skill that reaches the network or a shell must not be graded as inert.
- **A path that escapes the directory it was pointed at** — skills are third-party input.
- **A crash on malformed front matter or a broken symlink.**

## What does not count

- A rule firing on input you consider correct. That is a false positive: open
  an issue with the sample and it gets a regression test.
- A rule you want added. Open an issue or a PR.

## Timing

I triage within a week and will confirm receipt. If a fix needs to sit in a
branch for a while, the advisory goes out when the fix lands, not before.
