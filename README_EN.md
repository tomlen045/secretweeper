# 🧹 secretweeper

> **The last security gate before your code leaves the machine.** Scan, archaeology, redact — one file, zero dependencies, results in 3 seconds.

[简体中文](README.md) | English

```bash
curl -fsSL https://gcore.jsdelivr.net/gh/tomlen045/secretweeper@main/secretweeper.py -o secretweeper.py
python3 secretweeper.py selftest   # 14/14 PASS before you trust it
```

**One Python file (~360 lines). No pip install. macOS / Linux.**

## Why

Every developer has done this: hardcode a key, add a `.gitignore` line, commit, push — **and only then remember the file was already tracked**.

`.gitignore` only blocks untracked files. Anything already in the index sails through, ignore rule or not. That's the off-by-ignore trap: you think you're covered; you just feel covered.

Worse is history: once a key lands in a commit, `git rm` doesn't save you. It stays in history for anyone who clones. The only correct fix is revoking the credential — but first you need to know which commit let it in.

secretweeper turns all three jobs into one command:

| Command | What it does |
|---|---|
| `scan` | Scan the worktree (staged / full). HIGH findings exit 1. |
| `history` | Walk every commit and pin down the one that leaked the key. |
| `redact` | Replace in place with `${VAR}`; the secret lands in a 0600 `.env`. |
| `detect` | Off-by-ignore traps: ignored-but-tracked files. |

## Three invariants

1. **Reports never contain a full secret** — only `first6…last4` masks. Safe to screenshot into a group chat.
2. **HIGH finding = exit code 1** — drop it into pre-commit / CI as a gate, no wrapper needed.
3. **Fake ignores get named** — files matched by `.gitignore` yet still tracked are called out.

## Detectors

12 detector families, HIGH/MED levels:

- **HIGH (structured credentials, near-zero false positives)**: AWS `AKIA*`, GitHub `ghp_/gho_/ghu_/ghs_/ghr_`, Gitee 32-hex, GitLab `glpat-`, Slack `xox*-`, Google `AIza*`, Stripe `sk_live_*`, Aliyun `LTAI*`, Telegram bot tokens, private key blocks, JWTs
- **MED (assignment shapes, human review)**: `password=...`, `api_key: ...` lines

## Verified

```text
$ secretweeper scan --full
secretweeper v1.0.0  ·  scope=full(tracked)  ·  scanned=31 file(s)

[!] 命中 1 处：
  HIGH [github-token] GitHub token  deploy_creds.sh:2  ghp_A1…Q7r8
$ echo $?
1
```

Skewed-reality demo: a 31-file mock repo (30 clean + 1 seeded key) — only the guilty file is named, zero false positives. 14 built-in self-tests pass. A key committed then deleted is still dug up by `history`.

## pre-commit in 10 seconds

```bash
# .git/hooks/pre-commit
#!/bin/sh
python3 /path/to/secretweeper.py scan --staged
```

HIGH finding → commit blocked. In CI, use `scan --full`.

## Redact loop

```bash
$ secretweeper redact --file settings.py --secret $K --as GOOGLE_KEY
redact settings.py：替换 2 处 → ${GOOGLE_KEY}
  .env ← 密钥已写入（0600）
```

**The last step is yours**: if the key ever reached a remote, it lives in history forever — revoke and rotate it on the platform. The tool prints this reminder for a reason.

## Honest limitations

- Single-file regex scanning: gitleaks/trufflehog beat it on coverage and audit features. For big teams and compliance, use the heavy tools. secretweeper is the personal / small-team last gate.
- `history` streams `git log -p` in one process; for 10k+ commit repos use `--max-count` to chunk it.
- redact only edits the worktree. History rewriting (filter-repo/BFG) is a different job — but `history` tells you whether you need it.

## License

MIT
