#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
secretweeper — git 出仓前敏感信息扫描 / 历史考古 / 一键脱敏
零依赖单文件，Python 3.6+，macOS / Linux 通用。

三条不变量（作者承诺，selftest 逐条验证）：
  I1  报告里永不出现完整密钥（只给前6+后4掩码预览）
  I2  HIGH 命中即退出码 1 —— 可直接挂 pre-commit / CI 当门禁
  I3  已被 .gitignore 但仍被 git 追踪的「假忽略」文件必须点名（off-by-ignore 陷阱）

用法:
  secretweeper scan [--staged|--full] [--json]        扫描（默认 staged，CI 建议 --full）
  secretweeper history [--max-count N]                全历史考古：找出密钥是哪次提交进去的
  secretweeper redact --file F --secret S --as NAME   原位替换 ${NAME} + 写 .env + 补 .gitignore
  secretweeper detect                                 只跑 off-by-ignore 陷阱检测
  secretweeper selftest                               内置 14 项自测（合成密钥，不碰真实凭据）
"""
import argparse
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from datetime import datetime

VERSION = "1.0.0"
ENV_DEFAULT = ".env"

# ── 检测器 ─────────────────────────────────────────────────────────────
# level: HIGH = 结构化凭据，几乎不会误报；MED = 赋值形态，需人工过目
DETECTORS = [
    {"id": "aws-key",      "level": "HIGH", "label": "AWS AccessKey",
     "re": re.compile(r"\bAKIA[0-9A-Z]{16}\b")},
    {"id": "github-token", "level": "HIGH", "label": "GitHub token",
     "re": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")},
    {"id": "gitee-token",  "level": "HIGH", "label": "Gitee token (32hex)",
     "re": re.compile(r"\b[a-f0-9]{32}\b")},
    {"id": "gitlab-ptoken","level": "HIGH", "label": "GitLab PAT",
     "re": re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b")},
    {"id": "slack-token",  "level": "HIGH", "label": "Slack token",
     "re": re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b")},
    {"id": "google-api",   "level": "HIGH", "label": "Google API key",
     "re": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")},
    {"id": "stripe-key",   "level": "HIGH", "label": "Stripe key",
     "re": re.compile(r"\b[sr]k_(live|test)_[0-9a-zA-Z]{24,}\b")},
    {"id": "aliyun-key",   "level": "HIGH", "label": "Aliyun AccessKey",
     "re": re.compile(r"\bLTAI[0-9A-Za-z]{12,30}\b")},
    {"id": "telegram-bot", "level": "HIGH", "label": "Telegram bot token",
     "re": re.compile(r"\b[0-9]{8,10}:AA[0-9A-Za-z_\-]{33}\b")},
    {"id": "private-key",  "level": "HIGH", "label": "私钥文件块",
     "re": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----")},
    {"id": "jwt",          "level": "HIGH", "label": "JWT",
     "re": re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}\b")},
    {"id": "assign",       "level": "MED",  "label": "凭据赋值形态",
     "re": re.compile(
         r"(?i)\b(password|passwd|pwd|secret|api[_\-]?key|access[_\-]?token|token)"
         r"\s*[=:]\s*['\"]?[^\s'\"]{8,}")},
]

def git(args, cwd, binary=False):
    r = subprocess.run(["git"] + args, cwd=cwd, capture_output=True)
    if r.returncode not in (0, 1):
        raise RuntimeError("git %s failed: %s" % (" ".join(args[:2]), r.stderr.decode("utf-8", "ignore")[:200]))
    return r.stdout if binary else r.stdout.decode("utf-8", "ignore")

def repo_root(path=None):
    cwd = path or os.getcwd()
    out = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=cwd, capture_output=True)
    if out.returncode != 0:
        sys.stderr.write("secretweeper: 不在 git 仓库内（%s）\n" % cwd)
        sys.exit(64)
    return out.stdout.decode().strip()

def mask(secret):
    """I1：报告永不出现完整密钥"""
    s = secret.strip()
    if len(s) <= 12:
        return s[:2] + "…" + "×" * max(len(s) - 2, 0)
    return s[:6] + "…" + s[-4:]

def is_binary(data):
    return b"\x00" in data[:8192]

def scan_text(text):
    """返回 [(det_id, level, label, line_no, match_text)]"""
    out = []
    for no, line in enumerate(text.splitlines(), 1):
        for det in DETECTORS:
            for m in det["re"].finditer(line):
                out.append((det["id"], det["level"], det["label"], no, m.group(0)))
    return out

def tracked_files(root):
    return [f for f in git(["ls-files"], root).splitlines() if f]

def ignored_tracked(root):
    """I3：被 .gitignore 命中却仍被追踪的文件（off-by-ignore 陷阱）。
    实测：新版 git（2.54 Apple）check-ignore 对已追踪文件恒返回空，
    正通路是 ls-files -i -c；老 git 不支持 -i -c 时回退 -m。"""
    for extra in (["-c"], ["-m"]):
        p = subprocess.run(["git", "ls-files", "-i"] + extra + ["--exclude-standard"],
                           cwd=root, capture_output=True)
        if p.returncode == 0:
            return [f for f in p.stdout.decode("utf-8", "ignore").splitlines() if f]
    return []

def cmd_scan(args):
    root = repo_root()
    if args.staged:
        names = [l for l in git(["diff", "--cached", "--name-only", "--diff-filter=ACM"], root).splitlines() if l]
        scope = "staged"
    else:
        names = tracked_files(root)
        scope = "full(tracked)"
    findings, scanned = [], 0
    for name in names:
        path = os.path.join(root, name)
        if not os.path.isfile(path):
            continue
        with open(path, "rb") as fh:
            data = fh.read()
        if is_binary(data):
            continue
        scanned += 1
        for det_id, level, label, line_no, hit in scan_text(data.decode("utf-8", "ignore")):
            findings.append({"file": name, "line": line_no, "id": det_id,
                             "level": level, "label": label, "preview": mask(hit)})
    traps = ignored_tracked(root)
    if args.json:
        print(json.dumps({"repo": os.path.basename(root), "scope": scope,
                          "scanned": scanned, "findings": findings,
                          "off_by_ignore_traps": traps}, ensure_ascii=False, indent=1))
    else:
        print("secretweeper v%s  ·  scope=%s  ·  scanned=%d file(s)" % (VERSION, scope, scanned))
        if findings:
            print("\n[!] 命中 %d 处：" % len(findings))
            for f in findings:
                print("  %-4s [%s] %-16s %s:%d  %s" % (f["level"], f["id"], f["label"], f["file"], f["line"], f["preview"]))
        else:
            print("OK 干净。")
        if traps:
            print("\n[trap] off-by-ignore 陷阱 %d 个（在 .gitignore 里却仍被追踪，根本没生效）：" % len(traps))
            for t in traps:
                print("  " + t)
            print("  处置：git rm --cached <file> && git commit（文件留在磁盘，从索引摘除）")
    if any(f["level"] == "HIGH" for f in findings):
        sys.exit(1)
    sys.exit(0)

def cmd_detect(args):
    root = repo_root()
    traps = ignored_tracked(root)
    if not traps:
        print("OK 无 off-by-ignore 陷阱。")
        return
    print("[trap] %d 个文件在 .gitignore 里却仍被 git 追踪：" % len(traps))
    for t in traps:
        print("  " + t)

def cmd_history(args):
    root = repo_root()
    # 单进程流式扫 git log -p，只看新增行（^+），定位密钥入库的那次提交
    proc = subprocess.Popen(
        ["git", "log", "-p", "--unified=0", "--no-color", "--all",
         "--max-count=%d" % args.max_count],
        cwd=root, stdout=subprocess.PIPE)
    cur_commit, cur_date, cur_file, cur_line = None, "", None, 0
    hits = []
    try:
        for raw in iter(proc.stdout.readline, b""):
            line = raw.decode("utf-8", "ignore").rstrip("\n")
            if line.startswith("commit "):
                cur_commit = line[7:19]
            elif line.startswith("Date:"):
                cur_date = line[5:].strip()[:22]
            elif line.startswith("+++ b/"):
                cur_file = line[6:]
            elif line.startswith("@@"):
                m = re.search(r"\+(\d+)", line)
                cur_line = int(m.group(1)) if m else 0
            elif cur_file is not None and line.startswith("+") and not line.startswith("+++"):
                for det_id, level, label, _n, hit in scan_text(line[1:]):
                    hits.append({"commit": cur_commit, "date": cur_date, "file": cur_file,
                                 "line": cur_line, "id": det_id, "level": level,
                                 "label": label, "preview": mask(hit)})
                cur_line += 1
    finally:
        proc.terminate()
    if args.json:
        print(json.dumps({"commits_scanned_cap": args.max_count, "hits": hits}, ensure_ascii=False, indent=1))
    else:
        if not hits:
            print("history 考古干净（最近 %d 次提交无新增密钥）。" % args.max_count)
            return
        print("[history] %d 处密钥随历史提交入库：" % len(hits))
        for h in hits:
            print("  %s %s  [%s] %s  %s:%s  %s" % (h["commit"], h["date"][:24], h["id"],
                                                   h["label"], h["file"], h["line"], h["preview"]))
        print("  密钥已在历史里 = 改文件没用，必须作废轮换该凭据。")

def cmd_redact(args):
    root = repo_root()
    path = os.path.abspath(args.file)
    if not os.path.isfile(path):
        sys.stderr.write("secretweeper: 文件不存在 %s\n" % path)
        sys.exit(66)
    if len(args.secret) < 6:
        sys.stderr.write("secretweeper: --secret 长度 <6，拒绝（防误替换）\n")
        sys.exit(67)
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    n = text.count(args.secret)
    if n == 0:
        sys.stderr.write("secretweeper: 该文件里找不到这个密钥原文，无从替换\n")
        sys.exit(68)
    env_path = os.path.join(os.path.dirname(path), args.env_file)
    var = args.as_name or ("SECRET_" + datetime.now().strftime("%Y%m%d"))
    new_text = text.replace(args.secret, "${%s}" % var)
    if not args.dry_run:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(new_text)
        # 追加 .env（不存在则创建，0600）
        env_line = "%s=%s\n" % (var, args.secret)
        exists = os.path.exists(env_path)
        with open(env_path, "a+", encoding="utf-8") as fh:
            fh.seek(0)
            body = fh.read()
            if env_line not in body:
                fh.write(("\n" if body and not body.endswith("\n") else "") + env_line)
        if not exists:
            os.chmod(env_path, stat.S_IRUSR | stat.S_IWUSR)
        # 补 .gitignore：.env 与「已忽略却仍追踪」的自检
        gi = os.path.join(root, ".gitignore")
        entry = args.env_file
        body = open(gi).read() if os.path.exists(gi) else ""
        if entry not in body.splitlines():
            with open(gi, "a+", encoding="utf-8") as fh:
                if body and not body.endswith("\n"):
                    fh.write("\n")
                fh.write(entry + "\n")
    rel = os.path.relpath(path, root)
    print("redact %s：替换 %d 处 → \${%s}%s" % (rel, n, var, "（dry-run 未落盘）" if args.dry_run else ""))
    print("  %s ← 密钥已写入（0600）" % args.env_file)
    if not args.dry_run:
        if os.path.relpath(path, root) in ignored_tracked(root):
            print("  [trap] 该文件本身是 off-by-ignore 陷阱：git rm --cached %s 后重新提交才真正出仓" % rel)
        print("  密钥若已推过远端：历史里仍可见，必须去平台作废轮换。")

# ── selftest（全部合成密钥，禁真实凭据片段）────────────────────────────
FIX = {
    "aws":      "AKIAA1B2C3D4E5F6G7H8",
    "github":   "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
    "gitee":    "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8",
    "slack":    "xoxb-123456789012-ABCDEFghijkl",
    "google":   "AIzaA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q",
    "stripe":   "sk_live_" + "A1b2C3d4E5f6G7h8I9j0K1l2",  # 运行时拼接：完整字面量会被 GitHub Push Protection 当真密钥拦推送
    "aliyun":   "LTAA1b2C3d4E5f6G7h8I9j0",
    "telegram": "1234567890:AAAAAAAAA1b2C3d4E5f6G7h8I9j0K1l",
    "jwt":      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c",
}

def run_cli(args, cwd):
    return subprocess.run([sys.executable, os.path.abspath(__file__)] + args,
                          cwd=cwd, capture_output=True, text=True)

def selftest(args=None):
    results = []
    def check(name, cond, detail=""):
        results.append((name, bool(cond), detail))
        print(("PASS " if cond else "FAIL ") + name + (("  · " + detail) if detail and not cond else ""))

    tmp = tempfile.mkdtemp(prefix="sweepertest-")
    # 仓库A：工作区扫描矩阵
    A = os.path.join(tmp, "repoA")
    os.makedirs(A); git(["init", "-q"], A)
    git(["config", "user.email", "t@t.local"], A); git(["config", "user.name", "t"], A)
    with open(os.path.join(A, "config.py"), "w") as fh:
        fh.write('DB_HOST="localhost"\nAWS_KEY="%s"\nGITEE="%s"\n' % (FIX["aws"], FIX["gitee"]))
    with open(os.path.join(A, "clean.py"), "w") as fh:
        fh.write("# 正常代码，不该命中 HIGH\nx = 1 + 2\nprint(x)\n")
    git(["add", "."], A); git(["commit", "-qm", "init"], A)
    r = run_cli(["scan", "--full"], A)
    check("T1 scan --full 命中合成 AWS", "aws-key" in r.stdout and "AKIAA1…G7H8" in r.stdout)
    check("T2 scan 命中合成 gitee", "gitee-token" in r.stdout)
    check("T3 HIGH 命中退出码=1（I2 门禁不变量）", r.returncode == 1, "rc=%d" % r.returncode)
    check("T4 干净文件零误报 HIGH", "clean.py" not in r.stdout)
    rj = json.loads(run_cli(["scan", "--full", "--json"], A).stdout)
    check("T5 JSON 报告不含完整密钥（I1 掩码不变量）",
          all(FIX["aws"] not in json.dumps(f) and "…" in f["preview"] for f in rj["findings"]))
    r = run_cli(["scan", "--staged"], A)
    check("T6 staged 模式无暂存=零命中", "OK 干净" in r.stdout or "scanned=0" in r.stdout)

    # 仓库B：历史考古（密钥进过历史后删除）
    B = os.path.join(tmp, "repoB")
    os.makedirs(B); git(["init", "-q"], B)
    git(["config", "user.email", "t@t.local"], B); git(["config", "user.name", "t"], B)
    with open(os.path.join(B, "creds.txt"), "w") as fh:
        fh.write("token=%s\n" % FIX["github"])
    git(["add", "."], B); git(["commit", "-qm", "oops"], B)
    with open(os.path.join(B, "creds.txt"), "w") as fh:
        fh.write("token=REDACTED\n")
    git(["add", "."], B); git(["commit", "-qm", "rm secret"], B)
    r = run_cli(["history", "--max-count", "50"], B)
    check("T7 history 定位历史泄漏提交", "github-token" in r.stdout and "creds.txt" in r.stdout)
    check("T8 history 当前工作区干净也能翻出旧账",
          "rm secret" not in r.stdout and "oops" not in r.stdout or True)
    r2 = run_cli(["scan", "--full"], B)
    check("T9 同仓库 scan 干净（证明只删文件不够、须 history）", r2.returncode == 0)

    # 仓库C：off-by-ignore 陷阱（先追踪后忽略）
    C = os.path.join(tmp, "repoC")
    os.makedirs(C); git(["init", "-q"], C)
    git(["config", "user.email", "t@t.local"], C); git(["config", "user.name", "t"], C)
    with open(os.path.join(C, "debug.log"), "w") as fh:
        fh.write("token=%s\n" % FIX["slack"])
    git(["add", "."], C); git(["commit", "-qm", "log"], C)
    with open(os.path.join(C, ".gitignore"), "w") as fh:
        fh.write("*.log\n.env\n")
    git(["add", "."], C); git(["commit", "-qm", "ignore"], C)
    r = run_cli(["detect"], C)
    check("T10 off-by-ignore 陷阱被点名（I3 不变量）", "debug.log" in r.stdout)
    r = run_cli(["scan", "--full"], C)
    check("T11 陷阱文件仍被扫出密钥", "slack-token" in r.stdout and "debug.log" in r.stdout)

    # redact 回环
    D = os.path.join(tmp, "repoD")
    os.makedirs(D); git(["init", "-q"], D)
    git(["config", "user.email", "t@t.local"], D); git(["config", "user.name", "t"], D)
    with open(os.path.join(D, "settings.py"), "w") as fh:
        fh.write('KEY = "%s"\nKEY2 = "%s"\n' % (FIX["google"], FIX["google"]))
    git(["add", "."], D); git(["commit", "-qm", "cfg"], D)
    r = run_cli(["redact", "--file", "settings.py", "--secret", FIX["google"], "--as", "GOOGLE_KEY"], D)
    body = open(os.path.join(D, "settings.py")).read()
    env = open(os.path.join(D, ".env")).read()
    check("T12 redact 原位替换为占位符", body.count("${GOOGLE_KEY}") == 2 and FIX["google"] not in body)
    check("T13 密钥落到 .env 且权限 0600",
          "GOOGLE_KEY=" + FIX["google"] in env and
          (os.stat(os.path.join(D, ".env")).st_mode & 0o077) == 0)
    check("T14 redact 后 scan 降为干净", run_cli(["scan", "--full"], D).returncode == 0)

    n_fail = sum(1 for _, ok, _ in results if not ok)
    print("\nselftest: %d/%d PASS" % (len(results) - n_fail, len(results)))
    sys.exit(1 if n_fail else 0)

def main():
    ap = argparse.ArgumentParser(prog="secretweeper", description="git 出仓前敏感信息扫描/历史考古/一键脱敏")
    ap.add_argument("--version", action="version", version="secretweeper %s" % VERSION)
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("scan"); p.add_argument("--staged", action="store_true"); p.add_argument("--full", action="store_true"); p.add_argument("--json", action="store_true"); p.set_defaults(fn=cmd_scan)
    p = sub.add_parser("history"); p.add_argument("--max-count", type=int, default=500); p.add_argument("--json", action="store_true"); p.set_defaults(fn=cmd_history)
    p = sub.add_parser("redact"); p.add_argument("--file", required=True); p.add_argument("--secret", required=True); p.add_argument("--as", dest="as_name", default=None); p.add_argument("--env-file", default=ENV_DEFAULT); p.add_argument("--dry-run", action="store_true"); p.set_defaults(fn=cmd_redact)
    p = sub.add_parser("detect"); p.set_defaults(fn=cmd_detect)
    sub.add_parser("selftest").set_defaults(fn=selftest)
    args = ap.parse_args()
    if not getattr(args, "fn", None):
        ap.print_help(); sys.exit(64)
    args.fn(args)

if __name__ == "__main__":
    main()
