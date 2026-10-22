# 🧹 secretweeper

> **git 出仓前的最后一道安检。** 扫描、考古、脱敏——单文件，零依赖，3 秒出结果。

简体中文 | [English](README_EN.md)

```bash
curl -fsSL https://gcore.jsdelivr.net/gh/tomlen045/secretweeper@main/secretweeper.py -o secretweeper.py
python3 secretweeper.py selftest   # 14/14 PASS 再用
```

**一个 Python 文件（约 360 行），无 pip install，macOS / Linux 通用。**

## 为什么

每个开发者都见过这一幕：密钥写死在代码里，`.gitignore` 里补了一行，提交、推送——**然后才想起来那个文件早就被追踪了**。

`.gitignore` 只拦「未追踪」的文件。已经进了索引的，写不写忽略规则都照常入库。这就是 off-by-ignore 陷阱：你以为防住了，其实只是求了个心安。

更糟的是历史：密钥进过一次提交，`git rm` 之后它还在历史里躺着，谁 clone 仓库谁翻得到。唯一正确的处置是作废轮换——但前提是，你得先知道它是什么时候进去的。

secretweeper 把这三件事做成一条命令：

| 命令 | 干什么 |
|---|---|
| `scan` | 扫工作区（staged / full 两档），HIGH 命中退出码 1 |
| `history` | 翻全部提交历史，定位密钥是哪次提交进去的 |
| `redact` | 原位替换成 `${VAR}` 占位符，密钥落进 0600 的 `.env` |
| `detect` | 专查 off-by-ignore 陷阱：在忽略名单里却仍被追踪的文件 |

## 三条不变量

工具自己也是代码，代码要有承诺。selftest 逐条验证：

1. **报告永不出现完整密钥** —— 只给「前 6 位…后 4 位」掩码。截图发群里也不漏。
2. **HIGH 命中即退出码 1** —— 直接挂 pre-commit / CI 当门禁，不需要包装脚本。
3. **假忽略必被点名** —— 被 `.gitignore` 命中却仍被追踪的文件，单独列出来打脸。

## 认什么

12 类检测器，HIGH/MED 两级：

- **HIGH（结构化凭据，几乎不误报）**：AWS `AKIA*`、GitHub `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`、Gitee 32hex、GitLab `glpat-`、Slack `xox*-`、Google `AIza*`、Stripe `sk_live_*`、阿里云 `LTAI*`、Telegram bot token、私钥文件块、JWT
- **MED（赋值形态，需人工过目）**：`password=...`、`api_key: ...` 这类凭据赋值行

## 实测

```text
$ secretweeper scan --full
secretweeper v1.0.0  ·  scope=full(tracked)  ·  scanned=31 file(s)

[!] 命中 1 处：
  HIGH [github-token] GitHub token  deploy_creds.sh:2  ghp_A1…Q7r8
$ echo $?
1
```

偏态实战：31 个文件的模拟仓库（30 个干净 + 1 个埋密钥），只点名真凶，零误报；14 项内置自测全绿；密钥进过历史再删掉，`history` 照样把那笔旧账翻出来。

## 挂 pre-commit（10 秒）

```bash
# .git/hooks/pre-commit
#!/bin/sh
python3 /path/to/secretweeper.py scan --staged
```

HIGH 命中 → 提交被拦。CI 里换 `scan --full`，全仓扫描。

## 脱敏闭环

```bash
$ secretweeper redact --file settings.py --secret $K --as GOOGLE_KEY
redact settings.py：替换 2 处 → ${GOOGLE_KEY}
  .env ← 密钥已写入（0600）
```

代码里只剩 `${GOOGLE_KEY}` 占位符，真值进 `.env`（自动 0600、自动补 .gitignore）。

**最后一步只能你来**：密钥推过远端，历史里就永远有它——去平台作废轮换，没有别的路。工具会把这句话打进输出里提醒你。

## 坑位声明（说点不中听的）

- 单文件正则方案，误报率与覆盖面天然不如 gitleaks/trufflehog。 **大团队、要审计合规的，请直接上重型方案**，secretweeper 的定位是「个人与小组的出仓前最后一道土安检」。
- `history` 是单进程流式扫 `git log -p`，万级提交的大仓库建议配 `--max-count` 分段跑。
- redact 只改工作区。历史重写（filter-repo/BFG）是另一个专业活，本工具不碰——但 `history` 会告诉你需不需要碰。

## License

MIT
