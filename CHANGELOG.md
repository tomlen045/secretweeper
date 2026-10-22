# Changelog

## 1.0.0 (2026-10-22)

- 首版发布。
- scan：staged / full 双模式，12 类检测器（HIGH/MED 两级），HIGH 命中退出码 1。
- history：流式扫 git log -p 新增行，定位密钥入库提交。
- redact：原位替换 ${VAR} + .env(0600) + 自动补 .gitignore。
- detect：off-by-ignore 陷阱检测（ls-files -i 正通路，兼容老 git 回退）。
- selftest：14 项内置自测，全合成密钥（不碰真实凭据）。
