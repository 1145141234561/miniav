# MiniAV — 教学级离线恶意软件检测器

面向网络安全教学的 Windows 离线扫描器：特征库 + YARA 规则 + 行为启发式 + 脚本解混淆，全部本地运行、零联网、**绝不执行样本**。

## 特性

- **三层签名架构**：哈希（md5/sha1/sha256）/ 模式（regex·hex）/ 行为组合
- **YARA 引擎**：13 组规则文件，含上游 [YARA-Rules/rules](https://github.com/Yara-Rules/rules) 合并的 11,675 条公开规则（已完成识别型规则误报剔除与跨文件依赖修复）
- **脚本解混淆**：多层解码候选（UTF-8/GBK/UTF-16 探测、gbk-replace 兜底、整体/行字符反转还原），还原文本自动复扫
- **PyInstaller 静态解析**：CArchive TOC 解析 + 内嵌 PE 载荷启发（覆盖银狐 onefile 投递链）
- **快速分诊**：`triage` 一键完成 解包 → 内存读取（抗 Defender 删除竞态）→ 行为串分类 → IOC 提取
- **质量保障**：34 组 selftest + 19 项离线 E2E，新功能必须带测试用例

## 使用

### 发行包

下载 `MiniAV-Pack.zip` 解压后运行 `MiniAV.exe`（签名库与规则外置于同级目录，可热更新，无需重打包）。

### 源码运行（Python 3.14+）

```bash
python -m miniantivirus scan <文件或目录> [--report 报告.html] [--quarantine] [--jobs N]
python -m miniantivirus watch <目录>          # 准实时监视扫描
python -m miniantivirus analyze <样本>        # 深度静态体检（不执行）
python -m miniantivirus.triage <样本>         # 快速分诊 + JSON 报告
python -m miniantivirus.selftest              # 全量自检
```

## 目录结构

```
miniantivirus/   源码（scanner / cli / deobf / triage / pyinst / sandbox / memscan ...）
rules/           YARA 规则（silverfox·worms 自有规则 + external_* 上游合并）
docs/            检测规则设计文档
signatures.json  特征库
```

## 安全说明

- 本仓库**不含任何真实恶意样本**：`samples/`、`quarantine/`、构建产物与签名证书均在 `.gitignore` 中排除
- 规则与 IOC 来自公开威胁情报（如 CNCERT 专项通报、Cisco Talos 报告）或人工编写，仅用于检测
- 严禁将本项目用于任何违法用途；仅供安全研究与教学

## 许可

Apache-2.0（见 [LICENSE](LICENSE)）。其中 `rules/external_*.yar` 派生自 [YARA-Rules/rules](https://github.com/YARA-Rules/rules)（Apache-2.0）。
