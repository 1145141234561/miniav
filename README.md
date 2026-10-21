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
python -m miniantivirus test              # 全量自检
```

## 联网扫描配置（其他设备启用）

`vt` / `--vt` 联网信誉查询开箱即用零配置（离线功能不受影响）。要在**其他设备**启用在线多引擎查询，按以下步骤配置：

### 第 1 步：注册 VirusTotal 并获取 API Key

1. 打开 [https://www.virustotal.com](https://www.virustotal.com)，点击右上角 **Sign up** 免费注册（邮箱即可）
2. 登录后点击右上角**头像 → API key**，页面显示的那串 64 位十六进制字符就是你的 Key
3. 免费配额：**4 次/分钟、500 次/天**（本程序已内置 15 秒最小间隔 + 7 天本地缓存兜底）

### 第 2 步：把 Key 配置到 MiniAV（二选一）

**方式 A：便携配置文件（推荐）**

先随便跑一次联网命令（如 `MiniAV.exe scan 某文件 --vt`），程序会在 **exe 同目录**自动生成 `vt_config.json` 模板（源码运行则在项目根目录），用记事本打开填入两个字段：

```json
{
  "api_key": "第 1 步拿到的 64 位 Key",
  "proxy": "http://127.0.0.1:7890"
}
```

- `api_key`：必填，你的 VirusTotal Key
- `proxy`：**国内网络通常必须填**（virustotal.com 在大陆被墙，需指向本机代理软件的 HTTP 端口，Clash 默认 `http://127.0.0.1:7890`、v2rayN 默认 `http://127.0.0.1:10809`）；海外设备留空 `""`

**方式 B：环境变量**

```
setx VT_API_KEY "你的64位Key"
```

（重开终端生效；优先级高于配置文件。代理仍建议在 `vt_config.json` 里配。）

### 第 3 步：验证

```
MiniAV.exe vt C:\Windows\System32\notepad.exe
```

输出 `harmless: xx / malicious: 0` 之类统计即配置成功；报「未配置联网扫描」说明 Key 没填对，报「VT 网络错误」说明代理没配对。

> Key 请妥善保管：它等同你的 VT 账号身份，不要提交到公开仓库或发给他人。上传扫描（`--upload`）会把文件公开共享给 VT 多引擎，上限 32MB，涉密样本勿传。

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
