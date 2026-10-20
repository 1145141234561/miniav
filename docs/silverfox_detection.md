# 银狐（Silver Fox）家族多态变种检测——集成文档

> 适用版本：MiniAV 2026-10（含 YARA 规则层 / 特征包 / 行为链三层架构）
> 规则文件：`rules/silverfox.yar`（字面层 5 条 + 泛化层 5 条）
> 红线约束：全流程仅静态分析，绝不执行任何可疑样本。

## 1. 检测体系架构

MiniAV 对银狐的检测由三层构成，各层针对不同"替换成本"的攻击者资产：

```
┌─────────────────────────────────────────────────────────────┐
│  第一层  字面特征（快速召回）                                   │
│  哈希签名（signatures.json，39 条）· 具体域名/C2/组件名 YARA 串  │
│  覆盖：已知样本秒杀。变种重编译即失效 —— 只做召回不做依赖。        │
├─────────────────────────────────────────────────────────────┤
│  第二层  泛化特征（多态对抗核心）                                │
│  rules/silverfox.yar "多态泛化层" 5 条：                        │
│   SpoofInstaller_Gen  生成器厂商属性（PE 或 MSI OLE 双门）      │
│   ThreadCtx_Inject    线程上下文注入 API 四件套（功能结构锚）    │
│   OSS_C2_Gen          OSS 托管 + 投递路径双锚                  │
│   AweSun_Abuse        远控品牌串 与 执行编排代码同体             │
│   StageDrop_Public    公共目录投递 + 随机名正则/持久化动词       │
│  覆盖：仿冒目标/bucket/随机名轮换后仍命中。                      │
├─────────────────────────────────────────────────────────────┤
│  第三层  行为与结构（字节可变层兜底）                            │
│  pe_heuristics（注入 API 三分类/RWX/熵）· deobf 解混淆 ·        │
│  emu Unicorn 模拟 · sandbox 行为链（SBX-Defender-Exclusion、    │
│  SBX-Fox-* 组合）· autolearn 自动特征学习                        │
└─────────────────────────────────────────────────────────────┘
```

## 2. 平台集成点（零代码改动，自动生效）

`rules/` 目录是唯一的规则源，全链路自动收集：

| 环节 | 机制 | 说明 |
|---|---|---|
| 规则编译 | `scanner.ScanContext.get_rules()` | 按路径惰性编译 `rules/*.yar`，多进程每子进程独立编译（YARA Rules 不可 pickle） |
| 离线特征包 | `pack.py` 自动收集 `rules/*.yar|.yara` | 条目 ≤64、解压预算 16MB；`pack export` 即含 silverfox.yar |
| 离线扫描 | `offline <path> --pack ZIP` | cli.py 解包规则到临时目录喂 ScanContext |
| 常驻防护 | `watch` / `scan` | 同一 ScanContext，规则自动生效 |
| 恶意判定闭环 | `analyze --learn` | 判恶意样本经 autolearn 自动入库哈希+YARA，纳入下次特征包导出 |
| GUI 双入口 | 图形界面扫描/分析 | 与 CLI 共用签名库与规则目录 |

**新增/修改规则后唯一必做动作：重新导出特征包并同步到部署端**
（frozen 版另需重打包 exe 才能带上新的规则文件，见 §5）。

## 3. 针对多态变种的自动化检测流程

```
新样本/可疑文件进入
        │
        ▼
① 静态提取（不执行）：哈希/PE 结构/导入表/字符串/PyInstaller TOC/hex blob
        │
        ▼
② 三层并行判定
   ├─ 字面层：哈希+具体串 → 命中即高置信报告
   ├─ 泛化层：silverfox.yar 泛化 5 条 → 仿冒安装器/注入器/投递链检出
   └─ 行为层：deobf→emu→sandbox 行为链 → 关闭 Defender/加排除项/公共目录投递
        │
        ▼
③ 综合评分（analyzer）≥4 判恶意
        │
        ├── 判恶意 → ④ autolearn 自动学习：
        │     哈希（md5/sha1/sha256）+ 高置信 YARA 规则试编译后入库
        │     行为谱（behaviors 段）合并进家族指纹
        │
        └── 仅泛化层命中（可疑）→ 人工研判 → 确认后补字面 IOC 或调整泛化规则
        │
        ▼
⑤ 回归验证：selftest（test 子命令）+ test_offline.ps1（19 断言 E2E）
        │
        ▼
⑥ 发布：pack export 新特征包 → 同步部署端（frozen 版重打包+签名+Copy 特征）
```

关键设计：**变种对抗的本质是把"每次都变"的字段正则化/下沉行为层，
锚定攻击者不肯改的东西**（生成器指纹、功能性 API 组合、架构性模式）。

## 4. 验证记录（2026-10-20）

- 规则编译：`silverfox.yar` 10 条全过试编译（yara-python 4.x）
- 探针矩阵 7/7：MSI 仿冒属性探针、OSS C2 投递探针、远控滥用探针命中；
  合法远控本体、正常 PyInstaller 程序、分析报告文本均零误报
- 真实样本：`samples/silverfox6/5/ProgramPolicy.exe`（23MB 线程上下文注入器）
  精确命中 `SilverFox_ThreadCtx_Inject`
- 特征包：`pack export` 含 silverfox.yar（9 规则文件 / 39 哈希 / 3 模式）
- E2E：`offline samples/silverfox6 --pack` 全目录扫描通过（见 §6 命令）

## 5. 部署与更新流程

源码模式（开发/研究环境）：

```powershell
python -m miniantivirus pack export C:\path\to\silverfox_pack.zip
python -m miniantivirus offline samples\silverfox6 --pack silverfox_pack.zip --report report.html
# 检出返回码 1，清洁返回 0
```

frozen 版（分发环境）：

```powershell
pyinstaller MiniAV.spec --noconfirm          # 日志出现 Build complete! 即有效
Set-AuthenticodeSignature dist\MiniAV.exe -Certificate (Get-PfxCertificate .\MiniAVSigning.pfx) `
    -TimestampServer http://timestamp.digicert.com
Copy-Item signatures.json dist\
Copy-Item rules\*.yar dist\rules\
```

## 6. 新增规则纪律（防误报与防自匹配）

1. 门控前置：PE 用 `uint16(0)==0x5A4D`，MSI 用 `uint32(0)==0xE011CFD0`；
   无门规则只允许出现在高置信 IOC（如组件名）场景
2. 字符串断字：家族串用 `\s*` / `[_\s]{0,2}` 连接（如 `gh0st[_\s]{0,2}rat`），
   防规则源码被自身规则匹配
3. YARA 4.x 语法限制：无非捕获组 `(?:...)`（用捕获组替代）；修饰符跟在字符串定义处
4. 组合条件控制误报：多锚 `2 of` / 双锚与条件；密度门防结构性命中
   （参考 Evasion_UUID_Shellcode 的 `#uuid*1024 > filesize` 修复）
5. 高置信原则：截断哈希、1 字节常量哈希不入库；不确定的字符串宁可不加
6. 每条新规则必须：试编译 → 探针验证命中 → 良性样本验证不误报 →
   selftest 补用例 → test_offline 回归

## 7. 已知边界

- `ThreadCtx_Inject` 类 API 组合规则存在合法软件误报面（调试器/打包工具），
  定级 medium 需人工研判；`all of` 四件套已是纯 YARA 可达的最严组合，
  更精细的判定需 pefile 语义分析（pe_heuristics alloc/write/exec 三分类）
- MSI 内 zlib 压缩流的深层载荷 YARA 不可见，由 deobf 层与 TOC/hex 结构
  启发（pyinst.py / hex_blob_findings）覆盖
- 行为链判定仅作用于 `analyze` 命令与解混淆复扫，`offline` 原始文本
  不跑 SBX 规则（防止报告文本误报）
