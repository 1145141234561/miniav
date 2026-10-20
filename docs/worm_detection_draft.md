# 现代蠕虫检测规则草案

> 状态：**草案（draft）**——已启用规则 3 条（`rules/worms.yar`，探针验证通过），
> 待实证清单 4 项需真实样本/可信报告锚点后方可转正。
> 设计依据：现代蠕虫四层特征面（网络/主机/文件/行为组合），
> 高置信 IOC 原则——不凭空编造未实证锚点。

## 1. 已启用规则（rules/worms.yar，全部 medium 需人工研判）

| 规则 | 锚点结构 | 已知误报面与豁免 |
|---|---|---|
| `Worm_SSH_Propagation` | 凭据文件（id_rsa/authorized_keys）**与**自动化动作形态（`> .ssh/authorized_keys` 写入重定向、sshpass、`curl \| sh`）双锚 | Ansible 类配置管理——动作形态锚不含配置语法，实测零误报；报告文本（描述性中文）零误报 |
| `Worm_Share_Propagation` | MZ 门 + 管理共享（\\ADMIN$ / \\C$）+ 持久化动词（schtasks） | **PsExec/Sysinternals 合法远管**——由签名校验层豁免（sigcheck 有效不升级）；规则保持 medium |
| `Worm_Email_Script` | Outlook COM 自动化 + `.Attachments.Add` 自群发，filesize<4MB 门 | 营销群发走 SMTP/SDK 不走 Outlook COM，实测零误报 |

设计要点：SSH 规则第一版用 `ssh -oStrictHostKeyChecking` 字面锚，被
scp 变体绕过且描述性报告文本可命中——改为**动作形态锚**（写入重定向
符号形态）后同时解决两个问题。经验：字面串锚 → 行为形态锚的升级
是多态抗性同源问题（参照 silverfox 泛化层设计原则）。

## 2. 待实证清单（转正前置条件：真实样本或可信 IOC 报告）

| 项 | 目标锚点 | 实证来源要求 |
|---|---|---|
| EXP 前导字节 | 蠕虫携带的漏洞利用代码 blob（如 MS17-010 Trans2 前导） | 真实样本静态提取，≥2 独立样本交叉验证 |
| Mirai 系 telnet 爆破串 | 凭证字典表结构 / 报文前导 | 公开家族报告的完整哈希+串锚 |
| 蠕虫互斥体命名 | 家族命名模板正则 | 沙箱报告互斥体字段，≥3 样本归纳 |
| 云蠕虫挖矿锚 | docker API 2375 + 镜像名模板 | TeamTNT 系报告实证（docker 单串太宽不可独立成锚） |

## 3. sandbox 行为组合层（草案，未实现）

| 组合 | 成分 | 说明 |
|---|---|---|
| `SBX-Worm-Spread` | 横向扫描信号 + 释放执行 + 持久化 | 三连击架构签名，各成分复用现有规则（SBX-Persistence / SBX-Fox-PublicDrop 扩展） |
| `SBX-Worm-Keys` | SSH 目录读取 + authorized_keys 写入 | Linux 侧文本行为链，需 sandbox 现有文本通道扩展 |

## 4. 检测面与 MiniAV 集成点

- **YARA 静态层**：`rules/worms.yar`（已启用，pack 自动收集，无需代码改动）
- **签名校验豁免**：PsExec 类误报由三层签名架构处理——嵌入签名有效
  → 不升级可疑级别（现有机制，无代码改动）
- **行为层**：第 3 节组合规则待 sandbox.py 扩展（后续 commit）
- **自检**：selftest 第 32 组 6 项（3 命中 + 3 误报边界）

## 5. 转正流程

1. 获得真实蠕虫样本（zip+密码入 `samples/`，绝不执行）
2. 静态提取 → 补全第 2 节锚点 → 灰度观察误报
3. selftest/探针回归 → 移出"draft"标注 → pack 重新导出
