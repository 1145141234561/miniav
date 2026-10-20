"""miniantivirus 2.0 —— 教学级防御工具包。

模块结构：
  signatures  签名库读写与全局路径
  scanner     核心扫描（哈希/模式/EICAR/YARA/PE 启发式/压缩包/VT）
  archive     zip 压缩包扫描（预算/深度/压缩比防护，内存解包）
  sandbox     静态行为分析（绝不执行样本）
  analyzer    样本深度分析（任意文件一键全面静态体检）
  autolearn   样本自动学习：判定恶意后自动提取哈希+YARA 特征入库
  vt          VirusTotal 哈希信誉查询（仅查询，不上传）
  watcher     watchdog 准实时监视
  report      自包含 HTML 报告
  selfguard   自身完整性基线与篡改校验
  driverprotect  进程自保护驱动接口（MiniAVProt，ObRegisterCallbacks）
  selftest    端到端自检
  cli         命令行入口
"""

__version__ = "2.0.0"
