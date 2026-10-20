#!/usr/bin/env python3
"""miniantivirus.py —— 兼容入口。

实现已模块化到 miniantivirus/ 包，本文件保持旧用法可用：
    python miniantivirus.py scan .
    python miniantivirus.py test
等价的新入口：
    python -m miniantivirus scan .
"""

import sys

try:
    from miniantivirus.cli import main
except ImportError:
    sys.exit("未找到 miniantivirus 包：请把本文件保留在 miniantivirus/ 目录同级使用。")

if __name__ == "__main__":
    sys.exit(main())
