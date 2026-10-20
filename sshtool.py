#!/usr/bin/env python3
"""sshtool.py —— 基于 SSH 的合法远程运维工具。

仅用于管理你拥有或已获明确授权管理的服务器。所有连接走标准 SSH，
远程主机的 auth 日志会完整记录，本工具不含任何隐藏、混淆或反检测功能。

功能：
  list      显示清单中的主机
  exec      在一台或多台主机上执行命令
  shell     在单台主机上进行交互式命令循环
  put       通过 SFTP 上传文件
  get       通过 SFTP 下载文件
  sysinfo   采集标准系统信息（面向 Unix-like 主机）

每次命令与文件传输都会追加写入本目录下的 audit.log。

清单文件（与本脚本同目录的 inventory.json）格式：
{
  "hosts": [
    {
      "name": "web01",
      "host": "192.168.1.50",
      "port": 22,
      "username": "ops",
      "auth": {"method": "key", "key_file": "~/.ssh/id_ed25519"}
    },
    {
      "name": "db01",
      "host": "192.168.1.51",
      "port": 22,
      "username": "ops",
      "auth": {"method": "password", "password_env": "SSHTOOL_PW_DB01"}
    }
  ]
}

密钥/口令一律不写入清单：password 引用环境变量，缺失时在运行中交互输入。
"""

import argparse
import base64
import datetime
import getpass
import hashlib
import json
import os
import sys
from pathlib import Path

try:
    import paramiko
except ImportError:
    sys.exit("缺少依赖 paramiko，请先安装：pip install paramiko")

APP_DIR = Path(__file__).resolve().parent
DEFAULT_INVENTORY = APP_DIR / "inventory.json"
KNOWN_HOSTS = APP_DIR / ".known_hosts"
AUDIT_LOG = APP_DIR / "audit.log"

SYSINFO_COMMANDS = [
    ("hostname", "hostname"),
    ("os", "cat /etc/os-release 2>/dev/null | head -n 2"),
    ("kernel", "uname -a"),
    ("uptime", "uptime"),
    ("cpu_cores", "nproc"),
    ("memory", "free -m | head -n 2"),
    ("disk", "df -h"),
    ("logged_in", "who"),
]


def audit(label, action, detail, exit_code=None):
    """把一次操作追加写入本地审计日志。"""
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{ts}] {label} | {action} | {detail}"
    if exit_code is not None:
        entry += f" | exit={exit_code}"
    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as fh:
            fh.write(entry + "\n")
    except OSError as exc:
        print(f"[!] 审计日志写入失败: {exc}")


def load_inventory(path):
    path = Path(path)
    if not path.exists():
        sys.exit(
            f"未找到清单文件: {path}\n"
            f"请复制 inventory.example.json 为 inventory.json 并按需修改。"
        )
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        sys.exit(f"清单文件不是合法 JSON: {exc}")
    hosts = {}
    for entry in data.get("hosts", []):
        name = entry.get("name")
        if not name or "host" not in entry or "username" not in entry:
            sys.exit(f"清单条目缺少 name/host/username 字段: {entry}")
        hosts[name] = entry
    if not hosts:
        sys.exit("清单中没有定义任何主机。")
    return hosts


def select_hosts(inventory, spec):
    """按 'all' 或逗号分隔的名称列表挑选主机。"""
    if spec.strip().lower() == "all":
        return list(inventory.values())
    names = [n.strip() for n in spec.split(",") if n.strip()]
    unknown = [n for n in names if n not in inventory]
    if unknown:
        sys.exit(f"清单中不存在这些主机: {', '.join(unknown)}")
    return [inventory[n] for n in names]


class ConfirmHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """首次连接时向用户确认主机指纹，确认后保存到 .known_hosts。"""

    def missing_host_key(self, client, hostname, key):
        digest = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
        print(f"[!] 首次连接 {hostname}")
        print(f"    主机密钥 {key.get_name()} 指纹: SHA256:{digest}")
        answer = input("    是否信任并记录该主机密钥? [y/N] ").strip().lower()
        if answer != "y":
            raise paramiko.SSHException(f"用户拒绝了 {hostname} 的主机密钥")
        client.get_host_keys().add(hostname, key.get_name(), key)
        try:
            client.save_host_keys()
        except OSError as exc:
            print(f"[!] 无法保存已知主机文件: {exc}")


def connect(spec):
    """建立 SSH 连接（含主机密钥校验与认证），返回 SSHClient。"""
    label = f"{spec['username']}@{spec['host']}:{spec.get('port', 22)}"
    print(f"[*] 正在连接 {spec['name']} ({label}) ...")
    client = paramiko.SSHClient()
    KNOWN_HOSTS.touch(exist_ok=True)
    client.load_host_keys(str(KNOWN_HOSTS))
    client.set_missing_host_key_policy(ConfirmHostKeyPolicy())

    auth = spec.get("auth", {})
    method = auth.get("method", "key")
    kwargs = {
        "hostname": spec["host"],
        "port": int(spec.get("port", 22)),
        "username": spec["username"],
        "timeout": 10,
        "banner_timeout": 15,
        "auth_timeout": 15,
        "allow_agent": True,
        "look_for_keys": method == "key" and not auth.get("key_file"),
    }
    if method == "password":
        env_name = auth.get("password_env", "")
        password = os.environ.get(env_name, "")
        if not password:
            password = getpass.getpass(f"    {spec['username']}@{spec['host']} 的密码: ")
        kwargs["password"] = password
    elif method == "key":
        key_file = os.path.expanduser(auth.get("key_file", "~/.ssh/id_ed25519"))
        if not os.path.exists(key_file):
            raise FileNotFoundError(f"找不到私钥文件: {key_file}")
        kwargs["key_filename"] = key_file
        passphrase_env = auth.get("passphrase_env", "")
        if passphrase_env and os.environ.get(passphrase_env):
            kwargs["passphrase"] = os.environ[passphrase_env]
    else:
        raise ValueError(f"不支持的认证方式: {method}")

    client.connect(**kwargs)
    print(f"[+] 已连接 {spec['name']}")
    audit(spec["name"], "connect", f"{label} ({method})")
    return client


def run_command(client, command, timeout):
    """执行单条命令并返回 (退出码, stdout, stderr)。"""
    _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    rc = stdout.channel.recv_exit_status()
    return rc, out, err


def _print_output(out, err):
    if out:
        print(out, end="" if out.endswith("\n") else "\n")
    if err:
        print(err, end="" if err.endswith("\n") else "\n", file=sys.stderr)


def cmd_list(args):
    inventory = load_inventory(args.inventory)
    print(f"{'NAME':<16}{'ADDRESS':<30}{'USER':<16}AUTH")
    for name, spec in inventory.items():
        auth = spec.get("auth", {})
        method = auth.get("method", "key")
        if method == "password":
            auth_desc = f"password (env: {auth.get('password_env', '运行时输入')})"
        else:
            auth_desc = f"key ({auth.get('key_file', '~/.ssh/id_ed25519')})"
        addr = f"{spec['host']}:{spec.get('port', 22)}"
        print(f"{name:<16}{addr:<30}{spec['username']:<16}{auth_desc}")
    return 0


def cmd_exec(args):
    inventory = load_inventory(args.inventory)
    hosts = select_hosts(inventory, args.hosts)
    command = " ".join(args.command)
    failed = 0
    for spec in hosts:
        try:
            client = connect(spec)
        except Exception as exc:
            print(f"[!] {spec['name']}: 连接失败: {exc}")
            audit(spec["name"], "connect-failed", str(exc))
            failed += 1
            continue
        try:
            rc, out, err = run_command(client, command, args.timeout)
            _print_output(out, err)
            print(f"[i] {spec['name']}: 退出码 {rc}")
            audit(spec["name"], "exec", command, rc)
            if rc != 0:
                failed += 1
        except Exception as exc:
            print(f"[!] {spec['name']}: 命令执行失败: {exc}")
            audit(spec["name"], "exec-failed", f"{command} ({exc})")
            failed += 1
        finally:
            client.close()
    return 1 if failed else 0


def cmd_shell(args):
    inventory = load_inventory(args.inventory)
    hosts = select_hosts(inventory, args.host)
    if len(hosts) != 1:
        sys.exit("shell 模式只能指定一台主机")
    spec = hosts[0]
    try:
        client = connect(spec)
    except Exception as exc:
        sys.exit(f"连接失败: {exc}")
    print(f"[*] 进入 {spec['name']} 交互命令循环，输入 exit 或按 Ctrl+D 退出。")
    print("[i] 每行作为一条独立命令执行；需要保持状态的场景请写在一行内，如 'cd /tmp && ls'。")
    try:
        while True:
            try:
                line = input(f"{spec['name']}> ").strip()
            except EOFError:
                break
            if not line or line.lower() in ("exit", "quit"):
                break
            try:
                rc, out, err = run_command(client, line, args.timeout)
            except Exception as exc:
                print(f"[!] 命令执行失败: {exc}")
                audit(spec["name"], "shell-error", f"{line} ({exc})")
                continue
            _print_output(out, err)
            audit(spec["name"], "shell", line, rc)
    except KeyboardInterrupt:
        print()
    finally:
        client.close()
    return 0


def _per_host_path(local_path, name):
    """多主机下载时，给本地文件名追加主机名避免互相覆盖。"""
    p = Path(local_path)
    if p.suffix:
        return p.with_name(f"{p.stem}.{name}{p.suffix}")
    return p.with_name(p.name + "." + name)


def cmd_put(args):
    inventory = load_inventory(args.inventory)
    hosts = select_hosts(inventory, args.hosts)
    local = Path(args.local).expanduser()
    if not local.is_file():
        sys.exit(f"本地文件不存在: {local}")
    failed = 0
    for spec in hosts:
        try:
            client = connect(spec)
        except Exception as exc:
            print(f"[!] {spec['name']}: 连接失败: {exc}")
            audit(spec["name"], "connect-failed", str(exc))
            failed += 1
            continue
        try:
            sftp = client.open_sftp()
            remote = args.remote
            if remote.endswith("/"):
                remote += local.name
            sftp.put(str(local), remote, confirm=True)
            size = local.stat().st_size
            print(f"[+] {spec['name']}: 已上传 {local.name} -> {remote} ({size} 字节)")
            audit(spec["name"], "put", f"{local} -> {remote} ({size} 字节)")
            sftp.close()
        except Exception as exc:
            print(f"[!] {spec['name']}: 上传失败: {exc}")
            audit(spec["name"], "put-failed", f"{local} -> {args.remote} ({exc})")
            failed += 1
        finally:
            client.close()
    return 1 if failed else 0


def cmd_get(args):
    inventory = load_inventory(args.inventory)
    hosts = select_hosts(inventory, args.hosts)
    failed = 0
    for spec in hosts:
        try:
            client = connect(spec)
        except Exception as exc:
            print(f"[!] {spec['name']}: 连接失败: {exc}")
            audit(spec["name"], "connect-failed", str(exc))
            failed += 1
            continue
        try:
            sftp = client.open_sftp()
            target = Path(args.local).expanduser() if len(hosts) == 1 else _per_host_path(args.local, spec["name"])
            sftp.get(args.remote, str(target))
            size = target.stat().st_size
            print(f"[+] {spec['name']}: 已下载 {args.remote} -> {target} ({size} 字节)")
            audit(spec["name"], "get", f"{args.remote} -> {target} ({size} 字节)")
            sftp.close()
        except Exception as exc:
            print(f"[!] {spec['name']}: 下载失败: {exc}")
            audit(spec["name"], "get-failed", f"{args.remote} -> {args.local} ({exc})")
            failed += 1
        finally:
            client.close()
    return 1 if failed else 0


def cmd_sysinfo(args):
    inventory = load_inventory(args.inventory)
    hosts = select_hosts(inventory, args.hosts)
    failed = 0
    for spec in hosts:
        try:
            client = connect(spec)
        except Exception as exc:
            print(f"[!] {spec['name']}: 连接失败: {exc}")
            audit(spec["name"], "connect-failed", str(exc))
            failed += 1
            continue
        print(f"\n===== {spec['name']} ({spec['host']}) =====")
        try:
            for title, command in SYSINFO_COMMANDS:
                try:
                    rc, out, err = run_command(client, command, args.timeout)
                except Exception as exc:
                    print(f"[{title}] 执行出错: {exc}")
                    continue
                out = out.strip()
                print(f"[{title}] {out if out else '(无输出)'}")
                audit(spec["name"], "sysinfo", title, rc)
        finally:
            client.close()
    return 1 if failed else 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="sshtool",
        description="基于 SSH 的远程运维工具，仅用于管理你拥有或已获授权的服务器。",
        epilog="所有操作都会记录到 audit.log。清单文件格式见脚本开头文档字符串。",
    )
    parser.add_argument(
        "--inventory",
        default=str(DEFAULT_INVENTORY),
        help=f"主机清单 JSON 文件（默认: {DEFAULT_INVENTORY.name}）",
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    sub.add_parser("list", help="显示清单中的主机").set_defaults(func=cmd_list)

    p = sub.add_parser("exec", help="在一台或多台主机上执行命令")
    p.add_argument("--hosts", required=True, help="逗号分隔的主机名，或 'all'")
    p.add_argument("--timeout", type=int, default=60, help="命令超时秒数（默认 60）")
    p.add_argument("command", nargs="+", help="要执行的命令（前面加 -- 分隔）")
    p.set_defaults(func=cmd_exec)

    p = sub.add_parser("shell", help="在单台主机上进入交互式命令循环")
    p.add_argument("--host", required=True, help="单个主机名")
    p.add_argument("--timeout", type=int, default=60, help="单条命令超时秒数（默认 60）")
    p.set_defaults(func=cmd_shell)

    p = sub.add_parser("put", help="通过 SFTP 上传文件")
    p.add_argument("--hosts", required=True, help="逗号分隔的主机名，或 'all'")
    p.add_argument("--local", required=True, help="本地文件路径")
    p.add_argument("--remote", required=True, help="远端目标路径（以 / 结尾则保留原文件名）")
    p.set_defaults(func=cmd_put)

    p = sub.add_parser("get", help="通过 SFTP 下载文件")
    p.add_argument("--hosts", required=True, help="逗号分隔的主机名，或 'all'")
    p.add_argument("--remote", required=True, help="远端文件路径")
    p.add_argument("--local", required=True, help="本地目标路径（多主机时会自动追加主机名）")
    p.set_defaults(func=cmd_get)

    p = sub.add_parser("sysinfo", help="采集主机的标准系统信息")
    p.add_argument("--hosts", required=True, help="逗号分隔的主机名，或 'all'")
    p.add_argument("--timeout", type=int, default=30, help="单条命令超时秒数（默认 30）")
    p.set_defaults(func=cmd_sysinfo)

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    print("[i] sshtool：仅限用于你拥有或已获明确授权管理的系统。")
    return args.func(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] 已中断。")
        sys.exit(130)
