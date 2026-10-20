"""生成自包含 HTML 扫描报告（内联 CSS，支持深色模式，无外部依赖）。"""

import html
import time
from pathlib import Path

_LEVEL_CLS = {"high": "b-high", "medium": "b-med"}

_CSS = """
  :root { color-scheme: light dark;
    --bg: #fafafa; --card: #ffffff; --text: #1a1a1a; --muted: #666;
    --border: #ddd; --high: #E8463A; --med: #EFAA17; --low: #7a7a85; }
  @media (prefers-color-scheme: dark) {
    :root { --bg: #141416; --card: #1e1e22; --text: #e8e8ea; --muted: #9a9aa2;
            --border: #333; }
  }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 24px; background: var(--bg); color: var(--text);
         font: 14px/1.6 "Segoe UI", "Microsoft YaHei", sans-serif; }
  .card { max-width: 960px; margin: 0 auto; background: var(--card);
          border: 1px solid var(--border); border-radius: 10px; padding: 24px; }
  h1 { font-size: 18px; margin: 0 0 4px; }
  .meta { color: var(--muted); font-size: 13px; margin-bottom: 16px; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border);
           vertical-align: top; word-break: break-all; }
  th { font-size: 12px; color: var(--muted); text-transform: uppercase; }
  .badge { display: inline-block; padding: 1px 8px; border-radius: 999px;
           font-size: 12px; font-weight: 600; color: #fff; }
  .b-high { background: var(--high); }
  .b-med  { background: var(--med); color: #222; }
  .b-low  { background: var(--low); }
  .mono { font-family: Consolas, monospace; font-size: 13px; }
  .detail { color: var(--muted); font-size: 13px; }
  .empty { color: var(--muted); text-align: center; padding: 24px; }
"""


def write_html(dest, meta, rows):
    """rows: [{path, name, level, detail}]；返回写入路径。"""
    dest = Path(dest)

    trs = []
    for r in rows:
        level = str(r.get("level", "info"))
        cls = _LEVEL_CLS.get(level, "b-low")
        trs.append(
            "<tr><td class='mono'>{}</td><td><span class='badge {}'>{}</span></td>"
            "<td>{}</td><td class='detail'>{}</td></tr>".format(
                html.escape(str(r.get("path", ""))), cls, html.escape(level),
                html.escape(str(r.get("name", ""))),
                html.escape(str(r.get("detail", "")))))
    body = "\n".join(trs) or \
        "<tr><td colspan='4' class='empty'>无检出，目标干净。</td></tr>"

    doc = ("<!DOCTYPE html>\n<html lang=\"zh\">\n<head>\n<meta charset=\"utf-8\">\n"
           "<title>miniantivirus 扫描报告</title>\n<style>" + _CSS + "</style>\n"
           "</head>\n<body><div class=\"card\">\n<h1>miniantivirus 扫描报告</h1>\n"
           "<div class=\"meta\">目标: " + html.escape(str(meta.get("target", ""))) +
           " · 时间: " + html.escape(str(meta.get(
               "time", time.strftime("%Y-%m-%d %H:%M:%S")))) +
           " · 扫描 " + html.escape(str(meta.get("files", 0))) + " 个文件 · 检出 " +
           html.escape(str(meta.get("findings", 0))) + " 条</div>\n"
           "<table>\n<thead><tr><th>文件</th><th>级别</th><th>检出</th><th>详情</th>"
           "</tr></thead>\n<tbody>\n" + body + "\n</tbody>\n</table>\n"
           "</div></body></html>\n")

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(doc, encoding="utf-8")
    return dest
