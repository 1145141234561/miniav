"""VirusTotal 集成（v3 API）：哈希信誉查询 + 文件上传多引擎扫描。

需要环境变量 VT_API_KEY（https://www.virustotal.com 免费注册获取）。
公共 API 限速 4 次/分钟，这里用 15 秒最小间隔 + 本地缓存（7 天 TTL）兜底。
"""

import json
import os
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from .signatures import VT_CACHE

_API = "https://www.virustotal.com/api/v3/"
_BASE = _API + "files/"
_UPLOAD = _API + "files"    # 无尾斜杠：带斜杠会 301 重定向且 POST 被降级为 GET
MAX_UPLOAD = 32 * 1024 * 1024   # 免费 API 单文件上传上限
CACHE_TTL = 7 * 24 * 3600   # 缓存有效期 7 天
MIN_INTERVAL = 15.0         # 两次真实请求的最小间隔（秒）

_SHARED = None


def _load_cache():
    try:
        return json.loads(VT_CACHE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_cache(cache):
    try:
        VT_CACHE.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass


class VTClient:
    def __init__(self, api_key=None):
        self.api_key = api_key or os.environ.get("VT_API_KEY", "")
        self._last = 0.0

    @classmethod
    def shared(cls):
        global _SHARED
        if _SHARED is None:
            _SHARED = cls()
        return _SHARED

    @staticmethod
    def has_key():
        return bool(os.environ.get("VT_API_KEY"))

    def _rate_wait(self):
        wait = MIN_INTERVAL - (time.time() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.time()

    def query(self, sha, use_cache=True):
        """返回 last_analysis_stats dict；VT 无记录返回 None；失败抛 RuntimeError。"""
        if not self.api_key:
            raise RuntimeError("未设置 VT_API_KEY 环境变量")
        cache = _load_cache() if use_cache else {}
        rec = cache.get(sha)
        if rec and time.time() - rec.get("time", 0) < CACHE_TTL:
            return rec.get("stats")
        stats = self._http(sha)
        if use_cache:
            cache[sha] = {"time": time.time(), "stats": stats}
            _save_cache(cache)
        return stats

    def _http(self, sha):
        for attempt in (1, 2):
            self._rate_wait()
            req = urllib.request.Request(_BASE + sha, headers={"x-apikey": self.api_key})
            try:
                with urllib.request.urlopen(req, timeout=20) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
                return payload.get("data", {}).get("attributes", {}).get(
                    "last_analysis_stats")
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    return None
                if exc.code == 429 and attempt == 1:
                    print("[i] VirusTotal 限速，等待 30 秒后重试…")
                    time.sleep(30)
                    continue
                raise RuntimeError(f"VT 查询失败: HTTP {exc.code}")
            except (urllib.error.URLError, OSError) as exc:
                raise RuntimeError(f"VT 网络错误: {exc}")
        raise RuntimeError("VT 查询失败: 持续限速")

    def upload(self, path, poll_rounds=12):
        """上传文件到 VirusTotal 多引擎扫描（免费 API ≤32MB，公开共享）。

        返回 last_analysis_stats；分析超时抛 RuntimeError（可稍后用 query 再查）。
        """
        if not self.api_key:
            raise RuntimeError("未设置 VT_API_KEY 环境变量")
        p = Path(path)
        if not p.is_file():
            raise RuntimeError(f"文件不存在: {p}")
        if p.stat().st_size > MAX_UPLOAD:
            raise RuntimeError("文件超过免费 API 32MB 上传上限")
        aid = self._upload_file(p)
        for _ in range(poll_rounds):
            time.sleep(20)
            result = self._analysis(aid)
            if result is None:
                break
            status, stats = result
            if status == "completed" and stats is not None:
                return stats
        raise RuntimeError("VT 分析尚未完成，请稍后用 vt <sha256> 查询结果")

    def _upload_file(self, p):
        boundary = "miniav" + uuid.uuid4().hex
        with open(p, "rb") as fh:
            data = fh.read()
        body = (f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="{p.name}"\r\n'
                "Content-Type: application/octet-stream\r\n\r\n").encode("utf-8") \
            + data + f"\r\n--{boundary}--\r\n".encode("ascii")
        self._rate_wait()
        req = urllib.request.Request(
            _UPLOAD, data=body, method="POST",
            headers={"x-apikey": self.api_key,
                     "Content-Type": f"multipart/form-data; boundary={boundary}"})
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"VT 上传失败: HTTP {exc.code}")
        except (urllib.error.URLError, OSError) as exc:
            raise RuntimeError(f"VT 网络错误: {exc}")
        aid = payload.get("data", {}).get("id")
        if not aid:
            raise RuntimeError("VT 上传响应异常（未返回分析 ID）")
        return aid

    def _analysis(self, aid):
        self._rate_wait()
        req = urllib.request.Request(_API + "analyses/" + aid,
                                     headers={"x-apikey": self.api_key})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise RuntimeError(f"VT 查询分析失败: HTTP {exc.code}")
        except (urllib.error.URLError, OSError) as exc:
            raise RuntimeError(f"VT 网络错误: {exc}")
        attr = payload.get("data", {}).get("attributes", {})
        return attr.get("status"), attr.get("stats")


def finding_from_stats(stats):
    """把 last_analysis_stats 转为 finding dict；无可疑返回 None。"""
    if not stats:
        return None
    mal = stats.get("malicious", 0) or 0
    sus = stats.get("suspicious", 0) or 0
    if mal:
        return {"name": "VT-Community-Detection", "level": "high",
                "detail": f"VirusTotal 社区: {mal} 个引擎判定恶意"}
    if sus:
        return {"name": "VT-Community-Suspicious", "level": "medium",
                "detail": f"VirusTotal 社区: {sus} 个引擎判定可疑"}
    return None
