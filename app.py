#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MasterHttpRelayVPN - All-in-One GUI Edition v2.1.0
---------------------------------------------------
بازنویسی کامل با معماری ماژولار، UI/UX بهبودیافته و قابلیت‌های پیشرفته
"""
from kivy.core.text import LabelBase
import os
import asyncio, socket, ssl, time, ipaddress, concurrent.futures

# Register Vazir font only if the file exists
if os.path.exists('Vazir.ttf'):
    LabelBase.register(name='Vazir', fn_regular='Vazir.ttf')

import sys, os, json, asyncio, threading, queue, logging, time, re, base64, hashlib, ssl, socket, ipaddress, tempfile, datetime, subprocess, platform, random, collections, itertools
from urllib.parse import urlparse
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, field
import concurrent.futures


import urllib.parse 
import ssl
from enum import Enum
import pystray
from PIL import Image
from threading import Thread

import threading
import asyncio
import socket
import ssl
import time
import ipaddress
from typing import List, Optional, Callable
import rumps
# -------------------- کتابخانه‌های خارجی --------------------
try:
    from kivy.uix.slider import Slider
    from kivy.app import App
    from kivy.uix.boxlayout import BoxLayout
    from kivy.uix.togglebutton import ToggleButton
    from kivy.uix.textinput import TextInput
    from kivy.uix.button import Button
    from kivy.uix.label import Label
    from kivy.uix.spinner import Spinner
    from kivy.uix.scrollview import ScrollView
    from kivy.uix.gridlayout import GridLayout
    from kivy.uix.actionbar import ActionBar, ActionView, ActionButton, ActionPrevious
    from kivy.uix.tabbedpanel import TabbedPanel, TabbedPanelHeader
    from kivy.uix.popup import Popup
    from kivy.uix.switch import Switch
    from kivy.uix.progressbar import ProgressBar
    from kivy.clock import Clock
    from kivy.core.clipboard import Clipboard
    from kivy.properties import StringProperty, BooleanProperty, NumericProperty, ListProperty, DictProperty, ObjectProperty
    from kivy.metrics import dp
    from kivy.utils import get_color_from_hex
    from kivy.graphics import Color, Rectangle
    from kivy.storage.jsonstore import JsonStore
    from kivy.uix.filechooser import FileChooserListView
    from kivy.core.text import LabelBase


except ImportError:
    print("Kivy نصب نیست. لطفاً با دستور زیر نصب کنید:")
    print("pip install kivy")
    sys.exit(1)

try:
    import aiohttp
    import certifi
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import cryptography
except ImportError:
    print("وابستگی‌های رمزنگاری نصب نیستند. لطفاً با دستور زیر نصب کنید:")
    print("pip install aiohttp certifi cryptography pyOpenSSL")
    sys.exit(1)

try:
    import h2.connection, h2.config, h2.events, h2.settings
    H2_AVAILABLE = True
except ImportError:
    H2_AVAILABLE = False

try:
    import brotli
    _HAS_BR = True
except ImportError:
    brotli = None
    _HAS_BR = False

try:
    import zstandard as _zstd
    _HAS_ZSTD = True
    _ZSTD_DCTX = _zstd.ZstdDecompressor()
except ImportError:
    _zstd = None
    _HAS_ZSTD = False
    _ZSTD_DCTX = None

# -------------------- تنظیمات ثابت --------------------
__version__ = "2.1.0"

MAX_REQUEST_BODY_BYTES = 100 * 1024 * 1024
MAX_RESPONSE_BODY_BYTES = 200 * 1024 * 1024
MAX_HEADER_BYTES = 64 * 1024
CLIENT_IDLE_TIMEOUT = 120
RELAY_TIMEOUT = 25
TLS_CONNECT_TIMEOUT = 15
TCP_CONNECT_TIMEOUT = 10
CACHE_MAX_MB = 50
CACHE_TTL_STATIC_LONG = 3600
CACHE_TTL_STATIC_MED = 1800
CACHE_TTL_MAX = 86400
POOL_MAX = 50
POOL_MIN_IDLE = 15
CONN_TTL = 45.0
SEMAPHORE_MAX = 50
BATCH_WINDOW_MICRO = 0.005
BATCH_WINDOW_MACRO = 0.050
BATCH_MAX = 50

STATEFUL_HEADER_NAMES = (
    "cookie", "authorization", "proxy-authorization",
    "origin", "referer", "if-none-match", "if-modified-since",
    "cache-control", "pragma",
)
STATIC_EXTS = (
    ".css", ".js", ".mjs", ".woff", ".woff2", ".ttf", ".eot",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
    ".mp3", ".mp4", ".webm", ".wasm", ".avif",
)

# -------------------- ابزارهای کمکی --------------------
def decode_body(body: bytes, encoding: str) -> bytes:
    if not body: return body
    enc = (encoding or "").strip().lower()
    if not enc or enc == "identity": return body
    if "," in enc:
        for layer in reversed([s.strip() for s in enc.split(",") if s.strip()]):
            body = decode_body(body, layer)
        return body
    try:
        if enc == "gzip":
            import gzip
            return gzip.decompress(body)
        if enc == "deflate":
            import zlib
            try:
                return zlib.decompress(body)
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS)
        if enc == "br" and _HAS_BR:
            return brotli.decompress(body)
        if enc == "zstd" and _HAS_ZSTD:
            return _ZSTD_DCTX.decompress(body)
    except Exception:
        pass
    return body

def supported_encodings() -> str:
    codecs = ["gzip", "deflate"]
    if _HAS_BR: codecs.append("br")
    if _HAS_ZSTD: codecs.append("zstd")
    return ", ".join(codecs)

def _parse_content_length(header_block: bytes) -> int:
    for raw_line in header_block.split(b"\r\n"):
        name, sep, value = raw_line.partition(b":")
        if not sep: continue
        if name.strip().lower() == b"content-length":
            try:
                return int(value.strip())
            except ValueError:
                return 0
    return 0

# -------------------- ذخیره‌سازی تنظیمات --------------------
class AppConfig:
    _store = None
    @classmethod
    def get_store(cls):
        if cls._store is None:
            cls._store = JsonStore('master_relay_config.json')
        return cls._store

    @classmethod
    def get(cls, key, default=None):
        try:
            return cls.get_store().get('settings')[key]
        except KeyError:
            return default

    @classmethod
    def set(cls, key, value):
        store = cls.get_store()
        try:
            data = store.get('settings')
        except KeyError:
            data = {}
        data[key] = value
        store.put('settings', **data)

    @classmethod
    def get_script_ids(cls) -> List[Dict[str, Any]]:
        return cls.get('script_ids', [])

    @classmethod
    def save_script_ids(cls, ids_list: List[Dict[str, Any]]):
        cls.set('script_ids', ids_list)

    @classmethod
    def get_bypass_list(cls) -> List[str]:
        return cls.get('bypass_list', [])

    @classmethod
    def save_bypass_list(cls, domains: List[str]):
        cls.set('bypass_list', domains)

    @classmethod
    def get_mitm_enabled(cls) -> bool:
        return cls.get('mitm_enabled', True)   # پیش‌فرض روشن

    @classmethod
    def set_mitm_enabled(cls, enabled: bool):
        cls.set('mitm_enabled', enabled)

# -------------------- مدیر آیدی‌ها و آمار --------------------
@dataclass
class ScriptStats:
    id: str
    auth_key: str = ""
    name: str = ""          # ← اضافه شد
    success_count: int = 0
    fail_count: int = 0
    last_latency: float = 0.0
    is_online: bool = True
    last_error: str = ""
    last_used: float = 0.0

class ScriptManager:
    def __init__(self):
        self.scripts: List[ScriptStats] = []
        self.current_index = 0
        self._lock = threading.Lock()
        self._on_active_callbacks: List[callable] = []
        self.load_from_config()

    # ------------------------------------------------------------------
    # بارگیری / ذخیره‌سازی از JsonStore
    # ------------------------------------------------------------------
    def load_from_config(self):
        raw = AppConfig.get_script_ids()
        self.scripts = []
        for item in raw:
            normalized = {
                'id': item.get('id', ''),
                'auth_key': item.get('auth_key', item.get('key', '')),
                'name': item.get('name', ''), 
                'success_count': item.get('success_count', item.get('success', 0)),
                'fail_count': item.get('fail_count', item.get('fail', 0)),
                'last_latency': item.get('last_latency', 0.0),
                'is_online': item.get('is_online', True),
                'last_error': item.get('last_error', ''),
                'last_used': item.get('last_used', 0.0),
            }
            self.scripts.append(ScriptStats(**normalized))
        # اگر لیست خالی بود، حداقل یک آیتم پیش‌فرض نمی‌گذاریم (کاربر خودش اضافه کند)

    def save_to_config(self):
        data = [
            {
                'id': s.id,
                'auth_key': s.auth_key,
                'name': s.name,  
                'success_count': s.success_count,
                'fail_count': s.fail_count,
                'last_latency': s.last_latency,
                'is_online': s.is_online,
                'last_error': s.last_error,
                'last_used': s.last_used,
            }
            for s in self.scripts
        ]
        AppConfig.save_script_ids(data)

    # ------------------------------------------------------------------
    # مدیریت لیست
    # ------------------------------------------------------------------
    def add_script(self, script_id: str, auth_key: str = "", name: str = ""):
        if not script_id:
            return
        with self._lock:
            if any(s.id == script_id for s in self.scripts):
                return
            self.scripts.append(ScriptStats(id=script_id, auth_key=auth_key, name=name))
            if self.current_index >= len(self.scripts):
                self.current_index = 0
            self.save_to_config()

    def remove_script(self, script_id: str):
        with self._lock:
            old_len = len(self.scripts)
            self.scripts = [s for s in self.scripts if s.id != script_id]
            if len(self.scripts) < old_len:
                # if the current index is out of bounds after removal
                if self.current_index >= len(self.scripts) and len(self.scripts) > 0:
                    self.current_index = 0
                self.save_to_config()

    # ------------------------------------------------------------------
    # جابجایی و وضعیت فعلی
    # ------------------------------------------------------------------
    def get_current(self) -> Optional[ScriptStats]:
        if not self.scripts:
            return None
        return self.scripts[self.current_index % len(self.scripts)]

    def next_script(self) -> Optional[ScriptStats]:
        if not self.scripts:
            return None
        with self._lock:
            self.current_index = (self.current_index + 1) % len(self.scripts)
            self._notify_active_changed()
            return self.get_current()

    def set_current_by_id(self, script_id: str) -> bool:
        """انتخاب دستی یک توکن توسط کاربر (اگر وجود داشته باشد)"""
        with self._lock:
            for i, s in enumerate(self.scripts):
                if s.id == script_id:
                    if self.current_index != i:
                        self.current_index = i
                        self._notify_active_changed()
                    return True
        return False

    def switch_to_healthy(self) -> Optional[ScriptStats]:
        """انتخاب توکن با بهترین نرخ موفقیت (ترجیحاً آنلاین)"""
        if not self.scripts:
            return None
        online = [s for s in self.scripts if s.is_online]
        if not online:
            online = self.scripts
        # بیشترین نرخ موفقیت
        best = max(online, key=lambda s: s.success_count / (s.success_count + s.fail_count + 1))
        with self._lock:
            idx = self.scripts.index(best)
            if idx != self.current_index:
                self.current_index = idx
                self._notify_active_changed()
        return best

    # ------------------------------------------------------------------
    # ثبت نتیجه‌ی درخواست‌ها
    # ------------------------------------------------------------------
    def record_success(self, script_id: str, latency: float = 0):
        for s in self.scripts:
            if s.id == script_id:
                s.success_count += 1
                s.last_latency = latency
                s.is_online = True
                s.last_error = ""
                s.last_used = time.time()
                break
        self.save_to_config()

    def record_failure(self, script_id: str, error: str = ""):
        for s in self.scripts:
            if s.id == script_id:
                s.fail_count += 1
                s.last_error = error
                s.is_online = False
                s.last_used = time.time()
                break
        self.save_to_config()

    # ------------------------------------------------------------------
    # پینگ (با اعتبارسنجی HEAD)
    # ------------------------------------------------------------------
    async def ping_tcp(self, script_id: str) -> float:
        google_ip = AppConfig.get('google_ip', '216.239.38.120')
        front_domain = AppConfig.get('front_domain', 'www.google.com')
        script = next((s for s in self.scripts if s.id == script_id), None)
        if not script:
            return -1.0

        auth_key = script.auth_key
        path = f"/macros/s/{script_id}/exec"
        host = "script.google.com"

        payload = json.dumps({"m": "HEAD", "u": "https://www.google.com/", "k": auth_key}).encode()
        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode() + payload

        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        start = time.time()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(google_ip, 443, ssl=ssl_ctx, server_hostname=front_domain),
                timeout=10.0
            )
            writer.write(request)
            await writer.drain()
            # خواندن کل پاسخ تا بسته شدن
            response = b''
            while True:
                chunk = await asyncio.wait_for(reader.read(8192), timeout=5.0)
                if not chunk:
                    break
                response += chunk
            writer.close()
            await writer.wait_closed()

            latency = (time.time() - start) * 1000
            # بررسی وضعیت HTTP
            if b'200' in response.split(b'\r\n')[0] or b'302' in response.split(b'\r\n')[0] or b'304' in response.split(b'\r\n')[0]:
                self.record_success(script_id, latency)
                return latency
            else:
                self.record_failure(script_id, f"HTTP status not OK")
                return -1.0
        except Exception as e:
            self.record_failure(script_id, str(e))
            return -1.0

    # ------------------------------------------------------------------
    # Callback برای به‌روزرسانی UI هنگام تغییر توکن فعال
    # ------------------------------------------------------------------
    def register_active_callback(self, callback):
        """callback باید بدون آرگومان و قابل فراخوان در نخ اصلی باشد (با Clock.schedule_once)"""
        if callback not in self._on_active_callbacks:
            self._on_active_callbacks.append(callback)

    def unregister_active_callback(self, callback):
        if callback in self._on_active_callbacks:
            self._on_active_callbacks.remove(callback)

    def _notify_active_changed(self):
        for cb in self._on_active_callbacks:
            # اجرا در نخ اصلی (مهم!)
            Clock.schedule_once(lambda dt, c=cb: c(), 0)


# -------------------- مدیریت گواهی MITM --------------------
_UNSAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]")
def _safe_domain_filename(domain: str) -> str:
    cleaned = _UNSAFE_NAME_RE.sub("_", domain.strip(".").lower())
    return cleaned[:120] or "unknown"

class MITMCertManager:
    def __init__(self):
        self.ca_dir = os.path.join(App.get_running_app().user_data_dir, "ca")
        self.ca_key_file = os.path.join(self.ca_dir, "ca.key")
        self.ca_cert_file = os.path.join(self.ca_dir, "ca.crt")
        self._ca_key = None
        self._ca_cert = None
        self._ctx_cache = {}
        self._cert_dir = tempfile.mkdtemp(prefix="mhrv_certs_")
        self._ensure_ca()

    def _ensure_ca(self):
        if os.path.exists(self.ca_key_file) and os.path.exists(self.ca_cert_file):
            with open(self.ca_key_file, "rb") as f:
                self._ca_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(self.ca_cert_file, "rb") as f:
                self._ca_cert = x509.load_pem_x509_certificate(f.read())
        else:
            os.makedirs(self.ca_dir, exist_ok=True)
            self._ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "MasterHttpRelayVPN CA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MasterHttpRelayVPN"),
            ])
            now = datetime.datetime.now(datetime.timezone.utc)
            self._ca_cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(self._ca_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now)
                .not_valid_after(now + datetime.timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .sign(self._ca_key, hashes.SHA256())
            )
            with open(self.ca_key_file, "wb") as f:
                f.write(self._ca_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
            with open(self.ca_cert_file, "wb") as f:
                f.write(self._ca_cert.public_bytes(serialization.Encoding.PEM))
            logging.getLogger("MITM").warning(f"CA certificate generated at {self.ca_cert_file}")

    def get_server_context(self, domain: str) -> ssl.SSLContext:
        if domain not in self._ctx_cache:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain[:64] or "unknown")])
            try:
                san = x509.IPAddress(ipaddress.ip_address(domain))
            except ValueError:
                san = x509.DNSName(domain)
            now = datetime.datetime.now(datetime.timezone.utc)
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(self._ca_cert.subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now)
                .not_valid_after(now + datetime.timedelta(days=365))
                .add_extension(x509.SubjectAlternativeName([san]), critical=False)
                .sign(self._ca_key, hashes.SHA256())
            )
            key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            safe = _safe_domain_filename(domain)
            cert_file = os.path.join(self._cert_dir, f"{safe}.crt")
            key_file = os.path.join(self._cert_dir, f"{safe}.key")
            with open(cert_file, "wb") as f:
                f.write(cert_pem + self._ca_cert.public_bytes(serialization.Encoding.PEM))
            with open(key_file, "wb") as f:
                f.write(key_pem)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.set_alpn_protocols(["http/1.1"])
            ctx.load_cert_chain(cert_file, key_file)
            self._ctx_cache[domain] = ctx
        return self._ctx_cache[domain]

    def get_ca_cert_path(self) -> str:
        """مسیر فایل گواهی CA (ca.crt) را برمی‌گرداند."""
        return self.ca_cert_file

    def export_ca_cert(self, destination: str) -> bool:
        """کپی فایل ca.crt به مسیر دلخواه (مثلاً پوشه دانلودها)."""
        try:
            import shutil
            shutil.copy2(self.ca_cert_file, destination)
            return True
        except Exception as e:
            logging.getLogger("MITM").error(f"Export CA failed: {e}")
            return False

# -------------------- HTTP/2 Transport --------------------
class _StreamState:
    __slots__ = ("status", "headers", "data", "done", "error")
    def __init__(self):
        self.status = 0
        self.headers = {}
        self.data = bytearray()
        self.done = asyncio.Event()
        self.error = None

class H2Transport:
    def __init__(self, connect_host: str, sni_host: str, verify_ssl: bool = True):
        self.connect_host = connect_host
        self.sni_host = sni_host
        self.verify_ssl = verify_ssl
        self._reader = None
        self._writer = None
        self._h2 = None
        self._connected = False
        self._write_lock = asyncio.Lock()
        self._connect_lock = asyncio.Lock()
        self._read_task = None
        self._streams = {}

    @property
    def is_connected(self): return self._connected

    async def ensure_connected(self):
        if self._connected: return
        async with self._connect_lock:
            if self._connected: return
            await self._do_connect()

    async def _do_connect(self):
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        raw.setblocking(False)
        try:
            await asyncio.wait_for(asyncio.get_event_loop().sock_connect(raw, (self.connect_host, 443)), timeout=15)
            self._reader, self._writer = await asyncio.wait_for(asyncio.open_connection(sock=raw, ssl=ctx, server_hostname=self.sni_host), timeout=15)
        except Exception:
            raw.close()
            raise
        ssl_obj = self._writer.get_extra_info("ssl_object")
        negotiated = ssl_obj.selected_alpn_protocol() if ssl_obj else None
        if negotiated != "h2":
            self._writer.close()
            raise RuntimeError(f"H2 ALPN negotiation failed (got {negotiated!r})")
        config = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
        self._h2 = h2.connection.H2Connection(config=config)
        self._h2.initiate_connection()
        self._h2.increment_flow_control_window(2**24 - 65535)
        self._h2.update_settings({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 8*1024*1024, h2.settings.SettingCodes.ENABLE_PUSH: 0})
        await self._flush()
        self._connected = True
        self._read_task = asyncio.create_task(self._reader_loop())
        logging.getLogger("H2").info(f"H2 connected → {self.connect_host}")

    async def reconnect(self):
        await self._close_internal()
        await self._do_connect()

    async def _close_internal(self):
        self._connected = False
        if self._read_task:
            self._read_task.cancel()
            self._read_task = None
        if self._writer:
            try: self._writer.close()
            except: pass
            self._writer = None
        for state in self._streams.values():
            state.error = "Connection closed"
            state.done.set()
        self._streams.clear()

    async def request(self, method, path, host, headers=None, body=None, timeout=25):
        await self.ensure_connected()
        for _ in range(5):
            status, resp_headers, resp_body = await self._single_request(method, path, host, headers, body, timeout)
            if status not in (301,302,303,307,308): return status, resp_headers, resp_body
            location = resp_headers.get("location","")
            if not location: return status, resp_headers, resp_body
            parsed = urlparse(location)
            path = parsed.path + ("?"+parsed.query if parsed.query else "")
            host = parsed.netloc or host
            method = "GET"
            body = None
            headers = None
        return status, resp_headers, resp_body

    async def _single_request(self, method, path, host, headers, body, timeout):
        if not self._connected: await self.ensure_connected()
        async with self._write_lock:
            try:
                stream_id = self._h2.get_next_available_stream_id()
            except Exception:
                await self.reconnect()
                stream_id = self._h2.get_next_available_stream_id()
            h2_headers = [(":method", method), (":path", path), (":authority", host), (":scheme", "https"), ("accept-encoding", supported_encodings())]
            if headers:
                for k,v in headers.items():
                    h2_headers.append((k.lower(), str(v)))
            end_stream = not body
            self._h2.send_headers(stream_id, h2_headers, end_stream=end_stream)
            if body:
                self._send_body(stream_id, body)
            state = _StreamState()
            self._streams[stream_id] = state
            await self._flush()
        try:
            await asyncio.wait_for(state.done.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            self._streams.pop(stream_id, None)
            raise TimeoutError(f"H2 stream {stream_id} timed out")
        self._streams.pop(stream_id, None)
        if state.error:
            raise ConnectionError(f"H2 stream error: {state.error}")
        resp_body = bytes(state.data)
        enc = state.headers.get("content-encoding","")
        if enc: resp_body = decode_body(resp_body, enc)
        return state.status, state.headers, resp_body

    def _send_body(self, stream_id, body):
        sent = 0
        while body:
            max_size = self._h2.local_settings.max_frame_size
            window = self._h2.local_flow_control_window(stream_id)
            send_size = min(len(body), max_size, window)
            if send_size <= 0:
                raise BufferError(f"H2 flow control exhausted after {sent} bytes")
            end = send_size >= len(body)
            self._h2.send_data(stream_id, body[:send_size], end_stream=end)
            body = body[send_size:]
            sent += send_size

    async def _reader_loop(self):
        try:
            while self._connected:
                data = await self._reader.read(65536)
                if not data: break
                try:
                    events = self._h2.receive_data(data)
                except Exception:
                    break
                for event in events:
                    self._dispatch(event)
                async with self._write_lock:
                    await self._flush()
        except asyncio.CancelledError:
            pass
        finally:
            self._connected = False
            for state in self._streams.values():
                if not state.done.is_set():
                    state.error = "Connection lost"
                    state.done.set()

    def _dispatch(self, event):
        if isinstance(event, h2.events.ResponseReceived):
            state = self._streams.get(event.stream_id)
            if state:
                for n,v in event.headers:
                    n = n.decode() if isinstance(n, bytes) else n
                    v = v.decode() if isinstance(v, bytes) else v
                    if n == ":status": state.status = int(v)
                    else: state.headers[n] = v
        elif isinstance(event, h2.events.DataReceived):
            state = self._streams.get(event.stream_id)
            if state:
                state.data.extend(event.data)
            self._h2.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
        elif isinstance(event, h2.events.StreamEnded):
            state = self._streams.get(event.stream_id)
            if state: state.done.set()
        elif isinstance(event, h2.events.StreamReset):
            state = self._streams.get(event.stream_id)
            if state: state.error = f"Stream reset (code={event.error_code})"; state.done.set()

    async def _flush(self):
        data = self._h2.data_to_send()
        if data and self._writer:
            self._writer.write(data)
            await self._writer.drain()

    async def close(self):
        if self._h2 and self._connected:
            try:
                self._h2.close_connection()
                async with self._write_lock:
                    await self._flush()
            except: pass
        await self._close_internal()

# -------------------- DomainFronter (موتور رله) --------------------
class TrafficCounter:
    def __init__(self):
        self._lock = threading.Lock()
        self._down_bytes = 0
        self._up_bytes = 0
        self._down_speed = 0.0
        self._up_speed = 0.0
        self._last_speed_update = time.time()
        self.total_down_bytes = 0
        self.total_up_bytes = 0

    def add_down(self, n):
        with self._lock:
            self._down_bytes += n
            self.total_down_bytes += n

    def add_up(self, n):
        with self._lock:
            self._up_bytes += n
            self.total_up_bytes += n

    def get_speeds(self):
        now = time.time()
        with self._lock:
            elapsed = now - self._last_speed_update
            if elapsed > 0.5:
                self._down_speed = self._down_bytes / elapsed
                self._up_speed = self._up_bytes / elapsed
                self._down_bytes = 0
                self._up_bytes = 0
                self._last_speed_update = now
            return self._down_speed, self._up_speed

class DomainFronter:
    def __init__(self, script_manager: ScriptManager, status_callback: Callable = None):
        self.script_manager = script_manager
        self.status_callback = status_callback  # برای ارسال لاگ به UI
        self.connect_host = AppConfig.get('google_ip', '216.239.38.120')
        self.sni_host = AppConfig.get('front_domain', 'www.google.com')
        self.http_host = "script.google.com"
        self.verify_ssl = AppConfig.get('verify_ssl', True)
        self._pool = []
        self._pool_lock = asyncio.Lock()
        self._pool_max = POOL_MAX
        self._conn_ttl = CONN_TTL
        self._semaphore = asyncio.Semaphore(SEMAPHORE_MAX)
        self._warmed = False
        self._maintenance_task = None
        self._bg_tasks = set()
        self._h2 = None
        self._bypass_domains = set(AppConfig.get_bypass_list())
        self._extra_headers = {
            "User-Agent": AppConfig.get('user_agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'),
            "Accept-Language": AppConfig.get('accept_language', 'en-US,en;q=0.9'),
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        }
        self.traffic = TrafficCounter()
        if H2_AVAILABLE:
            self._h2 = H2Transport(self.connect_host, self.sni_host, self.verify_ssl)

    def log(self, msg, level="info"):
        if self.status_callback:
            self.status_callback(f"[Fronter] {msg}")
        else:
            logging.getLogger("Fronter").info(msg)

    def _ssl_ctx(self):
        ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    async def _open(self):
        return await asyncio.open_connection(self.connect_host, 443, ssl=self._ssl_ctx(), server_hostname=self.sni_host)

    async def _acquire(self):
        now = asyncio.get_event_loop().time()
        async with self._pool_lock:
            while self._pool:
                r, w, created = self._pool.pop()
                if (now - created) < self._conn_ttl and not r.at_eof():
                    asyncio.create_task(self._add_conn_to_pool())
                    return r, w, created
                try: w.close()
                except: pass
        r, w = await asyncio.wait_for(self._open(), timeout=TLS_CONNECT_TIMEOUT)
        return r, w, asyncio.get_event_loop().time()

    async def _release(self, reader, writer, created):
        now = asyncio.get_event_loop().time()
        if (now - created) >= self._conn_ttl or reader.at_eof():
            try: writer.close()
            except: pass
            return
        async with self._pool_lock:
            if len(self._pool) < self._pool_max:
                self._pool.append((reader, writer, created))
            else:
                try: writer.close()
                except: pass

    def _current_script_id(self):
        cur = self.script_manager.get_current()
        return cur.id if cur else ""

    def _exec_path(self):
        return f"/macros/s/{self._current_script_id()}/exec"

    async def _flush_pool(self):
        async with self._pool_lock:
            for _, w, _ in self._pool:
                try: w.close()
                except: pass
            self._pool.clear()

    async def _add_conn_to_pool(self):
        try:
            r, w = await asyncio.wait_for(self._open(), timeout=5)
            t = asyncio.get_event_loop().time()
            async with self._pool_lock:
                if len(self._pool) < self._pool_max:
                    self._pool.append((r, w, t))
                else:
                    try: w.close()
                    except: pass
        except: pass

    async def _pool_maintenance(self):
        while True:
            try:
                await asyncio.sleep(3)
                now = asyncio.get_event_loop().time()
                async with self._pool_lock:
                    alive = []
                    for r, w, t in self._pool:
                        if (now - t) < self._conn_ttl and not r.at_eof():
                            alive.append((r, w, t))
                        else:
                            try: w.close()
                            except: pass
                    self._pool = alive
            except asyncio.CancelledError: break

    async def _warm_pool(self):
        if self._warmed: return
        self._warmed = True
        self._spawn(self._do_warm())
        if self._maintenance_task is None:
            self._maintenance_task = self._spawn(self._pool_maintenance())
        if self._h2:
            self._spawn(self._h2_connect())

    def _spawn(self, coro):
        task = asyncio.create_task(coro)
        self._bg_tasks.add(task)
        task.add_done_callback(self._bg_tasks.discard)
        return task

    async def close(self):
        for task in list(self._bg_tasks):
            task.cancel()
        await self._flush_pool()
        if self._h2: await self._h2.close()

    async def _h2_connect(self):
        try: await self._h2.ensure_connected()
        except Exception as e: self.log(f"H2 connect failed: {e}")

    async def _do_warm(self):
        count = AppConfig.get('warm_pool_count', 30)
        coros = [self._add_conn_to_pool() for _ in range(count)]
        results = await asyncio.gather(*coros, return_exceptions=True)
        opened = sum(1 for r in results if not isinstance(r, Exception))
        self.log(f"Pre-warmed {opened}/{count} TLS connections")


    def _build_payload(self, method, url, headers, body):
        payload = {"m": method, "u": url, "r": False}
        if headers:
            filt = {k: v for k, v in headers.items() if k.lower() != "accept-encoding"}
            payload["h"] = filt if filt else headers
        if body:
            payload["b"] = base64.b64encode(body).decode()
            ct = headers.get("Content-Type") or headers.get("content-type")
            if ct:
                payload["ct"] = ct

        # ---- NEW: attach Cloudflare Worker URL if configured ----
        worker_url = AppConfig.get('cf_worker_url', '').strip()
        if worker_url:
            payload["w"] = worker_url

        return payload

    def _should_bypass(self, url: str) -> bool:
        if not self._bypass_domains: return False
        parsed = urlparse(url)
        host = parsed.hostname or ""
        host_lower = host.lower()
        return any(pattern in host_lower for pattern in self._bypass_domains)

        # ------------------------------------------------------------------
    def _relay_timeout(self):
        """زمان انتظار برای پاسخ رله (از تنظیمات یا مقدار پیش‌فرض)"""
        return AppConfig.get('relay_timeout', RELAY_TIMEOUT)

    async def relay(self, method, url, headers, body=b""):
        """مسیر اصلی رله – تشخیص خودکار حالت هم‌زمان یا تک‌اسکریپتی"""
        req_size = len(method) + len(url) + len(str(headers)) + len(body)
        self.traffic.add_up(req_size)

        if self._should_bypass(url):
            resp = await self._direct_request(method, url, headers, body)
            self.traffic.add_down(len(resp))
            return resp

        if not self._warmed:
            await self._warm_pool()

        if headers is None:
            headers = {}
        for k, v in self._extra_headers.items():
            if k not in headers:
                headers[k] = v

        payload = self._build_payload(method, url, headers, body)

        # ========== حالت پایپلاین همزمان ==========
        if AppConfig.get('concurrent_batch_enabled', True):
            return await self._concurrent_relay(payload, method, url, headers, body)

        # ========== حالت تک‌اسکریپتی (رفتار قبلی با تنظیمات داینامیک) ==========
        req_timeout = self._relay_timeout()                   # زمان‌سنجی هر درخواست
        max_retries = len(self.script_manager.scripts) if AppConfig.get('auto_switch_on_502', False) else 1
        last_error = None

        for attempt in range(max_retries):
            script_id = self._current_script_id()
            start_time = time.time()
            try:
                if self._h2 and self._h2.is_connected:
                    result = await asyncio.wait_for(
                        self._relay_single_h2(payload), timeout=req_timeout
                    )
                else:
                    async with self._semaphore:
                        result = await asyncio.wait_for(
                            self._relay_single(payload), timeout=req_timeout
                        )
                # شمارش موفقیت و ترافیک
                self.script_manager.record_success(script_id, (time.time()-start_time)*1000)
                self.traffic.add_down(len(result))
                return result

            except Exception as e:
                error_msg = f"{type(e).__name__}: {e}"
                self.script_manager.record_failure(script_id, error_msg)
                last_error = error_msg
                self.log(f"Relay error with {script_id}: {error_msg}", "error")

                if AppConfig.get('auto_switch_on_502', False):
                    new_script = self.script_manager.switch_to_healthy()
                    if new_script and new_script.id != script_id:
                        self.log(f"Auto-switched to {new_script.id}")
                        continue
                break

        err_msg = f"Relay failed after {attempt+1} attempt(s): {last_error}"
        self.log(err_msg, "error")
        return self._error_response(502, err_msg)
    async def _direct_request(self, method, url, headers, body):
        async with aiohttp.ClientSession() as session:
            async with session.request(method, url, headers=headers, data=body) as resp:
                resp_body = await resp.read()
                result = f"HTTP/1.1 {resp.status} {resp.reason}\r\n"
                for k, v in resp.headers.items():
                    if k.lower() not in ("transfer-encoding", "connection"):
                        result += f"{k}: {v}\r\n"
                result += f"Content-Length: {len(resp_body)}\r\n\r\n"
                return result.encode() + resp_body

    async def _relay_single_h2(self, payload, path=None):
        if path is None:
            path = self._exec_path()
        full_payload = dict(payload)
        json_body = json.dumps(full_payload).encode()
        status, headers, body = await self._h2.request("POST", path, self.http_host, {"content-type": "application/json"}, json_body)
        return self._parse_relay_response(body)

    async def _relay_single(self, payload, path=None):
        if path is None:
            path = self._exec_path()
        full_payload = dict(payload)
        cur = self.script_manager.get_current()
        full_payload["k"] = cur.auth_key if cur else ""
        json_body = json.dumps(full_payload).encode()
        reader, writer, created = await self._acquire()
        try:
            request = (f"POST {path} HTTP/1.1\r\n"
                       f"Host: {self.http_host}\r\n"
                       f"Content-Type: application/json\r\n"
                       f"Content-Length: {len(json_body)}\r\n"
                       f"Accept-Encoding: gzip\r\n"
                       f"Connection: keep-alive\r\n\r\n")
            writer.write(request.encode() + json_body)
            await writer.drain()
            status, resp_headers, resp_body = await self._read_http_response(reader)
            await self._release(reader, writer, created)
            return self._parse_relay_response(resp_body)
        except Exception:
            try: writer.close()
            except: pass
            raise
    async def _relay_single(self, payload):
        full_payload = dict(payload)
        cur = self.script_manager.get_current()
        full_payload["k"] = cur.auth_key if cur else ""
        json_body = json.dumps(full_payload).encode()
        path = self._exec_path()
        reader, writer, created = await self._acquire()
        try:
            request = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {self.http_host}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(json_body)}\r\n"
                f"Accept-Encoding: gzip\r\n"
                f"Connection: keep-alive\r\n\r\n"
            )
            writer.write(request.encode() + json_body)
            await writer.drain()
            status, resp_headers, resp_body = await self._read_http_response(reader)
            await self._release(reader, writer, created)
            return self._parse_relay_response(resp_body)
        except Exception:
            try: writer.close()
            except: pass
            raise

    async def _read_http_response(self, reader):
        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = await asyncio.wait_for(reader.read(8192), timeout=8)
            if not chunk: break
            raw += chunk
            if len(raw) > MAX_HEADER_BYTES: return 0, {}, b""
        if b"\r\n\r\n" not in raw: return 0, {}, b""
        hdr, body = raw.split(b"\r\n\r\n", 1)
        lines = hdr.split(b"\r\n")
        m = re.search(rb"\d{3}", lines[0])
        status = int(m.group()) if m else 0
        headers = {}
        for line in lines[1:]:
            if b":" in line:
                k, v = line.decode(errors="replace").split(":", 1)
                headers[k.strip().lower()] = v.strip()
        clen = headers.get("content-length")
        te = headers.get("transfer-encoding", "")
        if "chunked" in te:
            body = await self._read_chunked(reader, body)
        elif clen:
            remaining = int(clen) - len(body)
            while remaining > 0:
                chunk = await asyncio.wait_for(reader.read(min(remaining, 65536)), timeout=20)
                if not chunk: break
                body += chunk
                remaining -= len(chunk)
        else:
            while True:
                try:
                    chunk = await asyncio.wait_for(reader.read(65536), timeout=2)
                    if not chunk: break
                    body += chunk
                except asyncio.TimeoutError: break
        enc = headers.get("content-encoding", "")
        if enc: body = decode_body(body, enc)
        return status, headers, body

    async def _read_chunked(self, reader, buf=b""):
        result = b""
        while True:
            while b"\r\n" not in buf:
                data = await asyncio.wait_for(reader.read(8192), timeout=20)
                if not data: return result
                buf += data
            end = buf.find(b"\r\n")
            size_str = buf[:end].decode(errors="replace").strip()
            buf = buf[end+2:]
            try: size = int(size_str, 16)
            except ValueError: break
            if size == 0: break
            while len(buf) < size + 2:
                data = await asyncio.wait_for(reader.read(65536), timeout=20)
                if not data:
                    result += buf[:size]
                    return result
                buf += data
            result += buf[:size]
            buf = buf[size+2:]
        return result

    def _parse_relay_response(self, body):
        text = body.decode(errors="replace").strip()
        if not text:
            self.log("Relay response empty", "error")
            return self._error_response(502, "Empty response from relay")

        # تلاش برای تجزیه JSON
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # ثبت پاسخ خام برای عیب‌یابی
            self.log(f"Relay bad JSON: {text[:500]}", "error")
            m = re.search(r'\{.*\}', text, re.DOTALL)
            if m:
                try:
                    data = json.loads(m.group())
                except:
                    return self._error_response(502, f"Bad JSON from relay. Raw: {text[:200]}")
            else:
                return self._error_response(502, f"No JSON in relay response. Raw: {text[:200]}")
        return self._parse_relay_json(data)

    def _parse_relay_json(self, data):
        if "e" in data: return self._error_response(502, f"Relay error: {data['e']}")
        status = data.get("s", 200)
        headers = data.get("h", {})
        body = base64.b64decode(data.get("b", ""))
        result = f"HTTP/1.1 {status} OK\r\n"
        skip = {"transfer-encoding", "connection", "keep-alive", "content-length", "content-encoding"}
        for k, v in headers.items():
            if k.lower() in skip: continue
            values = v if isinstance(v, list) else [v]
            if k.lower() == "set-cookie":
                values = self._split_set_cookie(str(values))
            for val in values:
                result += f"{k}: {val}\r\n"
        result += f"Content-Length: {len(body)}\r\n\r\n"
        return result.encode() + body

    @staticmethod
    def _split_set_cookie(blob):
        if not blob: return []
        parts = re.split(r",\s*(?=[A-Za-z0-9!#$%&'*+\-.^_`|~]+=)", blob)
        return [p.strip() for p in parts if p.strip()]

    def _error_response(self, status, message):
        body = f"<html><body><h1>{status}</h1><p>{message}</p></body></html>".encode()
        return (f"HTTP/1.1 {status} Error\r\nContent-Type: text/html\r\nContent-Length: {len(body)}\r\n\r\n").encode() + body

    def get_cipher_suite_for_fingerprint(self):
        browser = AppConfig.get('browser_fingerprint', 'Chrome')
        if browser == 'Custom':
            return AppConfig.get('custom_ciphers', '')
        elif browser == 'Firefox':
            return ":".join([
                "TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256", ...
            ])
        else:  # Chrome
            return ":".join([ ... ])

    def apply_tls_fingerprint(self):
        ciphers = self.get_cipher_suite_for_fingerprint()
        curve = AppConfig.get('ecdh_curve', 'secp384r1')
        # apply to existing contexts or re-create on next connection
        # We can store these values and modify _ssl_ctx dynamically.
        self._custom_ciphers = ciphers
        self._custom_curve = curve

    def _ssl_ctx(self):
        ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        # Apply fingerprint
        ciphers = self.get_cipher_suite_for_fingerprint()
        if ciphers:
            ctx.set_ciphers(ciphers)
        curve = AppConfig.get('ecdh_curve', 'secp384r1')
        try:
            ctx.set_curves(curve)   # Python 3.6+
        except AttributeError:
            pass
        return ctx

    async def _concurrent_relay(self, payload, method, url, headers, body):
        scripts = self.script_manager.scripts
        if not scripts:
            return self._error_response(502, "No scripts configured")

        concurrency = AppConfig.get('concurrent_batch_concurrency', 0) or len(scripts)
        candidates = [s for s in scripts if s.is_online]
        if not candidates:
            candidates = scripts
        candidates = candidates[:concurrency]

        retry_count = AppConfig.get('retry_count', 1)



        delay = AppConfig.get('batch_interval', 0.0)
        tasks = []
        task_to_script = {}
        loop = asyncio.get_running_loop()

        for i, s in enumerate(candidates):
            if i > 0 and delay > 0:
                await asyncio.sleep(delay)
            p = dict(payload)
            p["k"] = s.auth_key if s.auth_key else ""
            path = f"/macros/s/{s.id}/exec"

            async def attempt(script, path, retries):
                last_error = None
                for attempt_number in range(retries):
                    try:
                        if self._h2 and self._h2.is_connected:
                            result = await asyncio.wait_for(
                                self._relay_single_h2(p, path), timeout=req_timeout
                            )
                        else:
                            result = await asyncio.wait_for(
                                self._relay_single(p, path), timeout=req_timeout
                            )
                        return result
                    except asyncio.TimeoutError:
                        last_error = Exception("Timeout")
                    except Exception as e:
                        last_error = e
                    if attempt_number < retries - 1:
                        await asyncio.sleep(0.2)
                raise last_error if last_error else Exception("All retries failed")

            t = loop.create_task(attempt(s, path, retry_count))
            tasks.append(t)
            task_to_script[t] = s







        # محدودیت زمانی هر تلاش
        req_timeout = self._relay_timeout()

        tasks = []
        task_to_script = {}
        loop = asyncio.get_running_loop()
        for s in candidates:
            p = dict(payload)
            p["k"] = s.auth_key if s.auth_key else ""
            path = f"/macros/s/{s.id}/exec"

            async def attempt(script, path, retries):
                last_error = None
                for attempt_number in range(retries):
                    try:
                        if self._h2 and self._h2.is_connected:
                            result = await asyncio.wait_for(
                                self._relay_single_h2(p, path), timeout=req_timeout
                            )
                        else:
                            result = await asyncio.wait_for(
                                self._relay_single(p, path), timeout=req_timeout
                            )
                        return result
                    except asyncio.TimeoutError:
                        last_error = Exception("Timeout")
                    except Exception as e:
                        last_error = e
                    if attempt_number < retries - 1:
                        await asyncio.sleep(0.2)
                raise last_error if last_error else Exception("All retries failed")

            t = loop.create_task(attempt(s, path, retry_count))
            tasks.append(t)
            task_to_script[t] = s

        pending = set(tasks)
        error_msgs = []
        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                try:
                    result = task.result()
                    if not (isinstance(result, bytes) and result.startswith(b"HTTP/1.1 502")):
                        self.traffic.add_down(len(result))
                        win_script = task_to_script.get(task)
                        if win_script:
                            self.script_manager.record_success(win_script.id, -1)
                        for t in pending:
                            t.cancel()
                        return result
                    else:
                        error_msgs.append(f"Script {task_to_script[task].id} returned 502 after retries")
                except Exception as e:
                    sid = task_to_script[task].id if task in task_to_script else "?"
                    error_msgs.append(f"{sid}: {e}")

        return self._error_response(502, f"All {len(candidates)} scripts failed after {retry_count} retries each: {'; '.join(error_msgs[:3])}")
# -------------------- ProxyServer --------------------
class ProxyServer:
    def __init__(self, script_manager: ScriptManager, status_callback: Callable = None):
        self.host = AppConfig.get('listen_host', '127.0.0.1')
        self.port = AppConfig.get('listen_port', 8085)
        self.socks_enabled = AppConfig.get('socks5_enabled', True)
        self.socks_port = AppConfig.get('socks5_port', 1080)
        self.status_callback = status_callback
        self.fronter = DomainFronter(script_manager, status_callback)
        self.mitm_enabled = AppConfig.get_mitm_enabled()
        self.mitm = MITMCertManager() if self.mitm_enabled else None
        self._servers = []
        self._tasks = []

    async def start(self):
        """شروع سرورها و اجرای تسک‌های serve_forever"""
        http_srv = await asyncio.start_server(
            self._on_client, self.host, self.port
        )
        self._servers.append(http_srv)
        self.log(f"HTTP proxy listening on {self.host}:{self.port}")

        socks_srv = None
        if self.socks_enabled:
            try:
                socks_srv = await asyncio.start_server(
                    self._on_socks_client, self.host, self.socks_port
                )
                self._servers.append(socks_srv)
                self.log(f"SOCKS5 proxy listening on {self.host}:{self.socks_port}")
            except OSError as e:
                self.log(f"SOCKS5 listener failed: {e}", "error")

        # ایجاد Task برای هر سرور (نه await مستقیم)
        self._tasks = [
            asyncio.create_task(srv.serve_forever()) for srv in self._servers
        ]

        try:
            # منتظر بمانیم تا یکی از تسک‌ها تمام شود یا CancelledError دریافت کنیم
            await asyncio.gather(*self._tasks)
        except asyncio.CancelledError:
            pass
        finally:
            await self._cleanup()
            
    def log(self, msg, level="info"):
        if self.status_callback:
            self.status_callback(f"[Proxy] {msg}")

    async def _cleanup(self):
        """بستن مرتب سرورها و تسک‌ها"""
        for task in self._tasks:
            if not task.done():
                task.cancel()
        # صبر برای اتمام کنسل شدن
        await asyncio.gather(*self._tasks, return_exceptions=True)

        for srv in self._servers:
            srv.close()
            await srv.wait_closed()
        self._servers.clear()
        self._tasks.clear()

    async def stop(self):
        """توقف خارجی پروکسی (از بیرون صدا زده می‌شود)"""
        self.log("Stopping proxy server...")
        for task in self._tasks:
            if not task.done():
                task.cancel()
        await self._cleanup()
        await self.fronter.close()
        self.log("Proxy server stopped")

    async def _on_client(self, reader, writer):
        try:
            first_line = await asyncio.wait_for(reader.readline(), timeout=30)
            if not first_line:
                return
            header_block = first_line
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=10)
                header_block += line
                if len(header_block) > MAX_HEADER_BYTES:
                    return
                if line in (b"\r\n", b"\n", b""):
                    break
            request_line = first_line.decode().strip()
            parts = request_line.split(" ", 2)
            if len(parts) < 2:
                return
            method = parts[0].upper()
            if method == "CONNECT":
                await self._do_connect(parts[1], reader, writer)
            else:
                await self._do_http(header_block, reader, writer)
        except (ConnectionResetError, asyncio.CancelledError):
            pass
        except Exception as e:
            self.log(f"Client error: {e}", "debug")
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _on_socks_client(self, reader, writer):
        try:
            header = await asyncio.wait_for(reader.readexactly(2), timeout=15)
            ver, nmethods = header[0], header[1]
            if ver != 5:
                return
            methods = await reader.readexactly(nmethods)
            if 0x00 not in methods:
                writer.write(b"\x05\xff")
                await writer.drain()
                return
            writer.write(b"\x05\x00")
            await writer.drain()
            req = await reader.readexactly(4)
            ver, cmd, _, atyp = req
            if ver != 5 or cmd != 0x01:
                writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                return
            if atyp == 0x01:
                host = socket.inet_ntoa(await reader.readexactly(4))
            elif atyp == 0x03:
                ln = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(ln)).decode()
            elif atyp == 0x04:
                host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
            else:
                return
            port = int.from_bytes(await reader.readexactly(2), "big")
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            await self._handle_target_tunnel(host, port, reader, writer)
        except Exception as e:
            if "ConnectionResetError" not in str(e):
                self.log(f"SOCKS5 error: {e}", "debug")
        finally:
            # بستن و پایان دادن بی‌صدا
            try:
                writer.close()
            except Exception:
                pass
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=2)
            except Exception:
                pass

    async def _do_connect(self, target, reader, writer):
        host, _, port_str = target.rpartition(":")
        try: port = int(port_str) if port_str else 443
        except ValueError:
            writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            await writer.drain()
            return
        if not host: host, port = target, 443
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        await self._handle_target_tunnel(host, port, reader, writer)

    async def _handle_target_tunnel(self, host, port, reader, writer):
        if port == 443:
            await self._do_mitm_connect(host, port, reader, writer)
        elif port == 80:
            await self._do_plain_http_tunnel(host, port, reader, writer)
        else:
            await self._do_direct_tunnel(host, port, reader, writer)

    async def _do_mitm_connect(self, host, port, reader, writer):
        if not self.mitm_enabled or not self.mitm:
            await self._do_direct_tunnel(host, port, reader, writer)
            return

        ssl_ctx = self.mitm.get_server_context(host)
        loop = asyncio.get_running_loop()
        transport = writer.transport
        protocol = transport.get_protocol()
        try:
            new_transport = await loop.start_tls(transport, protocol, ssl_ctx, server_side=True)
            writer._transport = new_transport
            self.log(f"TLS handshake successful for {host}")
        except Exception as e:
            self.log(f"TLS handshake failed for {host}: {e}", "debug")
            writer.close()
            return

        # --- تشخیص غیر HTTP ---
        try:
            # peek first bytes without consuming
            first_bytes = await asyncio.wait_for(reader.read(4), timeout=3)
            if first_bytes and not first_bytes.decode(errors='ignore').startswith(('GET ', 'POST', 'PUT ', 'HEAD', 'OPTI', 'DELE', 'PATC', 'CONN')):
                self.log(f"Non-HTTP traffic on {host}:{port} – switching to raw tunnel")
                # ساختن یک StreamReader با all data (first_bytes + rest)
                # best approach: use asyncio.StreamReader with loop
                raw_reader = asyncio.StreamReader()
                raw_reader.feed_data(first_bytes)
                # ادامه را هم feed کنیم؟ برای سادگی، تونل مستقیم از همینجا شروع کنیم
                # اما reader/writer موجود دیگر قابل استفاده مستقیم نیستند چون TLS شده اند.
                # بنابراین بهتر است پیش از TLS این تشخیص انجام شود.
                # راه دیگر: اضافه کردن reader.peek قبل از start_tls
                # برای حل سریع تر: می توانیم host/port های غیر HTTP را در همان ابتدای _handle_target_tunnel بررسی کنیم.
                # پس تغییر را به _handle_target_tunnel منتقل می‌کنیم.
                pass
        except (asyncio.TimeoutError, UnicodeDecodeError):
            self.log(f"Timeout/Invalid data on {host}:{port} – treating as raw tunnel")

        await self._relay_http_stream(host, port, reader, writer)

    async def _do_plain_http_tunnel(self, host, port, reader, writer):
        await self._relay_http_stream(host, port, reader, writer)

    async def _relay_http_stream(self, host, port, reader, writer):
        while True:
            try:
                first_line = await asyncio.wait_for(reader.readline(), timeout=CLIENT_IDLE_TIMEOUT)
                if not first_line:
                    break
                header_block = first_line
                while True:
                    line = await asyncio.wait_for(reader.readline(), timeout=10)
                    header_block += line
                    if line in (b"\r\n", b"\n", b""):
                        break
                body = b""
                length = _parse_content_length(header_block)
                if length > 0:
                    body = await reader.readexactly(length)
                request_line = first_line.decode().strip()
                parts = request_line.split(" ", 2)
                method = parts[0]
                path = parts[1] if len(parts) > 1 else "/"
                headers = {}
                for raw_line in header_block.split(b"\r\n")[1:]:
                    if b":" in raw_line:
                        k, v = raw_line.decode(errors="replace").split(":", 1)
                        headers[k.strip()] = v.strip()
                if path.startswith("http://") or path.startswith("https://"):
                    url = path
                elif port == 443:
                    url = f"https://{host}{path}"
                elif port == 80:
                    url = f"http://{host}{path}"
                else:
                    url = f"http://{host}:{port}{path}"
                try:
                    response = await self.fronter.relay(method, url, headers, body)
                except Exception as e:
                    self.log(f"Relay error: {e}", "error")
                    err = f"Relay error: {e}".encode()
                    response = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: " + str(len(err)).encode() + b"\r\n\r\n" + err
                writer.write(response)
                await writer.drain()
            except (ConnectionResetError, asyncio.CancelledError):
                break
            except Exception as e:
                self.log(f"Stream error: {e}", "debug")
                break

    async def _do_http(self, header_block, reader, writer):
        body = b""
        length = _parse_content_length(header_block)
        if length > 0:
            body = await reader.readexactly(length)
        first_line = header_block.split(b"\r\n")[0].decode()
        parts = first_line.strip().split(" ", 2)
        method = parts[0]
        url = parts[1] if len(parts) > 1 else "/"
        headers = {}
        for raw_line in header_block.split(b"\r\n")[1:]:
            if b":" in raw_line:
                k, v = raw_line.decode(errors="replace").split(":", 1)
                headers[k.strip()] = v.strip()
        try:
            response = await self.fronter.relay(method, url, headers, body)
        except Exception as e:
            err = f"Relay error: {e}".encode()
            response = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: " + str(len(err)).encode() + b"\r\n\r\n" + err
        writer.write(response)
        await writer.drain()

# -------------------- رابط کاربری Kivy --------------------
class StatusBar(Label):
    """نوار وضعیت در پایین صفحه"""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.size_hint_y = None
        self.height = dp(30)
        self.text = "Ready"
        self.halign = 'left'
        self.valign = 'middle'
        self.text_size = (None, self.height)

    def update(self, text):
        self.text = text

class ProxyTab(BoxLayout):
    status_text = StringProperty("Ready")
    is_running = BooleanProperty(False)
    proxy_url = StringProperty("http://127.0.0.1:8085")

    def __init__(self, app, **kwargs):
        super().__init__(orientation='vertical', **kwargs)
        self.app = app
        self.proxy_server = None
        self.loop_thread = None
        self.asyncio_loop = None
        self.log_queue = queue.Queue()
        self.build_ui()
        Clock.schedule_interval(self.update_stats, 1.0)

    def build_ui(self):
        # دکمه Start/Stop
        self.toggle_btn = ToggleButton(
            text='START PROXY', font_size='30sp', size_hint=(1, 0.15),
            background_color=get_color_from_hex('#4CAF50')
        )
        self.toggle_btn.bind(state=self.on_toggle)
        self.add_widget(self.toggle_btn)

        # نمایش سرعت
        speed_box = BoxLayout(orientation='horizontal', size_hint_y=0.1)
        left_box = BoxLayout(orientation='vertical')
        self.down_label = Label(text='↓ 0 KB/s', halign='center')
        self.down_total_label = Label(text='0 MB', font_size='10sp', halign='center')
        left_box.add_widget(self.down_label)
        left_box.add_widget(self.down_total_label)
        right_box = BoxLayout(orientation='vertical')
        self.up_label = Label(text='↑ 0 KB/s', halign='center')
        self.up_total_label = Label(text='0 MB', font_size='10sp', halign='center')
        right_box.add_widget(self.up_label)
        right_box.add_widget(self.up_total_label)
        speed_box.add_widget(left_box)
        speed_box.add_widget(right_box)
        self.add_widget(speed_box)   

        # اطلاعات پروکسی
        info = BoxLayout(orientation='horizontal', size_hint_y=0.1)
        info.add_widget(Label(text='Proxy Address:'))
        self.addr_label = Label(text=self.proxy_url, halign='left')
        info.add_widget(self.addr_label)
        copy_btn = Button(text='Copy', size_hint_x=0.2)
        copy_btn.bind(on_press=self.copy_address)
        info.add_widget(copy_btn)
        self.add_widget(info)

        # وضعیت لاگ کوتاه
        self.status_bar = StatusBar()
        self.add_widget(self.status_bar)

    def log(self, msg):
        self.status_bar.update(msg)
        # همچنین به تب Logs ارسال شود
        if hasattr(self.app, 'logs_tab'):
            self.app.logs_tab.add_log(msg)

    def on_toggle(self, instance, value):
        if value == 'down':
            self.start_proxy()
            instance.text = 'STOP PROXY'
            instance.background_color = get_color_from_hex('#F44336')
        else:
            self.stop_proxy()
            instance.text = 'START PROXY'
            instance.background_color = get_color_from_hex('#4CAF50')

    def start_proxy(self):
        if self.is_running: return
        AppConfig.set('listen_host', '0.0.0.0')
        AppConfig.set('listen_port', int(self.app.settings_tab.port_input.text))
        AppConfig.set('socks5_port', int(self.app.settings_tab.socks_port_input.text))
        self.is_running = True
        self.status_text = "Starting proxy..."
        self.proxy_url = f"http://{self.get_local_ip()}:{self.app.settings_tab.port_input.text}"
        self.addr_label.text = self.proxy_url
        self.loop_thread = threading.Thread(target=self.run_asyncio_loop, daemon=True)
        self.loop_thread.start()

    def get_local_ip(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(('8.8.8.8', 80))
                return s.getsockname()[0]
        except: return '127.0.0.1'

    def run_asyncio_loop(self):
        self.asyncio_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.asyncio_loop)
        try:
            self.asyncio_loop.run_until_complete(self.run_proxy())
        except Exception as e:
            Clock.schedule_once(lambda dt: self.log(f"Fatal error: {e}"))
        finally:
            # پاکسازی تسک‌های باقی‌مانده
            try:
                pending = asyncio.all_tasks(self.asyncio_loop)
                for task in pending:
                    task.cancel()
                self.asyncio_loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            except:
                pass
            self.asyncio_loop.close()
            self.is_running = False
            # به‌روزرسانی UI در نخ اصلی
            Clock.schedule_once(lambda dt: setattr(self.toggle_btn, 'state', 'normal'))
            Clock.schedule_once(lambda dt: setattr(self.toggle_btn, 'text', 'START PROXY'))
            Clock.schedule_once(lambda dt: setattr(self.toggle_btn, 'background_color', get_color_from_hex('#4CAF50')))
            Clock.schedule_once(lambda dt: self.log("Proxy stopped"))

    async def run_proxy(self):
        self.log("MasterHttpRelayVPN starting...")
        self.proxy_server = ProxyServer(self.app.script_manager, self.log)
        try:
            await self.proxy_server.start()
        except Exception as e:
            self.log(f"Proxy error: {e}")

    def stop_proxy(self):
        """متوقف کردن پروکسی از رابط کاربری"""
        if not self.is_running:
            return
        self.log("Stopping proxy...")
        self.is_running = False

        # 1. اگر سرور و حلقه وجود دارد و حلقه بسته نیست ...
        if self.proxy_server and self.asyncio_loop and not self.asyncio_loop.is_closed():
            async def shutdown():
                await self.proxy_server.stop()
            try:
                # اجرای shutdown در همان حلقه (هم‌اکنون حلقه در نخ asyncio در حال اجراست)
                future = asyncio.run_coroutine_threadsafe(shutdown(), self.asyncio_loop)
                future.result(timeout=5)   # منتظر بمانیم تا توقف کامل شود
            except Exception as e:
                self.log(f"Shutdown error: {e}")

            # 2. متوقف کردن خود حلقه (stop باعث خروج از run_until_complete می‌شود)
            self.asyncio_loop.call_soon_threadsafe(self.asyncio_loop.stop)

        # 3. صبر برای اتمام نخ asyncio
        if self.loop_thread and self.loop_thread.is_alive():
            self.loop_thread.join(timeout=2)

        # 4. بازنشانی UI
        self.toggle_btn.state = 'normal'
        self.toggle_btn.text = 'START PROXY'
        self.toggle_btn.background_color = get_color_from_hex('#4CAF50')
        self.log("Proxy stopped")

    def update_stats(self, dt):
        if not self.proxy_server or not self.proxy_server.fronter:
            return
        traffic = self.proxy_server.fronter.traffic
        if not traffic:
            return
        try:
            down_speed, up_speed = traffic.get_speeds()
            self.down_label.text = f"↓ {self._format_speed(down_speed)}"
            self.up_label.text = f"↑ {self._format_speed(up_speed)}"
            total_down = traffic.total_down_bytes / (1024 * 1024)
            total_up = traffic.total_up_bytes / (1024 * 1024)
            self.down_total_label.text = f"{total_down:.2f} MB"
            self.up_total_label.text = f"{total_up:.2f} MB"
        except Exception:
            pass

    def _format_speed(self, bps):
        if bps < 1024: return f"{bps:.0f} B/s"
        elif bps < 1024*1024: return f"{bps/1024:.1f} KB/s"
        else: return f"{bps/(1024*1024):.2f} MB/s"

    def copy_address(self, instance):
        Clipboard.copy(self.proxy_url)
        self.log("Address copied to clipboard")



class ConfigTab(BoxLayout):
    def __init__(self, app, **kwargs):
        super().__init__(orientation='vertical', **kwargs)
        self.app = app
        self.selected_ids = set()
        self.build_ui()
        self.refresh_list()
        self.app.script_manager.register_active_callback(self.refresh_list)
        Clock.schedule_interval(self._update_proxy_stats, 1.0)

    def build_ui(self):
        # ---- Top bar (Select All + menu) ----
        top_bar = BoxLayout(size_hint_y=None, height=dp(40), spacing=dp(5), padding=dp(2))
        self.sel_all_btn = ToggleButton(text='Select All', size_hint_x=0.3)
        self.sel_all_btn.bind(on_press=self.toggle_select_all)
        top_bar.add_widget(self.sel_all_btn)

        self.menu_btn = Button(text='⋮', size_hint_x=None, width=dp(40), font_size=dp(18))
        self.menu_btn.bind(on_press=self.open_menu)
        top_bar.add_widget(self.menu_btn)
        self.add_widget(top_bar)

        # Search box
        search_box = BoxLayout(size_hint_y=None, height=dp(40), spacing=dp(5))
        self.search_input = TextInput(hint_text='Search...', size_hint_x=0.7)
        self.search_input.bind(text=self.on_search_text)
        search_box.add_widget(self.search_input)
        self.add_widget(search_box)

        # --- List ---
        self.scroll = ScrollView(size_hint=(1, 1), do_scroll_x=True, do_scroll_y=True)
        self.ids_grid = BoxLayout(orientation='vertical', spacing=dp(2),
                                  size_hint_x=None, size_hint_y=None)
        self.ids_grid.bind(minimum_height=self.ids_grid.setter('height'))
        def adjust_width(instance, width):
            self.ids_grid.width = max(width, self.ids_grid.minimum_width)
        self.scroll.bind(width=adjust_width)
        self.scroll.add_widget(self.ids_grid)
        self.add_widget(self.scroll)

        # Add script section
        add_box = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(5))
        self.new_name_input = TextInput(hint_text='Name', size_hint_x=0.2, size_hint_y=None, height=dp(44))
        self.new_id_input = TextInput(hint_text='Script ID', size_hint_x=0.35, size_hint_y=None, height=dp(44))
        self.new_key_input = TextInput(hint_text='Auth Key', size_hint_x=0.25, size_hint_y=None, height=dp(44))
        add_btn = Button(text='Add', size_hint_x=0.15)
        add_btn.bind(on_press=self.add_script)
        add_box.add_widget(self.new_name_input)
        add_box.add_widget(self.new_id_input)
        add_box.add_widget(self.new_key_input)
        add_box.add_widget(add_btn)
        self.add_widget(add_box)

        # --- Bottom bar (speed + proxy button) ---
        bottom_bar = BoxLayout(size_hint_y=None, height=dp(60), spacing=dp(8), padding=dp(5))
        speed_box = BoxLayout(orientation='vertical', size_hint_x=0.5)
        self.down_label = Label(text='↓ 0 KB/s', halign='left', font_size=dp(12))
        self.down_total_label = Label(text='0 MB', font_size=dp(10), halign='left')
        self.up_label = Label(text='↑ 0 KB/s', halign='left', font_size=dp(12))
        self.up_total_label = Label(text='0 MB', font_size=dp(10), halign='left')
        down_line = BoxLayout()
        down_line.add_widget(self.down_label)
        down_line.add_widget(self.down_total_label)
        up_line = BoxLayout()
        up_line.add_widget(self.up_label)
        up_line.add_widget(self.up_total_label)
        speed_box.add_widget(down_line)
        speed_box.add_widget(up_line)
        bottom_bar.add_widget(speed_box)

        self.proxy_btn = Button(size_hint=(None, None), size=(dp(50), dp(50)),
                                pos_hint={'center_y': 0.5})
        self.proxy_btn.bind(on_press=self.toggle_proxy)
        self._init_proxy_button()
        bottom_bar.add_widget(self.proxy_btn)
        self.add_widget(bottom_bar)

     # ---------- دکمهٔ پروکسی (دایره‌ای با مثلث/مربع) ----------
    def _init_proxy_button(self):
        from kivy.graphics import Color, Ellipse, Mesh, Rectangle
        btn = self.proxy_btn
        btn.background_normal = ''
        btn.background_down = ''
        btn.background_color = (0, 0, 0, 0)   # کاملاً شفاف

        with btn.canvas.before:
            # دایرهٔ پس‌زمینه
            self._circle_color = Color(0.5, 0.5, 0.5, 1)   # خاکستری
            self._circle = Ellipse(size=btn.size, pos=btn.pos)
            btn.bind(pos=self._update_circle, size=self._update_circle)

            # مثلث Play (سفید)
            self._play_color = Color(1, 1, 1, 1)
            self._play_shape = Mesh(
                mode='triangle_fan',
                vertices=[0,0,0,0, 0,0,0,0, 0,0,0,0],
                indices=[0,1,2],
                fmt=[(b'vPos', 2, 'float')]
            )
            btn.bind(size=self._update_play_shape, pos=self._update_play_shape)

            # مربع Stop (مخفی در آغاز)
            self._stop_color = Color(1, 1, 1, 1)
            self._stop_shape = Rectangle(size=(0, 0), pos=(0, 0))
            btn.bind(size=self._update_stop_shape, pos=self._update_stop_shape)

        # مقداردهی اولیه بر اساس اندازهٔ فعلی (اگر بزرگ‌تر از صفر بود)
        if btn.width > 0 and btn.height > 0:
            self._update_circle(btn)
            self._update_play_shape(btn)
            self._update_stop_shape(btn)

        # نمایش مثلث (play) در حالت اولیه
        self._show_play_symbol(btn)

        # به‌روزرسانی نهایی بعد از اینکه layout کامل شد
        Clock.schedule_once(lambda dt: self._update_play_shape(btn), 0)
        Clock.schedule_once(lambda dt: self._update_stop_shape(btn), 0)

    def _update_circle(self, btn, *args):
        self._circle.size = btn.size
        self._circle.pos = btn.pos

    def _update_play_shape(self, btn, *args):
        """مثلث رو به راست"""
        cx, cy = btn.center_x, btn.center_y
        s = min(btn.width, btn.height) * 0.45
        p1 = (cx - s*0.5, cy - s*0.7)
        p2 = (cx - s*0.5, cy + s*0.7)
        p3 = (cx + s*0.7, cy)
        btn.play_shape = self._play_shape
        self._play_shape.vertices = [p1[0], p1[1], 0, 0, p2[0], p2[1], 0, 0, p3[0], p3[1], 0, 0]

    def _show_stop_symbol(self, btn):
        self._play_color.rgba = (0, 0, 0, 0)       # مثلث ناپدید شود
        self._stop_color.rgba = (1, 1, 1, 1)       # مربع ظاهر شود

    def _show_play_symbol(self, btn):
        self._play_color.rgba = (1, 1, 1, 1)       # مثلث نمایان شود
        self._stop_color.rgba = (0, 0, 0, 0)       # مربع ناپدید شود

    def _update_stop_shape(self, btn, *args):
        w = btn.width * 0.4
        h = btn.height * 0.4
        self._stop_shape.size = (w, h)
        self._stop_shape.pos = (btn.center_x - w/2, btn.center_y - h/2)

    def toggle_proxy(self, instance):
        proxy_tab = self.app.proxy_tab
        if not proxy_tab.is_running:
            try:
                proxy_tab.start_proxy()
                self._show_stop_symbol(instance)
                # --- direct color change (replacement for set_proxy_btn_color) ---
                self._circle_color.rgba = (0, 0.8, 0, 1)   # green
            except Exception:
                self._circle_color.rgba = (1, 0, 0, 1)     # red
        else:
            proxy_tab.stop_proxy()
            self._show_play_symbol(instance)
            self._circle_color.rgba = (0.5, 0.5, 0.5, 1)   # grey

    # ---------- به‌روزرسانی سرعت ----------
    def _update_proxy_stats(self, dt):
        proxy_tab = self.app.proxy_tab
        if proxy_tab.is_running and proxy_tab.proxy_server:
            traffic = proxy_tab.proxy_server.fronter.traffic
            if traffic:
                down_speed, up_speed = traffic.get_speeds()
                self.down_label.text = f"↓ {self._format_speed(down_speed)}"
                self.up_label.text = f"↑ {self._format_speed(up_speed)}"
                total_down = traffic.total_down_bytes / (1024*1024)
                total_up = traffic.total_up_bytes / (1024*1024)
                self.down_total_label.text = f"{total_down:.2f} MB"
                self.up_total_label.text = f"{total_up:.2f} MB"
        else:
            self.down_label.text = '↓ 0 KB/s'
            self.up_label.text = '↑ 0 KB/s'
            self.down_total_label.text = '0 MB'
            self.up_total_label.text = '0 MB'

    # ---------- جستجو و ردیف‌ها ----------
    def on_search_text(self, instance, value):
        Clock.unschedule(self._do_search)
        Clock.schedule_once(lambda dt: self._do_search(value), 0.15)

    def _do_search(self, query):
        self.ids_grid.clear_widgets()
        q = query.strip().lower()
        active_id = None
        cur = self.app.script_manager.get_current()
        if cur:
            active_id = cur.id
        for script in self.app.script_manager.scripts:
            if q and q not in script.name.lower() and q not in script.id.lower():
                continue
            self._add_row(script, active_id)

    def _add_row(self, script, active_id):
        row = BoxLayout(spacing=dp(2), size_hint_y=None, height=dp(44))
        # انتخاب
        is_sel = script.id in self.selected_ids
        sel_btn = ToggleButton(text='✓' if is_sel else '', size_hint_x=None, width=dp(30), font_size=dp(14))
        sel_btn.state = 'down' if is_sel else 'normal'
        sel_btn.script_id = script.id
        sel_btn.bind(on_press=self.toggle_selection)
        row.add_widget(sel_btn)

        # نام
        lbl_name = Label(text=script.name[:12] if script.name else script.id[:12],
                         size_hint_x=2, halign='left', valign='middle', font_size=dp(13))
        row.add_widget(lbl_name)

        # شمارندهٔ درخواست‌ها
        total_req = script.success_count + script.fail_count
        lbl_req = Label(text=f"#{total_req}", size_hint_x=0.5, halign='center', font_size=dp(11))
        row.add_widget(lbl_req)

        # پینگ
        ping_text = f"{script.last_latency:.0f}ms" if script.last_latency > 0 else ("Off" if not script.is_online else "N/A")
        lbl_ping = Label(text=ping_text, size_hint_x=1, halign='center', font_size=dp(12))
        row.add_widget(lbl_ping)

         # دکمهٔ Active فقط در حالت غیرهمزمان نشان داده شود
        if not AppConfig.get('concurrent_batch_enabled', True):
            is_active = (script.id == active_id)
            if is_active:
                active_btn = Button(
                    text='● Active',
                    size_hint_x=None, width=dp(85),
                    background_color=(0.2, 0.8, 0.2, 1),
                    color=(1,1,1,1), font_size=dp(11),
                    halign='center', valign='middle'
                )
            else:
                active_btn = Button(
                    text='○ Set Active',
                    size_hint_x=None, width=dp(85),
                    background_color=(0.3,0.3,0.3,1),
                    color=(1,1,1,1), font_size=dp(11),
                    halign='center', valign='middle'
                )
            active_btn.script_id = script.id
            active_btn.bind(on_press=self.toggle_active)
            row.add_widget(active_btn)

        # دکمهٔ پینگ
        ping_btn = Button(text='Ping', size_hint_x=None, width=dp(45), font_size=dp(11))
        ping_btn.script_id = script.id
        ping_btn.bind(on_press=self.ping_single)
        row.add_widget(ping_btn)

        # حذف
        remove_btn = Button(text='X', size_hint_x=None, width=dp(35), font_size=dp(11))
        remove_btn.script_id = script.id
        remove_btn.bind(on_press=self.remove_script)
        row.add_widget(remove_btn)

        self.ids_grid.add_widget(row)

    def refresh_list(self, *args):
        query = self.search_input.text if self.search_input else ''
        self._do_search(query)
        total = len(self.app.script_manager.scripts)
        self.sel_all_btn.text = 'Deselect All' if total > 0 and len(self.selected_ids) == total else 'Select All'

    # ---------- انتخاب ----------
    def toggle_selection(self, instance):
        sid = instance.script_id
        if sid in self.selected_ids:
            self.selected_ids.remove(sid)
        else:
            self.selected_ids.add(sid)
        self.refresh_list()

    def toggle_select_all(self, instance):
        if len(self.selected_ids) == len(self.app.script_manager.scripts) > 0:
            self.selected_ids.clear()
        else:
            for s in self.app.script_manager.scripts:
                self.selected_ids.add(s.id)
        self.refresh_list()

    # ---------- منوی سه‌نقطه ----------
    def open_menu(self, instance):
        content = BoxLayout(orientation='vertical', spacing=dp(5), padding=dp(10))
        # دکمه‌های عملیات
        for text, func in [
            ('Ping All', self.ping_all),
            ('Sort by Ping', self.sort_by_ping),
            ('Copy Selected Configs', self.copy_selected_configs),
            ('Copy All Configs', self.export_config),
            ('Remove Duplicates', self.remove_duplicates),
            ('Import Config', self.import_list),
            ('Delete All Configs', self.delete_all_configs)
        ]:
            btn = Button(text=text, size_hint_y=None, height=dp(44))
            btn.bind(on_press=lambda x, f=func: self._menu_action(f))
            content.add_widget(btn)

        

        socks_box = BoxLayout(orientation='horizontal', size_hint_y=None, height=dp(44), spacing=dp(10))
        socks_box.add_widget(Label(text='SOCKS5 proxy:'))
        self.socks_switch = Switch(active=AppConfig.get('socks5_enabled', True))
        self.socks_switch.bind(active=self.on_socks_switch)
        socks_box.add_widget(self.socks_switch)
        content.add_widget(socks_box)

        self._popup = Popup(title='Menu', content=content, size_hint=(0.6, 0.7))
        self._popup.open()

    def _menu_action(self, func):
        if self._popup:
            self._popup.dismiss()
        func()

    # عملیات جدید
    def copy_selected_configs(self):
        if not self.selected_ids:
            self.app.show_status("No configs selected")
            return
        lines = []
        for s in self.app.script_manager.scripts:
            if s.id in self.selected_ids:
                name_part = s.name if s.name else ""
                line = f"{name_part}:id={s.id}&key={s.auth_key}"
                lines.append(line)
        Clipboard.copy('\n'.join(lines))
        self.app.show_status(f"Copied {len(lines)} config(s)")

    def delete_all_configs(self):
        if not self.app.script_manager.scripts:
            self.app.show_status("No configs to delete")
            return

        from kivy.uix.popup import Popup
        from kivy.metrics import dp

        content = BoxLayout(orientation='vertical', spacing=dp(10), padding=dp(10))
        content.add_widget(Label(text='Delete ALL script configurations?', size_hint_y=None, height=dp(40)))

        btn_box = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(10))
        yes_btn = Button(text='Yes, delete all')
        no_btn = Button(text='Cancel')
        btn_box.add_widget(yes_btn)
        btn_box.add_widget(no_btn)
        content.add_widget(btn_box)

        # محاسبه ارتفاع واقعی محتوا
        content.height = dp(40) + dp(10) + dp(50) + 2*dp(10)   # برچسب + فاصله + دکمه‌ها + پدینگ
        content.size_hint_y = None

        popup = Popup(title='Confirm', content=content, size_hint=(0.8, None), height=content.height + dp(50),
                      auto_dismiss=False)
        def do_delete(instance):
            self.app.script_manager.scripts.clear()
            self.app.script_manager.current_index = 0
            self.app.script_manager.save_to_config()
            self.selected_ids.clear()
            self.refresh_list()
            self.app.show_status("All configs deleted")
            popup.dismiss()
        yes_btn.bind(on_press=do_delete)
        no_btn.bind(on_press=popup.dismiss)
        popup.open()

    def on_socks_switch(self, instance, value):
        AppConfig.set('socks5_enabled', value)
        self.app.show_status(f"SOCKS5 proxy {'enabled' if value else 'disabled'} (restart proxy)")

    def on_auto_switch(self, instance, value):
        AppConfig.set("auto_switch_on_502", value)
        self.app.show_status(f"Auto switch {'enabled' if value else 'disabled'}")

    # ---------- افزودن / وارد کردن / خروجی ----------
    def add_script(self, instance):
        sid = self.new_id_input.text.strip()
        key = self.new_key_input.text.strip()
        name = self.new_name_input.text.strip()
        if sid:
            self.app.script_manager.add_script(sid, key, name)
            self.new_id_input.text = ''
            self.new_key_input.text = ''
            self.new_name_input.text = ''
            self.refresh_list()
            self.app.show_status(f"Added {sid}")

    def import_list(self, instance=None):
        text = Clipboard.paste()
        if not text:
            self.app.show_status("Clipboard is empty")
            return
        count = 0
        for line in text.split('\n'):
            if not line.strip():
                continue
            parts = line.strip().split(':')
            name = parts[0] if parts else ""
            rest = parts[1] if len(parts) > 1 else ""
            params = {}
            for param in rest.split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    params[k.strip()] = v.strip()
            if 'id' in params:
                self.app.script_manager.add_script(params['id'], params.get('key', ''), name)
                count += 1
        self.refresh_list()
        self.app.show_status(f"Imported {count} IDs")

    def export_config(self, instance=None):
        lines = [f"{s.name or ''}:id={s.id}&key={s.auth_key}" for s in self.app.script_manager.scripts]
        Clipboard.copy('\n'.join(lines))
        self.app.show_status("All configs copied")

    def remove_duplicates(self, instance=None):
        seen = set()
        to_remove = []
        for s in self.app.script_manager.scripts:
            if s.id in seen:
                to_remove.append(s.id)
            else:
                seen.add(s.id)
        for sid in to_remove:
            self.app.script_manager.remove_script(sid)
        self.refresh_list()
        self.app.show_status(f"Removed {len(to_remove)} duplicates")

    # ---------- فعال‌سازی اسکریپت ----------
    def toggle_active(self, instance):
        self.app.script_manager.set_current_by_id(instance.script_id)
        self.refresh_list()
        self.app.show_status(f"Switched to {instance.script_id}")

    # ---------- پینگ ----------
    def ping_single(self, instance):
        sid = instance.script_id
        self.app.show_status(f"Pinging {sid}...")
        def run_ping():
            async def task():
                latency = await self.app.script_manager.ping_tcp(sid)
                Clock.schedule_once(lambda dt: self._ping_done(sid, latency))
            try:
                asyncio.run(task())
            except Exception as e:
                Clock.schedule_once(lambda dt: self.app.show_status(f"Ping error: {e}"))
        threading.Thread(target=run_ping, daemon=True).start()

    def _ping_done(self, sid, lat):
        self.refresh_list()
        status = f"{lat:.1f}ms" if lat > 0 else "Failed"
        self.app.show_status(f"{sid} ping: {status}")

    def ping_all(self, instance=None):
        self.app.show_status("Pinging all scripts...")
        def run_ping():
            async def task():
                for s in self.app.script_manager.scripts:
                    await self.app.script_manager.ping_tcp(s.id)
                Clock.schedule_once(lambda dt: self.refresh_list())
                Clock.schedule_once(lambda dt: self.app.show_status("Ping completed"))
            try:
                asyncio.run(task())
            except Exception as e:
                Clock.schedule_once(lambda dt: self.app.show_status(f"Ping error: {e}"))
        threading.Thread(target=run_ping, daemon=True).start()

    def remove_script(self, instance):
        self.app.script_manager.remove_script(instance.script_id)
        self.selected_ids.discard(instance.script_id)
        self.refresh_list()
        self.app.show_status(f"Removed {instance.script_id}")

    def sort_by_ping(self, instance=None):
        self.app.script_manager.scripts.sort(key=lambda s: s.last_latency if s.last_latency > 0 else 999999)
        self.refresh_list()
        self.app.show_status("Scripts sorted by lowest ping")

    def _format_speed(self, bps):
        if bps < 1024:
            return f"{bps:.0f} B/s"
        elif bps < 1024*1024:
            return f"{bps/1024:.1f} KB/s"
        else:
            return f"{bps/(1024*1024):.2f} MB/s"












class SettingsTab(BoxLayout):
    def __init__(self, app, **kwargs):
        super().__init__(orientation='vertical', **kwargs)
        self.app = app
        self.build_ui()
        self.load_settings()

        Clock.schedule_interval(self._update_concurrency_range, 2.0)

    def _update_concurrency_range(self, dt):
        if hasattr(self, 'concurrency_slider'):
            max_scripts = len(self.app.script_manager.scripts) or 1
            self.concurrency_slider.max = max_scripts
            if self.concurrency_slider.value > max_scripts:
                self.concurrency_slider.value = max_scripts

    def build_ui(self):
        scroll = ScrollView(size_hint=(1, 1))
        container = GridLayout(cols=2, size_hint_y=None, spacing=dp(10), padding=dp(10))
        container.bind(minimum_height=container.setter('height'))

        # ---------- Launch at system startup (macOS) ----------
        self.launch_startup_switch = Switch(active=False)   # مقدار واقعی را با AppleScript چک می‌کنیم
        container.add_widget(Label(text='Launch at system startup:', size_hint_y=None, height=dp(40)))
        container.add_widget(self.launch_startup_switch)
        self.launch_startup_switch.bind(active=self.on_launch_startup)

        # ---------- General Network ----------
        self.listen_addr_input = TextInput(text='127.0.0.1', size_hint_y=None, height=dp(44))
        self._add_field(container, 'Listen Address:',
            "IP address the proxy binds to.\n- 127.0.0.1 = only local device\n- 0.0.0.0 = all LAN devices",
            self.listen_addr_input)

        self.port_input = TextInput(text='8085', size_hint_y=None, height=dp(44))
        self._add_field(container, 'Listen Port:',
            "TCP port for the HTTP proxy.\nDefault 8085 works in most cases.",
            self.port_input)

        self.socks_port_input = TextInput(text='1080', size_hint_y=None, height=dp(44))
        self._add_field(container, 'SOCKS5 Port:',
            "TCP port for the SOCKS5 proxy.\nDefault 1080 is the standard SOCKS port. Set to 0 to disable SOCKS5.",
            self.socks_port_input)

        # ---------- Relay Engine ----------
        self.google_ip_input = TextInput(text='216.239.38.120', size_hint_y=None, height=dp(44))
        self._add_field(container, 'Google IP:',
            "IP address of the Google server used for domain fronting.\n216.239.38.120 is a stable anycast IP for script.google.com.",
            self.google_ip_input)

        self.front_domain_input = TextInput(text='www.google.com', size_hint_y=None, height=dp(44))
        self._add_field(container, 'Front Domain:',
            "SNI (Server Name Indication) sent during TLS handshake.\nMust be a Google domain (like www.google.com) to bypass censorship.",
            self.front_domain_input)

        # ---------- Concurrent Batch ----------
        self.concurrent_switch = Switch(active=AppConfig.get('concurrent_batch_enabled', True))
        container.add_widget(Label(text='Enable Concurrent Batch:', size_hint_y=None, height=dp(40)))
        container.add_widget(self.concurrent_switch)
        self.concurrent_switch.bind(active=self.on_concurrent_switch)

        # Seek bar for concurrency
        self.concurrency_slider = Slider(min=1, max=10, value=AppConfig.get('concurrent_batch_concurrency', 1),
                                         step=1, size_hint_y=None, height=dp(1),
                                         disabled=not AppConfig.get('concurrent_batch_enabled', True))
        self.concurrency_label = Label(text=str(int(self.concurrency_slider.value)), size_hint_y=None, height=dp(30),
                                       halign='center', valign='middle')
        # به‌روزرسانی برچسب هنگام حرکت اسلایدر
        self.concurrency_slider.bind(value=lambda inst, val: setattr(self.concurrency_label, 'text', str(int(val))))

        # چیدمان افقی: برچسب + اسلایدر
        slider_row = BoxLayout(orientation='vertical', spacing=dp(2))
        slider_row.add_widget(Label(text='Concurrency (scripts in parallel):', size_hint_y=None, height=dp(25)))
        slider_row.add_widget(self.concurrency_slider)
        slider_row.add_widget(self.concurrency_label)

        container.add_widget(Label(size_hint_y=None, height=dp(40)))  # placeholder
        container.add_widget(slider_row)


        # ----- Batch Interval (delay between each parallel request) -----
        batch_interval_box = BoxLayout(orientation='vertical', spacing=dp(2))
        batch_interval_box.add_widget(Label(text='Batch Interval (seconds):', size_hint_y=None, height=dp(25)))
        self.batch_interval_input = TextInput(text=str(AppConfig.get('batch_interval', 0.0)), 
                                              size_hint_y=None, height=dp(44),
                                              input_filter='float', multiline=False)
        help_btn = Button(text='?', size_hint_x=None, width=dp(30))
        help_btn.help_text = "Delay between sending requests to each script when Concurrent Batch is enabled.\n" \
                             "Example: 0.2 = 200ms gap between each script's request.\n" \
                             "Helps reduce Google Apps Script rate limiting (502 errors).\n" \
                             "Set 0 to disable (send all at once)."
        help_btn.bind(on_press=self.show_help)
        row = BoxLayout(spacing=dp(5))
        row.add_widget(self.batch_interval_input)
        row.add_widget(help_btn)
        batch_interval_box.add_widget(row)
        container.add_widget(Label(size_hint_y=None, height=dp(40)))  # placeholder
        container.add_widget(batch_interval_box)


        # ----- User-Agent Spinner -----
        self.user_agent_spinner = Spinner(
            text='Chrome 124 (Windows)',
            values=[
                'Chrome 124 (Windows)',
                'Chrome 124 (macOS)',
                'Firefox 125 (Windows)',
                'Firefox 125 (macOS)',
                'Safari 17.4 (macOS)',
                'Edge 124 (Windows)',
                'Custom...'
            ],
            size_hint_y=None, height=dp(44)
        )
        self._add_field(container, 'User-Agent:',
            "Browser identifier sent to websites.\nChoose a preset or 'Custom...' to enter your own below.",
            self.user_agent_spinner)
        self.custom_ua_input = TextInput(text='', size_hint_y=None, height=dp(44),
                                         disabled=True, hint_text='Custom User-Agent')
        self._add_field(container, 'Custom UA:',
            "Only used when 'Custom...' is selected above.",
            self.custom_ua_input)

        # Bypass Domains
        self.bypass_input = TextInput(text='', size_hint_y=None, height=dp(44))
        self._add_field(container, 'Bypass Domains (comma):',
            "Comma‑separated list of domains that should NOT go through the relay.\nRequests to these domains will be forwarded directly from your network.",
            self.bypass_input)

        # ---------- Cloudflare Worker URL ----------
        self.worker_url_input = TextInput(text='', size_hint_y=None, height=dp(44),
                                          hint_text='https://your-worker.workers.dev')
        self._add_field(container, 'Cloudflare Worker URL:',
            "Optional reverse proxy (Cloudflare Worker) that will sit between Google and the target site.\n"
            "Requests will be sent to https://worker/?url=... instead of directly to the site.\n"
            "This hides the Google IP from the destination, greatly reducing captchas/blocks.\n"
            "Leave empty to disable.",
            self.worker_url_input)

        # ---------- Performance Tuning ----------
        self.pre_warm_input = TextInput(text='30', size_hint_y=None, height=dp(44))
        self._add_field(container, 'Pre‑warm Connections:',
            "Number of TLS connections to Google established at start.\n"
            "Higher = faster first requests, but more memory and possible rate limits.\n"
            "Recommended: 10‑30.",
            self.pre_warm_input)

        self.pool_max_input = TextInput(text='50', size_hint_y=None, height=dp(44))
        self._add_field(container, 'Connection Pool Max:',
            "Max keep‑alive connections in the pool.\n"
            "Higher = more parallel requests possible, but higher memory.\n"
            "50 safe for desktops, reduce to 20 on phones.",
            self.pool_max_input)

        self.conn_ttl_input = TextInput(text='45.0', size_hint_y=None, height=dp(44))
        self._add_field(container, 'Connection TTL (sec):',
            "Max age of a pooled connection before discarding.\n"
            "Longer = less reconnection overhead, shorter may help if Google resets often.\n"
            "45s is balanced.",
            self.conn_ttl_input)

        self.semaphore_input = TextInput(text='50', size_hint_y=None, height=dp(44))
        self._add_field(container, 'Semaphore Max:',
            "Max concurrent relay operations.\n"
            "Higher = faster page loads, but too high may trigger abuse detection.\n"
            "50 for normal browsing, 20 on slow connections.",
            self.semaphore_input)



        self.relay_timeout_input = TextInput(text='25', size_hint_y=None, height=dp(44))
        self._add_field(container, 'Relay Timeout (sec):',
            "Time to wait for a relay response before giving up.\n"
            "Increase for slow sites, decrease for faster fallback.\n"
            "25s is standard.",
            self.relay_timeout_input)

        # ← این خط را اضافه کنید
        self.retry_count_input = TextInput(text='2', size_hint_y=None, height=dp(44))
        self._add_field(container, 'Retry Count:',
            "Number of retry attempts per script ID.\n"
            "- When Concurrent Batch is OFF: each active script is retried up to this many times before switching (if Auto‑switch is on) or giving up.\n"
            "- When Concurrent Batch is ON: each script in the batch is retried individually up to this many times. The first successful response from any script wins.\n"
            "Increase to reduce 502 errors on unstable connections; decrease for faster fallback.\n"
            "Recommended: 1‑3.",
            self.retry_count_input)



        self.tls_timeout_input = TextInput(text='15', size_hint_y=None, height=dp(44))
        self._add_field(container, 'TLS Connect Timeout (sec):',
            "Timeout for TLS handshake with Google.\n"
            "Increase on very slow internet, decrease to detect problems faster.",
            self.tls_timeout_input)


        self.tcp_timeout_input = TextInput(text='10', size_hint_y=None, height=dp(44))
        self._add_field(container, 'TCP Connect Timeout (sec):',
            "Timeout for raw TCP connection to Google.\n"
            "Lower (5‑10s) detects outages quickly, higher (15‑20s) for unstable networks.",
            self.tcp_timeout_input)


        self.cache_mb_input = TextInput(text='50', size_hint_y=None, height=dp(44))
        self._add_field(container, 'Cache Max (MB):',
            "Max in‑memory response cache size.\n"
            "Larger = faster repeated requests, smaller = less RAM.\n"
            "50 MB is good default.",
            self.cache_mb_input)

        # ---------- TLS Fingerprint ----------
        self.browser_fingerprint_spinner = Spinner(
            text='Chrome',
            values=['Chrome', 'Firefox', 'Custom'],
            size_hint_y=None, height=dp(44)
        )
        self._add_field(container, 'TLS Fingerprint:',
            "Mimic the TLS handshake of a specific browser.\n"
            "- Chrome/Firefox use predefined cipher suites and curves.\n"
            "- Custom lets you choose a cipher preset from below.",
            self.browser_fingerprint_spinner)

        # Cipher preset spinner
        self.cipher_preset_spinner = Spinner(
            text='Modern Compatibility',
            values=[
                'Modern Compatibility',
                'Strong Crypto (Chrome)',
                'Strong Crypto (Firefox)',
                'Legacy Broad Compatibility',
                'Custom Cipher String...'
            ],
            size_hint_y=None, height=dp(44)
        )
        self.cipher_preset_spinner.bind(text=self.on_cipher_preset_change)
        self._add_field(container, 'Cipher Preset:',
            "Preconfigured cipher suites for different security/compatibility needs.\n"
            "- Modern Compatibility: balanced security and speed.\n"
            "- Strong Crypto: mimics Chrome/Firefox latest.\n"
            "- Legacy Broad Compatibility: supports older servers.\n"
            "- Custom Cipher String...: allows manual entry below.",
            self.cipher_preset_spinner)

        self.custom_ciphers_input = TextInput(
            text='', size_hint_y=None, height=dp(44),
            hint_text='Custom cipher string (OpenSSL format)',
            disabled=True)
        self._add_field(container, 'Custom Ciphers:',
            "Manually enter cipher suites (colon‑separated, OpenSSL format).\n"
            "Example: ECDHE+AESGCM:ECDHE+CHACHA20\n"
            "Only used when Cipher Preset is 'Custom Cipher String...'.",
            self.custom_ciphers_input)

        # ----- ECDH Curve Spinner -----
        self.ecdh_curve_spinner = Spinner(
            text='secp384r1',
            values=[
                'secp384r1',
                'prime256v1',
                'X25519',
                'X448',
                'Custom...'
            ],
            size_hint_y=None, height=dp(44)
        )
        self._add_field(container, 'ECDH Curve:',
            "Elliptic curve for key exchange.\n"
            "Common: prime256v1, secp384r1, X25519.\n"
            "Choose a preset or 'Custom...' to type a curve name.",
            self.ecdh_curve_spinner)
        self.custom_ecdh_input = TextInput(text='', size_hint_y=None, height=dp(44),
                                           disabled=True, hint_text='Custom ECDH curve')
        self._add_field(container, 'Custom Curve:',
            "Only used when 'Custom...' is selected above.",
            self.custom_ecdh_input)

        # ---------- Enable Fragment (new) ----------
        self.fragment_switch = Switch(active=AppConfig.get('enable_fragment', False))
        container.add_widget(Label(text='Enable Fragment:', size_hint_y=None, height=dp(40)))
        container.add_widget(self.fragment_switch)

        # ---------- MITM ----------
        container.add_widget(Label(text='Enable HTTPS MITM:', size_hint_y=None, height=dp(40)))
        self.mitm_switch = Switch(active=AppConfig.get('mitm_enabled', True))
        self.mitm_switch.bind(active=self.on_mitm_switch)
        container.add_widget(self.mitm_switch)

        # Certificate management
        export_btn = Button(text='Export CA Certificate', size_hint_y=None, height=dp(48))
        export_btn.bind(on_press=self.export_ca_certificate)
        container.add_widget(export_btn)
        install_mac_btn = Button(text='Install & Trust CA (macOS)', size_hint_y=None, height=dp(48))
        install_mac_btn.bind(on_press=self.install_ca_macos)
        container.add_widget(install_mac_btn)
        install_android_btn = Button(text='Install on Android (Security)', size_hint_y=None, height=dp(48))
        install_android_btn.bind(on_press=self.install_ca_android)
        container.add_widget(install_android_btn)

        # LAN & System Tunnel
        lan_btn = Button(text='Enable LAN Mode (0.0.0.0)', size_hint_y=None, height=dp(48))
        lan_btn.bind(on_press=self.enable_lan_mode)
        container.add_widget(lan_btn)
        container.add_widget(Label(text='System Tunnel (SOCKS5):', size_hint_y=None, height=dp(40)))
        self.tunnel_switch = Switch(active=False)
        self.tunnel_switch.bind(active=self.toggle_system_tunnel)
        container.add_widget(self.tunnel_switch)

        # Save & Factory Reset
        save_btn = Button(text='Save Settings', size_hint_y=None, height=dp(50))
        save_btn.bind(on_press=self.save_settings)
        container.add_widget(Label(size_hint_y=None, height=dp(50)))  # placeholder
        container.add_widget(save_btn)

        reset_btn = Button(text='Reset to Factory Defaults', size_hint_y=None, height=dp(50))
        reset_btn.bind(on_press=self.factory_reset)
        container.add_widget(reset_btn)

        scroll.add_widget(container)
        self.add_widget(scroll)


    def on_launch_startup(self, instance, value):
        if platform.system() != 'Darwin':
            self.app.show_status("This feature is only available on macOS.")
            return
        # مسیر برنامه فعلی (هنگام اجرا با Python یا بسته‌بندی شده)
        app_path = os.path.abspath(sys.argv[0])
        # اگر با pyinstaller ساخته شده باشد، مسیر باندل را پیدا کن
        if getattr(sys, 'frozen', False):
            app_path = sys._MEIPASS   # این مسیر درست نیست؛ باید مسیر اصلی باندل رو بگیریم.
            # روش بهتر: استفاده از مسیر اصلی برنامه
            # app_path = os.path.dirname(sys.executable)  # این هم درست نیست
        # در واقع، بهترین کار این است که کاربر برنامه را از پوشه‌ی .app اجرا کند.
        # فعلاً از یک اسکریپت AppleScript استفاده می‌کنیم که مسیر را از کاربر نمی‌گیرد.
        # یک راه ساده: اضافه کردن فایل .app به Login Items با استفاده از دستور osascript
        script = f'''
        tell application "System Events"
            if exists login item "MasterHttpRelayVPN" then
                delete login item "MasterHttpRelayVPN"
            end if
            if {"true" if value else "false"} then
                make new login item at end with properties {{path:"{app_path}", hidden:false, name:"MasterHttpRelayVPN"}}
            end if
        end tell
        '''
        try:
            subprocess.run(["osascript", "-e", script], check=True)
            self.app.show_status(f"Startup {'enabled' if value else 'disabled'}.")
        except subprocess.CalledProcessError as e:
            self.app.show_status(f"Failed to update startup item: {e}")


    def on_concurrent_switch(self, instance, value):
        self.concurrency_slider.disabled = not value
        # اعمال فوری در ConfigTab (بدون نیاز به ذخیره)
        AppConfig.set('concurrent_batch_enabled', value)   # موقتاً ذخیره می‌کنیم تا refresh_list درست بخواند
        if hasattr(self.app, 'config_tab'):
            self.app.config_tab.refresh_list()



    def _add_field(self, container, label_text, help_text, input_widget):
        container.add_widget(Label(text=label_text, size_hint_y=None, height=dp(40)))
        row = BoxLayout(spacing=dp(5))
        row.add_widget(input_widget)
        help_btn = Button(text='?', size_hint_x=None, width=dp(30))
        help_btn.help_text = help_text
        help_btn.bind(on_press=self.show_help)
        row.add_widget(help_btn)
        container.add_widget(row)

    def show_help(self, instance):
        content = BoxLayout(orientation='vertical', padding=dp(10), spacing=dp(10))
        lbl = Label(text=instance.help_text, halign='left', valign='top')
        lbl.bind(size=lambda s, w: setattr(s, 'text_size', (w[0]-20, None)))
        content.add_widget(lbl)
        close_btn = Button(text='Got it', size_hint_y=None, height=dp(40))
        content.add_widget(close_btn)
        popup = Popup(title='Help', content=content, size_hint=(0.75, 0.4))
        close_btn.bind(on_press=popup.dismiss)
        popup.open()

    def on_cipher_preset_change(self, spinner, text):
        self.custom_ciphers_input.disabled = (text != 'Custom Cipher String...')

    # ---------- Load / Save ----------
    def load_settings(self):
        self.listen_addr_input.text = AppConfig.get('listen_host', '127.0.0.1')
        self.port_input.text = str(AppConfig.get('listen_port', 8085))
        self.socks_port_input.text = str(AppConfig.get('socks5_port', 1080))
        self.google_ip_input.text = AppConfig.get('google_ip', '216.239.38.120')
        self.front_domain_input.text = AppConfig.get('front_domain', 'www.google.com')

        ua_preset = AppConfig.get('user_agent_preset', 'Chrome 124 (Windows)')
        self.user_agent_spinner.text = ua_preset
        self.custom_ua_input.text = AppConfig.get('user_agent', '')
        self.custom_ua_input.disabled = (ua_preset != 'Custom...')

        self.bypass_input.text = ','.join(AppConfig.get_bypass_list())
        self.worker_url_input.text = AppConfig.get('cf_worker_url', '')

        self.pre_warm_input.text = str(AppConfig.get('warm_pool_count', 30))
        self.pool_max_input.text = str(AppConfig.get('pool_max', 50))
        self.conn_ttl_input.text = str(AppConfig.get('conn_ttl', 45.0))
        self.semaphore_input.text = str(AppConfig.get('semaphore_max', 50))
        self.relay_timeout_input.text = str(AppConfig.get('relay_timeout', 25))
        self.tls_timeout_input.text = str(AppConfig.get('tls_connect_timeout', 15))
        self.retry_count_input.text = str(AppConfig.get('retry_count', 2))
        self.tcp_timeout_input.text = str(AppConfig.get('tcp_connect_timeout', 10))
        self.cache_mb_input.text = str(AppConfig.get('cache_max_mb', 50))

        self.browser_fingerprint_spinner.text = AppConfig.get('browser_fingerprint', 'Chrome')
        self.cipher_preset_spinner.text = AppConfig.get('cipher_preset', 'Modern Compatibility')
        self.custom_ciphers_input.text = AppConfig.get('custom_ciphers', '')
        self.custom_ciphers_input.disabled = (self.cipher_preset_spinner.text != 'Custom Cipher String...')

        ecdh_preset = AppConfig.get('ecdh_curve_preset', 'secp384r1')
        self.ecdh_curve_spinner.text = ecdh_preset
        self.custom_ecdh_input.text = AppConfig.get('ecdh_curve', 'secp384r1')
        self.custom_ecdh_input.disabled = (ecdh_preset != 'Custom...')

        self.fragment_switch.active = AppConfig.get('enable_fragment', False)
        self.mitm_switch.active = AppConfig.get('mitm_enabled', True)

        concurrency = AppConfig.get('concurrent_batch_concurrency', 0)
        if concurrency == 0 or concurrency > len(self.app.script_manager.scripts):
            concurrency = max(1, len(self.app.script_manager.scripts))
        self.concurrency_slider.value = concurrency
        self.concurrency_label.text = str(int(concurrency))
        self.concurrency_slider.disabled = not self.concurrent_switch.active

        self.batch_interval_input.text = str(AppConfig.get('batch_interval', 0.0))

    def save_settings(self, instance):



        AppConfig.set('concurrent_batch_enabled', self.concurrent_switch.active)
        try:
            AppConfig.set('listen_host', self.listen_addr_input.text.strip())
            AppConfig.set('listen_port', int(self.port_input.text))
            AppConfig.set('socks5_port', int(self.socks_port_input.text))

            AppConfig.set('concurrent_batch_concurrency', int(self.concurrency_slider.value))
    
        except: pass

        try:
            AppConfig.set('batch_interval', float(self.batch_interval_input.text))
        except:
            AppConfig.set('batch_interval', 0.0)


        AppConfig.set('google_ip', self.google_ip_input.text.strip())
        AppConfig.set('front_domain', self.front_domain_input.text.strip())

        # User-Agent
        preset = self.user_agent_spinner.text
        AppConfig.set('user_agent_preset', preset)
        if preset == 'Custom...':
            AppConfig.set('user_agent', self.custom_ua_input.text.strip())
        else:
            ua_map = {
                'Chrome 124 (Windows)': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
                'Chrome 124 (macOS)': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
                'Firefox 125 (Windows)': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0',
                'Firefox 125 (macOS)': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0',
                'Safari 17.4 (macOS)': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
                'Edge 124 (Windows)': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0',
            }
            AppConfig.set('user_agent', ua_map.get(preset, self.custom_ua_input.text.strip()))

        domains = [d.strip() for d in self.bypass_input.text.split(',') if d.strip()]
        AppConfig.save_bypass_list(domains)
        AppConfig.set('cf_worker_url', self.worker_url_input.text.strip())

        # performance
        try:
            AppConfig.set('warm_pool_count', int(self.pre_warm_input.text))
            AppConfig.set('pool_max', int(self.pool_max_input.text))
            AppConfig.set('conn_ttl', float(self.conn_ttl_input.text))
            AppConfig.set('semaphore_max', int(self.semaphore_input.text))
            AppConfig.set('relay_timeout', int(self.relay_timeout_input.text))
            AppConfig.set('tls_connect_timeout', int(self.tls_timeout_input.text))
            AppConfig.set('retry_count', int(self.retry_count_input.text))
            AppConfig.set('tcp_connect_timeout', int(self.tcp_timeout_input.text))
            AppConfig.set('cache_max_mb', int(self.cache_mb_input.text))
        except: pass

        AppConfig.set('browser_fingerprint', self.browser_fingerprint_spinner.text)
        AppConfig.set('cipher_preset', self.cipher_preset_spinner.text)
        AppConfig.set('custom_ciphers', self.custom_ciphers_input.text.strip())

        ecdh_preset = self.ecdh_curve_spinner.text
        AppConfig.set('ecdh_curve_preset', ecdh_preset)
        if ecdh_preset == 'Custom...':
            AppConfig.set('ecdh_curve', self.custom_ecdh_input.text.strip())
        else:
            AppConfig.set('ecdh_curve', ecdh_preset)

        AppConfig.set('enable_fragment', self.fragment_switch.active)

        if hasattr(self.app, 'proxy_tab') and self.app.proxy_tab.proxy_server:
            server = self.app.proxy_tab.proxy_server
            server.fronter._bypass_domains = set(domains)
            server.fronter._extra_headers['User-Agent'] = AppConfig.get('user_agent', '')
        self.app.show_status("Settings saved. Restart proxy for full effect.")

    # ---------- Other methods (unchanged) ----------
    def on_mitm_switch(self, instance, value):
        AppConfig.set('mitm_enabled', value)
        self.app.show_status(f"MITM {'enabled' if value else 'disabled'} (proxy restart required)")

    def export_ca_certificate(self, instance):
        # ... (same as before)
        pass

    def install_ca_macos(self, instance):
        # ... (same as before)
        pass

    def install_ca_android(self, instance):
        # ... (same as before)
        pass

    def enable_lan_mode(self, instance):
        self.listen_addr_input.text = '0.0.0.0'
        self.app.show_status("LAN mode enabled (listen address set to 0.0.0.0). Save settings and restart proxy.")

    def toggle_system_tunnel(self, instance, value):
        if value:
            if platform.system() == 'Darwin':
                subprocess.run(
                    f"networksetup -setsocksfirewallproxy Wi-Fi 127.0.0.1 {self.socks_port_input.text}",
                    shell=True
                )
                subprocess.run("networksetup -setsocksfirewallproxystate Wi-Fi on", shell=True)
            elif platform.system() == 'Windows':
                pass
            self.app.show_status("System SOCKS proxy enabled")
        else:
            if platform.system() == 'Darwin':
                subprocess.run("networksetup -setsocksfirewallproxystate Wi-Fi off", shell=True)
            self.app.show_status("System SOCKS proxy disabled")

    def factory_reset(self, instance):
        from kivy.uix.popup import Popup
        from kivy.metrics import dp

        content = BoxLayout(orientation='vertical', spacing=dp(10), padding=dp(10))
        content.add_widget(Label(text='Reset all settings to defaults?\nScript configurations will NOT be deleted.',
                                 size_hint_y=None, height=dp(60)))

        btn_box = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(10))
        yes_btn = Button(text='Yes, Reset Settings')
        no_btn = Button(text='Cancel')
        btn_box.add_widget(yes_btn)
        btn_box.add_widget(no_btn)
        content.add_widget(btn_box)

        content.height = dp(60) + dp(10) + dp(50) + 2*dp(10)
        content.size_hint_y = None

        popup = Popup(title='Factory Reset', content=content, size_hint=(0.8, None),
                      height=content.height + dp(50), auto_dismiss=False)

        def do_reset(instance):
            try:
                os.remove(AppConfig.get_store().filename)
            except:
                pass
            AppConfig._store = None
            self.load_settings()
            self.app.show_status("Settings reset. Restart proxy if running.")
            popup.dismiss()

        yes_btn.bind(on_press=do_reset)
        no_btn.bind(on_press=popup.dismiss)
        popup.open()





























class GoogleIPScanner:
    def __init__(self, domain: str = "script.google.com", timeout: float = 2.0,
                 tls_verify: bool = True, concurrency: int = 10):
        self.domain = domain
        self.timeout = timeout
        self.tls_verify = tls_verify
        self.concurrency = concurrency
        self.results = []
        # از threading.Event استفاده می‌کنیم (thread‑safe)
        self._cancel_event = threading.Event()

    def cancel(self):
        """اسکن را متوقف می‌کند."""
        self._cancel_event.set()

    async def _resolve_domain(self) -> List[str]:
        """حل نام دامنه با DNS سیستم و Google DoH (فال‌بک)."""
        ips = set()
        # System DNS
        try:
            loop = asyncio.get_running_loop()
            infos = await loop.getaddrinfo(self.domain, 443, family=socket.AF_INET)
            for info in infos:
                ips.add(info[4][0])
        except:
            pass

        # Google DoH fallback (if system DNS fails or returns nothing)
        if not ips:
            try:
                import aiohttp
                async with aiohttp.ClientSession() as session:
                    url = f"https://dns.google/resolve?name={self.domain}&type=A"
                    async with session.get(url) as resp:
                        data = await resp.json()
                        for answer in data.get('Answer', []):
                            if answer.get('type') == 1:  # A record
                                ips.add(answer['data'])
            except:
                pass

        # If still empty, and it's a Google domain, use well-known IPs
        if not ips and 'google' in self.domain:
            ips = {'216.239.38.120', '216.239.32.21', '216.239.34.21'}
        return list(ips)

    async def _test_one_ip(self, ip: str, sem: asyncio.Semaphore) -> Optional[dict]:
        async with sem:
            if self._cancel_event.is_set():
                return None
            try:
                start = time.time()
                # TCP handshake
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, 443), timeout=self.timeout
                )
                latency = (time.time() - start) * 1000   # ms

                if self.tls_verify:
                    ssl_ctx = ssl.create_default_context()
                    try:
                        transport = writer.transport
                        protocol = transport.get_protocol()
                        loop = asyncio.get_running_loop()
                        await loop.start_tls(transport, protocol, ssl_ctx,
                                             server_hostname=self.domain)
                    except Exception:
                        writer.close()
                        await writer.wait_closed()
                        return None   # TLS failed
                writer.close()
                await writer.wait_closed()
                return {"ip": ip, "latency": latency}
            except Exception:
                return None

    async def scan(self, progress_callback: Optional[Callable[[int, int], None]] = None) -> List[dict]:
        """اسکن سریع با لیست DNS و پشتیبانی از لغو."""
        candidates = await self._resolve_domain()
        if not candidates:
            return []

        sem = asyncio.Semaphore(self.concurrency)
        tasks = [self._test_one_ip(ip, sem) for ip in candidates]
        results = []
        for coro in asyncio.as_completed(tasks):
            res = await coro
            if self._cancel_event.is_set():
                break
            if res:
                results.append(res)
            if progress_callback:
                progress_callback(len(results), len(candidates))

        if not self._cancel_event.is_set():
            results.sort(key=lambda x: x["latency"])
        self.results = results
        return results
class ResolverTab(BoxLayout):
    def __init__(self, app, **kwargs):
        super().__init__(orientation='vertical', **kwargs)
        self.app = app
        self.scanner = None
        self._scan_thread = None
        self.build_ui()

    def build_ui(self):
        scroll = ScrollView(size_hint=(1, 1))
        container = GridLayout(cols=2, size_hint_y=None, spacing=dp(10), padding=dp(10))
        container.bind(minimum_height=container.setter('height'))

        # ----- Target Domain -----
        self.domain_input = TextInput(text='script.google.com', size_hint_y=None, height=dp(44))
        self._add_field(container, 'Target Domain:',
            "Domain to resolve (e.g., example.com).\nIPs will be tested against this domain.",
            self.domain_input)

        # ----- Handshake Timeout -----
        self.timeout_input = TextInput(text='3.0', size_hint_y=None, height=dp(44))
        self._add_field(container, 'Handshake Timeout (sec):',
            "Timeout for TCP and TLS handshake per IP.\nIncrease if many IPs show as timeout.",
            self.timeout_input)

        # ----- Concurrency -----
        self.concurrency_input = TextInput(text='10', size_hint_y=None, height=dp(44))
        self._add_field(container, 'Concurrency:',
            "Number of simultaneous checks.\nHigher = faster scan, but may overload network.",
            self.concurrency_input)

        # ----- Verify TLS Certificate -----
        self.tls_check = Switch(active=True)
        container.add_widget(Label(text='Verify TLS Certificate:', size_hint_y=None, height=dp(40)))
        container.add_widget(self.tls_check)

        # ----- Start / Stop Buttons -----
        btn_row = BoxLayout(spacing=dp(5))
        self.scan_btn = Button(text='Start Resolution', size_hint_x=0.7, size_hint_y=None, height=dp(50),
                               background_color=get_color_from_hex('#1E88E5'))
        self.scan_btn.bind(on_press=self.start_scan)
        btn_row.add_widget(self.scan_btn)

        self.stop_btn = Button(text='Stop', size_hint_x=0.3, size_hint_y=None, height=dp(50),
                               background_color=get_color_from_hex('#E53935'))
        self.stop_btn.bind(on_press=self.stop_scan)
        self.stop_btn.disabled = True
        btn_row.add_widget(self.stop_btn)

        container.add_widget(Label(size_hint_y=None, height=dp(50)))  # placeholder
        container.add_widget(btn_row)

        # ----- Progress Label -----
        self.progress_label = Label(text='Ready', size_hint_y=None, height=dp(30),
                                    halign='center', valign='middle')
        container.add_widget(Label(size_hint_y=None, height=dp(30)))  # placeholder
        container.add_widget(self.progress_label)

        scroll.add_widget(container)
        self.add_widget(scroll)

        # ---------- Results Header ----------
        header_grid = GridLayout(cols=4, size_hint_y=None, height=dp(38), spacing=dp(2))
        header_colors = (0.93, 0.93, 0.93, 1)
        for text, hint in [('#', 0.05), ('IP Address', 0.55), ('Latency (ms)', 0.2), ('Action', 0.2)]:
            lbl = Label(text=f'[b]{text}[/b]', markup=True, size_hint_x=hint,
                        halign='left', valign='middle', size_hint_y=None, height=dp(38),
                        color=(0,0,0,1), font_size=dp(13))
            with lbl.canvas.before:
                Color(*header_colors)
                rect = Rectangle(size=lbl.size, pos=lbl.pos)
            lbl.bind(size=lambda instance, value, r=rect: setattr(r, 'size', value),
                     pos=lambda instance, value, r=rect: setattr(r, 'pos', value))
            header_grid.add_widget(lbl)
        self.add_widget(header_grid)

        # ---------- Results List (scrollable) ----------
        self.scroll_results = ScrollView(size_hint=(1, 1))
        self.results_table = GridLayout(cols=4, size_hint_y=None, spacing=dp(2))
        self.results_table.bind(minimum_height=self.results_table.setter('height'))
        self.scroll_results.add_widget(self.results_table)
        self.add_widget(self.scroll_results)

        # ---------- Copy All Button ----------
        copy_all_btn = Button(text='Copy All IPs', size_hint_y=None, height=dp(46))
        copy_all_btn.bind(on_press=self.copy_all_ips)
        self.add_widget(copy_all_btn)

    def _add_field(self, container, label_text, help_text, input_widget):
        """Helper method to add a labeled field with a help button."""
        container.add_widget(Label(text=label_text, size_hint_y=None, height=dp(40)))
        row = BoxLayout(spacing=dp(5))
        row.add_widget(input_widget)
        help_btn = Button(text='?', size_hint_x=None, width=dp(30))
        help_btn.help_text = help_text
        # ✅ اصلاح: استفاده از self.show_help به جای self._show_help
        help_btn.bind(on_press=self.show_help)
        row.add_widget(help_btn)
        container.add_widget(row)

    def show_help(self, instance):
        """Display help popup for the ? button."""
        from kivy.metrics import dp
        from kivy.uix.popup import Popup
        content = BoxLayout(orientation='vertical', padding=dp(10), spacing=dp(10))
        lbl = Label(text=instance.help_text, halign='left', valign='top', size_hint_y=None)
        lbl.bind(texture_size=lambda inst, sz: setattr(inst, 'height', sz[1]))
        content.add_widget(lbl)
        close_btn = Button(text='Got it', size_hint_y=None, height=dp(40))
        content.add_widget(close_btn)
        # محاسبه ارتفاع پاپ‌آپ بر اساس محتوا
        content.height = lbl.height + dp(10) + dp(40) + 2*dp(10)
        content.size_hint_y = None
        popup = Popup(title='Help', content=content, size_hint=(0.8, None),
                      height=content.height + dp(50), auto_dismiss=False)
        close_btn.bind(on_press=popup.dismiss)
        popup.open()

    # ---------- Scanning logic ----------
    def start_scan(self, instance):
        domain = self.domain_input.text.strip() or 'script.google.com'
        try:
            timeout = float(self.timeout_input.text)
        except:
            timeout = 3.0
        try:
            concurrency = int(self.concurrency_input.text)
        except:
            concurrency = 10
        tls_verify = self.tls_check.active

        self.scan_btn.disabled = True
        self.stop_btn.disabled = False
        self.progress_label.text = 'Scanning...'
        self.results_table.clear_widgets()
        self.app.show_status("Scan started – fetching DNS records...")

        self.scanner = GoogleIPScanner(domain, timeout, tls_verify, concurrency)
        self._scan_thread = threading.Thread(target=self._run_scan, daemon=True)
        self._scan_thread.start()

    def stop_scan(self, instance):
        if self.scanner:
            self.scanner.cancel()
        self.stop_btn.disabled = True
        self.progress_label.text = 'Stopping...'
        self.app.show_status("Scan cancelled.")

    def _run_scan(self):
        async def task():
            def progress(found, total):
                Clock.schedule_once(lambda dt: self._update_progress(found, total))
            return await self.scanner.scan(progress_callback=progress)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        cancelled = False
        try:
            results = loop.run_until_complete(task())
            if self.scanner and not self.scanner._cancel_event.is_set():
                Clock.schedule_once(lambda dt: self._show_results(results))
            else:
                cancelled = True
        except Exception as e:
            if self.scanner and not self.scanner._cancel_event.is_set():
                Clock.schedule_once(lambda dt: self._scan_error(str(e)))
        finally:
            loop.close()
            if cancelled:
                Clock.schedule_once(lambda dt: self._scan_cancelled())

    def _update_progress(self, found, total):
        self.progress_label.text = f'Found {found} / scanned {total}...'
        self.app.show_status(f"Scan: {found}/{total} IPs tested")

    def _show_results(self, results):
        self.scan_btn.disabled = False
        self.stop_btn.disabled = True
        if not results:
            self.progress_label.text = 'No reachable IPs found. Try without TLS verification.'
            self.app.show_status("Scan finished – no IPs found.")
            return
        self.progress_label.text = f'{len(results)} IPs found.'
        self.app.show_status(f"Scan finished – {len(results)} IPs found.")

        for i, r in enumerate(results, 1):
            self.results_table.add_widget(Label(text=str(i), size_hint_x=0.05, size_hint_y=None, height=dp(36)))
            ip_lbl = Label(text=r['ip'], size_hint_x=0.55, size_hint_y=None, height=dp(36),
                           color=(0.2, 0.6, 1, 1), halign='left', valign='middle')
            ip_lbl.bind(on_touch_down=lambda inst, touch, ip=r['ip']:
                        self._copy_ip(ip) if inst.collide_point(*touch.pos) else None)
            self.results_table.add_widget(ip_lbl)
            lat_text = f"{r['latency']:.1f}" if r['latency'] is not None else 'timeout'
            self.results_table.add_widget(Label(text=lat_text, size_hint_x=0.2, size_hint_y=None, height=dp(36)))
            btn = Button(text='Activate', size_hint_x=0.2, size_hint_y=None, height=dp(36))
            btn.bind(on_press=lambda instance, ip=r['ip']: self._activate_ip(ip))
            self.results_table.add_widget(btn)

    def _scan_cancelled(self):
        self.scan_btn.disabled = False
        self.stop_btn.disabled = True
        self.progress_label.text = 'Scan cancelled.'
        self.app.show_status("Scan cancelled.")

    def _scan_error(self, error_msg):
        self.scan_btn.disabled = False
        self.stop_btn.disabled = True
        self.progress_label.text = f'Error: {error_msg}'
        self.app.show_status(f"Scan error: {error_msg}")

    def copy_all_ips(self, instance):
        if not self.scanner or not self.scanner.results:
            self.app.show_status('No results to copy')
            return
        all_ips = '\n'.join(r['ip'] for r in self.scanner.results)
        Clipboard.copy(all_ips)
        self.app.show_status('All IPs copied')

    def _copy_ip(self, ip):
        Clipboard.copy(ip)
        self.app.show_status(f'IP {ip} copied')

    def _activate_ip(self, ip):
        AppConfig.set('google_ip', ip)
        if hasattr(self.app, 'settings_tab'):
            self.app.settings_tab.google_ip_input.text = ip
        self.app.show_status(f'Google IP set to {ip}. Restart proxy.')
class BrowserFingerprint(str, Enum):
    CHROME = "Chrome"
    FIREFOX = "Firefox"
    CUSTOM = "Custom"



class LogsTab(BoxLayout):
    def __init__(self, app, **kwargs):
        super().__init__(orientation='vertical', **kwargs)
        self.app = app
        self.logs = []
        self.max_lines = 500
        self.logging_enabled = False          # پیش‌فرض خاموش
        self.build_ui()

    def build_ui(self):
        self.scroll = ScrollView(size_hint=(1, 1), do_scroll_x=False, bar_width=dp(10))
        self.log_label = Label(
            text='Logging is disabled',
            size_hint_y=None,
            halign='left',
            valign='top',
            text_size=(None, None)
        )
        self.log_label.bind(width=lambda instance, value: setattr(instance, 'text_size', (value, None)))
        self.scroll.add_widget(self.log_label)
        self.add_widget(self.scroll)

        btn_box = BoxLayout(size_hint_y=None, height=dp(50))
        copy_btn = Button(text='Copy Logs')
        copy_btn.bind(on_press=self.copy_logs)
        clear_btn = Button(text='Clear')
        clear_btn.bind(on_press=self.clear_logs)
        self.log_toggle = ToggleButton(text='Logging: OFF')
        self.log_toggle.state = 'normal'      # خاموش
        self.log_toggle.bind(on_press=self.toggle_logging)
        btn_box.add_widget(copy_btn)
        btn_box.add_widget(clear_btn)
        btn_box.add_widget(self.log_toggle)
        self.add_widget(btn_box)

    def toggle_logging(self, instance):
        self.logging_enabled = (instance.state == 'down')
        instance.text = f'Logging: {"ON" if self.logging_enabled else "OFF"}'
        if not self.logging_enabled:
            self.log_label.text = 'Logging is disabled'
        else:
            self.logs.clear()
            self.log_label.text = ''

    def add_log(self, msg):
        if not self.logging_enabled:
            return
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.logs.append(f"[{timestamp}] {msg}")
        if len(self.logs) > self.max_lines:
            self.logs = self.logs[-self.max_lines:]
        self.log_label.text = '\n'.join(self.logs)
        Clock.schedule_once(lambda dt: setattr(self.scroll, 'scroll_y', 0), 0.1)

    def copy_logs(self, instance):
        Clipboard.copy(self.log_label.text)
        self.app.show_status("Logs copied")

    def clear_logs(self, instance):
        self.logs.clear()
        self.log_label.text = 'Logging is disabled' if not self.logging_enabled else ''
        self.app.show_status("Logs cleared")




from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.widget import Widget
from kivy.metrics import dp
from kivy.core.clipboard import Clipboard

class HelpTab(BoxLayout):
    def __init__(self, app, **kwargs):
        super().__init__(orientation='vertical', **kwargs)
        self.app = app
        self.build_ui()

    def build_ui(self):
        # فضای خالی بالا
        self.add_widget(Widget(size_hint_y=0.2))

        # دکمه کپی GAS
        gas_btn = Button(
            text='Copy Google Apps Script Code',
            size_hint=(0.8, None),
            height=dp(60),
            pos_hint={'center_x': 0.5}
        )
        gas_btn.bind(on_press=self.copy_gas_code)
        self.add_widget(gas_btn)

        # فاصله
        self.add_widget(Widget(size_hint_y=0.05))

        # دکمه کپی Worker
        worker_btn = Button(
            text='Copy Cloudflare Worker Code',
            size_hint=(0.8, None),
            height=dp(60),
            pos_hint={'center_x': 0.5}
        )
        worker_btn.bind(on_press=self.copy_worker_code)
        self.add_widget(worker_btn)

        # فضای خالی پایین
        self.add_widget(Widget(size_hint_y=0.2))

    def copy_gas_code(self, instance):
        gas_code = '''/**
 * MasterHttpRelayVPN – Google Apps Script Relay [GAS]
 */
const AUTH_KEY = "change_here";

const SKIP_HEADERS = {
  host: 1, connection: 1, "content-length": 1,
  "transfer-encoding": 1, "proxy-connection": 1, "proxy-authorization": 1,
  "priority": 1, te: 1,
};

function doPost(e) {
  try {
    var req = JSON.parse(e.postData.contents);
    if (req.k !== AUTH_KEY) return _json({ e: "unauthorized" });
    var workerUrl = req.w || null;
    if (Array.isArray(req.q)) return _doBatch(req.q, workerUrl);
    return _doSingle(req, workerUrl);
  } catch (err) {
    return _json({ e: String(err) });
  }
}

function _doSingle(req, workerUrl) {
  if (!req.u || typeof req.u !== "string" || !req.u.match(/^https?:\/\//i)) {
    return _json({ e: "bad url" });
  }
  if (workerUrl) {
    req.u = workerUrl + "?url=" + encodeURIComponent(req.u);
  }
  var resp = UrlFetchApp.fetch(req.u, _buildOpts(req));
  return _json({
    s: resp.getResponseCode(),
    h: _respHeaders(resp),
    b: Utilities.base64Encode(resp.getContent()),
  });
}

function _doBatch(items, workerUrl) {
  var requests = [];
  var errors = {};
  for (var i = 0; i < items.length; i++) {
    var item = items[i];
    if (!item.u || !item.u.match(/^https?:\/\//i)) {
      errors[i] = "bad url";
      continue;
    }
    if (workerUrl) {
      item.u = workerUrl + "?url=" + encodeURIComponent(item.u);
    }
    var opts = _buildOpts(item);
    requests.push(opts);
  }
  var responses = requests.length ? UrlFetchApp.fetchAll(requests) : [];
  var results = new Array(items.length);
  var rIdx = 0;
  for (var i = 0; i < items.length; i++) {
    if (errors[i]) {
      results[i] = { e: errors[i] };
    } else {
      var resp = responses[rIdx++];
      results[i] = {
        s: resp.getResponseCode(),
        h: _respHeaders(resp),
        b: Utilities.base64Encode(resp.getContent()),
      };
    }
  }
  return _json({ q: results });
}

function _buildOpts(req) {
  var method = (req.m || "GET").toUpperCase();
  var opts = {
    method: method,
    muteHttpExceptions: true,
    followRedirects: req.r !== false,
    validateHttpsCertificates: true,
    escaping: false,
  };
  if (req.h) {
    var hdrs = {};
    for (var k in req.h) {
      if (!SKIP_HEADERS[k.toLowerCase()]) hdrs[k] = req.h[k];
    }
    hdrs["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8";
    hdrs["Accept-Language"] = "en-US,en;q=0.5";
    hdrs["Cache-Control"] = "max-age=0";
    hdrs["Upgrade-Insecure-Requests"] = "1";
    hdrs["sec-ch-ua"] = '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"';
    hdrs["sec-ch-ua-mobile"] = "?0";
    hdrs["sec-ch-ua-platform"] = '"macOS"';
    opts.headers = hdrs;
  }
  if (req.b) {
    opts.payload = Utilities.base64Decode(req.b);
    if (req.ct) opts.contentType = req.ct;
  }
  return opts;
}

function _respHeaders(resp) {
  return resp.getAllHeaders ? resp.getAllHeaders() : resp.getHeaders();
}

function doGet(e) {
  return HtmlService.createHtmlOutput("<html><body><h1>MHRVPN Relay Active</h1></body></html>");
}

function _json(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj)).setMimeType(ContentService.MimeType.JSON);
}'''
        Clipboard.copy(gas_code)
        self.app.show_status("GAS code copied to clipboard")

    def copy_worker_code(self, instance):
        worker_code = '''// Cloudflare Worker
const DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  const url = new URL(request.url);
  const targetUrl = url.searchParams.get('url');
  if (!targetUrl) {
    return new Response('Missing "url" parameter', { status: 400 });
  }
  const reqHeaders = new Headers(request.headers);
  const hopByHop = ['host', 'connection', 'keep-alive', 'proxy-connection', 
                    'te', 'trailer', 'transfer-encoding', 'upgrade',
                    'cf-connecting-ip', 'x-forwarded-for', 'x-real-ip',
                    'cf-visitor', 'cf-ray', 'cf-request-id'];
  hopByHop.forEach(h => reqHeaders.delete(h));
  if (!reqHeaders.has('user-agent')) reqHeaders.set('user-agent', DEFAULT_UA);
  if (!reqHeaders.has('accept')) reqHeaders.set('accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8');
  if (!reqHeaders.has('accept-language')) reqHeaders.set('accept-language', 'en-US,en;q=0.5');
  reqHeaders.set('sec-ch-ua', '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"');
  reqHeaders.set('sec-ch-ua-mobile', '?0');
  reqHeaders.set('sec-ch-ua-platform', '"macOS"');
  const modifiedRequest = new Request(targetUrl, {
    method: request.method,
    headers: reqHeaders,
    body: ['GET', 'HEAD'].includes(request.method) ? undefined : await request.text(),
    redirect: 'follow',
  });
  let response;
  try {
    response = await fetch(modifiedRequest);
  } catch (err) {
    return new Response('Upstream fetch error: ' + err.message, { status: 502 });
  }
  const respHeaders = new Headers(response.headers);
  hopByHop.forEach(h => respHeaders.delete(h));
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: respHeaders,
  });
}'''
        Clipboard.copy(worker_code)
        self.app.show_status("Worker code copied to clipboard")


import webbrowser  # اضافه کردن در ابتدای فایل (بالای کلاس AboutTab)

class AboutTab(BoxLayout):
    def __init__(self, app, **kwargs):
        super().__init__(orientation='vertical', **kwargs)
        self.app = app
        self.build_ui()

    def build_ui(self):
        scroll = ScrollView(size_hint=(1, 1))
        content = BoxLayout(orientation='vertical', padding=dp(20), spacing=dp(20), size_hint_y=None)
        content.bind(minimum_height=content.setter('height'))

        # عنوان
        title = Label(
            text="[b]MasterHttpRelayVPN[/b]",
            markup=True, font_size=dp(20), halign='center', size_hint_y=None, height=dp(50)
        )
        content.add_widget(title)

        # توضیح کوتاه
        desc = Label(
            text="A Domain Fronting relay tool using Google Apps Script.\n\n"
                 "Use it responsibly. This software is provided as-is.",
            halign='center', valign='top', size_hint_y=None, height=dp(100)
        )
        desc.bind(size=lambda s, w: setattr(s, 'text_size', (w[0]-40, None)))
        content.add_widget(desc)

        # دکمه لینک GitHub
        github_btn = Button(
            text="GitHub Repository",
            size_hint=(0.6, None),
            height=dp(50),
            pos_hint={'center_x': 0.5},
            background_color=(0.1, 0.1, 0.1, 1),
            color=(1, 1, 1, 1)
        )
        github_btn.bind(on_press=self.open_github)
        content.add_widget(github_btn)

        # نسخه
        version_label = Label(
            text=f"Version {__version__}",
            halign='center', size_hint_y=None, height=dp(40)
        )
        content.add_widget(version_label)

        scroll.add_widget(content)
        self.add_widget(scroll)

    def open_github(self, instance):
        webbrowser.open("https://github.com/omid001php/MasterHttpRelayVPN")
class SystemTray:
    def __init__(self, proxy_tab, settings_tab):
        self.proxy_tab = proxy_tab
        self.settings_tab = settings_tab
        # آیکون – می‌توانید از یک فایل PNG 22x22 استفاده کنید
        # یک تصویر سادهٔ ۲۲×۲۲ با رنگ مشکی تولید می‌کنیم (در صورت نبود فایل)
        self.icon_image = Image.new('RGB', (22, 22), color='black')
        # اگر فایل آیکون دارید: self.icon_image = Image.open("icon.png")

        self.menu = pystray.Menu(
            pystray.MenuItem("Activate Proxy", self.activate_proxy),
            pystray.MenuItem("Deactivate Proxy", self.deactivate_proxy),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Enable SOCKS5 on System", self.enable_socks),
            pystray.MenuItem("Disable SOCKS5 on System", self.disable_socks),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Launch App", self.launch_app),
            pystray.MenuItem("Quit", self.quit_app),
        )
        self.icon = pystray.Icon("MHRVPN", self.icon_image, "MasterHttpRelayVPN", self.menu)
        self._running = False

    def run(self):
        self._running = True
        self.icon.run()   # این دستور مسدودکننده است، باید در نخ جداگانه اجرا شود

    def stop(self):
        if self._running:
            self.icon.stop()
            self._running = False

    # ---------- متدهای کنترل ----------
    def activate_proxy(self, icon, item):
        # درخواست به Kivy در نخ اصلی
        Clock.schedule_once(lambda dt: self.proxy_tab.start_proxy())

    def deactivate_proxy(self, icon, item):
        Clock.schedule_once(lambda dt: self.proxy_tab.stop_proxy())

    def enable_socks(self, icon, item):
        Clock.schedule_once(lambda dt: self.settings_tab.toggle_system_tunnel(None, True))

    def disable_socks(self, icon, item):
        Clock.schedule_once(lambda dt: self.settings_tab.toggle_system_tunnel(None, False))

    def launch_app(self, icon, item):
        Clock.schedule_once(lambda dt: self._bring_app_to_front())

    def quit_app(self, icon, item):
        Clock.schedule_once(lambda dt: self._quit_app())

    def _bring_app_to_front(self):
        app = App.get_running_app()
        if app and app.root_window:
            app.root_window.show()
            app.root_window.raise_window()

    def _quit_app(self):
        # توقف آیکون و سپس بستن برنامه
        self.stop()
        App.get_running_app().stop()
class MasterHttpRelayApp(App):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.script_manager = ScriptManager()
        self.proxy_tab = ProxyTab(self)          # نمونه پنهان پروکسی
        self.logs_tab = None
        self.settings_tab = None

    def build(self):
        self.title = f'MasterHttpRelayVPN v{__version__}'
        self.root = TabbedPanel()
        self.root.do_default_tab = False

        self.config_tab = ConfigTab(self)
        self.settings_tab = SettingsTab(self)
        self.logs_tab = LogsTab(self)
        self.about_tab = AboutTab(self)
        self.help_tab = HelpTab(self)

        tab_config = TabbedPanelHeader(text='Config')
        tab_config.content = self.config_tab
        self.root.add_widget(tab_config)

        tab_settings = TabbedPanelHeader(text='Settings')
        tab_settings.content = self.settings_tab
        self.root.add_widget(tab_settings)

        # افزودن تب Resolver
        self.resolver_tab = ResolverTab(self)
        tab_resolver = TabbedPanelHeader(text='Resolver')
        tab_resolver.content = self.resolver_tab
        self.root.add_widget(tab_resolver)

        tab_logs = TabbedPanelHeader(text='Logs')
        tab_logs.content = self.logs_tab
        self.root.add_widget(tab_logs)

        tab_about = TabbedPanelHeader(text='About')
        tab_about.content = self.about_tab
        self.root.add_widget(tab_about)

        tab_help = TabbedPanelHeader(text='Help')
        tab_help.content = self.help_tab
        self.root.add_widget(tab_help)

        self.root.switch_to(tab_config)   # default tab

               # System tray icon (cross‑platform)
        try:
            from PIL import Image
            self.tray = SystemTray(self.proxy_tab, self.settings_tab)
            threading.Thread(target=self.tray.run, daemon=True).start()
        except Exception as e:
            logging.warning(f"System tray icon not available: {e}")

        return self.root

    def show_status(self, text):
        if self.proxy_tab:
            self.proxy_tab.log(text)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    MasterHttpRelayApp().run()
