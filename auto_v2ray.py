#!/usr/bin/env python3
"""
auto_v2ray.py — 从订阅地址抓取代理节点，生成 Clash Verge (Meta 内核) 配置文件 v2.meta.yml
"""

import base64
import json
import re
import socket
import sys
import concurrent.futures
from datetime import datetime
from urllib.parse import parse_qs, unquote, urlparse

import requests
import yaml

# 修复 Windows 控制台编码问题
import io
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ('utf-8', 'utf8'):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')


# ---------------------------------------------------------------------------
# Base64 辅助
# ---------------------------------------------------------------------------

def safe_b64decode(s: str) -> bytes:
    """Base64 解码，自动补齐 padding，同时支持标准和 URL-safe 变体。"""
    s = s.strip()
    s = s.replace("-", "+").replace("_", "/")
    padding = 4 - len(s) % 4
    if padding and padding != 4:
        s += "=" * padding
    return base64.b64decode(s)


# ---------------------------------------------------------------------------
# GitHub URL 转 raw
# ---------------------------------------------------------------------------

def github_to_raw(url: str) -> str:
    """将 github.com 仓库页面 URL 转成 raw.githubusercontent.com 直链。"""
    m = re.match(
        r"https?://github\.com/([^/]+)/([^/]+)/blob/(.+)", url
    )
    if m:
        return f"https://raw.githubusercontent.com/{m.group(1)}/{m.group(2)}/{m.group(3)}"
    return url


# ---------------------------------------------------------------------------
# 抓取订阅
# ---------------------------------------------------------------------------

def fetch_subscriptions(urls: list[str]) -> list[str]:
    """逐个抓取订阅 URL，返回所有代理 URI 行的列表。"""
    all_lines: list[str] = []
    headers = {
        "User-Agent": "ClashMeta/1.0",
        "Accept": "*/*",
    }
    for raw_url in urls:
        # 去掉 URL 中 # 后面的注释部分
        url = raw_url.split("#")[0].strip()
        if not url:
            continue
        url = github_to_raw(url)
        print(f"[fetch] {url}")
        try:
            resp = requests.get(url, headers=headers, timeout=15, allow_redirects=True)
            resp.raise_for_status()
            content = resp.text.strip()
        except Exception as e:
            print(f"  ✗ 失败: {e}")
            continue

        # 尝试 Base64 整体解码
        lines = try_decode_subscription(content)
        print(f"  ✓ 获取 {len(lines)} 条")
        all_lines.extend(lines)
    return all_lines


def try_decode_subscription(content: str) -> list[str]:
    """尝试 Base64 解码整个订阅内容；如果失败则按行分割。"""
    # 如果内容已经是 URI 格式开头，直接按行拆分
    if re.match(r"(vmess|vless|ss|ssr|trojan|hysteria2?|hy2|tuic|socks5?)://", content):
        return [l.strip() for l in content.splitlines() if l.strip()]

    # 尝试 YAML / JSON —— 有些订阅直接返回 Clash 配置
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict) and "proxies" in data:
            # 直接返回空列表，后续会从 clash 配置中提取
            return ["__clash_yaml__:" + content]
    except Exception:
        pass

    # 尝试 Base64 解码
    try:
        decoded = safe_b64decode(content).decode("utf-8", errors="replace").strip()
        return [l.strip() for l in decoded.splitlines() if l.strip()]
    except Exception:
        pass

    # 最后按行返回
    return [l.strip() for l in content.splitlines() if l.strip()]


# ---------------------------------------------------------------------------
# 协议解析器
# ---------------------------------------------------------------------------

def parse_vmess(uri: str) -> dict | None:
    """vmess://base64json"""
    try:
        payload = uri[len("vmess://"):]
        raw = safe_b64decode(payload).decode("utf-8", errors="replace")
        j = json.loads(raw)
    except Exception:
        return None

    name = j.get("ps") or j.get("remark") or ""
    server = j.get("add", "")
    port = int(j.get("port", 0))
    if not server or not port:
        return None

    proxy: dict = {
        "name": name or f"vmess-{server}:{port}",
        "type": "vmess",
        "server": server,
        "port": port,
        "uuid": j.get("id", ""),
        "alterId": int(j.get("aid", 0)),
        "cipher": j.get("scy", "auto") or "auto",
    }

    net = j.get("net", "tcp")
    tls = j.get("tls", "")
    proxy["network"] = net
    proxy["tls"] = tls in ("tls", "1", "true")

    if proxy["tls"]:
        sni = j.get("sni") or j.get("host", "")
        if sni:
            proxy["servername"] = sni
        proxy["skip-cert-verify"] = True

    host = j.get("host", "")
    path = j.get("path", "")

    if net == "ws":
        ws_opts: dict = {}
        if path:
            ws_opts["path"] = path
        if host:
            ws_opts["headers"] = {"Host": host}
        if ws_opts:
            proxy["ws-opts"] = ws_opts
    elif net == "h2":
        h2_opts: dict = {}
        if path:
            h2_opts["path"] = path
        if host:
            h2_opts["host"] = [host]
        if h2_opts:
            proxy["h2-opts"] = h2_opts
    elif net == "grpc":
        grpc_path = j.get("path", "")
        if grpc_path:
            proxy["grpc-opts"] = {"grpc-service-name": grpc_path}

    proxy["udp"] = True
    return proxy


def parse_vless(uri: str) -> dict | None:
    """vless://uuid@server:port?params#name"""
    try:
        rest = uri[len("vless://"):]
        if "#" in rest:
            rest, fragment = rest.rsplit("#", 1)
            name = unquote(fragment)
        else:
            name = ""
        userinfo, hostport_qs = rest.split("@", 1)
        uuid = userinfo

        if "?" in hostport_qs:
            hostport, qs_str = hostport_qs.split("?", 1)
        else:
            hostport, qs_str = hostport_qs, ""

        # 处理 IPv6 地址
        if hostport.startswith("["):
            bracket_end = hostport.index("]")
            server = hostport[1:bracket_end]
            port = int(hostport[bracket_end + 2:])
        else:
            server, port_str = hostport.rsplit(":", 1)
            port = int(port_str)

        params = parse_qs(qs_str, keep_blank_values=True)
        # parse_qs 返回列表，取第一个值
        p = {k: v[0] for k, v in params.items()}
    except Exception:
        return None

    if not server or not port:
        return None

    proxy: dict = {
        "name": name or f"vless-{server}:{port}",
        "type": "vless",
        "server": server,
        "port": port,
        "uuid": uuid,
        "udp": True,
    }

    security = p.get("security", "none")
    net_type = p.get("type", "tcp")

    if security == "tls":
        proxy["tls"] = True
        sni = p.get("sni") or p.get("host", "")
        if sni:
            proxy["servername"] = sni
        fp = p.get("fp", "")
        if fp:
            proxy["client-fingerprint"] = fp
        proxy["skip-cert-verify"] = True
    elif security == "reality":
        proxy["tls"] = True
        sni = p.get("sni", "")
        if sni:
            proxy["servername"] = sni
        pbk = p.get("pbk", "")
        sid = p.get("sid", "")
        reality_opts: dict = {}
        if pbk:
            reality_opts["public-key"] = pbk
        if sid:
            reality_opts["short-id"] = sid
        if reality_opts:
            proxy["reality-opts"] = reality_opts
        fp = p.get("fp", "")
        if fp:
            proxy["client-fingerprint"] = fp
        proxy["skip-cert-verify"] = False
    else:
        proxy["tls"] = False

    flow = p.get("flow", "")
    if flow:
        proxy["flow"] = flow

    encryption = p.get("encryption", "none")
    if encryption:
        proxy["encryption"] = encryption

    proxy["network"] = net_type

    if net_type == "ws":
        ws_opts: dict = {}
        path = p.get("path", "")
        if path:
            ws_opts["path"] = unquote(path)
        host = p.get("host", "")
        if host:
            ws_opts["headers"] = {"Host": host}
        if ws_opts:
            proxy["ws-opts"] = ws_opts
    elif net_type == "grpc":
        sn = p.get("serviceName", "")
        if sn:
            proxy["grpc-opts"] = {"grpc-service-name": sn}
    elif net_type == "h2":
        h2_opts: dict = {}
        path = p.get("path", "")
        if path:
            h2_opts["path"] = unquote(path)
        host = p.get("host", "")
        if host:
            h2_opts["host"] = [host]
        if h2_opts:
            proxy["h2-opts"] = h2_opts

    return proxy


def parse_ss(uri: str) -> dict | None:
    """ss://base64(method:password)@server:port#name  或 SIP002 格式"""
    try:
        rest = uri[len("ss://"):]
        name = ""
        if "#" in rest:
            rest, fragment = rest.rsplit("#", 1)
            name = unquote(fragment)

        if "@" in rest:
            # 可能是 SIP002: base64(method:password)@server:port
            # 也可能是 method:password@server:port (无 base64)
            parts = rest.split("@", 1)
            userinfo_raw = parts[0]
            hostport = parts[1]

            # 尝试 base64 解码 userinfo
            try:
                userinfo = safe_b64decode(userinfo_raw).decode("utf-8")
            except Exception:
                userinfo = userinfo_raw

            if ":" not in userinfo:
                return None
            method, password = userinfo.split(":", 1)

            # 处理查询参数
            if "?" in hostport:
                hostport = hostport.split("?", 1)[0]

            if hostport.startswith("["):
                bracket_end = hostport.index("]")
                server = hostport[1:bracket_end]
                port = int(hostport[bracket_end + 2:])
            else:
                server, port_str = hostport.rsplit(":", 1)
                port = int(port_str)
        else:
            # 整体 base64 编码: ss://base64(method:password@server:port)
            decoded = safe_b64decode(rest).decode("utf-8")
            if "@" not in decoded:
                return None
            userinfo, hostport = decoded.rsplit("@", 1)
            method, password = userinfo.split(":", 1)
            server, port_str = hostport.rsplit(":", 1)
            port = int(port_str)

        if not server or not port:
            return None

        return {
            "name": name or f"ss-{server}:{port}",
            "type": "ss",
            "server": server,
            "port": port,
            "password": password,
            "cipher": method,
        }
    except Exception:
        return None


def parse_ssr(uri: str) -> dict | None:
    """ssr://base64(server:port:protocol:method:obfs:base64pass/?params)"""
    try:
        rest = uri[len("ssr://"):]
        decoded = safe_b64decode(rest).decode("utf-8", errors="replace")
        # server:port:protocol:method:obfs:base64pass/?obfsparam=...&remarks=...
        main_part, _, param_part = decoded.partition("/?")
        parts = main_part.split(":")
        if len(parts) < 6:
            return None
        server = parts[0]
        port = int(parts[1])
        protocol = parts[2]
        method = parts[3]
        obfs = parts[4]
        password_b64 = parts[5]
        password = safe_b64decode(password_b64).decode("utf-8", errors="replace")

        params = parse_qs(param_part, keep_blank_values=True)
        p = {k: v[0] for k, v in params.items()}

        name = ""
        if "remarks" in p:
            try:
                name = safe_b64decode(p["remarks"]).decode("utf-8", errors="replace")
            except Exception:
                name = p["remarks"]

        obfs_param = ""
        if "obfsparam" in p:
            try:
                obfs_param = safe_b64decode(p["obfsparam"]).decode("utf-8", errors="replace")
            except Exception:
                obfs_param = p["obfsparam"]

        proto_param = ""
        if "protoparam" in p:
            try:
                proto_param = safe_b64decode(p["protoparam"]).decode("utf-8", errors="replace")
            except Exception:
                proto_param = p["protoparam"]

        proxy: dict = {
            "name": name or f"ssr-{server}:{port}",
            "type": "ssr",
            "server": server,
            "port": port,
            "password": password,
            "cipher": method,
            "protocol": protocol,
            "obfs": obfs,
        }
        if proto_param:
            proxy["protocol-param"] = proto_param
        if obfs_param:
            proxy["obfs-param"] = obfs_param

        return proxy
    except Exception:
        return None


def parse_trojan(uri: str) -> dict | None:
    """trojan://password@server:port?params#name"""
    try:
        rest = uri[len("trojan://"):]
        name = ""
        if "#" in rest:
            rest, fragment = rest.rsplit("#", 1)
            name = unquote(fragment)

        userinfo, hostport_qs = rest.split("@", 1)
        password = unquote(userinfo)

        if "?" in hostport_qs:
            hostport, qs_str = hostport_qs.split("?", 1)
        else:
            hostport, qs_str = hostport_qs, ""

        if hostport.startswith("["):
            bracket_end = hostport.index("]")
            server = hostport[1:bracket_end]
            port = int(hostport[bracket_end + 2:])
        else:
            server, port_str = hostport.rsplit(":", 1)
            port = int(port_str)

        params = parse_qs(qs_str, keep_blank_values=True)
        p = {k: v[0] for k, v in params.items()}
    except Exception:
        return None

    if not server or not port:
        return None

    proxy: dict = {
        "name": name or f"trojan-{server}:{port}",
        "type": "trojan",
        "server": server,
        "port": port,
        "password": password,
        "udp": True,
        "skip-cert-verify": True,
    }

    sni = p.get("sni") or p.get("peer", "")
    if sni:
        proxy["sni"] = sni

    net_type = p.get("type", "tcp")
    if net_type == "ws":
        proxy["network"] = "ws"
        ws_opts: dict = {}
        path = p.get("path", "")
        if path:
            ws_opts["path"] = unquote(path)
        host = p.get("host", "")
        if host:
            ws_opts["headers"] = {"Host": host}
        if ws_opts:
            proxy["ws-opts"] = ws_opts
    elif net_type == "grpc":
        proxy["network"] = "grpc"
        sn = p.get("serviceName", "")
        if sn:
            proxy["grpc-opts"] = {"grpc-service-name": sn}

    fp = p.get("fp", "")
    if fp:
        proxy["client-fingerprint"] = fp

    return proxy


def parse_hysteria2(uri: str) -> dict | None:
    """hysteria2://password@server:port?params#name  (也支持 hy2://)"""
    try:
        # 统一前缀
        if uri.startswith("hy2://"):
            rest = uri[len("hy2://"):]
        else:
            rest = uri[len("hysteria2://"):]

        name = ""
        if "#" in rest:
            rest, fragment = rest.rsplit("#", 1)
            name = unquote(fragment)

        userinfo, hostport_qs = rest.split("@", 1)
        password = unquote(userinfo)

        if "?" in hostport_qs:
            hostport, qs_str = hostport_qs.split("?", 1)
        else:
            hostport, qs_str = hostport_qs, ""

        if hostport.startswith("["):
            bracket_end = hostport.index("]")
            server = hostport[1:bracket_end]
            port = int(hostport[bracket_end + 2:])
        else:
            server, port_str = hostport.rsplit(":", 1)
            port = int(port_str)

        params = parse_qs(qs_str, keep_blank_values=True)
        p = {k: v[0] for k, v in params.items()}
    except Exception:
        return None

    if not server or not port:
        return None

    proxy: dict = {
        "name": name or f"hysteria2-{server}:{port}",
        "type": "hysteria2",
        "server": server,
        "port": port,
        "password": password,
        "udp": True,
    }

    sni = p.get("sni", "")
    if sni:
        proxy["sni"] = sni
    obfs = p.get("obfs", "")
    if obfs:
        proxy["obfs"] = obfs
    obfs_password = p.get("obfs-password", "")
    if obfs_password:
        proxy["obfs-password"] = obfs_password
    proxy["skip-cert-verify"] = True

    return proxy


# ---------------------------------------------------------------------------
# 从 Clash YAML 配置中直接提取 proxies
# ---------------------------------------------------------------------------

def extract_clash_proxies(content: str) -> list[dict]:
    """如果订阅返回的是 Clash 配置文件，直接提取 proxies 列表。"""
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict) and "proxies" in data:
            proxies = data["proxies"]
            if isinstance(proxies, list):
                return [p for p in proxies if isinstance(p, dict) and "name" in p]
    except Exception:
        pass
    return []


# ---------------------------------------------------------------------------
# 解析入口
# ---------------------------------------------------------------------------

PARSERS = {
    "vmess://": parse_vmess,
    "vless://": parse_vless,
    "ss://": parse_ss,
    "ssr://": parse_ssr,
    "trojan://": parse_trojan,
    "hysteria2://": parse_hysteria2,
    "hy2://": parse_hysteria2,
}


def parse_lines(lines: list[str]) -> list[dict]:
    proxies: list[dict] = []
    for line in lines:
        # 处理 Clash YAML 直传
        if line.startswith("__clash_yaml__:"):
            content = line[len("__clash_yaml__:"):]
            proxies.extend(extract_clash_proxies(content))
            continue

        for scheme, parser in PARSERS.items():
            if line.startswith(scheme):
                result = parser(line)
                if result:
                    proxies.append(result)
                break
    return proxies


# ---------------------------------------------------------------------------
# 去重 & 名称去重
# ---------------------------------------------------------------------------

def dedup_proxies(proxies: list[dict]) -> list[dict]:
    """按 (server, port, type) 去重。遇到重名则追加编号。"""
    seen_keys: set[tuple] = set()
    unique: list[dict] = []
    for p in proxies:
        key = (p.get("server", ""), p.get("port", 0), p.get("type", ""))
        if key in seen_keys:
            continue
        seen_keys.add(key)
        unique.append(p)

    # 名称去重
    name_count: dict[str, int] = {}
    for p in unique:
        n = p["name"]
        if n in name_count:
            name_count[n] += 1
            p["name"] = f"{n}_{name_count[n]}"
        else:
            name_count[n] = 0

    return unique


# ---------------------------------------------------------------------------
# 地区分组
# ---------------------------------------------------------------------------

REGION_KEYWORDS: dict[str, list[str]] = {
    "🇯🇵 日本": ["日本", "JP", "Japan", "东京", "大阪", "🇯🇵"],
    "🇺🇸 美国": ["美国", "US", "United States", "USA", "🇺🇸", "洛杉矶", "纽约",
                 "紐約", "San Jose", "Ashburn", "圣路易斯", "Piscataway", "聖荷西"],
    "🇸🇬 新加坡": ["新加坡", "SG", "Singapore", "🇸🇬"],
    "🇰🇷 韩国": ["韩国", "KR", "Korea", "首尔", "🇰🇷"],
    "🇬🇧 英国": ["英国", "GB", "UK", "United Kingdom", "🇬🇧", "伦敦"],
    "🇩🇪 德国": ["德国", "DE", "Germany", "🇩🇪", "法兰克福"],
    "🇫🇷 法国": ["法国", "FR", "France", "🇫🇷", "鲁贝", "巴黎"],
    "🇷🇺 俄罗斯": ["俄罗斯", "RU", "Russia", "🇷🇺", "莫斯科"],
    "🇨🇦 加拿大": ["加拿大", "CA", "Canada", "🇨🇦"],
    "🇦🇺 澳大利亚": ["澳大利亚", "AU", "Australia", "🇦🇺", "悉尼"],
    "🇮🇳 印度": ["印度", "IN", "India", "🇮🇳", "海得拉巴", "孟买"],
    "🇧🇷 巴西": ["巴西", "BR", "Brazil", "🇧🇷", "圣保罗"],
}


def classify_regions(proxies: list[dict]) -> dict[str, list[str]]:
    """按关键字将节点分到各地区组。"""
    groups: dict[str, list[str]] = {region: [] for region in REGION_KEYWORDS}
    for p in proxies:
        name = p["name"]
        for region, keywords in REGION_KEYWORDS.items():
            for kw in keywords:
                if kw.lower() in name.lower():
                    groups[region].append(name)
                    break
    # 去掉空组
    return {k: v for k, v in groups.items() if v}


# ---------------------------------------------------------------------------
# 生成配置
# ---------------------------------------------------------------------------

def build_config(proxies: list[dict]) -> dict:
    """以 outcome.meta.yml 为蓝本，构建完整 Clash Meta 配置。"""
    all_names = [p["name"] for p in proxies]
    region_groups = classify_regions(proxies)

    config: dict = {}

    # 固定部分
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    config["allow-lan"] = False
    config["dns"] = {
        "enable": True,
        "enhanced-mode": "redir-host",
        "fallback": ["8.8.8.8", "1.1.1.1"],
        "ipv6": True,
        "listen": ":1053",
        "nameserver": ["223.5.5.5", "114.114.114.114"],
    }
    config["external-controller"] = "0.0.0.0:9090"
    config["global-client-fingerprint"] = "chrome"
    config["ipv6"] = True
    config["log-level"] = "warning"
    config["mixed-port"] = 7890
    config["mode"] = "rule"

    # proxies
    config["proxies"] = proxies

    # proxy-groups
    pg: list[dict] = []

    # 选择代理
    pg.append({
        "name": "🚀 选择代理",
        "type": "select",
        "proxies": ["♻ 自动选择", "🔰 延迟最低", "✅ 手动选择", "🗺️ 选择地区"],
    })

    # 自动选择 (fallback)
    pg.append({
        "name": "♻ 自动选择",
        "type": "fallback",
        "url": "https://www.google.com/",
        "interval": 300,
        "proxies": list(all_names),
    })

    # 延迟最低 (url-test)
    pg.append({
        "name": "🔰 延迟最低",
        "type": "url-test",
        "url": "https://www.google.com/",
        "interval": 300,
        "tolerance": 20,
        "proxies": list(all_names),
    })

    # 手动选择
    pg.append({
        "name": "✅ 手动选择",
        "type": "select",
        "proxies": list(all_names),
    })

    # 突破锁区 / 疑似国内 / 漏网之鱼 / 病毒网站 / 广告拦截
    pg.append({
        "name": "🌐 突破锁区",
        "type": "select",
        "proxies": ["DIRECT", "🚀 选择代理"],
    })
    pg.append({
        "name": "❓ 疑似国内",
        "type": "select",
        "proxies": ["DIRECT", "🚀 选择代理", "REJECT"],
    })
    pg.append({
        "name": "🐟 漏网之鱼",
        "type": "select",
        "proxies": ["DIRECT", "🚀 选择代理"],
    })
    pg.append({
        "name": "🚨 病毒网站",
        "type": "select",
        "proxies": ["REJECT", "DIRECT"],
    })
    pg.append({
        "name": "⛔ 广告拦截",
        "type": "select",
        "proxies": ["REJECT", "DIRECT", "🚀 选择代理"],
    })

    # 选择地区
    available_regions = list(region_groups.keys())
    if available_regions:
        pg.append({
            "name": "🗺️ 选择地区",
            "type": "select",
            "proxies": available_regions,
        })

    # 地区子组
    for region_name, node_names in region_groups.items():
        pg.append({
            "name": region_name,
            "type": "select",
            "proxies": node_names,
        })

    config["proxy-groups"] = pg

    # rules
    config["rules"] = [
        "DOMAIN-SUFFIX,ads.google.com,⛔ 广告拦截",
        "DOMAIN-SUFFIX,adservice.google.com,⛔ 广告拦截",
        "DOMAIN-SUFFIX,googleadservices.com,⛔ 广告拦截",
        "DOMAIN-SUFFIX,doubleclick.net,⛔ 广告拦截",
        "DOMAIN-SUFFIX,ad.com,⛔ 广告拦截",
        "DOMAIN-SUFFIX,adnxs.com,⛔ 广告拦截",
        "DOMAIN-SUFFIX,adsrvr.org,⛔ 广告拦截",
        "DOMAIN-SUFFIX,pgdt.ugdtimg.com,⛔ 广告拦截",
        "DOMAIN-KEYWORD,adservice,⛔ 广告拦截",
        "DOMAIN-KEYWORD,tracking,⛔ 广告拦截",
        "DOMAIN-SUFFIX,malware-site.example,🚨 病毒网站",
        # 国内直连
        "DOMAIN-SUFFIX,cn,DIRECT",
        "DOMAIN-SUFFIX,baidu.com,DIRECT",
        "DOMAIN-SUFFIX,qq.com,DIRECT",
        "DOMAIN-SUFFIX,taobao.com,DIRECT",
        "DOMAIN-SUFFIX,tmall.com,DIRECT",
        "DOMAIN-SUFFIX,jd.com,DIRECT",
        "DOMAIN-SUFFIX,alipay.com,DIRECT",
        "DOMAIN-SUFFIX,163.com,DIRECT",
        "DOMAIN-SUFFIX,126.com,DIRECT",
        "DOMAIN-SUFFIX,weibo.com,DIRECT",
        "DOMAIN-SUFFIX,bilibili.com,DIRECT",
        "DOMAIN-SUFFIX,zhihu.com,DIRECT",
        "DOMAIN-SUFFIX,douyin.com,DIRECT",
        "DOMAIN-SUFFIX,toutiao.com,DIRECT",
        "DOMAIN-SUFFIX,csdn.net,DIRECT",
        "DOMAIN-SUFFIX,aliyun.com,DIRECT",
        "DOMAIN-SUFFIX,aliyuncs.com,DIRECT",
        "DOMAIN-SUFFIX,tencentcloud.com,DIRECT",
        "DOMAIN-SUFFIX,meituan.com,DIRECT",
        "DOMAIN-SUFFIX,dianping.com,DIRECT",
        "DOMAIN-SUFFIX,mi.com,DIRECT",
        "DOMAIN-SUFFIX,xiaomi.com,DIRECT",
        # 代理
        "DOMAIN-SUFFIX,google.com,🚀 选择代理",
        "DOMAIN-SUFFIX,google.co.jp,🚀 选择代理",
        "DOMAIN-SUFFIX,googleapis.com,🚀 选择代理",
        "DOMAIN-SUFFIX,gstatic.com,🚀 选择代理",
        "DOMAIN-SUFFIX,youtube.com,🚀 选择代理",
        "DOMAIN-SUFFIX,ytimg.com,🚀 选择代理",
        "DOMAIN-SUFFIX,googlevideo.com,🚀 选择代理",
        "DOMAIN-SUFFIX,gmail.com,🚀 选择代理",
        "DOMAIN-SUFFIX,github.com,🚀 选择代理",
        "DOMAIN-SUFFIX,githubusercontent.com,🚀 选择代理",
        "DOMAIN-SUFFIX,twitter.com,🚀 选择代理",
        "DOMAIN-SUFFIX,x.com,🚀 选择代理",
        "DOMAIN-SUFFIX,twimg.com,🚀 选择代理",
        "DOMAIN-SUFFIX,facebook.com,🚀 选择代理",
        "DOMAIN-SUFFIX,fbcdn.net,🚀 选择代理",
        "DOMAIN-SUFFIX,instagram.com,🚀 选择代理",
        "DOMAIN-SUFFIX,whatsapp.com,🚀 选择代理",
        "DOMAIN-SUFFIX,telegram.org,🚀 选择代理",
        "DOMAIN-SUFFIX,t.me,🚀 选择代理",
        "DOMAIN-SUFFIX,wikipedia.org,🚀 选择代理",
        "DOMAIN-SUFFIX,reddit.com,🚀 选择代理",
        "DOMAIN-SUFFIX,netflix.com,🚀 选择代理",
        "DOMAIN-SUFFIX,nflxvideo.net,🚀 选择代理",
        "DOMAIN-SUFFIX,spotify.com,🚀 选择代理",
        "DOMAIN-SUFFIX,discord.com,🚀 选择代理",
        "DOMAIN-SUFFIX,discordapp.com,🚀 选择代理",
        "DOMAIN-SUFFIX,openai.com,🚀 选择代理",
        "DOMAIN-SUFFIX,claude.ai,🚀 选择代理",
        "DOMAIN-SUFFIX,anthropic.com,🚀 选择代理",
        "DOMAIN-SUFFIX,chatgpt.com,🚀 选择代理",
        "DOMAIN-SUFFIX,amazonaws.com,🚀 选择代理",
        "DOMAIN-SUFFIX,cloudflare.com,🚀 选择代理",
        "DOMAIN-SUFFIX,microsoft.com,🚀 选择代理",
        "DOMAIN-SUFFIX,apple.com,🚀 选择代理",
        "DOMAIN-SUFFIX,icloud.com,🚀 选择代理",
        "DOMAIN-SUFFIX,amazon.com,🚀 选择代理",
        "DOMAIN-SUFFIX,twitch.tv,🚀 选择代理",
        "DOMAIN-SUFFIX,steam.com,🚀 选择代理",
        "DOMAIN-SUFFIX,steampowered.com,🚀 选择代理",
        "DOMAIN-SUFFIX,steamcommunity.com,🚀 选择代理",
        "DOMAIN-SUFFIX,pixiv.net,🚀 选择代理",
        "DOMAIN-SUFFIX,pximg.net,🚀 选择代理",
        "DOMAIN-SUFFIX,docker.com,🚀 选择代理",
        "DOMAIN-SUFFIX,docker.io,🚀 选择代理",
        "DOMAIN-SUFFIX,npmjs.org,🚀 选择代理",
        "DOMAIN-SUFFIX,pypi.org,🚀 选择代理",
        "DOMAIN-SUFFIX,huggingface.co,🚀 选择代理",
        "DOMAIN-SUFFIX,medium.com,🚀 选择代理",
        "DOMAIN-SUFFIX,stackoverflow.com,🚀 选择代理",
        # 锁区
        "DOMAIN-SUFFIX,hulu.com,🌐 突破锁区",
        "DOMAIN-SUFFIX,hbo.com,🌐 突破锁区",
        "DOMAIN-SUFFIX,hbomax.com,🌐 突破锁区",
        "DOMAIN-SUFFIX,disneyplus.com,🌐 突破锁区",
        "DOMAIN-SUFFIX,disney-plus.net,🌐 突破锁区",
        "DOMAIN-SUFFIX,primevideo.com,🌐 突破锁区",
        "DOMAIN-SUFFIX,dazn.com,🌐 突破锁区",
        # 兜底
        "GEOIP,CN,❓ 疑似国内",
        "MATCH,🐟 漏网之鱼",
    ]

    # sniffer
    config["sniffer"] = {
        "enable": True,
        "skip-domain": ["Mijia Cloud", "dlg.io.mi.com", "+.apple.com"],
        "sniff": {
            "HTTP": {
                "override-destination": True,
                "ports": [80, "8080-8880"],
            },
            "TLS": {
                "ports": [443, 8443],
            },
        },
    }

    config["tcp-concurrent"] = True
    config["unified-delay"] = True

    return config


# ---------------------------------------------------------------------------
# YAML 输出 (保持与样本一致的风格)
# ---------------------------------------------------------------------------

class MetaDumper(yaml.SafeDumper):
    """自定义 YAML Dumper: 保证可读性。"""
    pass


# 让字符串中含有特殊字符时用引号
def _str_representer(dumper, data):
    if any(c in data for c in ":#{}[]!@&*?,|>'\"\\\n"):
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="'")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


MetaDumper.add_representer(str, _str_representer)


def write_config(config: dict, output_path: str):
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(f"# Update: {now}\n")
        yaml.dump(
            config,
            f,
            Dumper=MetaDumper,
            allow_unicode=True,
            default_flow_style=False,
            sort_keys=False,
            width=1000,
        )


# ---------------------------------------------------------------------------
# 节点测速 (TCP 连接延迟)
# ---------------------------------------------------------------------------

LATENCY_TIMEOUT = 3.0  # 超时阈值（秒）
LATENCY_WORKERS = 50   # 并发线程数


def test_latency(proxy: dict) -> int | None:
    """TCP 连接测速，返回延迟毫秒数；超时或失败返回 None。"""
    server = proxy.get("server", "")
    port = proxy.get("port", 0)
    if not server or not port:
        return None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(LATENCY_TIMEOUT)
        start = __import__("time").perf_counter()
        sock.connect((server, int(port)))
        elapsed = __import__("time").perf_counter() - start
        sock.close()
        return int(elapsed * 1000)
    except Exception:
        return None


def filter_by_latency(proxies: list[dict]) -> list[dict]:
    """并发测速，为每个节点添加 delay 字段，删除超时节点，按延迟排序。"""
    total = len(proxies)
    results: list[tuple[dict, int | None]] = []

    print(f"[*] 开始测速 ({total} 个节点, 超时 {LATENCY_TIMEOUT}s, 并发 {LATENCY_WORKERS}) ...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=LATENCY_WORKERS) as pool:
        futures = {pool.submit(test_latency, p): p for p in proxies}
        done_count = 0
        for future in concurrent.futures.as_completed(futures):
            p = futures[future]
            ms = future.result()
            results.append((p, ms))
            done_count += 1
            if done_count % 20 == 0 or done_count == total:
                print(f"  测速进度: {done_count}/{total}")

    alive: list[dict] = []
    timeout_count = 0
    for p, ms in results:
        if ms is not None:
            p["delay"] = ms
            alive.append(p)
        else:
            timeout_count += 1

    # 按延迟排序
    alive.sort(key=lambda x: x.get("delay", 99999))

    # 在节点名称前加上延迟标签
    for p in alive:
        ms = p.get("delay", 0)
        p["name"] = f"[{ms}ms] {p['name']}"

    print(f"  可用: {len(alive)}, 超时/失败: {timeout_count}")
    return alive


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    import os

    script_dir = os.path.dirname(os.path.abspath(__file__))
    sub_file = os.path.join(script_dir, "v2ray订阅地址.yaml")
    output_file = os.path.join(script_dir, "v2.meta.yml")

    # 1. 读取订阅地址
    print(f"[*] 读取订阅地址: {sub_file}")
    with open(sub_file, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    urls = data.get("subscribe_urls", [])
    if not urls:
        print("[!] 未找到订阅地址，退出")
        sys.exit(1)
    print(f"[*] 共 {len(urls)} 个订阅源\n")

    # 2. 抓取
    lines = fetch_subscriptions(urls)
    print(f"\n[*] 共获取 {len(lines)} 条原始记录")

    # 3. 解析
    proxies = parse_lines(lines)
    print(f"[*] 成功解析 {len(proxies)} 个节点")

    # 4. 去重
    proxies = dedup_proxies(proxies)
    print(f"[*] 去重后 {len(proxies)} 个节点")

    if not proxies:
        print("[!] 没有可用节点，退出")
        sys.exit(1)

    # 5. 测速筛选
    proxies = filter_by_latency(proxies)
    if not proxies:
        print("[!] 所有节点超时，退出")
        sys.exit(1)

    # 6. 生成配置
    config = build_config(proxies)

    # 7. 输出
    write_config(config, output_file)
    print(f"\n[✓] 配置已写入: {output_file}")
    print(f"    节点数: {len(proxies)}")
    region_groups = classify_regions(proxies)
    for region, nodes in region_groups.items():
        print(f"    {region}: {len(nodes)} 个")


if __name__ == "__main__":
    main()
