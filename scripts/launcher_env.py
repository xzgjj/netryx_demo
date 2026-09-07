# -*- coding: utf-8 -*-
"""launcher_env.py — netryx_demo 按需手动启动器:启动前环境检测模块(标准库,零第三方依赖)

用途: 在启动 netryx 引擎(engine/netryx.py, --host 0.0.0.0 --port 8765)之前,
一次性检查清楚"能不能跑、手机能不能访问、该注意什么",输出中文 + 可行动指引;
供手动启动器与后续 audit-06/07 复用。

对外接口(上层 import 用,签名稳定):
  collect_network_context() -> dict
      枚举本机 IPv4 地址与默认网关(详见函数 docstring);
  check_port_free(port=8765) -> (bool, str)
  check_python() -> (bool, str)
  check_data_writable() -> (bool, str)
  check_firewall_hint() -> bool
  render_report(ctx) -> str
      中文报告纯文本(按 环境/网络/建议 分组),由调用方打印;
  main() -> int
      命令行入口,支持 --port N;退出码见下。

退出码约定:
  0  全部通过;
  1  端口被占用(本模块只报告状态,是否继续由上层决定);
  2  环境硬性问题(Python 版本过低 / 数据目录不可写)。

代码基线: Python 3.8+ 语法(禁止 3.9+ 新语法,如 str.removeprefix / dict | dict);
仅 import 标准库;子进程调用统一显式超时(防卡死)。
"""
import ipaddress
import os
import re
import socket
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(ROOT, "netryx-data")

DEFAULT_PORT = 8765
PYTHON_MIN = (3, 8)
PYTHON_URL = "https://www.python.org/downloads/"
PROBE_NAME = ".launcher_env_probe"

# 虚拟/非业务网卡名称关键词(大小写不敏感;命中视为虚拟网卡、降低主网卡优先级)
VIRTUAL_MARKERS = (
    "vmware", "virtualbox", "vbox", "vmnet", "vethernet",
    "hyper-v", "hyperv", "wsl", "docker", "tunnel", "teredo",
    "loopback", "tap-", "tailscale", "zerotier", "virtual",
    "bluetooth", "蓝牙",
)

# ipconfig 字段键(_norm_key 归一化后匹配;中英文系统均兼容)
_KEYS_IPV4 = ("ipv4address", "ipaddress", "ipv4地址", "ip地址")
_KEYS_GATEWAY = ("defaultgateway", "默认网关")

# 网卡块头前缀(中英文系统均匹配;取冒号前文本后剥掉,只留网卡名)
_ADAPTER_PREFIXES = ("wireless lan adapter ", "ethernet adapter ",
                     "tunnel adapter ", "无线局域网适配器 ",
                     "以太网适配器 ", "隧道适配器 ")


# ------------------------------------------------------------------ 工具
def _norm_key(raw):
    """ipconfig 字段名归一化: 去空白与点号,转小写。

    例: "IPv4 Address . . . . . . . ." -> "ipv4address";
        "IPv4 地址" -> "ipv4地址"; "Default Gateway" -> "defaultgateway"。
    """
    return re.sub(r"[\s.]+", "", raw).lower()


def _decode_output(raw):
    """子进程输出解码: 先 utf-8(英文/UTF-8 系统),失败回退 gb18030(中文 Windows)。"""
    if not raw:
        return ""
    for enc in ("utf-8", "gb18030"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def _run_ipconfig():
    """执行 ipconfig(显式超时防卡死);失败/超时返回空串。"""
    try:
        p = subprocess.run(["ipconfig"], capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return _decode_output(p.stdout)


def _valid_ipv4(text):
    """纯 IPv4 判定(用 ipaddress;None/空串/IPv6/垃圾串返回 False)。"""
    if not text or not isinstance(text, str):
        return False
    try:
        return ipaddress.ip_address(text.strip()).version == 4
    except ValueError:
        return False


def _is_usable_ipv4(ip):
    """可用 IPv4 判定: 排除回环(127.0.0.0/8)、链路本地(169.254.0.0/16)、0.0.0.0。"""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (addr.version == 4 and not addr.is_loopback
            and not addr.is_link_local and not addr.is_unspecified)


def _is_private_ip(ip):
    """私有地址判定(ipaddress;非法输入返回 False)。"""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _class_rank(ip):
    """私有地址段启发优先序: 192.168.* > 10.* > 172.16-31.*;其余返回 0。"""
    parts = ip.split(".")
    if len(parts) != 4:
        return 0
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return 0
    if a == 192 and b == 168:
        return 3
    if a == 10:
        return 2
    if a == 172 and 16 <= b <= 31:
        return 1
    return 0


def _is_virtual_adapter(name):
    """按网卡名称关键词判断是否虚拟/非业务网卡(VMware/VirtualBox/WSL/Hyper-V/隧道等)。"""
    low = (name or "").lower()
    return any(marker in low for marker in VIRTUAL_MARKERS)


def _clean_adapter_name(header):
    """剥掉 ipconfig 块头的前缀(如 "Ethernet adapter "),只留网卡名。"""
    low = header.lower()
    for prefix in _ADAPTER_PREFIXES:
        if low.startswith(prefix):
            return header[len(prefix):]
    return header


# ------------------------------------------------------------------ 网络上下文
def _parse_ipconfig(text):
    """解析 ipconfig 输出 -> 网卡记录列表(适配器中英文键兼容)。

    结构约定: 非缩进行且以 ":" 结尾者为网卡块头(块名 = 冒号前文本);
    块内缩进行按 "字段名 ... : 值" 划分,识别 IPv4 地址与默认网关,
    识别失败不影响其他条目(可部分解析)。返回 [{"ip", "adapter", "gateway",
    "has_gateway", "virtual"}, ...],按出现顺序排列。
    """
    entries = []
    adapter = ""
    ips = []
    gateway = None

    def flush():
        nonlocal gateway
        for ip in ips:
            if not _valid_ipv4(ip):
                continue
            gw = gateway if _valid_ipv4(gateway) else None
            entries.append({
                "ip": ip,
                "adapter": adapter or "(未知网卡)",
                "gateway": gw,
                "has_gateway": gw is not None,
                "virtual": _is_virtual_adapter(adapter),
            })
        ips.clear()
        gateway = None

    for line in text.splitlines():
        if not line.strip():
            continue
        if line[:1] in (" ", "\t"):
            key, _, value = line.partition(":")
            norm = _norm_key(key)
            value = value.strip()
            if norm in _KEYS_IPV4 and _valid_ipv4(value):
                ips.append(value)
            elif norm in _KEYS_GATEWAY and _valid_ipv4(value):
                gateway = value
        else:
            if line.rstrip().endswith(":"):
                flush()
                adapter = _clean_adapter_name(line.rstrip()[:-1].strip())
    flush()
    return entries


def _socket_ips():
    """socket 方案枚举本机 IPv4(gethostname + getaddrinfo + gethostbyname_ex 组合)。

    ipconfig 不可用时的兜底: 拿不到网卡名与网关,但能拿到地址列表。
    结果去重(保持首次出现顺序)并过滤回环/链路本地。
    """
    found = []

    def add(ip):
        if ip and _is_usable_ipv4(ip) and ip not in found:
            found.append(ip)

    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = None
    if hostname:
        try:
            for item in socket.getaddrinfo(hostname, None,
                                           socket.AF_INET, socket.SOCK_STREAM):
                add(item[4][0])
        except socket.gaierror:
            pass
        try:
            for ip in socket.gethostbyname_ex(hostname)[2]:
                add(ip)
        except socket.gaierror:
            pass
    return found


def _pick_primary(interfaces):
    """主网卡启发式: 打分选优,取分数最高者(并列取先出现者)。

    评分项: 有默认网关 +8 / 非虚拟网卡 +4 / 私有地址 +2 / 地址段优先序(1-3)。
    语义等价于"取第一个非虚拟私有地址"(简单启发),打分为其确定化: 即使
    虚拟网卡名称不可识别(非英文名称),也能优先选中带默认网关的业务网卡。
    全部地址不可用时返回 None。
    """
    best = None
    best_score = -1
    for item in interfaces:
        if not _is_usable_ipv4(item["ip"]):
            continue
        score = 0
        if item.get("has_gateway"):
            score += 8
        if not item.get("virtual"):
            score += 4
        if _is_private_ip(item["ip"]):
            score += 2
        score += _class_rank(item["ip"])
        if score > best_score:
            best = item["ip"]
            best_score = score
    return best


def collect_network_context():
    """枚举本机网络上下文,返回 dict:
      ips         所有可用 IPv4(排除 127.*/169.254.*),按网卡顺序
      primary_ip  主网卡建议(启发式;无可用地址为 None)
      gateway     默认网关(优先取主网卡对应网关;解析失败为 None)
      subnet_hint 主 IP 的 /24 网段字符串,如 "192.168.3.0/24"
      platform    sys.platform
      interfaces  详细条目列表(附加信息,见 _parse_ipconfig 返回结构)

    Windows: 优先解析 `ipconfig`(能拿到默认网关与网卡名,中英文系统兼容,
    中文输出按 gb18030 解码);解析失败或无记录时回退 socket 枚举
    (网关/网卡名为空)。其他平台直接 socket 枚举。
    """
    interfaces = []
    if sys.platform.startswith("win"):
        interfaces = _parse_ipconfig(_run_ipconfig())
    if not interfaces:
        for ip in _socket_ips():
            interfaces.append({
                "ip": ip,
                "adapter": "(socket 枚举)",
                "gateway": None,
                "has_gateway": False,
                "virtual": False,
            })
    ips = [item["ip"] for item in interfaces]
    primary = _pick_primary(interfaces)
    gateway = None
    if primary:
        for item in interfaces:
            if item["ip"] == primary and item["gateway"]:
                gateway = item["gateway"]
                break
    if gateway is None:  # 主网卡无网关时,取首个能解析到的网关(仅信息参考)
        for item in interfaces:
            if item["gateway"]:
                gateway = item["gateway"]
                break
    subnet_hint = None
    if primary:
        subnet_hint = str(ipaddress.ip_network("%s/24" % primary, strict=False))
    return {"ips": ips, "primary_ip": primary, "gateway": gateway,
            "subnet_hint": subnet_hint, "platform": sys.platform,
            "interfaces": interfaces}


# ------------------------------------------------------------------ 单项检查
def check_port_free(port=DEFAULT_PORT):
    """检测端口是否可被服务绑定(绑定 0.0.0.0,与引擎 --host 0.0.0.0 行为一致)。

    返回 (ok, message):
      ok=True  端口空闲(可绑定);
      ok=False 端口已被占用,message 含修复指引(换端口 --port 参)。
    超出 1-65535 或探测异常时不判占用(ok=True),但会在消息中说明原因。
    """
    if not isinstance(port, int) or not (0 < port <= 65535):
        return (True, "端口 %r 不在有效范围(1-65535),未探测(视作空闲);"
                      "修复指引: 启动时改用有效端口" % port)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("0.0.0.0", port))
        return (True, "端口 %d 空闲" % port)
    except OSError as e:
        errno_ = getattr(e, "errno", None)
        if errno_ in (10048, 98):  # WSAEADDRINUSE / EADDRINUSE
            return (False, "端口 %d 已被占用,可能已在运行;"
                           "修复指引: 结束占用进程,或换端口(--port 参)启动" % port)
        return (True, "端口 %d 探测异常(%s),未判占用;启动前建议先确认" % (port, e))
    finally:
        s.close()


def check_python():
    """检查 Python 版本 >= 3.8(引擎与本模块的运行基线)。"""
    v = sys.version_info
    ok = (v.major, v.minor) >= PYTHON_MIN
    if ok:
        return (True, "Python %d.%d.%d (>= %d.%d 满足)" % (
            v.major, v.minor, v.micro, PYTHON_MIN[0], PYTHON_MIN[1]))
    return (False, "Python %d.%d.%d 过低(需 >= %d.%d);修复指引: 到 %s 下载安装 "
                   "Python %d.x,安装时务必勾选 \"Add Python to PATH\"" % (
        v.major, v.minor, v.micro, PYTHON_MIN[0], PYTHON_MIN[1],
        PYTHON_URL, PYTHON_MIN[0]))


def check_data_writable():
    """检查 netryx-data/ 可写(探针写删;与 build.py check_data_dir 同一模式)。

    写删任一失败即判不可写;失败消息含修复指引(权限/磁盘满/重定向数据目录)。
    """
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
    except OSError as e:
        return (False, "创建数据目录 %s 失败(%s);修复指引: 检查磁盘空间与目录"
                       "权限,或设置环境变量 NETRYX_DATA 指向可写目录" % (DATA_DIR, e))
    probe = os.path.join(DATA_DIR, PROBE_NAME)
    try:
        with open(probe, "w", encoding="utf-8") as f:
            f.write("ok\n")
    except OSError as e:
        return (False, "数据目录不可写(探针写入失败 %s: %s);修复指引: 检查目录"
                       "权限(只读/被占用)与磁盘空间,或用环境变量 NETRYX_DATA "
                       "重定向到可写目录" % (probe, e))
    try:
        os.remove(probe)
    except OSError as e:
        return (False, "数据目录不可写(探针删除失败 %s: %s);修复指引: 检查杀毒/"
                       "文件占用后重试,或用环境变量 NETRYX_DATA 重定向到可写目录"
                       % (probe, e))
    return (True, "数据目录 %s 可写(探针写删通过)"
                  % os.path.relpath(DATA_DIR, ROOT))


def check_firewall_hint():
    """是否给出防火墙提醒: 仅 Windows 需要(首次监听 0.0.0.0 需允许专用网络)。"""
    return sys.platform.startswith("win")


# ------------------------------------------------------------------ 报告
def _platform_label(platform):
    """平台代号转人类可读标签;未知原样返回。"""
    if platform.startswith("win"):
        return "Windows (%s)" % platform
    if platform == "linux":
        return "Linux"
    if platform == "darwin":
        return "macOS"
    return platform or "(未知)"


def render_report(ctx):
    """渲染中文环境检查报告(纯文本,由调用方打印;仿 build.py 一行一项风格)。

    ctx 结构(main 组装,也可手造用于测试):
      network        collect_network_context() 的返回 dict
      port           检测端口(int)
      results        {"python": (ok, msg), "data_writable": (ok, msg),
                      "port_free": (ok, msg)}
      firewall_hint  bool,是否给 Windows 防火墙提醒
    FAIL 项的消息中已内嵌"修复指引: ...",报告不再重复。
    """
    net = ctx.get("network") or {}
    results = ctx.get("results") or {}
    port = ctx.get("port", DEFAULT_PORT)
    primary = net.get("primary_ip")
    gateway = net.get("gateway")
    interfaces = net.get("interfaces") or []
    lines = []
    bar = "=" * 64
    lines.append(bar)
    lines.append(" netryx_demo 启动前环境检测 (launcher_env)")
    lines.append(bar)

    # ---- 环境 ----
    lines.append("[环境]")
    for key, label in (("python", "Python 版本"),
                       ("data_writable", "数据目录")):
        ok, msg = results.get(key, (True, "未执行"))
        lines.append("  [%s] %s: %s" % ("OK" if ok else "FAIL", label, msg))

    # ---- 网络 ----
    lines.append("[网络]")
    ok, msg = results.get("port_free", (True, "未执行"))
    lines.append("  [%s] 端口 %d: %s" % ("OK" if ok else "FAIL", port, msg))
    lines.append("  [信息] 平台: %s" % _platform_label(net.get("platform", "")))
    if interfaces:
        lines.append("  [信息] 本机 IPv4 地址(共 %d 个):" % len(interfaces))
        for idx, item in enumerate(interfaces, 1):
            mark = "  [主网卡建议]" if item["ip"] == primary else ""
            lines.append("      %d. %-15s %s%s" % (
                idx, item["ip"], item.get("adapter", ""), mark))
            if item.get("gateway"):
                lines.append("          网关: %s" % item["gateway"])
    else:
        lines.append("  [FAIL] 未发现可用 IPv4 地址(已排除 127.*/169.254.*);"
                     "修复指引: 连接有效网络(有线/WiFi)后重试")
    if primary:
        lines.append("  网络段: %s" % (net.get("subnet_hint")
                                      or ("%s/24" % primary)))
        lines.append("  默认网关: %s" % (gateway or "(未解析到)"))
        lines.append("  手机访问地址: http://%s:%d" % (primary, port))
        lines.append("  修复指引: 手机无法访问时,确认手机与电脑在同一 WiFi,"
                     "并能 ping 通 %s" % (gateway or primary))
    else:
        lines.append("  本机访问地址: http://127.0.0.1:%d" % port)
        lines.append("  手机访问地址: 未确定;修复指引: 连接有效网络后重试")

    # ---- 建议 ----
    lines.append("[建议]")
    if ctx.get("firewall_hint"):
        lines.append("  [!] Windows 首次运行: 如弹出防火墙提示,请勾选"
                     "\"专用网络\"并允许访问,否则手机访问会被拦截")
    lines.append("  [!] 默认账号 admin/admin,登录后请到 Settings 修改密码")
    if any(item.get("virtual") for item in interfaces):
        lines.append("  [!] 检测到虚拟网卡(VMware/VirtualBox 等): 手机访问必须"
                     "使用上方主网卡地址,勿用虚拟网卡段(192.168.56.x/119.x 等)")
    if primary and gateway:
        lines.append("  [!] 手机访问必须与电脑同一网段(%s)" % net.get("subnet_hint"))

    # ---- 结论 ----
    py_ok = results.get("python", (True, ""))[0]
    data_ok = results.get("data_writable", (True, ""))[0]
    port_ok = results.get("port_free", (True, ""))[0]
    lines.append(bar)
    if not (py_ok and data_ok):
        lines.append("存在环境硬性问题,请先按上方\"修复指引\"处理 (退出码 2)")
    elif not port_ok:
        lines.append("端口被占用: 已给出处理指引,是否继续启用备用端口由上层决定 "
                     "(退出码 1)")
    else:
        lines.append("全部检查通过,可以启动服务 (退出码 0)")
    lines.append(bar)
    return "\n".join(lines)


# ------------------------------------------------------------------ 命令行
def _to_port(text):
    """字符串转端口号(int);非整数返回 None(范围校验交给 check_port_free)。"""
    try:
        return int(text)
    except (TypeError, ValueError):
        return None


def _parse_args(argv):
    """解析命令行参数: 仅识别 --port N 与 --port=N;非法用法返回 None。"""
    port = DEFAULT_PORT
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--port":
            if i + 1 >= len(argv):
                return None
            parsed = _to_port(argv[i + 1])
            if parsed is None:
                return None
            port = parsed
            i += 2
        elif arg.startswith("--port="):
            parsed = _to_port(arg.split("=", 1)[1])
            if parsed is None:
                return None
            port = parsed
            i += 1
        elif arg in ("-h", "--help"):
            return None
        else:
            return None
    return {"port": port}


def main():
    """命令行入口: 顺序收集(网络上下文 -> 端口 -> Python -> 数据目录 -> 防火墙
    提示)后渲染并打印报告;返回退出码(0/1/2,见模块 docstring)。"""
    args = _parse_args(sys.argv[1:])
    if args is None:
        sys.stdout.write("用法: %s [--port 8765]\n"
                         % os.path.basename(sys.argv[0]))
        return 1
    port = args["port"]

    network = collect_network_context()
    port_ok, port_msg = check_port_free(port)
    py_ok, py_msg = check_python()
    data_ok, data_msg = check_data_writable()
    firewall_hint = check_firewall_hint()
    ctx = {
        "network": network,
        "port": port,
        "results": {
            "python": (py_ok, py_msg),
            "data_writable": (data_ok, data_msg),
            "port_free": (port_ok, port_msg),
        },
        "firewall_hint": firewall_hint,
    }
    sys.stdout.write(render_report(ctx))
    sys.stdout.write("\n")
    if not (py_ok and data_ok):
        return 2
    if not port_ok:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
