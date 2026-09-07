# -*- coding: utf-8 -*-
"""launch.py — netryx_demo 一键启动器(主流程,标准库,零第三方依赖)。

编排 scripts/launcher_env.py(环境体检/报告)与 scripts/launcher_engine.py
(引擎子进程管理),主流程: 环境检测 -> 渲染报告 -> 决策 -> 启动提示 ->
start_engine/wait_ready -> 就绪横幅 -> 信号处理 -> 阻塞保持 -> 退出摘要,
全程 finally 兜底清理(无残留)。

加载: 先把项目根 ROOT 插入 sys.path,优先 ``from scripts import ...``
(scripts/ 无 __init__.py 时靠 Python 3.3+ 命名空间包),失败再按文件路径用
importlib.util 加载(与 launcher_engine.py 同一方案;两模块内部已处理路径,
这里只保证自身能 import 它们)。

退出码约定:
  0  成功(含 --help;启动->就绪->正常保持后停止);
  1  启动或端口问题(端口被占用 / 引擎启动失败 / 未就绪 / 参数用法错误);
  2  环境硬性问题(Python 版本过低 / 数据目录不可写,含 --check-only 体检结论);
  3  未预期异常(捕获并打印 traceback)。

运行: python -X utf8 scripts\\launch.py [--port 8765] [--host 0.0.0.0]
       [--data-dir <路径>] [--check-only]

代码基线: Python 3.8+ 语法(未用 3.9+ 新语法,如 str.removeprefix / dict | dict);
仅 import 标准库;子进程调用统一显式超时(防卡死,由 launcher_engine 内建)。
"""
import argparse
import importlib.util
import os
import sys
import time
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(ROOT, "scripts")
ENV_FILE = os.path.join(SCRIPTS_DIR, "launcher_env.py")
ENGINE_FILE = os.path.join(SCRIPTS_DIR, "launcher_engine.py")

DEFAULT_PORT = 8765
DEFAULT_HOST = "0.0.0.0"
DEFAULT_DATA_DIR = os.path.join(ROOT, "netryx-data")
READY_TIMEOUT = 30.0          # wait_ready 超时(秒),与 launcher_engine 默认一致
HOLD_POLL_INTERVAL = 0.5      # 阻塞保持轮询间隔(秒)
TAIL_LINES = 6                # 失败/退出摘要展示的最近输出行数

# 退出码(见模块 docstring)
EXIT_OK = 0
EXIT_RUN = 1
EXIT_ENV = 2
EXIT_UNEXPECTED = 3

EXIT_CONTROL_C = 0xC000013A   # Windows 进程被 Ctrl+C / Ctrl+Break 终止

# ANSI 颜色(仅 stdout 为 TTY 时生效;重定向/管道下自动退化为纯文本)
_ANSI = {
    "green": "\033[32m",
    "yellow": "\033[33m",
    "red": "\033[31m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}


# ------------------------------------------------------------------ 模块加载
_MODULES = {}


def _load_file_module(name, path):
    """按模块名 + 文件路径加载脚本(缓存于 sys.modules;与 launcher_engine 同名).

    launcher_engine 自身也会经 ``scripts.launcher_env`` 加载环境模块,
    这里同名写入 sys.modules,保证两份加载指向同一模块对象。
    """
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError("无法加载模块 %s(路径: %s)" % (name, path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def load_modules():
    """加载 launcher_env / launcher_engine -> (env, engine);结果缓存。

    方案与 launcher_engine 一致: ROOT 入 sys.path 后先走命名空间包导入
    (scripts/ 无 __init__.py,Python 3.3+ 支持),失败按文件路径 importlib 兜底。
    """
    if "env" in _MODULES:
        return _MODULES["env"], _MODULES["engine"]
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    try:
        from scripts import launcher_env, launcher_engine  # noqa: F401
        env, engine = launcher_env, launcher_engine
    except (ImportError, ValueError):
        env = _load_file_module("scripts.launcher_env", ENV_FILE)
        engine = _load_file_module("scripts.launcher_engine", ENGINE_FILE)
    _MODULES["env"], _MODULES["engine"] = env, engine
    return env, engine


# ------------------------------------------------------------------ 输出辅助
def _configure_streams():
    """stdout/stderr 改为 errors="replace": 非 utf-8 代码页输出中文/emoji 不抛错.

    正常运行路径以 ``python -X utf8`` 启动(编码 utf-8,不做任何替换);
    此配置仅为裸奔(未加 -X utf8)时兜底,保证流程不中断。
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(errors="replace")
            except (OSError, ValueError, TypeError):
                pass


def _enable_ansi():
    """Windows 控制台启用 ANSI 转义(业界通行 os.system("") 技法;仅 TTY 时调用)."""
    if os.name == "nt" and sys.stdout.isatty():
        try:
            os.system("")
        except OSError:
            pass


def paint(text, color=None, bold=False):
    """给文本着色: stdout 是 TTY 时加 ANSI 码,否则原样返回(管道/重定向安全)。"""
    if not sys.stdout.isatty():
        return text
    codes = []
    if bold:
        codes.append(_ANSI["bold"])
    if color:
        codes.append(_ANSI.get(color, ""))
    if not codes:
        return text
    return "".join(codes) + text + _ANSI["reset"]


def _print(message="", **kwargs):
    """带 flush 的打印: 管道/重定向下仍实时输出(与引擎日志 tee 的实时性对齐)。"""
    print(message, flush=True, **kwargs)


# ------------------------------------------------------------------ 环境体检
def _probe_dir_writable(path):
    """数据目录写删探针(独立实现): --data-dir 非默认目录时的体检。

    与 launcher_env.check_data_writable 同一模式(建目录 + 探针写删),
    返回 (ok, message),失败消息含修复指引。
    """
    try:
        os.makedirs(path, exist_ok=True)
    except OSError as exc:
        return False, ("创建数据目录 %s 失败(%s);修复指引: 检查磁盘空间与目录"
                       "权限,或改用其它 --data-dir" % (path, exc))
    probe = os.path.join(path, ".launcher_probe")
    try:
        with open(probe, "w", encoding="utf-8") as fh:
            fh.write("ok\n")
        os.remove(probe)
    except OSError as exc:
        return False, ("数据目录不可写(探针 %s 失败: %s);修复指引: 检查目录权限"
                       "(只读/被占用)与磁盘空间,或改用其它 --data-dir" % (probe, exc))
    return True, "数据目录 %s 可写(探针写删通过,--data-dir 指定)" % path


def run_checks(port=DEFAULT_PORT, data_dir=None):
    """执行环境体检,返回与 launcher_env.render_report 兼容的 ctx(dict)。

    顺序固定: check_python -> 数据目录 -> check_port_free -> 网络上下文
    (先硬性环境,再网络;网络上下文供报告展示"手机访问"信息)。
    数据目录: 与 launcher_env 默认目录一致时直接用其 check_data_writable
    (消费契约);--data-dir 指定了其它目录时用本地探针核验该目录。
    """
    env, _engine = load_modules()
    if data_dir is None:
        data_dir = DEFAULT_DATA_DIR
    data_dir = os.path.abspath(data_dir)

    py_ok, py_msg = env.check_python()
    if os.path.normcase(data_dir) == os.path.normcase(env.DATA_DIR):
        data_ok, data_msg = env.check_data_writable()
    else:
        data_ok, data_msg = _probe_dir_writable(data_dir)
    port_ok, port_msg = env.check_port_free(port=port)
    network = env.collect_network_context()

    firewall_hint = False
    check_hint = getattr(env, "check_firewall_hint", None)
    if callable(check_hint):
        firewall_hint = bool(check_hint())
    return {
        "network": network,
        "port": port,
        "data_dir": data_dir,
        "results": {
            "python": (py_ok, py_msg),
            "data_writable": (data_ok, data_msg),
            "port_free": (port_ok, port_msg),
        },
        "firewall_hint": firewall_hint,
    }


def decision(ctx):
    """体检结论 -> 退出码语义: EXIT_OK(全过)/ EXIT_RUN(端口占用)/ EXIT_ENV(硬问题)。"""
    results = ctx.get("results") or {}
    py_ok = results.get("python", (True, ""))[0]
    data_ok = results.get("data_writable", (True, ""))[0]
    port_ok = results.get("port_free", (True, ""))[0]
    if not (py_ok and data_ok):
        return EXIT_ENV
    if not port_ok:
        return EXIT_RUN
    return EXIT_OK


# ------------------------------------------------------------------ 横幅
def render_banners(ctx, mode="start"):
    """渲染横幅文本(mode: "start" 启动中 / "ready" 已就绪),由调用方着色打印。

    ctx 为 run_checks 返回结构;primary_ip 取 launcher_env 的主网卡建议,
    未识别时给出"手机需手动输入电脑 IP"的提示。
    """
    port = ctx.get("port", DEFAULT_PORT)
    primary = (ctx.get("network") or {}).get("primary_ip")
    lines = []
    if mode == "start":
        lines.append("=" * 60)
        if primary:
            lines.append("启动中... 手机访问 http://%s:%d" % (primary, port))
        else:
            lines.append("启动中... 未识别主网卡,手机需手动输入电脑 IP"
                         "(见上方网卡列表,或用 ipconfig 查询)")
        lines.append("(本机访问 http://127.0.0.1:%d;Ctrl+C 或关闭窗口停止)"
                     % port)
        lines.append("=" * 60)
    elif mode == "ready":
        lines.append("=" * 60)
        if primary:
            lines.append("✅ 服务已就绪:http://127.0.0.1:%d(本机)/ "
                         "http://%s:%d(手机);Ctrl+C 或关闭窗口停止;日志: log/engine.log"
                         % (port, primary, port))
        else:
            lines.append("✅ 服务已就绪:http://127.0.0.1:%d(本机)；手机: "
                         "http://<电脑IP>:%d(用 ipconfig 查本机 IPv4);"
                         "Ctrl+C 或关闭窗口停止;日志: log/engine.log"
                         % (port, port))
        lines.append("=" * 60)
    return "\n".join(lines)


# ------------------------------------------------------------------ 主流程
def _describe_exit_code(code):
    """引擎退出码 -> 人类可读说明(0 正常;0xC000013A 为 Windows 手动终止)。"""
    if code == 0:
        return "(正常退出)"
    if code == EXIT_CONTROL_C:
        return "(0xC000013A, 被 Ctrl+C/Ctrl+Break 终止)"
    return "(非零退出)"


def serve(port=DEFAULT_PORT, host=DEFAULT_HOST, data_dir=None, ctx=None,
          ready_timeout=READY_TIMEOUT):
    """启动引擎并保持运行: 启动横幅 -> start_engine -> wait_ready -> 就绪横幅 ->
    信号处理 -> 阻塞保持 -> 引擎退出摘要;finally 兜底 stop_engine(防残留)。

    返回退出码: EXIT_OK 正常;EXIT_RUN 启动失败/未就绪/引擎非零退出。
    """
    env, engine = load_modules()
    tee = engine.default_tee()
    if ctx is None:
        ctx = run_checks(port=port, data_dir=data_dir)
    if data_dir is None:
        data_dir = ctx.get("data_dir") or DEFAULT_DATA_DIR
    data_dir = os.path.abspath(data_dir)

    _print(paint(render_banners(ctx, mode="start"), color="green", bold=True))
    proc = None
    try:
        try:
            proc = engine.start_engine(port=port, data_dir=data_dir, host=host)
        except (ValueError, FileNotFoundError, RuntimeError) as exc:
            _print(paint("[错误] 启动引擎失败: %s" % exc, color="red", bold=True))
            return EXIT_RUN

        ready_ok, ready_msg = engine.wait_ready(proc, port, timeout=ready_timeout)
        if not ready_ok:
            tail = "; ".join(tee.recent_lines(TAIL_LINES)) or "(无输出)"
            _print(paint("[错误] 服务未就绪: %s" % ready_msg, color="red", bold=True))
            _print(paint("[错误] 引擎最近输出: %s" % tail, color="red"))
            _print("[提示] 修复指引: 1) 确认没有重复启动(关闭其它启动窗口);"
                   "2) 防火墙弹窗时勾选\"专用网络\"并允许;"
                   "3) 端口被占用时用 --port 换端口;4) 完整日志见 log/engine.log")
            engine.stop_engine(proc)
            return EXIT_RUN

        _print(paint(render_banners(ctx, mode="ready"), color="green", bold=True))
        engine.install_signal_handlers(proc)

        # 阻塞保持: 引擎退出(自行结束/被终止)时结束循环
        while proc.poll() is None:
            time.sleep(HOLD_POLL_INTERVAL)
        code = proc.poll()
        tail = "; ".join(tee.recent_lines(TAIL_LINES)) or "(无输出)"
        _print("")
        _print("引擎进程已退出,退出码=%s %s;最近输出: %s"
               % (code, _describe_exit_code(code), tail))
        return EXIT_OK if code == 0 else EXIT_RUN
    except KeyboardInterrupt:
        # 兜底: 信号处理未安装(非主线程等)时 Ctrl+C 走这里
        _print("\n收到中断,正在停止引擎...")
        return EXIT_OK
    finally:
        if proc is not None:
            engine.stop_engine(proc)
        tee.join_reader(1.0)
        tee.stop()
        _print("已停止")


def _parse_args(argv=None):
    """解析命令行参数(--port/--host/--data-dir/--check-only);返回 Namespace。"""
    parser = argparse.ArgumentParser(
        description="netryx_demo 启动器: 环境自检 -> 启动引擎 -> 保持运行(手机可访问)",
        epilog="示例: python -X utf8 scripts\\launch.py --port 8766\n"
               "      python -X utf8 scripts\\launch.py --check-only")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help="引擎端口(默认 %d)" % DEFAULT_PORT)
    parser.add_argument("--host", default=DEFAULT_HOST,
                        help="监听地址(默认 %s)" % DEFAULT_HOST)
    parser.add_argument("--data-dir", default=None,
                        help="数据目录(默认 <项目根>/netryx-data)")
    parser.add_argument("--check-only", action="store_true",
                        help="只做环境体检并报告,不启动服务")
    return parser.parse_args(argv)


def _run(args):
    """argparse 之后的实际流程;返回退出码。"""
    data_dir = os.path.abspath(args.data_dir) if args.data_dir else DEFAULT_DATA_DIR
    ctx = run_checks(port=args.port, data_dir=data_dir)
    _print(load_modules()[0].render_report(ctx))
    _print("")

    verdict = decision(ctx)
    if args.check_only:
        return verdict
    if verdict == EXIT_ENV:
        _print(paint("[错误] 存在环境硬性问题,请先按报告中\"修复指引\"处理后"
                     "再启动(退出码 %d)" % EXIT_ENV, color="red", bold=True))
        return EXIT_ENV
    if verdict == EXIT_RUN:
        _print(paint("[错误] 端口 %d 被占用: 可能引擎已在运行;请结束占用进程,"
                     "或使用 --port 换端口(退出码 %d)"
                     % (args.port, EXIT_RUN), color="red", bold=True))
        return EXIT_RUN
    return serve(port=args.port, host=args.host, data_dir=data_dir, ctx=ctx)


def main(argv=None):
    """命令行入口;返回退出码(0/1/2/3,见模块 docstring)。"""
    _configure_streams()
    _enable_ansi()
    try:
        args = _parse_args(argv)
    except SystemExit as exc:  # argparse: --help 退出 0;用法错误退出 2 -> 归入 1
        return EXIT_OK if exc.code == 0 else EXIT_RUN
    try:
        return _run(args)
    except SystemExit:
        raise  # 信号处理器的 sys.exit(0) 原样放行(保持退出码 0)
    except KeyboardInterrupt:
        _print("\n已中断")
        return EXIT_OK
    except Exception as exc:  # noqa: BLE001 未预期异常 -> 摘要 + 退出 3
        _print(paint("[错误] 未预期异常: %s" % exc, color="red", bold=True))
        traceback.print_exc()
        return EXIT_UNEXPECTED


if __name__ == "__main__":
    sys.exit(main())
