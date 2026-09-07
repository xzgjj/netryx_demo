# -*- coding: utf-8 -*-
"""verifier_launcher.py — 启动器关键场景演练工具(交付前冒烟,标准库,零第三方依赖)。

用途(SPEC §3.12 "最坏情况矩阵"的可重复演练):
  把启动器(scripts/launch.py + launcher_env + launcher_engine)的关键场景做成
  一键执行的实际演练。交付前跑一遍即可回答:健康体检是否通过、端口占用提示
  是否到位、坏数据目录是否给出修复指引、报告完整性、引擎启动-就绪-停止契约
  是否成立。

场景(S1-S7,见 scenarios()):
  S1 健康体检:   launch.py --check-only -> 退出码 0,报告"全部检查通过";
  S2 端口占用:   演练内用 socket 占住 9999,再 --check-only --port 9999
                 -> 退出码 1,输出含"换端口/占用"提示(演练结束即释放端口);
  S3 坏数据目录: 先建一个临时文件,把它的路径当 --data-dir
                 -> 退出码 2,输出含"数据目录"修复指引(演练后清理临时文件);
  S4 报告完整性: --check-only 输出含"手机访问地址"与"admin/admin";
  S5 引擎契约:   launcher_engine.start_engine + wait_ready + stop_engine
                 在小端口 9998 全链演练 -> ok=True;残留检测(端口无 LISTENING);
  S6 主网卡引导: --check-only 输出须含"主网卡建议"与"手机访问地址 http://",
                 且不含"未识别主网卡"——多网卡/虚拟网卡场景下验证用户被引导
                 到正确地址(本机 3 网卡,应打出建议);
  S7 快速失败:   tcp_probe 对空闲端口 9997 判"未监听";wait_ready 对"引擎启动
                 即失败"的进程在 3 秒内返回 False——验证未就绪路径快速失败
                 (不空等 30s;不启动真实引擎,quick 下也演练)。

实现要点:
  - 所有子进程统一 [sys.executable, "-X", "utf8", ...] + 显式超时(单场景 120s),
    超时按失败计入(与项目"子进程调用统一显式超时"纪律一致,防卡死);
  - S2/S3/S5 的临时资源(占位 socket、临时文件与目录、引擎子进程与日志 tee)
    均在 finally 中释放/终止,保证演练后 9998/9999 无残留监听;
  - 端口探测用"尝试连接"判据(与 launcher_engine._host_port_free 同一模式),
    避免 bind 的 TIME_WAIT 误判;
  - S5 使用 9998 小端口与临时数据目录,不触碰生产默认端口 8765,不与现有服务冲突。

结果与退出码:
  run_all() 逐场景输出 [PASS]/[FAIL] 行(rc 与提示命中);
  报告同时写入 log/verifier-launcher-<时间戳>.json,顶层
  {ok,total,passed,failed,scenarios};全部通过退出 0,任一失败退出 1。

运行:
  python -X utf8 scripts\\verifier_launcher.py [--only S2,S4] [--quick]
    --only   仅演练指定场景(逗号分隔;按名字,如 "S2 端口占用"/"S2",或序号 1-7);
    --quick  跳过 S5(引擎全链最慢,约 5-10 秒;S7 无真实引擎,quick 下也演练)。

代码基线: Python 3.8+ 语法(未用 3.9+ 新语法,如 str.removeprefix / dict | dict);
仅 import 标准库。
"""
import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAUNCHER_PATH = os.path.join(ROOT, "scripts", "launch.py")
LOG_DIR = os.path.join(ROOT, "log")

SCENARIO_TIMEOUT = 120.0      # 单场景子进程超时(秒)
ENGINE_PORT = 9998            # S5 演练端口(避开默认 8765,不与现有服务冲突)
BUSY_PORT = 9999              # S2 占位端口(仅演练内)
SMOKE_IDLE_PORT = 9997        # S7 冒烟: 已知空闲端口(不启动任何服务)
FAST_FAIL_LIMIT = 3.0         # S7 未就绪快速失败上限(秒)
READY_TIMEOUT = 30.0          # S5 wait_ready 超时(秒)
TAIL_LINES = 12               # 场景输出尾部展示行数
RELEASE_TIMEOUT = 6.0         # S5 停止后残留检测等待(秒)

_ANSI = {"green": "\033[32m", "yellow": "\033[33m", "red": "\033[31m",
         "bold": "\033[1m", "reset": "\033[0m"}

# 引擎模块缓存(与 launch.py 同方案: ROOT 入 sys.path 后命名空间包导入)
_engine_module = None


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


def _print(message=""):
    """带 flush 的打印(管道/重定向下仍实时输出)。"""
    print(message, flush=True)


# ------------------------------------------------------------------ 子进程
def run_launcher(args, timeout=SCENARIO_TIMEOUT):
    """运行 scripts/launch.py(子进程: [python, -X utf8, launch.py] + args)。

    返回 (退出码, 输出文本);退出码为 None 表示超时或无法启动(按失败计)。
    """
    cmd = [sys.executable, "-X", "utf8", LAUNCHER_PATH] + [str(a) for a in args]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              encoding="utf-8", errors="replace",
                              timeout=timeout, cwd=ROOT)
    except subprocess.TimeoutExpired:
        return None, "演练超时(>%.0fs): %s" % (timeout, " ".join(cmd))
    except OSError as exc:
        return None, "启动演练子进程失败(%s): %s" % (cmd[0], exc)
    return proc.returncode, (proc.stdout or "") + ("\n" if proc.stderr else "") + (proc.stderr or "")


# ------------------------------------------------------------------ 端口探测
def tcp_probe(host, port, timeout=0.5):
    """尝试连接 host:port(0.5s 超时),返回 (可连接?, 错误说明)。

    判据与 launcher_engine._probe_tcp 一致: "无人能连接"视作端口无监听,
    避开 bind 对 TIME_WAIT 的误判。
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, ""
    except OSError as exc:
        return False, str(exc)


def wait_port_released(port, host="127.0.0.1", timeout=RELEASE_TIMEOUT, poll=0.3):
    """轮询等待端口无人监听(连接被拒),返回 (是否已释放, 说明)。"""
    deadline = time.time() + timeout
    last_err = ""
    while time.time() < deadline:
        ok, err = tcp_probe(host, port, timeout=0.4)
        if not ok:
            return True, "端口 %d 无 LISTENING(连接被拒, 无残留)" % port
        last_err = err
        time.sleep(poll)
    return False, "端口 %d 仍可连接(存在残留监听): %s" % (port, last_err)


# ------------------------------------------------------------------ 场景实现
def sc_check_only():
    """S1 健康体检: launch.py --check-only -> 期望 rc 0,报告"全部检查通过"。"""
    return run_launcher(["--check-only"])


def sc_port_busy(port=BUSY_PORT):
    """S2 端口占用: 演练内占住 port,再体检该端口 -> 期望 rc 1 + 换端口/占用提示。

    占位 socket 仅本场景存活,finally 关闭释放,不影响后续场景。
    """
    holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        holder.bind(("0.0.0.0", port))
        holder.listen(1)
        return run_launcher(["--check-only", "--port", str(port)])
    except OSError as exc:
        return None, ("占位端口 %d 失败(%s): %s;可能是演练环境已有服务监听该端口"
                      % (port, type(exc).__name__, exc))
    finally:
        try:
            holder.close()
        except OSError:
            pass


def sc_bad_data_dir():
    """S3 坏数据目录: 建临时文件并以其路径当 --data-dir -> 期望 rc 2 + 数据目录指引。

    --data-dir 指向一个已存在文件时,launch.py 的目录探针报"创建数据目录失败",
    结论为环境硬性问题(退出码 2);临时文件与目录在 finally 清理。
    """
    tmpdir = tempfile.mkdtemp(prefix="verifier-s3-")
    bad_path = os.path.join(tmpdir, "not_a_dir_placeholder")
    try:
        with open(bad_path, "w", encoding="utf-8") as fh:
            fh.write("占位文件: 用文件路径冒充 --data-dir 目录\n")
        return run_launcher(["--check-only", "--data-dir", bad_path])
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def sc_report_complete():
    """S4 报告完整性: --check-only 输出须含"手机访问地址"与"admin/admin"。"""
    return run_launcher(["--check-only"])


def _load_engine_module():
    """加载 scripts/launcher_engine(与 launch.py 同方案,结果缓存)。"""
    global _engine_module
    if _engine_module is not None:
        return _engine_module
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    from scripts import launcher_engine
    _engine_module = launcher_engine
    return launcher_engine


def sc_engine_contract(port=ENGINE_PORT, ready_timeout=READY_TIMEOUT):
    """S5 引擎契约: start_engine -> wait_ready -> stop_engine 全链 + 残留检测。

    使用 9998 小端口与临时数据目录,不触碰默认 8765 与真实服务;
    返回 (0, 摘要) 全链通过,否则 (1, 失败原因)。
    """
    engine = _load_engine_module()
    tmpdir = tempfile.mkdtemp(prefix="verifier-s5-")
    proc = None
    try:
        ok_before, why_before = tcp_probe("127.0.0.1", port, timeout=0.4)
        if ok_before:
            return 1, ("前置检查失败: 端口 %d 已被监听(%s),无法演练引擎链"
                       % (port, why_before))
        proc = engine.start_engine(port=port, data_dir=tmpdir,
                                   host=engine.DEFAULT_HOST)
        ready_ok, ready_msg = engine.wait_ready(proc, port, timeout=ready_timeout)
        if not ready_ok:
            return 1, "引擎链失败(wait_ready): %s" % ready_msg
        engine.stop_engine(proc)
        proc = None  # 已停止,防 finally 重复终止
        released, rel_msg = wait_port_released(port)
        if not released:
            return 1, "引擎链残留: %s" % rel_msg
        return 0, ("引擎契约演练通过: 启动->就绪('%s')->停止 全链 ok; 残留检测: %s"
                   % (ready_msg, rel_msg))
    except (ValueError, FileNotFoundError, RuntimeError) as exc:
        return 1, "引擎链失败(启动): %s" % exc
    finally:
        if proc is not None:
            try:
                engine.stop_engine(proc)
            except Exception:  # noqa: BLE001 清理路径收敛,不向外抛
                pass
        try:
            engine.default_tee().stop()
        except Exception:  # noqa: BLE001
            pass
        shutil.rmtree(tmpdir, ignore_errors=True)


def sc_main_nic_guidance():
    """S6 主网卡引导: --check-only 输出须给出主网卡建议与手机访问地址。

    本机多网卡(含虚拟网卡)时,launcher_env.render_report 应为选中的主网卡
    打 [主网卡建议] 标记,并给出"手机访问地址: http://<IP>:<port>";
    断言在注册表 expect_hint 中: 同时命中"主网卡建议/手机访问地址/http://",
    且不含"未识别主网卡"(避免用户被引导到虚拟网卡段)。
    """
    return run_launcher(["--check-only"])


def sc_fast_fail_not_ready(port=SMOKE_IDLE_PORT, fast_limit=FAST_FAIL_LIMIT):
    """S7 快速失败: 空闲端口判"未监听" + wait_ready 对未就绪路径快速返回 False。

    两步(均不启动真实引擎,与 S5 分工):
      1) tcp_probe(127.0.0.1, 9997) 应不可连接(判"未监听")——验证探测判据;
      2) 用"已退出的一次性子进程"模拟引擎启动即失败,调 launcher_engine.
         wait_ready(其快速失败分支: 进程已退出便立刻返回 False,不空等 30s),
         须在 fast_limit(3s)内返回 False——验证"启动失败/未就绪"路径快速失败。
    结构断言全在本函数内(不依赖提示文本,expect_hint 传 None);
    返回 (0, 摘要);任一判定不满足返回 (1, 失败原因)。
    """
    engine = _load_engine_module()
    ok, err = tcp_probe("127.0.0.1", port, timeout=0.4)
    if ok:
        return 1, ("前置检查失败: 端口 %d 已被监听(%s),无法演练未监听判定"
                   % (port, err))
    try:
        proc = subprocess.Popen([sys.executable, "-c", "pass"],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        proc.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, "无法准备模拟子进程: %s" % exc
    started = time.time()
    ready_ok, ready_msg = engine.wait_ready(proc, port, timeout=READY_TIMEOUT)
    elapsed = time.time() - started
    if ready_ok:
        return 1, "快速失败契约被破坏: 未启动的端口被判为就绪(%s)" % ready_msg
    if elapsed >= fast_limit:
        return 1, ("快速失败契约未满足: wait_ready 耗时 %.1fs(要求 <%.1fs): %s"
                   % (elapsed, fast_limit, ready_msg))
    return 0, ("接口冒烟通过: 端口 %d 未监听(探测判据 ok);wait_ready 对已退出"
               "进程 %.1f 秒内返回 False(%s)" % (port, elapsed, ready_msg))


# ------------------------------------------------------------------ 注册表
def scenarios():
    """场景注册表: 每项 {name, fn, expect_rc, expect_hint}(S1-S7,依序执行)。

    fn 返回 (实际退出码, 输出文本);expect_rc 为预期退出码;
    expect_hint 为提示判定规格(见 match_hint: 字符串 / ("any", [...]) /
    ("all", [...]) / ("none", [...]) / 复合元组);None 表示纯结构化断言
    (场景 fn 内部自判,不查提示文本,如 S7)。
    """
    return [
        {"name": "S1 健康体检", "fn": sc_check_only, "expect_rc": 0,
         "expect_hint": "全部检查通过"},
        {"name": "S2 端口占用", "fn": sc_port_busy, "expect_rc": 1,
         "expect_hint": ("any", ["换端口", "占用"])},
        {"name": "S3 坏数据目录", "fn": sc_bad_data_dir, "expect_rc": 2,
         "expect_hint": "数据目录"},
        {"name": "S4 报告完整性", "fn": sc_report_complete, "expect_rc": 0,
         "expect_hint": ("all", ["手机访问地址", "admin/admin"])},
        {"name": "S5 引擎契约", "fn": sc_engine_contract, "expect_rc": 0,
         "expect_hint": ("all", ["已就绪", "无 LISTENING"])},
        {"name": "S6 主网卡引导", "fn": sc_main_nic_guidance, "expect_rc": 0,
         "expect_hint": (("all", ["主网卡建议", "手机访问地址", "http://"]),
                         ("none", ["未识别主网卡"]))},
        {"name": "S7 快速失败", "fn": sc_fast_fail_not_ready, "expect_rc": 0,
         "expect_hint": None},
    ]


# ------------------------------------------------------------------ 判定
def match_hint(spec, output):
    """expect_hint 命中判定(大小写不敏感;中文按原文匹配)。

    spec 形式:
      字符串                  -> 输出须包含该文本;
      ("any", [文本, ...])    -> 至少一个文本命中(如 S2 的"换端口/占用");
      ("all", [文本, ...])    -> 全部文本命中(如 S4 的"手机访问地址"+"admin/admin");
      ("none", [文本, ...])   -> 全部文本都不命中(如 S6 禁止出现"未识别主网卡");
      (子规格, 子规格, ...)    -> 复合约束: 每个子规格都须命中(如 S6 的
                                 "必须出现 + 禁止出现"组合;首个元素是 tuple 即复合)。
    """
    text = (output or "").lower()
    if isinstance(spec, str):
        return spec.lower() in text
    if isinstance(spec[0], tuple):  # 复合约束: 全部子规格成立
        return all(match_hint(sub, output) for sub in spec)
    mode, items = spec[0], [str(item) for item in spec[1]]
    lowered = [item.lower() for item in items]
    if mode == "any":
        return any(item in text for item in lowered)
    if mode == "none":
        return not any(item in text for item in lowered)
    if mode == "all":
        return all(item in text for item in lowered)
    raise ValueError("未知 hint 模式: %r" % (mode,))


def select_scenarios(tokens, registry=None):
    """按 --only 过滤: token 为序号(1-7)或场景名(完整名或 "S2" 前缀,大小写不敏感)。

    返回 (selected, unknown):selected 保持注册表顺序且去重;unknown 为未识别
    token 列表(调用方提示后忽略)。
    """
    registry = registry if registry is not None else scenarios()
    selected, unknown = [], []
    for token in tokens:
        token = (token or "").strip()
        if not token:
            continue
        hit = None
        if token.isdigit():
            index = int(token)
            if 1 <= index <= len(registry):
                hit = registry[index - 1]
        if hit is None:
            low = token.lower()
            for item in registry:
                name = item["name"].lower()
                if name == low or name.startswith(low):
                    hit = item
                    break
        if hit is None:
            unknown.append(token)
        elif hit not in selected:
            selected.append(hit)
    order = {id(item): index for index, item in enumerate(registry)}
    selected.sort(key=lambda item: order[id(item)])
    return selected, unknown


# ------------------------------------------------------------------ 报告
def build_report(results):
    """由 run_scenario 结果列表组装顶层 {ok,total,passed,failed,scenarios}。"""
    total = len(results)
    passed = sum(1 for item in results if item["passed"])
    return {"ok": total > 0 and passed == total, "total": total,
            "passed": passed, "failed": total - passed, "scenarios": results}


def write_report(report, log_dir=None, timestamp=None):
    """报告写 log/verifier-launcher-<时间戳>.json(utf-8);返回文件路径。"""
    log_dir = log_dir or LOG_DIR
    os.makedirs(log_dir, exist_ok=True)
    ts = timestamp or time.strftime("%Y%m%d-%H%M%S")
    path = os.path.join(log_dir, "verifier-launcher-%s.json" % ts)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    return path


# ------------------------------------------------------------------ 执行
def run_scenario(item, timeout=SCENARIO_TIMEOUT):
    """执行单个场景,返回 {name, passed, rc_actual, rc_expect, hint_found,
    hint_expect, out_tail};场景自身异常按失败计(rc 置 None)。

    expect_hint 为 None 时表示纯结构化断言(场景 fn 内部自判,如 S7),
    提示维度直接视为命中,不查输出文本。
    """
    name = item["name"]
    expect_rc = item["expect_rc"]
    expect_hint = item["expect_hint"]
    try:
        rc, output = item["fn"]()
    except Exception as exc:  # noqa: BLE001 演练异常按失败计,不中断后续场景
        rc = None
        output = "[演练异常] %s: %s" % (type(exc).__name__, exc)
    output = output or ""
    lines = output.splitlines()
    hint_found = True if expect_hint is None else match_hint(expect_hint, output)
    passed = (rc == expect_rc) and hint_found
    return {"name": name, "passed": passed, "rc_actual": rc,
            "rc_expect": expect_rc, "hint_found": hint_found,
            "hint_expect": expect_hint, "out_tail": lines[-TAIL_LINES:]}


def run_all(only=None, quick=False, log_dir=None):
    """依序执行场景;逐场景输出 [PASS]/[FAIL] 行;写 JSON 报告。

    返回 (是否全过, 报告 dict)。only 为 --only 的 token 列表(可选);
    quick 跳过 S5(显式 --only 指定 S5 时尊重选择)。
    """
    registry = scenarios()
    if only:
        selected, unknown = select_scenarios(only, registry)
        for token in unknown:
            _print("[警告] 未识别的场景: %s(可用: %s)"
                   % (token, ", ".join(item["name"] for item in registry)))
        items = selected
    else:
        items = registry
    if quick and not only:
        items = [item for item in items if not item["name"].startswith("S5")]
    if not items:
        _print("[错误] 没有可演练的场景(检查 --only/--quick 参数)")
        report = build_report([])
        write_report(report, log_dir=log_dir)
        return False, report

    results = []
    for item in items:
        result = run_scenario(item)
        results.append(result)
        mark = "PASS" if result["passed"] else "FAIL"
        color = "green" if result["passed"] else "red"
        rc_disp = result["rc_actual"] if result["rc_actual"] is not None else "无"
        hint_disp = "命中" if result["hint_found"] else "未命中"
        _print(paint("[%s] %s (rc=%s/%s, 提示=%s)"
                     % (mark, result["name"], rc_disp, result["rc_expect"],
                        hint_disp), color=color, bold=True))
        for line in result["out_tail"]:
            _print("      | %s" % line)

    report = build_report(results)
    path = write_report(report, log_dir=log_dir)
    _print("")
    _print("演练完成: 共 %d 个场景,通过 %d,失败 %d;报告: %s"
           % (report["total"], report["passed"], report["failed"], path))
    return report["ok"], report


# ------------------------------------------------------------------ 命令行
def _parse_args(argv=None):
    """解析命令行参数(--only/--quick);返回 Namespace。"""
    parser = argparse.ArgumentParser(
        description="netryx_demo 启动器关键场景演练工具(交付前冒烟)",
        epilog="示例: python -X utf8 scripts\\verifier_launcher.py --quick\n"
               "      python -X utf8 scripts\\verifier_launcher.py --only S2,S4")
    parser.add_argument("--only", default="",
                        help="仅演练指定场景(逗号分隔;按名字或序号 1-7)")
    parser.add_argument("--quick", action="store_true",
                        help="跳过 S5(引擎全链最慢)")
    return parser.parse_args(argv)


def main(argv=None):
    """命令行入口: 执行演练;全部通过退出 0,任一失败退出 1。"""
    args = _parse_args(argv)
    only = [tok.strip() for tok in args.only.split(",") if tok.strip()] \
        if args.only else None
    ok, _report = run_all(only=only, quick=args.quick)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
