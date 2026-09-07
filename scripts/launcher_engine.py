# -*- coding: utf-8 -*-
"""launcher_engine.py — "按需手动启动器"的引擎进程管理模块(标准库,零第三方依赖)。

对内: LogTee(子进程日志 tee)、start_engine / wait_ready / stop_engine(进程管理)、
install_signal_handlers(bootstrap 信号处理)、main(命令行演示)。
契约: 只调用 scripts/launcher_env.py 的
collect_network_context() -> dict / check_port_free(port=8765) -> (bool, str) /
check_python() -> (bool, str) / check_data_writable() -> (bool, str) /
render_report(ctx) -> str,不假设其内部实现。

加载: 先把项目根 ROOT 插入 sys.path,优先 ``import scripts.launcher_env``
(scripts/ 无 __init__.py 时靠 Python 3.3+ 命名空间包);失败再按文件路径用
importlib.util 加载,自动兜底。代码基线 Python 3.8+(未用 3.9+ 新语法)。
"""

import argparse
import collections
import importlib.util
import logging
import logging.handlers
import os
import signal
import socket
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENGINE_PATH = os.path.join(ROOT, "engine", "netryx.py")
LAUNCHER_ENV_PATH = os.path.join(ROOT, "scripts", "launcher_env.py")
DEFAULT_LOG_DIR = os.path.join(ROOT, "log")
DEFAULT_DATA_DIR = os.path.join(ROOT, "netryx-data")
LOG_FILE_NAME = "engine.log"
LOG_MAX_BYTES = 5 * 1024 * 1024
LOG_BACKUP_COUNT = 10
DEFAULT_PORT = 8765
DEFAULT_HOST = "0.0.0.0"
WAIT_POLL_INTERVAL = 0.5     # wait_ready 轮询间隔(秒)
EXIT_CONTROL_C = 0xC000013A  # Windows 进程被 Ctrl+C / Ctrl+Break 终止

# ---------------------------------------------------------------------------
# launcher_env 按契约加载
# ---------------------------------------------------------------------------

_env_module = None


def _load_env_module():
    """加载 scripts/launcher_env.py(包导入优先,路径加载兜底;结果缓存)。"""
    global _env_module
    if _env_module is not None:
        return _env_module
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    try:
        import scripts.launcher_env as mod
    except (ImportError, ValueError):
        if not os.path.isfile(LAUNCHER_ENV_PATH):
            raise ImportError("无法加载 launcher_env(缺少文件 %s);请确认 "
                              "scripts/launcher_env.py 已生成" % LAUNCHER_ENV_PATH)
        spec = importlib.util.spec_from_file_location("scripts.launcher_env",
                                                      LAUNCHER_ENV_PATH)
        if spec is None or spec.loader is None:
            raise ImportError("无法加载 launcher_env(路径: %s)" % LAUNCHER_ENV_PATH)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["scripts.launcher_env"] = mod
        spec.loader.exec_module(mod)
    _env_module = mod
    return mod

# ---------------------------------------------------------------------------
# 日志 tee
# ---------------------------------------------------------------------------


class LogTee(object):
    """引擎子进程日志 tee: 轮转文件(log/engine.log, 5MB×10, utf-8)+ stdout 双 handler。

    用法: tee.start(); proc = start_engine(...)  # 内部自动 attach 读取线程;
    tee.stop()  # 关闭 handler,子进程已退出时顺带等待读取线程收尾。
    """

    _LOG_FORMAT = "[%(asctime)s] [engine] %(levelname)s %(message)s"
    _DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
    _TAIL_KEEP = 8

    def __init__(self, log_dir=None, level=logging.INFO):
        self.log_dir = log_dir or DEFAULT_LOG_DIR
        self.log_file = os.path.join(self.log_dir, LOG_FILE_NAME)
        self.level = level
        self.logger = logging.getLogger("netryx_engine")
        self.logger.setLevel(level)
        self.logger.propagate = False
        self._file_handler = None
        self._stream_handler = None
        self._reader = None
        self._proc = None
        self._tail = collections.deque(maxlen=self._TAIL_KEEP)
        self._tail_lock = threading.Lock()

    def start(self):
        """创建文件 + stdout 双 handler(幂等;日志目录自动创建)。"""
        if self._file_handler is not None:
            return
        os.makedirs(self.log_dir, exist_ok=True)
        fmt = logging.Formatter(self._LOG_FORMAT, datefmt=self._DATE_FORMAT)
        file_handler = logging.handlers.RotatingFileHandler(
            self.log_file, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT,
            encoding="utf-8")
        file_handler.setFormatter(fmt)
        file_handler.setLevel(self.level)
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(fmt)
        stream_handler.setLevel(self.level)
        self.logger.addHandler(file_handler)
        self.logger.addHandler(stream_handler)
        self._file_handler = file_handler
        self._stream_handler = stream_handler

    def stop(self, wait_reader=True, timeout=2.0):
        """移除并关闭两个 handler;子进程已退出时等待读取线程收尾(不 join 存活进程)。"""
        if wait_reader:
            self.join_reader(timeout)
        for handler in (self._file_handler, self._stream_handler):
            if handler is None:
                continue
            try:
                self.logger.removeHandler(handler)
            except (ValueError, KeyError):
                pass
            try:
                handler.flush()
                handler.close()
            except (OSError, ValueError):
                pass
        self._file_handler = None
        self._stream_handler = None

    def attach(self, proc):
        """关联子进程并启动后台读取线程(daemon;重复调用只生效一次)。"""
        if proc is None:
            return
        self._proc = proc
        if self._reader is not None and self._reader.is_alive():
            return
        self._reader = threading.Thread(target=self._read_loop,
                                        name="netryx-engine-log-reader",
                                        daemon=True)
        self._reader.start()

    def join_reader(self, timeout=2.0):
        """等待读取线程结束;子进程仍存活时直接返回(避免与管道 readline 死锁)。"""
        reader = self._reader
        if reader is None or not reader.is_alive():
            return
        proc = self._proc
        if proc is not None and proc.poll() is None:
            return
        reader.join(timeout)

    def log(self, message, level=logging.INFO):
        """写一条日志(时间戳与 [engine] 前缀由 formatter 统一加)。"""
        self.logger.log(level, "%s", message)

    def recent_lines(self, count=6):
        """返回最近 count 行引擎输出(用于失败报告)。"""
        with self._tail_lock:
            return list(self._tail)[-count:]

    def _remember(self, text):
        with self._tail_lock:
            self._tail.append(text)

    def _read_loop(self):
        """逐行读取子进程管道并转日志;管道关闭后按退出码记 INFO(0)/ERROR(非 0)。"""
        proc = self._proc
        if proc is None or proc.stdout is None:
            return
        stream = proc.stdout
        try:
            for raw in iter(stream.readline, b""):
                text = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                if not text:
                    continue
                self._remember(text)
                self.logger.info("%s", text)
            code = proc.poll()
            if code is None:
                try:
                    code = proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    code = None
            if code is not None:
                note = "子进程退出,退出码=%s%s" % (code, self._exit_note(code))
                self._remember(note)
                # 正常停止(0)或用户手动 Ctrl+C/关窗(0xC000013A)= INFO;
                # 其余非零退出才记 ERROR(启动器"关闭即停"是核心使用路径,非异常)
                if code == 0 or code == EXIT_CONTROL_C:
                    self.logger.info("%s", note)
                else:
                    self.logger.error("%s", note)
        except Exception as exc:  # 读取线程收敛: 异常只记日志,不向外抛
            try:
                self.logger.warning("日志读取线程异常结束: %s", exc)
            except Exception:
                pass
        finally:
            try:
                stream.close()
            except Exception:
                pass

    @staticmethod
    def _exit_note(code):
        """退出码 -> 人类可读说明(Windows 控制台终止码有专名)。"""
        if code == EXIT_CONTROL_C:
            return " (0xC000013A, 被 Ctrl+C/Ctrl+Break 终止)"
        return ""


_tee_instance = None


def default_tee():
    """返回模块级共享 LogTee 实例(start_engine 默认使用,惰性创建)。"""
    global _tee_instance
    if _tee_instance is None:
        _tee_instance = LogTee()
    return _tee_instance

# ---------------------------------------------------------------------------
# 端口探测
# ---------------------------------------------------------------------------


def _probe_tcp(host, port, timeout=0.5):
    """尝试连接 host:port,返回 (可连接?, 错误信息)。"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, ""
    except OSError as exc:
        return False, str(exc)


def _host_port_free(host, port):
    """端口可否监听: 以"无人能连接"为判据(避开 bind 的 TIME_WAIT 误判)。"""
    ok, _err = _probe_tcp(host, port, timeout=0.4)
    return not ok

# ---------------------------------------------------------------------------
# 引擎启动 / 就绪 / 停止
# ---------------------------------------------------------------------------


def start_engine(port=DEFAULT_PORT, data_dir=None, host=DEFAULT_HOST):
    """启动引擎子进程(engine/netryx.py),返回 subprocess.Popen 对象。

    命令 [sys.executable, "-X", "utf8", netryx.py, "--host", host, "--port",
    port, "--no-browser"];环境注入 NETRYX_DATA(data_dir 或 ROOT/netryx-data)、
    NETRYX_NO_BROWSER=1、PYTHONIOENCODING=utf-8、PYTHONUNBUFFERED=1(实时日志)。
    Windows 以 CREATE_NEW_PROCESS_GROUP 启动(停止时按进程组发 Ctrl+Break);
    stdout/stderr 合并为同一 PIPE 交给共享 LogTee 逐行读取;端口已被监听时
    抛 RuntimeError(避免 wait_ready 误判为就绪)。
    """
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise ValueError("端口必须是整数: %r" % (port,))
    if not (0 < port <= 65535):
        raise ValueError("端口超出有效范围(1-65535): %s" % port)
    if not os.path.isfile(ENGINE_PATH):
        raise FileNotFoundError("找不到引擎脚本: %s" % ENGINE_PATH)

    if data_dir is None:
        data_dir = DEFAULT_DATA_DIR
    data_dir = os.path.abspath(data_dir)
    try:
        os.makedirs(data_dir, exist_ok=True)
    except OSError as exc:
        raise RuntimeError("无法创建数据目录 %s(%s)" % (data_dir, exc))

    if not _host_port_free("127.0.0.1", port):
        raise RuntimeError("端口 %d 已被监听,无法启动;修复指引: 换端口(--port "
                           "参数)或停掉占用进程" % port)

    cmd = [sys.executable, "-X", "utf8", ENGINE_PATH,
           "--host", host, "--port", str(port), "--no-browser"]
    env = dict(os.environ)
    env["NETRYX_DATA"] = data_dir
    env["NETRYX_NO_BROWSER"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUNBUFFERED"] = "1"
    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0

    tee = default_tee()
    tee.start()
    tee.log("启动引擎命令: %s" % " ".join(cmd))
    try:
        proc = subprocess.Popen(cmd, env=env, cwd=ROOT, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT,
                                creationflags=creationflags)
    except OSError as exc:
        raise RuntimeError("启动引擎失败(%s): %s" % (cmd[0], exc))
    tee.log("引擎进程已启动(pid=%s, 端口=%s, 数据目录=%s)"
            % (proc.pid, port, data_dir))
    # 停止时"是否进程组启动"标记: Popen 不暴露 creationflags,只能自记。
    if creationflags:
        proc._netryx_process_group = True
    tee.attach(proc)
    return proc


def wait_ready(proc, port, timeout=30.0):
    """轮询端口直到可连接,返回 (就绪?, 说明 str)。

    每 0.5 秒探测 127.0.0.1:port,最多 timeout/0.5 次;轮询间隙检测进程提前
    退出(立即返回 False + 退出码/最近输出);就绪后复核进程仍存活(防误判)。
    """
    if proc is None:
        return False, "进程对象为空,无法等待"
    attempts = max(1, int(timeout / WAIT_POLL_INTERVAL))
    tee = default_tee()
    last_err = ""
    for index in range(1, attempts + 1):
        if proc.poll() is not None:
            tail = "; ".join(tee.recent_lines(6)) or "(无输出)"
            return False, ("引擎进程提前退出(退出码=%s); 最近输出: %s"
                           % (proc.returncode, tail))
        ok, err = _probe_tcp("127.0.0.1", port, timeout=0.5)
        if ok:
            if proc.poll() is not None:
                return False, "端口 %d 可连接,但引擎进程已退出(退出码=%s)" % (
                    port, proc.returncode)
            elapsed = index * WAIT_POLL_INTERVAL
            return True, ("引擎已就绪(第 %d 次探测, %.1fs): http://127.0.0.1:%d"
                          % (index, elapsed, port))
        last_err = err
        time.sleep(WAIT_POLL_INTERVAL)
    return False, ("等待就绪超时(%.1fs, %d 次探测): 端口 %d 一直无法连接; "
                   "最后错误: %s; 最近输出: %s"
                   % (timeout, attempts, port, last_err,
                      "; ".join(tee.recent_lines(6)) or "(无输出)"))


def _terminate_group(proc):
    """Windows 进程组发 Ctrl+Break(仅限本模块进程组启动的子进程),失败回退 terminate()。

    信号只送达该进程组、不波及本进程;非 Windows 或未建组时直接 terminate()。
    """
    if os.name == "nt" and getattr(proc, "_netryx_process_group", False):
        try:
            proc.send_signal(signal.CTRL_BREAK_EVENT)
            return
        except (OSError, ValueError):
            pass
    proc.terminate()


def _kill_tree(proc):
    """强杀进程树(Windows taskkill /F /T;失败回退 proc.kill())。"""
    if os.name == "nt":
        try:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True, timeout=5)
            return
        except (OSError, subprocess.TimeoutExpired):
            pass
    proc.kill()


def _close_pipe(proc):
    """关闭子进程 stdout 管道(读取线程已自行关闭时是 no-op)。"""
    try:
        if proc.stdout is not None:
            proc.stdout.close()
    except (OSError, ValueError):
        pass


def stop_engine(proc, timeout=10.0):
    """停止引擎子进程: 优先优雅终止(进程组 Ctrl+Break/SIGTERM),超时强杀;返回是否已停止。

    - Windows: 先向进程组发 Ctrl+Break,失败回退 terminate();超时后
      taskkill /F /T 强杀整棵进程树(再兜底 proc.kill());
    - 其他平台: terminate()(SIGTERM),超时后 kill()(SIGKILL);
    - finally 关闭管道并等待日志读取线程收尾(记录退出码,保证无残留)。
    """
    if proc is None:
        return True
    if proc.poll() is not None:  # 已退出: 等读取线程收尾后再关管道
        default_tee().join_reader(2.0)
        _close_pipe(proc)
        return True
    tee = default_tee()
    try:
        _terminate_group(proc)
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            tee.log("优雅终止超时(%.1fs),强制终止进程树..." % timeout,
                    level=logging.WARNING)
            _kill_tree(proc)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
    finally:
        tee.join_reader(2.0)   # 先等读取线程排空管道并记录退出码
        _close_pipe(proc)
    return True


def install_signal_handlers(proc):
    """安装 SIGINT/SIGTERM 处理: 停止引擎后 sys.exit(0)(bootstrap 用)。

    仅主线程有效(信号注册受限于主线程),非主线程调用时安全跳过。
    返回是否安装成功。
    """
    if threading.current_thread() is not threading.main_thread():
        return False

    def _handler(signum, frame):
        try:
            name = signal.Signals(signum).name
        except ValueError:
            name = "信号(%s)" % signum
        print("\n收到 %s,正在停止引擎..." % name)
        try:
            stop_engine(proc)
        finally:
            sys.exit(0)

    try:
        signal.signal(signal.SIGINT, _handler)
    except (OSError, ValueError):
        return False
    try:
        signal.signal(signal.SIGTERM, _handler)
    except (OSError, ValueError):
        pass  # 极少数平台无 SIGTERM;SIGINT 已覆盖
    return True

# ---------------------------------------------------------------------------
# 演示入口
# ---------------------------------------------------------------------------


def _wait_enter_or_timeout(seconds):
    """等待按回车;seconds<=0 无限等待;返回是否按了回车。

    Windows 用 msvcrt.kbhit(仅控制台输入有效),其他平台用 select;
    无控制台/输入被重定向时降级为按时间等待(超时返回 False)。
    """
    deadline = None if seconds is None or seconds <= 0 else time.time() + seconds

    def idle_wait():
        """无输入渠道时的兜底: 等到期返回 True;无限等待直接返回 False。"""
        if deadline is None:
            return False
        while time.time() < deadline:
            time.sleep(0.2)
        return True

    if os.name == "nt":
        import msvcrt
        try:
            while True:
                if msvcrt.kbhit():
                    msvcrt.getwch()
                    return True
                if deadline is not None and time.time() >= deadline:
                    return False
                time.sleep(0.1)
        except (OSError, ValueError):
            return idle_wait()
    import select
    timeout = None if deadline is None else max(0.0, deadline - time.time())
    try:
        readable, _unused, _unused2 = select.select([sys.stdin], [], [], timeout)
    except (OSError, ValueError):
        return idle_wait()
    if readable:
        try:
            sys.stdin.readline()
        except OSError:
            pass
        return True
    return False


def _parse_engine_args(argv):
    """解析 main 的命令行参数(引擎侧参数归 start_engine 处理)。"""
    parser = argparse.ArgumentParser(
        description="按需手动启动器演示: 环境检测 -> 启动引擎 -> 等待就绪 -> 停止",
        epilog="示例: python scripts\\launcher_engine.py --port 8766")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help="引擎端口(默认 %s)" % DEFAULT_PORT)
    parser.add_argument("--host", default=DEFAULT_HOST,
                        help="监听地址(默认 %s)" % DEFAULT_HOST)
    parser.add_argument("--data-dir", default=None,
                        help="数据目录(默认 ROOT/netryx-data)")
    parser.add_argument("--timeout", type=float, default=30.0,
                        help="就绪等待超时秒数(默认 30)")
    parser.add_argument("--hold", type=float, default=10.0,
                        help="就绪后保持秒数,<=0 表示按回车才停(默认 10)")
    return parser.parse_args(argv)


def main(argv=None):
    """命令行演示: 环境校验 -> 报告 -> 启动 -> 就绪 -> 保持 -> 停止。

    退出码: 0 成功;1 启动失败(端口占用/未就绪/环境校验不过);2 launcher_env
    加载失败。任何路径都在 finally 中清理子进程与日志 tee。
    """
    args = _parse_engine_args(argv)
    tee = default_tee()
    proc = None
    result = 0
    try:
        try:
            env = _load_env_module()
        except ImportError as exc:
            print("[启动失败] %s" % exc)
            return 2

        network = env.collect_network_context()
        port_ok, port_msg = env.check_port_free(port=args.port)
        py_ok, py_msg = env.check_python()
        data_ok, data_msg = env.check_data_writable()
        firewall_hint = False
        check_hint = getattr(env, "check_firewall_hint", None)
        if callable(check_hint):
            firewall_hint = bool(check_hint())
        ctx = {
            "network": network,
            "port": args.port,
            "results": {
                "python": (py_ok, py_msg),
                "data_writable": (data_ok, data_msg),
                "port_free": (port_ok, port_msg),
            },
            "firewall_hint": firewall_hint,
        }
        print(env.render_report(ctx))
        if not (py_ok and data_ok):
            print("结论: 启动失败(环境硬性问题,见上方修复指引)")
            return 2
        if not port_ok:
            print("结论: 启动失败(端口 %d 被占用)" % args.port)
            return 1

        proc = start_engine(port=args.port, data_dir=args.data_dir,
                            host=args.host)
        install_signal_handlers(proc)
        ok_ready, reason = wait_ready(proc, args.port, timeout=args.timeout)
        if not ok_ready:
            print("结论: 启动失败(%s)" % reason)
            return 1
        print("启动成功: %s" % reason)

        if args.hold <= 0:
            print("引擎保持运行中,按 ENTER 停止...")
            _wait_enter_or_timeout(0)
        else:
            print("引擎保持运行中,按 ENTER 立即停止(或 %.0f 秒后自动停止)..."
                  % args.hold)
            _wait_enter_or_timeout(args.hold)
    except KeyboardInterrupt:
        print("\n中止演示(KeyboardInterrupt)")
        result = 0
    finally:
        if proc is not None:
            stopped = stop_engine(proc)
            if stopped:
                print("引擎进程已停止(退出码=%s)"
                      % (proc.poll() if proc.poll() is not None else "未知"))
        else:
            tee.join_reader(1.0)
        tee.stop()
    if result == 0:
        print("结论: 启动成功")
    return result


if __name__ == "__main__":
    sys.exit(main())
