# -*- coding: utf-8 -*-
"""netryx_demo 统一工程入口(标准库,零第三方依赖)

子命令:
  check  环境与接口基线验证(Python 版本/文件完整性/数据目录可写/系统命令/端口)
  test   运行 tests/ 下的全部测试
  clean  清理构建与运行残留(__pycache__/build/dist)
  log    整理并查看 log/ 目录(带轮转约束)
  all    依次执行 check -> test -> log

用法:python build.py <check|test|clean|log|all>
退出码:0 成功 / 1 失败 / 2 环境问题
"""
import logging
import os
import re
import shutil
import subprocess
import sys
import unittest
from logging.handlers import RotatingFileHandler

ROOT = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(ROOT, "log")
LOG_FILE = os.path.join(LOG_DIR, "build.log")
LOG_MAX_BYTES = 5 * 1024 * 1024    # 单文件 5MB
LOG_BACKUP_COUNT = 10              # 最多 10 份
ENGINE_DIR = os.path.join(ROOT, "engine")
DATA_DIR = os.path.join(ROOT, "netryx-data")
PORT = 8765

log = logging.getLogger("build")


def _setup_logging():
    os.makedirs(LOG_DIR, exist_ok=True)
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    fh = RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_BYTES,
                             backupCount=LOG_BACKUP_COUNT, encoding="utf-8")
    fh.setFormatter(fmt)
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    log.addHandler(fh)
    log.addHandler(sh)


def _run(cmd, timeout=10):
    """带超时的子进程调用(防卡死);返回 (code, output)。"""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, errors="replace")
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return -1, "timeout after %ss: %s" % (timeout, " ".join(cmd))
    except Exception as e:  # 文件不存在等
        return -1, str(e)


# ---------------------------------------------------------------- check
def check_python():
    v = sys.version_info
    ok = (v.major, v.minor) >= (3, 8)
    log.info("python %d.%d.%d %s", v.major, v.minor, v.micro,
             "OK" if ok else "FAIL(需 >=3.8)")
    return ok


def check_files():
    need = [os.path.join(ENGINE_DIR, "netryx.py"),
            os.path.join(ENGINE_DIR, "ui.html")]
    miss = [p for p in need if not os.path.isfile(p)]
    for p in need:
        log.info("file %s %s", os.path.relpath(p, ROOT),
                 "OK" if os.path.isfile(p) else "MISSING")
    return not miss


def check_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)
    probe = os.path.join(DATA_DIR, ".write_probe")
    try:
        with open(probe, "w", encoding="utf-8") as f:
            f.write("ok")
        os.remove(probe)
        log.info("data dir writable: %s", DATA_DIR)
        return True
    except OSError as e:
        log.info("data dir NOT writable: %s (%s)", DATA_DIR, e)
        return False


def check_system_tools():
    ok = True
    for cmd, label in ((["ping", "-n", "1", "-w", "200", "127.0.0.1"], "ping"),
                       (["ipconfig"], "ipconfig")):
        code, out = _run(cmd)
        good = (code == 0)
        log.info("sys tool %s %s", label, "OK" if good else "FAIL(%s)" % out[:120])
        ok = ok and good
    return ok


def check_port():
    """socket.bind 探测 8765(标准库,免 powershell 依赖)。
    EADDRINUSE => 引擎可能已在运行(WARN,不 FAIL)。"""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", PORT))
        log.info("port %d: free", PORT)
        return True
    except OSError as e:
        if getattr(e, "errno", None) in (10048, 98):   # WSAEADDRINUSE / EADDRINUSE
            log.info("port %d: LISTENING(WARN) - 引擎可能已在运行", PORT)
            return True
        log.info("port %d: probe failed(%s)", PORT, e)
        return True
    finally:
        s.close()


def run_check():
    results = [check_python(), check_files(), check_data_dir(),
               check_system_tools(), check_port()]
    ok = all(results)
    log.info("check %s", "PASS" if ok else "FAIL")
    return 0 if ok else 2


# ---------------------------------------------------------------- test
def _venv_python():
    p = os.path.join(ROOT, ".venv", "Scripts", "python.exe")
    return p if os.path.isfile(p) else None


def run_test():
    tests_dir = os.path.join(ROOT, "tests")
    if not os.path.isdir(tests_dir):
        log.info("tests/ 不存在,跳过(Phase 1 建桩后启用)")
        return 0
    py = _venv_python()
    if not py:
        log.info(
            "FAIL: 未找到 .venv;请先运行: python -m venv .venv && "
            ".venv\\Scripts\\python -m pip install pytest")
        return 2
    log.info("running pytest in %s ...", tests_dir)
    code, out = _run([py, "-m", "pytest", "tests/", "-q", "--tb=short"], timeout=600)
    sys.stdout.write(out)
    ok = (code == 0)
    log.info("test %s (rc=%d)", "PASS" if ok else "FAIL", code)
    return 0 if ok else 1


# ---------------------------------------------------------------- clean
def run_clean():
    removed = []
    for target in ("__pycache__", "build", "dist"):
        p = os.path.join(ROOT, target)
        if os.path.isdir(p):
            shutil.rmtree(p, ignore_errors=True)
            removed.append(target)
    # engine/tests 下递归 __pycache__
    for base in (os.path.join(ROOT, "engine"), os.path.join(ROOT, "tests"),
                 os.path.join(ROOT, "scripts")):
        for dirpath, dirnames, _ in os.walk(base):
            for d in list(dirnames):
                if d == "__pycache__":
                    shutil.rmtree(os.path.join(dirpath, d), ignore_errors=True)
                    removed.append(os.path.relpath(os.path.join(dirpath, d), ROOT))
    log.info("clean %s", "removed: %s" % ", ".join(removed) if removed else "nothing")
    return 0


# ---------------------------------------------------------------- log
def run_log(show=True):
    os.makedirs(LOG_DIR, exist_ok=True)
    if show and os.path.isfile(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        log.info("log/build.log: %d lines (tail 20)", len(lines))
        for line in lines[-20:]:
            print(line.rstrip())
    log.info("log dir: %s (constraint: <=%d files x <=%dMB)",
             LOG_DIR, LOG_BACKUP_COUNT, LOG_MAX_BYTES // (1024 * 1024))
    return 0


# ---------------------------------------------------------------- main
def main():
    _setup_logging()
    cmd = sys.argv[1] if len(sys.argv) > 1 else "check"
    if cmd == "check":
        return run_check()
    if cmd == "test":
        return run_test()
    if cmd == "clean":
        return run_clean()
    if cmd == "log":
        return run_log()
    if cmd == "all":
        rc = run_check()
        rc = rc or run_test()
        rc = rc or run_log(show=False)
        return rc
    log.info("unknown cmd %r; usage: build.py <check|test|clean|log|all>", cmd)
    return 1


if __name__ == "__main__":
    sys.exit(main())
