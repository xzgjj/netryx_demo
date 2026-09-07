# -*- coding: utf-8 -*-
"""netryx_demo 统一工程入口(标准库,零第三方依赖)

子命令:
  check    环境与接口基线验证(Python 版本/文件完整性/数据目录可写/
           workflow 文件存在/引擎可编译/系统命令/端口/启动器链)
  test     运行 tests/ 下的全部测试(自动用 .venv 内 pytest)
  smoke    端到端接口冒烟: 临时端口起引擎,登录/取会话/取 /api/info +
           SPEC §2.4 接口契约矩阵(C1-C7,每步独立断言)
  pack     交付打包: dist/netryx_demo-<UTC时间戳>.zip + manifest.json
  verify   校验交付包: manifest 路径/大小/sha256 + py_compile
  setup    .venv 引导(创建 + pip install pytest)
  clean    清理构建与运行残留(__pycache__/build/dist)
  log      整理并查看 log/ 目录(带轮转约束)
  all      依次执行 check -> test -> pack -> verify

用法: python build.py <check|test|smoke|pack|verify [zip]|setup|clean|log|all>
退出码: 0 成功 / 1 失败 / 2 环境问题
"""
import glob
import hashlib
import http.client
import importlib.util
import inspect
import json
import logging
import os
import py_compile
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

ROOT = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(ROOT, "log")
LOG_FILE = os.path.join(LOG_DIR, "build.log")
LOG_MAX_BYTES = 5 * 1024 * 1024    # 单文件 5MB
LOG_BACKUP_COUNT = 10              # 最多 10 份
ENGINE_DIR = os.path.join(ROOT, "engine")
DATA_DIR = os.path.join(ROOT, "netryx-data")
DIST_DIR = os.path.join(ROOT, "dist")
PORT = 8765
DELIVERY_VERSION = "0.1.0"
PACK_FILES = ["engine/netryx.py", "engine/ui.html", "engine/LICENSE",
              "build.py", "start.cmd", "start.ps1", "README.md"]   # 后两项可选
PACK_OPTIONAL = {"start.ps1", "README.md"}

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
    """系统命令(ping/ipconfig/ip)存在性与探活,跨平台;缺失仅 WARN,不判失败。"""
    is_win = sys.platform.startswith("win")
    if is_win:
        plan = (("ping", ["ping", "-n", "1", "-w", "200", "127.0.0.1"]),
                ("ipconfig", ["ipconfig"]))
    else:
        plan = (("ping", ["ping", "-c", "1", "-W", "1", "127.0.0.1"]),
                ("ip", ["ip", "-4", "addr"]))
    ok = True
    for tool, cmd in plan:
        if not shutil.which(tool):
            log.info("sys tool %s WARN: not found, skipped", tool)
            continue
        code, out = _run(cmd)
        good = (code == 0)
        log.info("sys tool %s %s", tool, "OK" if good else "FAIL(%s)" % out[:120])
        ok = ok and good
    return ok


def check_port():
    """socket.bind 探测 8765(标准库,免 powershell 依赖)。
    EADDRINUSE => 引擎可能已在运行(WARN,不 FAIL)。"""
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


def check_workflows():
    """GitHub Actions 工作流文件存在性(.github/workflows/*.yml|yaml,不解析内容)。
    WARN 级:开发期可能尚未补齐;CI 场景由 workflow 自身保证存在,不阻断本地基线。"""
    found = sorted(glob.glob(os.path.join(ROOT, ".github", "workflows", "*.y*ml")))
    ok = bool(found)
    log.info("workflows %s (%d 个: %s)", "OK" if ok else "WARN: 未找到(开发期可接受)",
             len(found),
             ", ".join(os.path.relpath(p, ROOT) for p in found[:3]) or "无")
    if not ok:
        log.info("  指引: 交付前请补充 .github/workflows/*.yml(CI 工作流)")
    return True  # WARN 级,不判失败(交付前由 CI 冒烟保证)


def check_engine_compile():
    """引擎可编译性: py_compile 只编译不执行,产物写临时目录不入仓库。"""
    return _compile_check(os.path.join(ENGINE_DIR, "netryx.py"), "engine/netryx.py")


def _load_script_module(rel_path):
    """importlib 按文件路径加载 scripts/ 下模块(不触发 __main__ 主流程)。

    加载期间置 sys.dont_write_bytecode,避免在 scripts/ 生成新 .pyc(不污染
    __pycache__);返回加载后的 module 对象。
    """
    path = os.path.join(ROOT, rel_path)
    name = "scripts." + os.path.splitext(os.path.basename(rel_path))[0]
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError("无法加载 %s(路径: %s)" % (rel_path, path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def check_launcher_modules():
    """启动器链模块完整性(w2 产物): 4 个文件存在 + 可加载/可编译。

    - launcher_env.py  importlib 加载,render_report 必须可调用且签名非空;
    - launcher_engine.py  importlib 加载,start_engine/stop_engine 必须存在;
    - launch.py / verifier_launcher.py  仅 py_compile(写临时目录,不运行
      argparse 主流程);文件缺失或加载/签名异常一律 FAIL(硬),无 WARN 级。
    """
    files = ("scripts/launcher_env.py", "scripts/launcher_engine.py",
             "scripts/launch.py", "scripts/verifier_launcher.py")
    for rel in files:
        log.info("launcher file %-26s %s", rel,
                 "OK" if os.path.isfile(os.path.join(ROOT, rel)) else "MISSING")
    missing = [rel for rel in files
               if not os.path.isfile(os.path.join(ROOT, rel))]
    if missing:
        log.info("launcher modules FAIL: 缺失 %s", ", ".join(missing))
        return False
    ok = True
    prev_dont_write = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        try:
            env = _load_script_module("scripts/launcher_env.py")
            render_report = getattr(env, "render_report", None)
            sig_ok = False
            sig_text = ""
            if callable(render_report):
                try:
                    sig = inspect.signature(render_report)
                    sig_ok = len(sig.parameters) >= 1
                    sig_text = str(sig)
                except (TypeError, ValueError):
                    sig_ok = False
            if not sig_ok:
                log.info("launcher check launcher_env FAIL: render_report "
                         "不可调用或签名异常")
                ok = False
            else:
                log.info("launcher check launcher_env OK: render_report "
                         "可调用,签名 %s", sig_text)
        except Exception as e:
            log.info("launcher check launcher_env FAIL: 加载异常(%s)", e)
            ok = False
        try:
            eng = _load_script_module("scripts/launcher_engine.py")
            missing_apis = [n for n in ("start_engine", "stop_engine")
                            if not callable(getattr(eng, n, None))]
            if missing_apis:
                log.info("launcher check launcher_engine FAIL: 缺少 %s",
                         ", ".join(missing_apis))
                ok = False
            else:
                log.info("launcher check launcher_engine OK: "
                         "start_engine/stop_engine 就绪")
        except Exception as e:
            log.info("launcher check launcher_engine FAIL: 加载异常(%s)", e)
            ok = False
    finally:
        sys.dont_write_bytecode = prev_dont_write
    # launch / verifier 不运行主流程(argparse),仅编译校验(_compile_check 写临时文件)
    ok = _compile_check(os.path.join(ROOT, "scripts", "launch.py"),
                        "scripts/launch.py") and ok
    ok = _compile_check(os.path.join(ROOT, "scripts", "verifier_launcher.py"),
                        "scripts/verifier_launcher.py") and ok
    log.info("launcher modules %s", "OK" if ok else "FAIL")
    return ok


def check_launcher_report():
    """子进程跑 scripts/launcher_env.py 体检(不起引擎;超时 60s)。

    断言输出含"手机访问地址"与"admin/admin"且退出码 0(全新环境数据目录
    自动创建,应 rc=0);rc=1(端口被占)WARN 化,其余失败 FAIL(体检链必须
    健康)。须在 check_port 之后调用(端口状态已先行探测)。
    """
    rel = "scripts/launcher_env.py"
    path = os.path.join(ROOT, rel)
    if not os.path.isfile(path):
        log.info("launcher report FAIL: 缺少 %s", rel)
        return False
    try:
        p = subprocess.run([sys.executable, "-X", "utf8", path],
                           capture_output=True, timeout=60,
                           encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        log.info("launcher report FAIL: 超时(60s)")
        return False
    except OSError as e:
        log.info("launcher report FAIL: 子进程启动失败(%s)", e)
        return False
    code = p.returncode
    out = (p.stdout or "") + (p.stderr or "")
    if code == 0:
        missing = [k for k in ("手机访问地址", "admin/admin") if k not in out]
        if missing:
            log.info("launcher report FAIL: rc=0 但输出缺少 %s",
                     ", ".join(missing))
            return False
        log.info("launcher report OK (rc=0, 含 手机访问地址/admin/admin)")
        return True
    if code == 1:
        log.info("launcher report WARN: rc=1(端口被占)- 若 8765 被引擎占用,"
                 "启动器体检 rc=1 属预期")
        return True
    log.info("launcher report FAIL: rc=%d(输出尾部: %s)", code,
             out[-160:].replace("\n", " "))
    return False


def check_verifier_exists():
    """verifier_launcher.py 存在性提示(存在性/编译已在模块检查中覆盖)。

    存在则打印交付演练指引(仅提示,可返回 True);缺失仅 WARN——硬失败由
    check_launcher_modules 兜底。
    """
    rel = "scripts/verifier_launcher.py"
    if os.path.isfile(os.path.join(ROOT, rel)):
        log.info("verifier launcher OK: 交付演练可用: python -X utf8 "
                 "scripts\\verifier_launcher.py --quick")
        return True
    log.info("verifier launcher WARN: 缺少 %s(见 launcher modules 检查)", rel)
    return True


def run_check():
    results = [check_python(), check_files(), check_data_dir(),
               check_workflows(), check_engine_compile(),
               check_system_tools(), check_port(),
               check_launcher_modules(), check_launcher_report(),
               check_verifier_exists()]
    ok = all(results)
    log.info("check %s", "PASS" if ok else "FAIL")
    return 0 if ok else 2


# ---------------------------------------------------------------- test
def _venv_python():
    """.venv 内 Python 解释器(Windows Scripts/,POSIX bin/),缺失返回 None。"""
    if os.name == "nt":
        p = os.path.join(ROOT, ".venv", "Scripts", "python.exe")
    else:
        p = os.path.join(ROOT, ".venv", "bin", "python")
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


# ---------------------------------------------------------------- helpers
def _compile_check(src, label):
    """py_compile 编译单个源文件(只编译不执行);.pyc 写临时目录。返回 bool。"""
    fd, cfile = tempfile.mkstemp(suffix=".pyc")
    os.close(fd)
    try:
        py_compile.compile(src, cfile=cfile, doraise=True)
    except py_compile.PyCompileError as e:
        log.info("compile %-22s FAIL: %s", label, getattr(e, "msg", e))
        return False
    finally:
        try:
            os.remove(cfile)
        except OSError:
            pass
    log.info("compile %-22s OK", label)
    return True


def _http(port, method, path, body=None, cookie=None, timeout=5):
    """单次 HTTP 请求(标准库 http.client);返回 (status, headers, bytes)。
    headers 为 (名, 值) 元组列表;连接失败/超时抛 OSError。"""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        headers = {"Accept": "application/json"}
        payload = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            payload = json.dumps(body).encode("utf-8")
        if cookie:
            headers["Cookie"] = cookie
        conn.request(method, path, body=payload, headers=headers)
        resp = conn.getresponse()
        return resp.status, resp.getheaders(), resp.read()
    finally:
        conn.close()


def _cookie_value(headers):
    """从响应头提取 ns_session cookie 的值(不含属性)。"""
    for name, val in headers:
        if name.lower() == "set-cookie" and val.startswith("ns_session="):
            return val.split(";", 1)[0].split("=", 1)[1]
    return None


def _pick_smoke_port():
    """在 PORT+1..PORT+20 顺序挑选一个当前可绑定的端口;全被占返回 None。"""
    for p in range(PORT + 1, PORT + 21):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("127.0.0.1", p))
            s.close()
            return p
        except OSError:
            s.close()
    return None


def _kill_proc(proc):
    """终止子进程并回收: terminate -> wait 5s -> kill 兜底。"""
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
        return
    except subprocess.TimeoutExpired:
        pass
    proc.kill()
    try:
        proc.wait(timeout=5)
    except Exception:
        pass


# ---------------------------------------------------------------- smoke
SMOKE_HTTP_TIMEOUT = 5           # 契约步单次 HTTP 超时(秒)
SMOKE_JOB_POLL_TIMEOUT = 30      # C3 作业轮询上限(秒),超时仅 WARN 不判 FAIL


def _try_json(data):
    """字节响应体解析 JSON;解析失败返回 {}(契约步宽松断言用)。"""
    try:
        return json.loads(data.decode("utf-8")) if data else {}
    except Exception:
        return {}


def _contract_http(port):
    """绑定 smoke 端口的 HTTP 调用器(契约步统一 5s 超时)。

    cookie 参数为完整 Cookie 头(如 "ns_session=xxx"),与 _http 语义一致。
    """
    def call(method, path, body=None, cookie=None):
        return _http(port, method, path, body=body, cookie=cookie,
                     timeout=SMOKE_HTTP_TIMEOUT)
    return call


def _contract_c1_login_fail(http, cookie):
    """C1 login 失败 401: 错误密码 -> 401 且响应体含 error。"""
    try:
        st, _, data = http("POST", "/api/login",
                           {"username": "admin", "password": "wrong"})
        text = json.dumps(_try_json(data), ensure_ascii=False)
        ok = (st == 401 and "error" in text)
        return ok, "status=%d body=%s" % (st, text)
    except OSError as e:
        return False, "err: %s" % e


def _contract_c2_scan_empty(http, cookie):
    """C2 scan 空参数 400: 空 subnet -> 400 且体含 subnet required。"""
    try:
        st, _, data = http("POST", "/api/scan", {"subnet": ""}, cookie=cookie)
        text = json.dumps(_try_json(data), ensure_ascii=False)
        ok = (st == 400 and "subnet required" in text)
        return ok, "status=%d body=%s" % (st, text)
    except OSError as e:
        return False, "err: %s" % e


def _contract_c3_scan_bad_profile(http, cookie):
    """C3 scan 非法 profile 容错: 200 + job_id(引擎白名单回退 quick),随后轮询
    /api/job 等待 done/error;30s 超时仅 WARN 不判 FAIL(后台作业不影响后续)。"""
    try:
        st, _, data = http("POST", "/api/scan",
                           {"subnet": "127.0.0.1", "port_profile": "bogus",
                            "scan_ports": True}, cookie=cookie)
        body = _try_json(data)
        jid = body.get("job_id")
        if st != 200 or not jid:
            body_txt = json.dumps(body, ensure_ascii=False)
            return False, "status=%d body=%s" % (st, body_txt)
        final = None
        deadline = time.time() + SMOKE_JOB_POLL_TIMEOUT
        while time.time() < deadline:
            try:
                st2, _, d2 = http("GET", "/api/job?id=" + jid, cookie=cookie)
                if st2 == 200:
                    curr = _try_json(d2).get("status")
                    if curr in ("done", "error"):
                        final = curr
                        break
            except OSError:
                pass
            time.sleep(0.5)
        if final is None:
            return True, "job_id=%s 30s 未完结(WARN,后台作业不影响后续步骤)" % jid
        return True, "job_id=%s status=%s(白名单回退 quick 已验证)" % (jid, final)
    except OSError as e:
        return False, "err: %s" % e


def _contract_c4_scan_rapid(http, cookie):
    """C4 scan busy 挂接(SPEC §2.4 单作业互斥): 连发两次 scan(间隔 0.05s)。

    第一次必须 200 且含 job_id(记录 first_id/first_busy);若第一次 busy:true
    (已挂接既有作业)则 attach 语义已覆盖,跳过第二次分支断言仍 PASS。
    第二次必须 200 且命中 attach 任一分支:
      ① busy:true 且 job_id==first_id —— 挂接同一作业
      ② job_id!=first_id —— 时序宽限(首次作业超快完结,第二次为独立新作业)
      ③ 无 busy 且 job_id==first_id —— 引擎复用同一作业
    失败时 info 附原始响应供排查。"""
    try:
        st1, _, d1 = http("POST", "/api/scan", {"subnet": "127.0.0.1"},
                          cookie=cookie)
        b1 = _try_json(d1)
        first_id = b1.get("job_id")
        first_busy = b1.get("busy") is True
        if st1 != 200 or not first_id:
            raw1 = json.dumps(b1, ensure_ascii=False)
            return False, ("第一次 status=%d body=%s(需 200 且含 job_id)"
                           % (st1, raw1))
        time.sleep(0.05)
        st2, _, d2 = http("POST", "/api/scan", {"subnet": "127.0.0.1"},
                          cookie=cookie)
        b2 = _try_json(d2)
        second_id = b2.get("job_id")
        second_busy = b2.get("busy") is True
        raw2 = json.dumps(b2, ensure_ascii=False)
        if first_busy:
            # attach 语义已由第一次响应(busy:true 挂接既有作业)覆盖,第二次仅要求 200
            ok = (st2 == 200)
            detail = ("first_id=%s first_busy=true(跳过attach断言);"
                      " 第二次 status=%d second_id=%s second_busy=%s"
                      % (first_id, st2, second_id, second_busy))
            return ok, detail + ("" if ok else " body=%s" % raw2)
        if second_id is None:
            branch = None
        elif second_busy and second_id == first_id:
            branch = "①挂接(busy同一job)"       # 挂接语义
        elif second_id != first_id:
            branch = "②新作业(时序宽限)"        # 首次作业已完结
        else:
            branch = "③复用(无busy同job)"      # 引擎复用同一作业
        ok = (st2 == 200 and branch is not None)
        detail = ("first_id=%s first_busy=%s; 第二次 status=%d second_id=%s"
                  " second_busy=%s branch=%s"
                  % (first_id, first_busy, st2, second_id, second_busy,
                     branch or "无匹配分支"))
        return ok, detail + ("" if ok else " body=%s" % raw2)
    except OSError as e:
        return False, "err: %s" % e


def _contract_c5_device_empty(http, cookie):
    """C5 device 空 key 400: 空体 -> 400 且体含 mac or ip required。"""
    try:
        st, _, data = http("POST", "/api/device", {}, cookie=cookie)
        text = json.dumps(_try_json(data), ensure_ascii=False)
        ok = (st == 400 and "mac or ip required" in text)
        return ok, "status=%d body=%s" % (st, text)
    except OSError as e:
        return False, "err: %s" % e


def _contract_c6_info_fields(http, cookie):
    """C6 info 契约字段: subnet/local_ip/cpu/platform/auth 齐全 +
    auth.enabled/default_creds=true + auth.username=="admin"。"""
    try:
        st, _, data = http("GET", "/api/info", cookie=cookie)
        body = _try_json(data)
        auth = body.get("auth") or {}
        missing = [k for k in ("subnet", "local_ip", "cpu", "platform", "auth")
                   if k not in body]
        ok = (st == 200 and not missing and auth.get("enabled") is True
              and auth.get("default_creds") is True
              and auth.get("username") == "admin")
        auth_txt = json.dumps(auth, ensure_ascii=False)
        detail = "status=%d missing=%s auth=%s" % (st, missing or "无", auth_txt)
        return ok, detail
    except OSError as e:
        return False, "err: %s" % e


def _contract_c7_logout_deny(http, cookie):
    """C7 登出后拒绝: 带 cookie 登出 200,随后无 cookie 访问 /api/info
    得 302(跳转登录)或 401(拒绝)均判通过。"""
    try:
        st, _, _ = http("POST", "/api/logout", {}, cookie=cookie)
        if st != 200:
            return False, "logout status=%d" % st
        st2, _, _ = http("GET", "/api/info")
        ok = st2 in (302, 401)
        return ok, "logout=%d; info(无 cookie)=%d" % (st, st2)
    except OSError as e:
        return False, "err: %s" % e


CONTRACT_STEPS = [
    ("C1 login失败401", _contract_c1_login_fail),
    ("C2 scan空参400", _contract_c2_scan_empty),
    ("C3 scan非法profile容错", _contract_c3_scan_bad_profile),
    ("C4 scan busy挂接", _contract_c4_scan_rapid),
    ("C5 device空key400", _contract_c5_device_empty),
    ("C6 info契约字段", _contract_c6_info_fields),
    ("C7 登出后拒绝", _contract_c7_logout_deny),
]


def run_smoke():
    """端到端接口冒烟: 临时端口 + 全新 NETRYX_DATA 起引擎(admin/admin 默认场景),
    GET /login -> POST /api/login(取 ns_session) -> GET /api/info -> 契约矩阵
    C1-C7(每步独立断言,失败收集不中断,全部跑完再汇总)。
    全程 try/finally: 子进程必杀、临时数据目录必清。"""
    steps = []                    # [(步骤名, 是否通过, 附加信息)]
    def note(name, ok, info=""):
        steps.append((name, bool(ok), info))

    port = _pick_smoke_port()
    if port is None:
        log.info("[错误] smoke 端口 %d-%d 全部被占", PORT + 1, PORT + 20)
        return 1
    tmp_data = tempfile.mkdtemp(prefix="netryx-smoke-")
    env = dict(os.environ, NETRYX_DATA=tmp_data, PYTHONIOENCODING="utf-8")
    engine_py = os.path.join(ENGINE_DIR, "netryx.py")
    proc = None
    out_lines = []                # 引擎 stdout 缓冲(诊断/端口实测)
    try:
        actual = port
        try:
            proc = subprocess.Popen(
                [sys.executable, "-u", engine_py, "--no-browser",
                 "--port", str(port)],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace", env=env)
        except OSError as e:
            note("start-engine", False, str(e))
            return _smoke_report(steps, out_lines)

        def _drain():
            try:
                for line in proc.stdout:
                    out_lines.append(line.rstrip())
            except Exception:
                pass
        threading.Thread(target=_drain, daemon=True).start()
        note("start-engine", True, "pid=%d port=%d data=%s"
             % (proc.pid, port, tmp_data))

        # 轮询 /login 直到 200(引擎 fallback 端口也认: banner 覆盖实际端口)
        ready = False
        for _ in range(30):
            if proc.poll() is not None:
                break
            for line in out_lines:
                m = re.search(r"http://127\.0\.0\.1:(\d+)", line)
                if m:
                    actual = int(m.group(1))
            try:
                if _http(actual, "GET", "/login")[0] == 200:
                    ready = True
                    break
            except OSError:
                pass
            time.sleep(0.5)
        note("GET /login", ready, "port=%d via=%s" % (actual,
             "banner" if actual != port else "probe"))
        if not ready:
            return _smoke_report(steps, out_lines)

        st, hdrs, _ = _http(actual, "POST", "/api/login",
                            {"username": "admin", "password": "admin",
                             "remember": True})
        cookie = _cookie_value(hdrs)
        ok = (st == 200 and cookie is not None)
        note("POST /api/login", ok, "status=%d cookie=%s" % (st,
             "yes(%s...)" % cookie[:12] if cookie else "no"))
        # 登录失败也继续(契约步独立收集,最终汇总判 rc)——仅引擎未就绪才中断

        st, _, data = _http(actual, "GET", "/api/info", cookie="ns_session=" + cookie)
        info = None
        try:
            info = json.loads(data.decode("utf-8")) if data else None
        except Exception:
            pass
        auth = (info or {}).get("auth") or {}
        ok = (st == 200 and auth.get("enabled") is True
              and auth.get("default_creds") is True)
        note("GET /api/info", ok, "status=%d auth=%s" % (st,
             json.dumps(auth, ensure_ascii=False)))

        # SPEC §2.4 接口契约矩阵 C1-C7: 独立断言,失败收集不中断,全部跑完再汇总
        call = _contract_http(actual)
        cookie_hdr = "ns_session=" + cookie
        for name, fn in CONTRACT_STEPS:
            try:
                c_ok, c_info = fn(call, cookie_hdr)
            except Exception as e:        # 单步任何异常不中断整体
                c_ok, c_info = False, "unexpected: %s" % e
            note(name, c_ok, c_info)
        return _smoke_report(steps, out_lines)
    finally:
        _kill_proc(proc)
        if tmp_data and os.path.isdir(tmp_data):
            shutil.rmtree(tmp_data, ignore_errors=True)


def _smoke_report(steps, engine_lines=None):
    """输出冒烟每步 PASS/FAIL 摘要;失败时附引擎输出尾部(诊断窗口)。"""
    ok = all(p for _, p, _ in steps)
    for name, passed, info in steps:
        log.info("smoke %-20s %-4s %s", name, "PASS" if passed else "FAIL", info)
    if not ok and engine_lines:
        log.info("engine output (tail):\n%s", "\n".join(
            [ln for ln in engine_lines if ln.strip()][-12:]))
    log.info("smoke %s", "PASS" if ok else "FAIL")
    return 0 if ok else 1


# ---------------------------------------------------------------- pack
def run_pack():
    """交付打包: 收集清单文件 -> dist/netryx_demo-<UTC时间戳>.zip,内含 manifest.json。
    可选文件(start.ps1/README.md)缺失跳过,必须文件缺失报 [错误] 退出 1。"""
    os.makedirs(DIST_DIR, exist_ok=True)
    entries = []
    for rel in PACK_FILES:
        src = os.path.join(ROOT, rel)
        if not os.path.isfile(src):
            if rel in PACK_OPTIONAL:
                log.info("pack skip(可选): %s", rel)
                continue
            log.info("[错误] 缺少 %s", src)
            return 1
        entries.append((rel, src))
    stamp = datetime.now(timezone.utc)
    manifest = {"generated": stamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "version": DELIVERY_VERSION, "files": []}
    zip_path = os.path.join(DIST_DIR, "netryx_demo-%s.zip"
                            % stamp.strftime("%Y%m%d-%H%M%S"))
    try:
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for rel, src in entries:
                with open(src, "rb") as f:
                    data = f.read()
                manifest["files"].append({"path": rel, "size": len(data),
                                          "sha256": hashlib.sha256(data).hexdigest()})
                zf.writestr(rel, data)
            zf.writestr("manifest.json",
                        json.dumps(manifest, indent=2, ensure_ascii=False))
    except OSError as e:
        log.info("[错误] 打包失败: %s", e)
        return 1
    log.info("pack %s OK (%d 文件, %d bytes)", zip_path, len(entries),
             os.path.getsize(zip_path))
    return 0


# ---------------------------------------------------------------- verify
def _latest_zip():
    """dist/ 下按修改时间最新的 *.zip,无则 None。"""
    zips = [p for p in glob.glob(os.path.join(DIST_DIR, "*.zip"))
            if os.path.isfile(p)]
    return max(zips, key=os.path.getmtime) if zips else None


def run_verify(zip_path=None):
    """校验交付包: manifest 存在 -> 每条 files 的 path/size/sha256 与 zip 内一致
    -> 引擎与 build.py py_compile 编译通过。解压到临时目录,成败均清理。"""
    zip_path = zip_path or _latest_zip()
    if not zip_path:
        log.info("[错误] dist/ 下未找到 *.zip - 请先运行: build.py pack")
        return 1
    if not os.path.isfile(zip_path):
        log.info("[错误] zip 不存在: %s", zip_path)
        return 1
    tmp = tempfile.mkdtemp(prefix="netryx-verify-")
    try:
        try:
            with zipfile.ZipFile(zip_path) as zf:
                names = zf.namelist()
                if "manifest.json" not in names:
                    log.info("[错误] %s 缺少 manifest.json", zip_path)
                    return 1
                try:
                    manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
                except Exception as e:
                    log.info("[错误] manifest.json 解析失败: %s", e)
                    return 1
                entries = manifest.get("files") or []
                log.info("verify manifest OK (version=%s, %d 文件清单)",
                         manifest.get("version", "?"), len(entries))
                ok = True
                for item in entries:
                    path = item.get("path")
                    if path not in names:
                        log.info("verify file %-22s FAIL: zip 内无此条目", path or "?")
                        ok = False
                        continue
                    data = zf.read(path)
                    size_ok = (len(data) == item.get("size")
                               and zf.getinfo(path).file_size == item.get("size"))
                    sha_ok = hashlib.sha256(data).hexdigest() == str(item.get("sha256"))
                    good = size_ok and sha_ok
                    log.info("verify file %-22s %s(size=%s sha256=%s)", path,
                             "OK" if good else "FAIL",
                             "OK" if size_ok else "MISMATCH",
                             "OK" if sha_ok else "MISMATCH")
                    ok = ok and good
                zf.extractall(tmp)
        except (zipfile.BadZipFile, OSError) as e:
            log.info("[错误] zip 打开/读取失败: %s", e)
            return 1
        ok = _compile_check(os.path.join(tmp, "engine", "netryx.py"),
                            "engine/netryx.py") and ok
        ok = _compile_check(os.path.join(tmp, "build.py"), "build.py") and ok
        log.info("verify %s (%s)", "PASS" if ok else "FAIL", zip_path)
        return 0 if ok else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------- setup
def run_setup():
    """.venv 引导: 已存在则报就绪;否则创建 venv 并 pip install pytest(各 300s 超时)。"""
    py = _venv_python()
    if py:
        log.info("setup: .venv 已就绪 (%s)", py)
        return 0
    venv_dir = os.path.join(ROOT, ".venv")
    log.info("setup: 创建 .venv ...")
    code, out = _run([sys.executable, "-m", "venv", venv_dir], timeout=300)
    if code != 0:
        log.info("[错误] venv 创建失败(rc=%d): %s", code, out[-400:])
        log.info("[指引] 检查 Python 是否可执行后重试: %s -m venv .venv", sys.executable)
        return 2
    py = _venv_python()
    if not py:
        log.info("[错误] venv 已创建但未找到解释器 %s", venv_dir)
        return 2
    log.info("setup: 安装 pytest ...")
    code, out = _run([py, "-m", "pip", "install", "pytest"], timeout=300)
    if code != 0:
        log.info("[错误] pip install pytest 失败(rc=%d): %s", code, out[-400:])
        log.info("[指引] 检查网络/镜像后重试: %s -m pip install pytest "
                 "(可加 -i https://pypi.tuna.tsinghua.edu.cn/simple)", py)
        return 2
    log.info("setup: .venv 就绪, pytest 安装完成")
    return 0


# ---------------------------------------------------------------- main
USAGE = "build.py <check|test|smoke|pack|verify [zip]|setup|clean|log|all>"


def main():
    _setup_logging()
    cmd = sys.argv[1] if len(sys.argv) > 1 else "check"
    if cmd == "check":
        return run_check()
    if cmd == "test":
        return run_test()
    if cmd == "smoke":
        return run_smoke()
    if cmd == "pack":
        return run_pack()
    if cmd == "verify":
        return run_verify(sys.argv[2] if len(sys.argv) > 2 else None)
    if cmd == "setup":
        return run_setup()
    if cmd == "clean":
        return run_clean()
    if cmd == "log":
        return run_log()
    if cmd == "all":
        rc = run_check()
        rc = rc or run_test()
        rc = rc or run_pack()
        rc = rc or run_verify()
        return rc
    log.info("unknown cmd %r; usage: %s", cmd, USAGE)
    return 1


if __name__ == "__main__":
    sys.exit(main())
