#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""本地 CI 模拟脚本(标准库,零第三方依赖;等价 .github/workflows/ci.yml 的
build-test + package 两 job 在本机单平台上的序列,黑盒 fail-fast)。

模拟序列(与 CI 一致,任一步失败立即停止):
  check -> smoke -> pack -> verify
  (smoke 会真实启动引擎 127.0.0.1 临时端口,约 5-10s,属正常)

输出:
  1) stdout 人类可读摘要(每步 PASS/FAIL + 总耗时)
  2) log/ci-sim-<UTC 时间戳>.json 完整机器可读报告
     顶层 {ok, steps:[{name,start,end,rc,dur_s,tail}], total_s, finished_at}

用法:
  python scripts/ci_simulate.py [--skip-smoke] [--clean]
    --skip-smoke  跳过 smoke,仅环境/打包链(check -> pack -> verify)
    --clean       全部步骤结束后额外执行 build.py clean

退出码:
  0        全部步骤通过(以及可选的 clean 成功)
  N>0      首个失败步骤的 rc(步骤自身失败,如 check=2 环境问题 / smoke=1)
  1        步骤超时或被整体 1800s 上限中止(无子进程 rc 可传播)
  2        自身错误(build.py 缺失 / 参数异常 / 被中断)
"""
import argparse
import datetime
import json
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD_PY = os.path.join(ROOT, "build.py")
LOG_DIR = os.path.join(ROOT, "log")

STEP_TIMEOUT = 300.0       # 单步超时(秒);check 在 CI 亦为分钟级小任务
OVERALL_TIMEOUT = 1800.0   # 整体上限(秒),超时中止并退出 1
TAIL_LINES = 12            # 每步日志尾部保留行数
ALL_STEPS = ("check", "smoke", "pack", "verify")
NO_SMOKE_STEPS = ("check", "pack", "verify")


def _now_iso():
    """当前 UTC 时间的 ISO-8601 字符串(秒级,机器可读)。"""
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def _tail(text, n=TAIL_LINES):
    """取输出尾部至多 n 行(先去尾部空行,逐行去右侧空白)。"""
    lines = (text or "").rsplit("\n", 1)[0].split("\n")
    while lines and not lines[-1].strip():
        lines.pop()
    return [ln.rstrip() for ln in lines[-n:]]


def run_step(name, timeout):
    """执行单个 build.py 子命令(子进程,-X utf8,带超时,捕获输出)。

    返回步骤记录 dict: {name, start, end, rc, dur_s, tail};
    rc=-1 表示无真实退出码(超时/无法启动)。超时子进程由 subprocess.run 自动终止。
    """
    start = time.time()
    cmd = [sys.executable, "-X", "utf8", BUILD_PY, name]
    try:
        p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout)
        rc = p.returncode
        out = (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        rc = -1
        out = "[超时] 步骤 %s 超过 %.0fs 未完成(子进程已终止)" % (name, timeout)
    except OSError as e:                       # 解释器/脚本不可执行等
        rc = -1
        out = "[错误] 无法启动子进程: %s" % (e,)
    end = time.time()
    return {"name": name, "start": _now_iso(), "end": _now_iso(),
            "rc": rc, "dur_s": round(end - start, 3), "tail": _tail(out)}


def run_chain(steps, report):
    """fail-fast 执行步骤链并写入 report["steps"];返回首个失败 rc,全过返回 0。"""
    started = time.time()
    for name in steps:
        elapsed = time.time() - started
        remaining = OVERALL_TIMEOUT - elapsed
        if remaining <= 0:
            report["steps"].append({
                "name": name, "start": _now_iso(), "end": _now_iso(), "rc": -1,
                "dur_s": 0.0,
                "tail": ["[中止] 整体 %.0fs 上限已耗尽,剩余步骤未执行"
                         % OVERALL_TIMEOUT]})
            return -1
        step = run_step(name, min(STEP_TIMEOUT, remaining))
        report["steps"].append(step)
        if step["rc"] != 0:
            return step["rc"]
    return 0


def run_clean(report):
    """--clean 时追加执行 build.py clean;返回其 rc(0/其他,失败时非 0)。"""
    report["steps"].append(run_step("clean", STEP_TIMEOUT))
    return report["steps"][-1]["rc"]


def write_report(report):
    """把完整报告写入 log/ci-sim-<UTC ts>.json,返回写入路径(同秒重跑自动换名)。"""
    os.makedirs(LOG_DIR, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y%m%d-%H%M%S")
    path = os.path.join(LOG_DIR, "ci-sim-%s.json" % stamp)
    n = 2
    while os.path.exists(path):
        path = os.path.join(LOG_DIR, "ci-sim-%s-%d.json" % (stamp, n))
        n += 1
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    return path


def print_summary(report, path):
    """stdout 人类可读摘要:每步 PASS/FAIL + 失败步骤尾部日志 + 总耗时。"""
    print("=" * 62)
    print("CI 模拟摘要(%s)" % report.get("scenario", "build-test+package"))
    print("=" * 62)
    for step in report["steps"]:
        status = "PASS" if step["rc"] == 0 else "FAIL"
        print("[%s] %-7s rc=%s dur=%.3fs" % (status, step["name"],
                                             step["rc"], step["dur_s"]))
        if step["rc"] != 0 and step["tail"]:
            print("    tail(%d):" % len(step["tail"]))
            for line in step["tail"]:
                print("      %s" % line)
    print("-" * 62)
    if report.get("error"):
        print("错误: %s" % report["error"])
    print("总耗时: %.3fs" % report["total_s"])
    print("结果: %s" % ("PASS" if report["ok"] else "FAIL"))
    print("报告: %s" % os.path.relpath(path, ROOT))


def main():
    """入口:解析参数 -> 执行步骤链(fail-fast)-> finally 必写报告再退出。"""
    parser = argparse.ArgumentParser(
        description="本地 CI 模拟:check->smoke->pack->verify(fail-fast)")
    parser.add_argument("--skip-smoke", action="store_true",
                        help="跳过 smoke,仅环境/打包链(check->pack->verify)")
    parser.add_argument("--clean", action="store_true",
                        help="全部步骤结束后额外执行 build.py clean")
    args = parser.parse_args()

    report = {"ok": False, "steps": [], "total_s": 0.0, "finished_at": None}
    rc = 2                       # 自身错误兜底
    started = time.time()
    try:
        if not os.path.isfile(BUILD_PY):
            report["error"] = "build.py 不存在: %s" % BUILD_PY
            return rc            # finally 仍会写报告
        steps = NO_SMOKE_STEPS if args.skip_smoke else ALL_STEPS
        report["scenario"] = "build-test+package(skip-smoke)" \
            if args.skip_smoke else "build-test+package"
        rc = run_chain(steps, report)
        if rc == 0 and args.clean:
            clean_rc = run_clean(report)
            if clean_rc != 0:
                rc = clean_rc
        if rc < 0:               # 整体超时/中止:无子进程 rc 可传播
            rc = 1
        report["ok"] = (rc == 0)
        return rc
    except KeyboardInterrupt:
        report["error"] = "被用户中断(Ctrl+C)"
        return 2
    finally:
        report["finished_at"] = _now_iso()
        report["total_s"] = round(time.time() - started, 3)
        path = write_report(report)
        print_summary(report, path)


if __name__ == "__main__":
    sys.exit(main())
