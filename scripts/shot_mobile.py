# 手机端(390x844)截图验证:登录页 -> 登录 -> dashboard -> 触发扫描 -> 结果截图
import re
import sys
import time
from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8765"
OUT = "D:/vsc_project/lan-network-manager/shots"
import os
os.makedirs(OUT, exist_ok=True)

with sync_playwright() as p:
    b = p.chromium.launch()
    ctx = b.new_context(viewport={"width": 390, "height": 844}, device_scale_factor=2)
    page = ctx.new_page()

    page.goto(BASE + "/login", wait_until="networkidle")
    page.screenshot(path=f"{OUT}/1_login.png")
    print("login shot ok")

    page.fill("#u", "admin")
    page.fill("#p", "admin")  # 默认 admin/admin(首次启动)
    page.click("#f button[type=submit], #f button")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(1500)
    page.screenshot(path=f"{OUT}/2_dashboard.png")
    print("dashboard shot ok, url=", page.url)

    # 触发扫描(找 Scan 按钮)
    btn = page.get_by_role("button", name=re.compile("scan", re.I)).first
    if btn.count() > 0:
        btn.click()
        page.wait_for_timeout(3000)
        page.screenshot(path=f"{OUT}/3_scanning.png")
        # 等扫描完成:最多 120s,轮询直到出现设备数/卡片,或"Scan"按钮重新可用
        for _ in range(40):
            page.wait_for_timeout(3000)
            txt = page.inner_text("body")
            if "192.168.3." in txt and ("Scan" in txt or "扫描" in txt):
                # 粗略判断完成:出现设备列表文本
                pass
            page.screenshot(path=f"{OUT}/4_scan_progress.png")
            # 若按钮重新可用(未在 scanning),大概率已完成
            cls = btn.get_attribute("class") or ""
            if "disabled" not in cls and "scanning" not in cls.lower():
                page.wait_for_timeout(5000)
                page.screenshot(path=f"{OUT}/5_result.png", full_page=True)
                print("result shot ok")
                break
        # 拓扑图视图截图
        topo = page.get_by_text(re.compile("topology|map", re.I)).first
        if topo.count() > 0:
            topo.click()
            page.wait_for_timeout(2500)
            page.screenshot(path=f"{OUT}/6_topology.png")
            print("topology shot ok")
    else:
        print("scan button not found; body starts:", page.inner_text("body")[:300])

    b.close()
print("done")
