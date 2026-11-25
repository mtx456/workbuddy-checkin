#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WorkBuddy 积分助手 —— 签到 + 派猫猫旅行（通用云端版）

特性：
  - 零第三方依赖，仅用 Python 标准库，可运行于任意有 Python 3 的环境（含云端定时调度）。
  - 不依赖本机 WorkBuddy 客户端，不读取任何本地文件，不写任何本地日志。
  - 不含任何账号凭证：accessToken / uid / domain 全部由使用者在运行时提供。
  - 幂等安全：今日已签 / 今日已派 / 旅行中 均自动跳过，不重复操作。
  - 输出脱敏：token 仅以 eyJ...xxxx 形态出现，不打印明文。
  - 有限重试：网络错误 / 5xx 自动重试 2 次；状态查询失败时幂等兜底并标记 uncertain。

凭证提供方式（三选一，优先级从高到低）：
  1. 命令行参数：--token <accessToken> [--uid <uid>] [--domain <domain>]
  2. 环境变量：WORKBUDDY_TOKEN [--uid 时可用 WORKBUDDY_UID]
  3. uid / domain 若未提供，会尝试从 accessToken 的 JWT 载荷中自动解析（sub / iss）。

用法示例：
  export WORKBUDDY_TOKEN="eyJ..."
  python workbuddy_points.py                       # 签到 + 派猫（默认 all）
  python workbuddy_points.py --mode checkin        # 只签到
  python workbuddy_points.py --mode travel         # 只派猫
  python workbuddy_points.py --token "eyJ..." --uid "xxx" --domain "www.workbuddy.cn"

如何获取 accessToken：
  在你自己已登录的 WorkBuddy 客户端登录态中取得（形如 eyJ 开头的 JWT）。
  获取方式请自行参考客户端机制，本工具不内置任何解密或抓取逻辑，也不代你保存凭证。
"""
import argparse
import base64
import datetime
import json
import os
import sys
import time
import urllib.error
import urllib.request

# 官方接口（WorkBuddy 成长体系公开 HTTP 接口）
ENDPOINT = "https://copilot.tencent.com"
CHECKIN_STATUS_PATH = "/v2/billing/meter/checkin-activity-status"
CHECKIN_CLAIM_PATH = "/v2/billing/meter/daily-checkin"
TRAVEL_STATUS_PATH = "/activity/growth/buddy/travel/status"
TRAVEL_CONFIG_PATH = "/activity/growth/buddy/travel/config"
TRAVEL_DEPART_PATH = "/activity/growth/buddy/travel/depart"
TRAVEL_CLAIM_PATH = "/activity/growth/buddy/travel/claim"

DEFAULT_DOMAIN = "www.workbuddy.cn"
MAX_RETRIES = 2   # 网络错误 / 5xx 最多重试次数
RETRY_DELAY = 1   # 重试间隔（秒）


def bj_now():
    """北京时间字符串。"""
    return (datetime.datetime.now(datetime.timezone.utc) +
            datetime.timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")


def mask(secret):
    """凭证脱敏：仅保留前 5 后 4 位。"""
    if not isinstance(secret, str) or len(secret) <= 10:
        return "<empty/short>"
    return secret[:5] + "..." + secret[-4:]


def parse_jwt(token):
    """解析 JWT 载荷（不校验签名，仅取字段），失败返回 {}。"""
    try:
        seg = token.split(".")[1]
        seg += "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg))
    except Exception:
        return {}


def resolve_identity(token, uid_arg, domain_arg):
    """从 token 解析 uid / domain / 过期时间，命令行/环境变量优先。"""
    payload = parse_jwt(token)
    uid = (uid_arg or os.environ.get("WORKBUDDY_UID") or payload.get("sub") or "")
    domain = (domain_arg or os.environ.get("WORKBUDDY_DOMAIN") or "")
    if not domain:
        iss = payload.get("iss") or ""  # e.g. https://www.workbuddy.cn/auth/realms/copilot
        if "://" in iss:
            domain = iss.split("://", 1)[1].split("/", 1)[0]
        domain = domain or DEFAULT_DOMAIN
    exp = payload.get("exp")
    days_left = None
    if isinstance(exp, (int, float)):
        days_left = (exp - datetime.datetime.now().timestamp()) / 86400.0
    return uid, domain, days_left


def is_ok(code, resp):
    """统一判断响应是否成功：HTTP 200 且 code 为 0（兼容字符串 "0" 与缺失）。"""
    if code != 200 or not isinstance(resp, dict):
        return False
    if "code" not in resp:
        return True
    return resp.get("code") == 0 or resp.get("code") == "0"


def make_client(token, uid, domain, endpoint):
    """构造一个带鉴权头的 HTTP POST/GET 请求器（网络错误/5xx 自动有限重试）。"""
    def call_once(method, path, body=None):
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            "X-User-Id": uid or "",
            "X-Domain": domain or "",
            "User-Agent": "Mozilla/5.0 WorkBuddy/5.3",
            "Referer": "https://www.workbuddy.cn/",
        }
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(endpoint + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=25) as resp:
                return resp.getcode(), json.loads(resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", "replace") if e.fp else ""
            try:
                return e.code, json.loads(raw)
            except Exception:
                return e.code, {"_raw": raw}
        except Exception as e:
            return -1, {"error": "request_failed: %s" % e}

    def call(method, path, body=None):
        code, resp = call_once(method, path, body)
        for _ in range(MAX_RETRIES):
            retryable = (code == -1) or (isinstance(code, int) and 500 <= code <= 599)
            if not retryable:
                break
            time.sleep(RETRY_DELAY)
            code, resp = call_once(method, path, body)
        return code, resp
    return call


def do_checkin(call):
    """每日签到：先查状态，未签才领取；状态查询失败时领取接口幂等兜底。"""
    code, resp = call("POST", CHECKIN_STATUS_PATH, {})
    if not is_ok(code, resp):
        # 状态查询失败（含重试后）：领取接口幂等，直接尝试领取；结果标记 uncertain 供核对
        cc, cr = call("POST", CHECKIN_CLAIM_PATH, {})
        if is_ok(cc, cr):
            d = cr.get("data", {}) or {}
            return {"status": "success", "uncertain": True, "reason": "status_query_failed",
                    "message": "状态查询失败，已直接领取成功（请核对）",
                    "credit": d.get("credit"),
                    "streak_days": d.get("streak_days"),
                    "total_credits": d.get("total_credits"),
                    "is_streak_day": cr.get("is_streak_day")}, d
        return {"status": "error", "uncertain": True, "phase": "status", "http": code,
                "reason": "status_query_failed",
                "hint": "状态查询与兜底领取均未成功，请稍后重跑确认（幂等，不会重复领取）",
                "body": resp, "claim_body": cr}, {}
    data = resp.get("data", {}) or {}
    streak = data.get("streak_days")
    total = data.get("total_credits")
    if data.get("today_checked_in"):
        return {"status": "already_signed", "message": "今日已签到, 安全跳过 (幂等)",
                "streak_days": streak, "total_credits": total}, data
    code, resp = call("POST", CHECKIN_CLAIM_PATH, {})
    if not is_ok(code, resp):
        return {"status": "error", "phase": "claim", "http": code, "body": resp}, data
    d = resp.get("data", {}) or {}
    return {"status": "success", "message": "领取成功",
            "credit": d.get("credit"),
            "streak_days": d.get("streak_days", streak),
            "total_credits": d.get("total_credits", total),
            "is_streak_day": resp.get("is_streak_day")}, d


def do_travel(call, location_id):
    """派猫猫旅行：先领已到家的奖励，再派空闲的猫出去；状态查询失败时幂等兜底。"""
    code, resp = call("GET", TRAVEL_STATUS_PATH)
    if not is_ok(code, resp):
        # 状态查询失败：领取接口幂等，直接尝试领取兜底；未派出部分明确提示供核对
        cc, cr = call("POST", TRAVEL_CLAIM_PATH, {})
        return {"state_before": "unknown", "uncertain": True, "reason": "status_query_failed",
                "claim": "success" if is_ok(cc, cr) else "failed:http=%s" % cc,
                "hint": "状态查询失败，已尝试幂等领取；派出未执行，请重跑确认（幂等，不会重复领取）"}
    data = resp.get("data", {}) or {}
    state = data.get("state")  # idle | traveling | arrived
    limit = bool(data.get("daily_limit_reached"))
    out = {"state_before": state}

    # 猫已到家 -> 先领取（逾期作废，故优先处理）
    if state == "arrived":
        cc, cr = call("POST", TRAVEL_CLAIM_PATH, {})
        out["claim"] = "success" if is_ok(cc, cr) else "failed:http=%s" % cc
        # 领取后刷新状态，决定是否继续派出去
        c2, r2 = call("GET", TRAVEL_STATUS_PATH)
        if is_ok(c2, r2):
            d2 = r2.get("data", {}) or {}
            state, limit = d2.get("state"), bool(d2.get("daily_limit_reached"))

    # 空闲且未达每日上限 -> 派出去
    if state == "idle" and not limit:
        loc = location_id
        if not loc:  # 未指定则取配置的第一个地点
            lc, lr = call("GET", TRAVEL_CONFIG_PATH)
            if is_ok(lc, lr):
                locs = ((lr.get("data", {}) or {}).get("locations") or [])
                if locs:
                    loc = locs[0].get("id", 1)
        dc, dr = call("POST", TRAVEL_DEPART_PATH, {"location_id": loc})
        out["depart"] = "success" if is_ok(dc, dr) else "failed:http=%s" % dc
        out["location_id"] = loc
    elif state == "traveling":
        out["skip"] = "traveling"
    elif limit:
        out["skip"] = "daily_limit_reached"
    return out


def main():
    parser = argparse.ArgumentParser(description="WorkBuddy 积分助手（签到 + 派猫猫旅行）")
    parser.add_argument("--token", help="accessToken（也可设环境变量 WORKBUDDY_TOKEN）")
    parser.add_argument("--uid", help="用户 UID（可选，默认从 token 的 sub 解析）")
    parser.add_argument("--domain", help="X-Domain（可选，默认从 token 的 iss 解析或 www.workbuddy.cn）")
    parser.add_argument("--endpoint", default=ENDPOINT, help="API 基址（默认 %s）" % ENDPOINT)
    parser.add_argument("--mode", choices=["all", "checkin", "travel"], default="all",
                        help="执行范围：all=签到+派猫（默认）/ checkin / travel")
    parser.add_argument("--location-id", type=int, default=1,
                        help="派猫地点 ID（默认 1；积分由系统随机，与地点无关）")
    parser.add_argument("--show-token", action="store_true", help="是否在输出中显示脱敏后的 token")
    args = parser.parse_args()

    token = (args.token or os.environ.get("WORKBUDDY_TOKEN") or "").strip()
    if not token:
        print(json.dumps({
            "status": "error", "reason": "no_token",
            "hint": "缺少 accessToken。请通过 --token 传入，或设置环境变量 WORKBUDDY_TOKEN（示例：export WORKBUDDY_TOKEN=\"eyJ...\"）",
        }, ensure_ascii=False))
        return 2

    uid, domain, days_left = resolve_identity(token, args.uid, args.domain)
    result = {"date": bj_now(), "mode": args.mode}
    if args.show_token:
        result["token"] = mask(token)

    if days_left is not None:
        result["token_days_left"] = round(days_left, 1)
        if days_left <= 0:
            result.update(status="error", reason="token_expired",
                          hint="accessToken 已过期。请在已登录的 WorkBuddy 客户端重新获取 token 并更新配置后重跑")
            print(json.dumps(result, ensure_ascii=False))
            return 6
        if days_left <= 3:
            result["warning"] = "token 将在 %.1f 天内到期，请尽快更新" % days_left

    call = make_client(token, uid, domain, args.endpoint)

    if args.mode in ("all", "checkin"):
        res, _ = do_checkin(call)
        result["checkin"] = res
    if args.mode in ("all", "travel"):
        result["travel"] = do_travel(call, args.location_id)

    result["status"] = result.get("status", "ok")
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
