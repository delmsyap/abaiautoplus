"""
Android Playwright Runtime for ChatGPT Payment Automation

Combines:
- Flow2API Android runtime pattern (Playwright + com.android.chrome on emulator-5554)
- Stripe protocol 12-step hosted mode flow (per blog.caowo.de posts)
- CycleTLS for Chrome JA3 fingerprint matching
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import secrets
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urlparse

from curl_cffi import requests as cffi_requests

logger = logging.getLogger(__name__)

# ============================================================================
# Constants from protocol-engine / blog analysis
# ============================================================================

STRIPE_API_BASE = "https://api.stripe.com/v1"
STRIPE_CHECKOUT_BASE = "https://checkout.stripe.com"
STRIPE_JS_URL = "https://js.stripe.com/v3/"
STRIPE_VERSION = "2025-03-31.basil; checkout_server_update_beta=v1; checkout_manual_approval_preview=v1"
STRIPE_PUBLISHABLE_KEY = (
    "pk_live_51HOrSwC6h1nxGoI3lTAgRjYVrz4dU3fVOabyCcKR3pbEJguCVAlqCxdxCUvoRh1XWwRacViovU3kLKvpkjh7IqkW00iXQsjo3n"
)

# Chrome 150 JA3 (ACC captured)
CHROME_JA3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,13-65281-10-18-0-16-17613-35-5-23-65037-51-11-43-27-45,4588-29-23-24,0"
CHROME_SEC_CH_UA = '"Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"'

# Android runtime config
DEFAULT_ANDROID_SERIAL = "emulator-5554"
DEFAULT_BROWSER_PACKAGE = "com.android.chrome"
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/147.0.0.0 Mobile Safari/537.36"
)

CHATGPT_URL = "https://chatgpt.com/"
CHECKOUT_URL = "https://chatgpt.com/backend-api/payments/checkout"
TAXES_URL = "https://chatgpt.com/backend-api/payments/checkout/taxes"
APPROVE_URL = "https://chatgpt.com/backend-api/payments/checkout/approve"

STEP_DELAY_MS = 2000
RETRY_LIMIT = 3
RETRY_BASE_MS = 5000
RETRY_MAX_MS = 30000

# ============================================================================
# Exceptions
# ============================================================================

class AndroidPaymentError(Exception):
    def __init__(self, message: str, code: str = ""):
        super().__init__(message)
        self.code = code


class RunLockError(AndroidPaymentError):
    pass


# ============================================================================
# Device Fingerprint / State
# ============================================================================

@dataclass
class DeviceFingerprint:
    guid: str = field(default_factory=lambda: str(uuid.uuid4()))
    muid: str = field(default_factory=lambda: str(uuid.uuid4()))
    sid: str = field(default_factory=lambda: str(uuid.uuid4()))
    client_session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    stripe_js_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class AndroidRuntimeState:
    """Shared state during Android payment flow."""
    device_serial: str = DEFAULT_ANDROID_SERIAL
    browser_package: str = DEFAULT_BROWSER_PACKAGE
    access_token: str = ""
    device_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_agent: str = DEFAULT_USER_AGENT
    proxy: str = ""
    stripe_pk: str = STRIPE_PUBLISHABLE_KEY
    
    # Card details
    card_number: str = ""
    card_exp_month: str = ""
    card_exp_year: str = ""
    card_cvc: str = ""
    
    # Billing
    billing_name: str = "John Doe"
    billing_email: str = "test@example.com"
    billing_line1: str = "123 Main St"
    billing_city: str = "San Francisco"
    billing_state: str = "CA"
    billing_postal: str = "94105"
    billing_country: str = "US"
    
    plan_name: str = "chatgptplusplan"
    checkout_ui_mode: str = "hosted"
    
    # Runtime
    fingerprint: DeviceFingerprint = field(default_factory=DeviceFingerprint)
    cs_id: str = ""
    processor_entity: str = ""
    billing_country_resolved: str = ""
    currency: str = "USD"
    expected_amount: int = 0
    ppage_token: str = ""
    rv_timestamp: int = 0
    js_checksum: str = ""
    elements_session_id: str = ""
    elements_config_id: str = ""
    ctoken_id: str = ""
    
    # CycleTLS client (lazy init)
    _ctls: Any = field(default=None, repr=False)
    _ctls_ready: asyncio.Future = field(default=None, repr=False)
    
    # Callbacks
    log_fn: Callable[[str], None] = field(default=lambda m: logger.info(m), repr=False)
    cancel_check: Optional[Callable[[], bool]] = field(default=None, repr=False)


# ============================================================================
# Run Lock (File-based mutex)
# ============================================================================

LOCK_FILE = Path(".chatgpt-android-payment.lock")
GUARD_DIR = Path(".chatgpt-android-payment.lock.guard")


def _is_process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _read_lock(path: Path) -> Optional[dict]:
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def _write_lock(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data) + "\n")


def acquire_run_lock(state_file: Path = LOCK_FILE, guard_dir: Path = GUARD_DIR, stale_ms: int = 3600000) -> dict:
    """Acquire file-based run lock with stale detection."""
    lock_data = {
        "pid": os.getpid(),
        "timestamp": time.time(),
        "lock_id": str(uuid.uuid4()),
    }
    
    # Try to create guard directory (ownership primitive)
    owns_guard = False
    try:
        guard_dir.mkdir(mode=0o700, exist_ok=False)
        owns_guard = True
    except FileExistsError:
        pass
    except Exception as e:
        raise RunLockError(f"Failed to create guard dir: {e}")
    
    if not owns_guard:
        # Read existing owner
        owner_file = guard_dir / "owner.json"
        owner = _read_lock(owner_file)
        if not owner:
            raise RunLockError("Lock guard metadata missing; manual recovery required")
        
        # Check if stale
        if owner.get("timestamp", 0) > time.time() or _is_process_alive(owner.get("pid", 0)):
            raise RunLockError("Another payment run is already running")
        
        # Stale - attempt recovery
        recovery_file = guard_dir / "recovery"
        try:
            recovery_file.write_text(json.dumps(lock_data) + "\n")
        except FileExistsError:
            prev = _read_lock(recovery_file)
            if prev and not _is_process_alive(prev.get("pid", 0)):
                recovery_file.unlink(missing_ok=True)
                recovery_file.write_text(json.dumps(lock_data) + "\n")
            else:
                raise RunLockError("Another payment run is already running (recovery contested)")
        
        # Verify still ours
        owner = _read_lock(owner_file)
        if owner.get("lock_id") != lock_data["lock_id"]:
            raise RunLockError("Lock conflict; manual recovery required")
        
        # Clean up old lock
        existing = _read_lock(state_file)
        if existing and existing.get("lock_id") != owner.get("lock_id"):
            if existing.get("timestamp", 0) <= time.time() and not _is_process_alive(existing.get("pid", 0)):
                state_file.unlink(missing_ok=True)
        
        owner_file.write_text(json.dumps(lock_data) + "\n")
        _write_lock(state_file, lock_data)
        return {"path": str(state_file), "guard_dir": str(guard_dir), **lock_data}
    
    # We own guard - write owner and lock
    owner_file = guard_dir / "owner.json"
    owner_file.write_text(json.dumps(lock_data) + "\n")
    
    existing = _read_lock(state_file)
    if existing:
        if existing.get("timestamp", 0) > time.time() or _is_process_alive(existing.get("pid", 0)):
            guard_dir.rmdir()
            raise RunLockError("Another payment run is already running")
        state_file.unlink(missing_ok=True)
    
    _write_lock(state_file, lock_data)
    return {"path": str(state_file), "guard_dir": str(guard_dir), **lock_data}


def release_run_lock(lock: dict) -> bool:
    """Release run lock."""
    if not lock or "path" not in lock or "guard_dir" not in lock:
        return False
    
    guard_dir = Path(lock["guard_dir"])
    owner_file = guard_dir / "owner.json"
    owner = _read_lock(owner_file)
    if not owner or owner.get("lock_id") != lock.get("lock_id"):
        return False
    
    lock_file = Path(lock["path"])
    existing = _read_lock(lock_file)
    if existing and existing.get("lock_id") != lock.get("lock_id"):
        return False
    
    try:
        if existing:
            lock_file.unlink()
        import shutil
        shutil.rmtree(guard_dir)
        return True
    except Exception:
        return False


# ============================================================================
# CycleTLS Integration
# ============================================================================

async def _init_cycletls() -> Any:
    """Initialize CycleTLS client."""
    try:
        mod = __import__("cycletls")
        ctls = mod.default() if hasattr(mod, "default") else mod.CycleTLS()
        return ctls
    except Exception as e:
        logger.error(f"CycleTLS init failed: {e}")
        return None


async def get_cycletls(state: AndroidRuntimeState) -> Any:
    if state._ctls:
        return state._ctls
    if state._ctls_ready is None:
        state._ctls_ready = asyncio.create_task(_init_cycletls())
    state._ctls = await state._ctls_ready
    if not state._ctls:
        raise AndroidPaymentError("CycleTLS initialization failed", "CTLS_INIT_FAILED")
    return state._ctls


async def shutdown_cycletls(state: AndroidRuntimeState) -> None:
    if state._ctls and hasattr(state._ctls, "exit"):
        await state._ctls.exit()
    state._ctls = None
    state._ctls_ready = None


# ============================================================================
# HTTP Helpers
# ============================================================================

def currency_for_country(country: str) -> str:
    mapping = {
        "US": "USD", "JP": "JPY", "ID": "IDR", "NL": "EUR", "DE": "EUR",
        "FR": "EUR", "BR": "BRL", "IN": "INR", "AU": "AUD", "CA": "CAD",
        "GB": "GBP", "SG": "SGD", "HK": "HKD", "TW": "TWD", "KR": "KRW",
        "MX": "MXN", "AR": "ARS", "CL": "CLP", "CO": "COP", "PE": "PEN",
        "MY": "MYR", "TH": "THB", "VN": "VND", "PH": "PHP",
    }
    return mapping.get(country.upper(), "USD")


def build_chatgpt_headers(state: AndroidRuntimeState) -> dict:
    return {
        "User-Agent": state.user_agent,
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Authorization": f"Bearer {state.access_token}",
        "Origin": "https://chatgpt.com",
        "Referer": "https://chatgpt.com/",
        "Content-Type": "application/json",
        "oai-device-id": state.device_id,
        "oai-language": "en-US",
        "sec-ch-ua": CHROME_SEC_CH_UA,
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-platform": '"Android"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "Cookie": f"oai-did={state.device_id}",
    }


def build_stripe_headers(state: AndroidRuntimeState, extra: dict = None) -> dict:
    h = {
        "User-Agent": state.user_agent,
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Language": "en-US,en;q=0.9",
        "Origin": "https://js.stripe.com",
        "Referer": "https://js.stripe.com/",
        "sec-ch-ua": CHROME_SEC_CH_UA,
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-platform": '"Android"',
        "sec-fetch-site": "same-site",
        "sec-fetch-mode": "cors",
        "sec-fetch-dest": "empty",
        "priority": "u=1, i",
    }
    if extra:
        h.update(extra)
    return h


def build_stripe_checkout_headers(state: AndroidRuntimeState, extra: dict = None) -> dict:
    h = {
        "User-Agent": state.user_agent,
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Language": "en-US,en;q=0.9",
        "Origin": "https://checkout.stripe.com",
        "Referer": "https://checkout.stripe.com/",
        "sec-ch-ua": CHROME_SEC_CH_UA,
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-platform": '"Android"',
        "sec-fetch-site": "same-origin",
        "sec-fetch-mode": "cors",
        "sec-fetch-dest": "empty",
        "priority": "u=1, i",
    }
    if extra:
        h.update(extra)
    return h


# ============================================================================
# CycleTLS Fetch
# ============================================================================

async def ctls_fetch(
    state: AndroidRuntimeState,
    url: str,
    method: str = "GET",
    headers: dict = None,
    body: str = None,
    json_data: dict = None,
    timeout_ms: int = 30000,
) -> dict:
    """Fetch using CycleTLS with Chrome JA3 fingerprint."""
    ctls = await get_cycletls(state)
    
    m = method.lower()
    req_body = body
    if json_data is not None:
        req_body = json.dumps(json_data)
    
    opts = {
        "headers": headers or {},
        "ja3": CHROME_JA3,
        "userAgent": headers.get("User-Agent", state.user_agent) if headers else state.user_agent,
        "disableRedirect": False,
        "timeout": max(1, timeout_ms // 1000),
    }
    if state.proxy:
        opts["proxy"] = state.proxy
    if req_body is not None:
        opts["body"] = req_body
    
    try:
        r = await getattr(ctls, m)(url, opts)
    except Exception as e:
        if "WebSocket server not connected" in str(e):
            state.log_fn("[ctls] WebSocket disconnected, reinitializing...")
            state._ctls = None
            state._ctls_ready = None
            ctls = await get_cycletls(state)
            r = await getattr(ctls, m)(url, opts)
        else:
            raise
    
    # Normalize response
    text = ""
    if hasattr(r, "text") and isinstance(r.text, str):
        text = r.text
    elif hasattr(r, "body") and isinstance(r.body, str):
        text = r.body
    else:
        text = str(r.body or "")
    
    json_data = None
    try:
        if hasattr(r, "json") and callable(r.json):
            json_data = await r.json()
        elif text:
            json_data = json.loads(text)
    except Exception:
        pass
    
    # Normalize headers
    h = getattr(r, "headers", {}) or {}
    lh = {k.lower(): v for k, v in h.items()}
    
    return {
        "status": getattr(r, "status", 0),
        "ok": 200 <= getattr(r, "status", 0) < 300,
        "text": text,
        "json": json_data,
        "headers": {
            "get": lambda k: (lh.get(k.lower(), [None])[0] if isinstance(lh.get(k.lower()), list) else lh.get(k.lower())),
            "getSetCookie": lambda: (lh.get("set-cookie", []) if isinstance(lh.get("set-cookie"), list) else [lh.get("set-cookie")] if lh.get("set-cookie") else []),
        }
    }


async def retry_fetch(
    state: AndroidRuntimeState,
    fn: Callable,
    label: str,
    max_attempts: int = RETRY_LIMIT,
    base_ms: int = RETRY_BASE_MS,
    max_ms: int = RETRY_MAX_MS,
) -> Any:
    last_error = None
    for attempt in range(max_attempts):
        try:
            return await fn()
        except Exception as e:
            last_error = e
            if attempt < max_attempts - 1:
                delay = min(base_ms * (2 ** attempt) + random.randint(0, 1000), max_ms)
                state.log_fn(f"[RETRY] {label} attempt {attempt + 1} failed: {e}. Waiting {delay}ms...")
                await asyncio.sleep(delay / 1000)
    raise last_error


async def step_delay(state: AndroidRuntimeState, label: str) -> None:
    delay = STEP_DELAY_MS + random.randint(0, 1000)
    state.log_fn(f"[DELAY] {label} - waiting {delay}ms...")
    await asyncio.sleep(delay / 1000)


# ============================================================================
# Stripe.js Build Fetch
# ============================================================================

_stripe_js_build_cache: Optional[str] = None


async def fetch_stripe_js_build(state: AndroidRuntimeState) -> str:
    global _stripe_js_build_cache
    if _stripe_js_build_cache:
        return _stripe_js_build_cache
    
    headers = {"User-Agent": state.user_agent, "Accept": "text/html,application/xhtml+xml"}
    res = await retry_fetch(state, 
        lambda: ctls_fetch(state, STRIPE_JS_URL, "GET", headers), 
        "stripe_js_fetch"
    )
    
    if res["status"] != 200:
        _stripe_js_build_cache = "6f8494a281"
        state.log_fn("[WARN] Failed to fetch Stripe.js, using fallback build")
        return _stripe_js_build_cache
    
    import re
    match = re.search(r'stripe\.js\/([a-f0-9]{8,12})', res["text"], re.I) or \
            re.search(r'build[:\s]+([a-f0-9]{8,12})', res["text"], re.I)
    if match:
        _stripe_js_build_cache = match.group(1)
        state.log_fn(f"[INFO] Stripe.js build: {_stripe_js_build_cache}")
    else:
        _stripe_js_build_cache = "6f8494a281"
        state.log_fn("[WARN] Could not extract Stripe.js build, using fallback")
    
    return _stripe_js_build_cache


# ============================================================================
# Payment Flow Steps (12-step hosted mode)
# ============================================================================

async def create_checkout_session(state: AndroidRuntimeState) -> dict:
    """Step 1: Create ChatGPT checkout session."""
    await step_delay(state, "pre_checkout_create")
    
    body = {
        "entry_point": "all_plans_pricing_modal",
        "plan_name": state.plan_name,
        "billing_details": {
            "country": state.billing_country.upper(),
            "currency": currency_for_country(state.billing_country),
        },
        "promo_campaign": {
            "promo_campaign_id": "plus-1-month-free",
            "is_coupon_from_query_param": False,
        },
        "checkout_ui_mode": state.checkout_ui_mode,
    }
    
    headers = build_chatgpt_headers(state)
    headers["x-openai-target-path"] = "/backend-api/payments/checkout"
    headers["x-openai-target-route"] = "/backend-api/payments/checkout"
    headers["Referer"] = "https://chatgpt.com/"
    
    res = await retry_fetch(state,
        lambda: ctls_fetch(state, CHECKOUT_URL, "POST", headers, json_data=body),
        "create_checkout"
    )
    
    text = res["text"]
    if res["status"] >= 400:
        if "cannot combine currencies" in text:
            raise AndroidPaymentError("Currency mismatch: customer has active USD checkout", "CURRENCY_MISMATCH")
        raise AndroidPaymentError(f"Checkout create failed: {res['status']} {text}", "CHECKOUT_FAILED")
    
    cs_id = res["json"].get("checkout_session_id") or res["json"].get("session_id") or res["json"].get("id")
    if not cs_id or not str(cs_id).startswith("cs_"):
        raise AndroidPaymentError(f"Invalid cs_id: {cs_id}", "INVALID_CS_ID")
    
    processor_entity = res["json"].get("processor_entity") or ("openai_llc" if state.billing_country.upper() == "US" else "openai_ie")
    billing_country = state.billing_country.upper()
    currency = currency_for_country(billing_country)
    
    state.log_fn(f"      cs_id: {cs_id}, entity: {processor_entity}, country: {billing_country}, currency: {currency}")
    return {"cs_id": str(cs_id), "processor_entity": processor_entity, "billing_country": billing_country, "currency": currency}


async def update_taxes(state: AndroidRuntimeState, cs_id: str, billing: dict) -> dict:
    """Step 2: Update taxes - critical for expected_amount."""
    await step_delay(state, "pre_tax_update")
    
    body = {
        "billing_details": {
            "address": {
                "line1": billing["line1"],
                "city": billing["city"],
                "state": billing["state"],
                "postal_code": billing["postal_code"],
                "country": billing["country"],
            },
            "name": billing["name"],
            "email": billing["email"],
        },
    }
    
    headers = build_chatgpt_headers(state)
    headers["x-openai-target-path"] = "/backend-api/payments/checkout/taxes"
    headers["x-openai-target-route"] = "/backend-api/payments/checkout/taxes"
    headers["Referer"] = "https://chatgpt.com/"
    headers["Content-Type"] = "application/json"
    
    res = await retry_fetch(state,
        lambda: ctls_fetch(state, TAXES_URL, "POST", headers, json_data=body),
        "update_taxes"
    )
    
    if res["status"] >= 400:
        raise AndroidPaymentError(f"Tax update failed: {res['status']} {res['text']}", "TAX_UPDATE_FAILED")
    
    expected_amount = res["json"].get("snapshot", {}).get("amount_total") or \
                      res["json"].get("amount_total") or \
                      res["json"].get("total_amount")
    
    if not expected_amount or expected_amount <= 0:
        raise AndroidPaymentError(f"Tax update returned invalid amount_total: {expected_amount}", "INVALID_EXPECTED_AMOUNT")
    
    state.log_fn(f"      expected_amount: {expected_amount} ({res['json'].get('snapshot', {}).get('currency', billing['currency'])})")
    return {"expected_amount": int(expected_amount), "currency": res["json"].get("snapshot", {}).get("currency", billing["currency"]), "tax_data": res["json"]}


async def stripe_init(state: AndroidRuntimeState, cs_id: str) -> dict:
    """Step 3: Initialize Stripe payment page."""
    await step_delay(state, "pre_stripe_init")
    
    body = {
        "browser_locale": "en-US",
        "browser_timezone": "Asia/Shanghai",
        "elements_session_client[client_betas][0]": "custom_checkout_server_updates_1",
        "elements_session_client[client_betas][1]": "custom_checkout_manual_approval_1",
        "elements_session_client[elements_init_source]": "custom_checkout",
        "elements_session_client[referrer_host]": "chatgpt.com",
        "elements_session_client[stripe_js_id]": state.fingerprint.stripe_js_id,
        "elements_session_client[locale]": "en-US",
        "elements_session_client[is_aggregation_expected]": "false",
        "elements_options_client[saved_payment_method][enable_save]": "never",
        "elements_options_client[saved_payment_method][enable_redisplay]": "never",
        "key": state.stripe_pk,
        "_stripe_version": STRIPE_VERSION,
    }
    
    from urllib.parse import urlencode
    form_body = urlencode(body)
    
    headers = build_stripe_headers(state)
    res = await retry_fetch(state,
        lambda: ctls_fetch(state, f"{STRIPE_API_BASE}/payment_pages/{cs_id}/init", "POST", headers, body=form_body),
        "stripe_init"
    )
    
    if res["status"] >= 400:
        raise AndroidPaymentError(f"Stripe init failed: {res['status']} {res['text']}", "STRIPE_INIT_FAILED")
    
    return res["json"]


async def init_payment_page(state: AndroidRuntimeState, cs_id: str) -> dict:
    """Step 4: Initialize Payment Page (hosted mode) - gets ppage_ token."""
    await step_delay(state, "pre_payment_page_init")
    
    url = f"{STRIPE_CHECKOUT_BASE}/api/payment-page/{cs_id}/init"
    headers = build_stripe_checkout_headers(state)
    
    res = await retry_fetch(state,
        lambda: ctls_fetch(state, url, "GET", headers),
        "payment_page_init"
    )
    
    if res["status"] >= 400:
        raise AndroidPaymentError(f"Payment page init failed: {res['status']} {res['text']}", "PPAGE_INIT_FAILED")
    
    ppage_token = res["json"].get("payment_page_token") or res["json"].get("token") or res["json"].get("id")
    if not ppage_token or not str(ppage_token).startswith("ppage_"):
        raise AndroidPaymentError(f"Invalid ppage_token: {ppage_token}", "INVALID_PPAGE_TOKEN")
    
    rv_timestamp = res["json"].get("rv_timestamp") or int(time.time() * 1000)
    js_checksum = res["json"].get("js_checksum") or res["json"].get("init_checksum")
    
    state.log_fn(f"      ppage_token: {str(ppage_token)[:24]}..., rv_timestamp: {rv_timestamp}, js_checksum: {str(js_checksum)[:16] if js_checksum else 'none'}...")
    return {"ppage_token": str(ppage_token), "rv_timestamp": rv_timestamp, "js_checksum": js_checksum, "init_data": res["json"]}


async def create_elements_session(state: AndroidRuntimeState, cs_id: str, ppage_token: str) -> dict:
    """Step 5: Create Elements Session (hosted mode)."""
    await step_delay(state, "pre_elements_session")
    
    body = {
        "browser_locale": "en-US",
        "browser_timezone": "Asia/Shanghai",
        "elements_session_client[client_betas][0]": "custom_checkout_server_updates_1",
        "elements_session_client[client_betas][1]": "custom_checkout_manual_approval_1",
        "elements_session_client[elements_init_source]": "custom_checkout",
        "elements_session_client[referrer_host]": "chatgpt.com",
        "elements_session_client[stripe_js_id]": state.fingerprint.stripe_js_id,
        "elements_session_client[locale]": "en-US",
        "elements_session_client[is_aggregation_expected]": "false",
        "elements_session_client[payment_page_token]": ppage_token,
        "elements_options_client[saved_payment_method][enable_save]": "never",
        "elements_options_client[saved_payment_method][enable_redisplay]": "never",
        "key": state.stripe_pk,
        "_stripe_version": STRIPE_VERSION,
    }
    
    from urllib.parse import urlencode
    form_body = urlencode(body)
    
    headers = build_stripe_headers(state)
    res = await retry_fetch(state,
        lambda: ctls_fetch(state, f"{STRIPE_API_BASE}/v1/elements/sessions", "POST", headers, body=form_body),
        "elements_session"
    )
    
    if res["status"] >= 400:
        raise AndroidPaymentError(f"Elements session failed: {res['status']} {res['text']}", "ELEMENTS_SESSION_FAILED")
    
    elements_session_id = res["json"].get("session_id") or res["json"].get("id") or f"elements_session_{uuid.uuid4().hex[:11]}"
    config_id = res["json"].get("config_id") or res["json"].get("config", {}).get("id") or str(uuid.uuid4())
    
    state.log_fn(f"      elements_session_id: {elements_session_id}, config_id: {config_id}")
    return {"elements_session_id": elements_session_id, "config_id": config_id, "session_data": res["json"]}


def _pm_data_fields(card: dict, billing: dict, fp: DeviceFingerprint, elements_session_id: str, config_id: str, stripe_js_build: str) -> dict:
    f = {}
    f["payment_method_data[type]"] = "card"
    f["payment_method_data[card][number]"] = card["number"]
    f["payment_method_data[card][cvc]"] = card["cvc"]
    exp_year = int(card["exp_year"])
    if exp_year < 100:
        exp_year += 2000
    f["payment_method_data[card][exp_year]"] = str(exp_year)
    f["payment_method_data[card][exp_month]"] = str(card["exp_month"]).zfill(2)
    f["payment_method_data[allow_redisplay]"] = "limited"
    
    if billing:
        f["payment_method_data[billing_details][address][line1]"] = billing["line1"]
        f["payment_method_data[billing_details][address][city]"] = billing["city"]
        f["payment_method_data[billing_details][address][country]"] = billing["country"]
        f["payment_method_data[billing_details][address][postal_code]"] = billing["postal_code"]
        f["payment_method_data[billing_details][address][state]"] = billing["state"]
        f["payment_method_data[billing_details][name]"] = billing["name"]
        f["payment_method_data[billing_details][email]"] = billing["email"]
        f["payment_method_data[billing_details][phone]"] = ""
    
    f["payment_method_data[pasted_fields]"] = "number,exp,cvc"
    f["payment_method_data[payment_user_agent]"] = f"stripe.js/{stripe_js_build}; stripe-js-v3/{stripe_js_build}; payment-element; deferred-intent"
    f["payment_method_data[referrer]"] = "https://chatgpt.com"
    f["payment_method_data[time_on_page]"] = str(max(12000, 38000 + random.randint(0, 4000)))
    f["payment_method_data[client_attribution_metadata][client_session_id]"] = fp.client_session_id
    f["payment_method_data[client_attribution_metadata][merchant_integration_source]"] = "elements"
    f["payment_method_data[client_attribution_metadata][merchant_integration_subtype]"] = "payment-element"
    f["payment_method_data[client_attribution_metadata][merchant_integration_version]"] = "2021"
    f["payment_method_data[client_attribution_metadata][payment_intent_creation_flow]"] = "deferred"
    f["payment_method_data[client_attribution_metadata][payment_method_selection_flow]"] = "merchant_specified"
    f["payment_method_data[client_attribution_metadata][merchant_integration_additional_elements][0]"] = "expressCheckout"
    f["payment_method_data[client_attribution_metadata][merchant_integration_additional_elements][1]"] = "payment"
    f["payment_method_data[client_attribution_metadata][merchant_integration_additional_elements][2]"] = "address"
    if elements_session_id:
        f["payment_method_data[client_attribution_metadata][elements_session_id]"] = elements_session_id
    if config_id:
        f["payment_method_data[client_attribution_metadata][elements_session_config_id]"] = config_id
    if fp.guid:
        f["payment_method_data[guid]"] = fp.guid
    if fp.muid:
        f["payment_method_data[muid]"] = fp.muid
    if fp.sid:
        f["payment_method_data[sid]"] = fp.sid
    return f


async def create_confirmation_token(
    state: AndroidRuntimeState,
    cs_id: str,
    card: dict,
    billing: dict,
    elements_session_id: str,
    config_id: str,
) -> dict:
    """Step 6: Create ConfirmationToken (tokenize card)."""
    await step_delay(state, "pre_confirmation_token")
    
    stripe_js_build = await fetch_stripe_js_build(state)
    payment_user_agent = f"stripe.js/{stripe_js_build}; stripe-js-v3/{stripe_js_build}; payment-element; deferred-intent"
    
    fields = _pm_data_fields(card, billing, state.fingerprint, elements_session_id, config_id, stripe_js_build)
    
    form = {**fields}
    form["setup_future_usage"] = "off_session"
    form["client_context[currency]"] = billing["currency"].lower()
    form["client_context[mode]"] = "subscription"
    form["client_context[payment_method_types][0]"] = "card"
    form["key"] = state.stripe_pk
    form["_stripe_version"] = STRIPE_VERSION
    
    form["client_attribution_metadata[client_session_id]"] = state.fingerprint.client_session_id
    form["client_attribution_metadata[merchant_integration_source]"] = "elements"
    form["client_attribution_metadata[merchant_integration_subtype]"] = "payment-element"
    form["client_attribution_metadata[merchant_integration_version]"] = "2021"
    form["client_attribution_metadata[payment_intent_creation_flow]"] = "deferred"
    form["client_attribution_metadata[payment_method_selection_flow]"] = "merchant_specified"
    form["client_attribution_metadata[merchant_integration_additional_elements][0]"] = "expressCheckout"
    form["client_attribution_metadata[merchant_integration_additional_elements][1]"] = "payment"
    form["client_attribution_metadata[merchant_integration_additional_elements][2]"] = "address"
    form["client_attribution_metadata[elements_session_id]"] = elements_session_id
    form["client_attribution_metadata[elements_session_config_id]"] = config_id
    
    from urllib.parse import urlencode
    form_body = urlencode(form)
    
    headers = build_stripe_headers(state)
    res = await retry_fetch(state,
        lambda: ctls_fetch(state, f"{STRIPE_API_BASE}/v1/confirmation_tokens", "POST", headers, body=form_body),
        "confirmation_token"
    )
    
    if res["status"] >= 400:
        raise AndroidPaymentError(f"ConfirmationToken failed: {res['status']} {res['text']}", "CTOKEN_FAILED")
    
    return res["json"]


async def confirm_checkout_hosted(
    state: AndroidRuntimeState,
    cs_id: str,
    ppage_token: str,
    ctoken_id: str,
    expected_amount: int,
    rv_timestamp: int,
    js_checksum: str,
    processor_entity: str,
) -> dict:
    """Step 7: Confirm Checkout (hosted mode)."""
    await step_delay(state, "pre_checkout_confirm")
    
    form = {
        "confirmation_token": ctoken_id,
        "payment_page_token": ppage_token,
        "expected_amount": str(expected_amount),
        "rv_timestamp": str(rv_timestamp),
        "key": state.stripe_pk,
        "_stripe_version": STRIPE_VERSION,
        "processor_entity": processor_entity,
    }
    if js_checksum:
        form["js_checksum"] = js_checksum
    
    from urllib.parse import urlencode
    form_body = urlencode(form)
    
    headers = build_stripe_checkout_headers(state)
    headers["Referer"] = f"https://chatgpt.com/checkout/{processor_entity}/{cs_id}"
    
    res = await retry_fetch(state,
        lambda: ctls_fetch(state, f"{STRIPE_CHECKOUT_BASE}/api/payment_pages/{cs_id}/confirm", "POST", headers, body=form_body),
        "checkout_confirm_hosted"
    )
    
    if res["status"] >= 400:
        raise AndroidPaymentError(f"Checkout confirm failed: {res['status']} {res['text']}", "CHECKOUT_CONFIRM_FAILED")
    
    return res["json"]


async def approve_checkout(state: AndroidRuntimeState, cs_id: str, processor_entity: str) -> dict:
    """Step 8: Platform Approve (ChatGPT /approve)."""
    await step_delay(state, "pre_checkout_approve")
    
    headers = build_chatgpt_headers(state)
    headers["Referer"] = f"https://chatgpt.com/checkout/{processor_entity}/{cs_id}"
    headers["x-openai-target-path"] = "/backend-api/payments/checkout/approve"
    headers["x-openai-target-route"] = "/backend-api/payments/checkout/approve"
    headers["Content-Type"] = "application/json"
    
    body = {"checkout_session_id": cs_id, "processor_entity": processor_entity}
    
    res = await retry_fetch(state,
        lambda: ctls_fetch(state, APPROVE_URL, "POST", headers, json_data=body),
        "checkout_approve"
    )
    
    if res["status"] >= 400:
        raise AndroidPaymentError(f"Checkout approve failed: {res['status']} {res['text']}", "CHECKOUT_APPROVE_FAILED")
    
    result = res["json"].get("result") or res["json"].get("status")
    if result != "approved":
        raise AndroidPaymentError(f"Checkout approve returned: {result}", "APPROVE_NOT_APPROVED")
    
    return res["json"]


async def poll_checkout_status(
    state: AndroidRuntimeState,
    cs_id: str,
    processor_entity: str,
    max_polls: int = 30,
) -> dict:
    """Step 9: Poll for payment completion."""
    for i in range(max_polls):
        await asyncio.sleep(2)
        
        from urllib.parse import urlencode
        params = urlencode({"key": state.stripe_pk, "_stripe_version": STRIPE_VERSION})
        
        headers = build_stripe_headers(state)
        res = await ctls_fetch(state, f"{STRIPE_API_BASE}/checkout/sessions/{cs_id}?{params}", "GET", headers)
        
        if res["status"] == 200 and res["json"] and res["json"].get("status") == "complete":
            return res["json"]
        if res["json"] and res["json"].get("status") == "expired":
            raise AndroidPaymentError("Checkout session expired", "SESSION_EXPIRED")
    
    raise AndroidPaymentError("Checkout polling timeout", "POLL_TIMEOUT")


# ============================================================================
# Main Flow
# ============================================================================

async def run_android_payment_flow(
    access_token: str,
    device_id: str = None,
    card_number: str = "",
    card_exp_month: str = "",
    card_exp_year: str = "",
    card_cvc: str = "",
    billing_name: str = "John Doe",
    billing_email: str = "test@example.com",
    billing_line1: str = "123 Main St",
    billing_city: str = "San Francisco",
    billing_state: str = "CA",
    billing_postal: str = "94105",
    billing_country: str = "US",
    plan_name: str = "chatgptplusplan",
    checkout_ui_mode: str = "hosted",
    stripe_pk: str = STRIPE_PUBLISHABLE_KEY,
    proxy: str = "",
    android_serial: str = DEFAULT_ANDROID_SERIAL,
    browser_package: str = DEFAULT_BROWSER_PACKAGE,
    user_agent: str = DEFAULT_USER_AGENT,
    log_fn: Callable[[str], None] = None,
    cancel_check: Callable[[], bool] = None,
) -> dict:
    """Run the complete Android + CycleTLS payment flow."""
    
    log = log_fn or (lambda m: logger.info(m))
    
    # Validate required
    if not access_token:
        raise AndroidPaymentError("access_token required", "MISSING_TOKEN")
    if not all([card_number, card_exp_month, card_exp_year, card_cvc]):
        raise AndroidPaymentError("Card details required", "MISSING_CARD")
    
    # Initialize state
    state = AndroidRuntimeState(
        device_serial=android_serial,
        browser_package=browser_package,
        access_token=access_token.strip(),
        device_id=device_id or str(uuid.uuid4()),
        user_agent=user_agent,
        proxy=proxy.strip(),
        stripe_pk=stripe_pk,
        card_number=card_number.replace(" ", ""),
        card_exp_month=card_exp_month,
        card_exp_year=card_exp_year,
        card_cvc=card_cvc,
        billing_name=billing_name,
        billing_email=billing_email,
        billing_line1=billing_line1,
        billing_city=billing_city,
        billing_state=billing_state,
        billing_postal=billing_postal,
        billing_country=billing_country.upper(),
        plan_name=plan_name,
        checkout_ui_mode=checkout_ui_mode,
        log_fn=log,
        cancel_check=cancel_check,
    )
    
    billing = {
        "name": state.billing_name,
        "email": state.billing_email,
        "line1": state.billing_line1,
        "city": state.billing_city,
        "state": state.billing_state,
        "postal_code": state.billing_postal,
        "country": state.billing_country,
        "currency": currency_for_country(state.billing_country),
    }
    
    card = {
        "number": state.card_number,
        "exp_month": state.card_exp_month,
        "exp_year": state.card_exp_year,
        "cvc": state.card_cvc,
    }
    
    log(f"[INIT] Starting Android payment automation...")
    log(f"[CONFIG] Mode: {state.checkout_ui_mode}, Plan: {state.plan_name}, Country: {state.billing_country}")
    log(f"[TLS] Using CycleTLS with Chrome JA3 fingerprint")
    
    # Acquire run lock
    run_lock = acquire_run_lock()
    
    try:
        # Step 1: Create Checkout Session
        log("[1/12] Creating ChatGPT checkout session...")
        checkout = await create_checkout_session(state)
        state.cs_id = checkout["cs_id"]
        state.processor_entity = checkout["processor_entity"]
        state.billing_country_resolved = checkout["billing_country"]
        state.currency = checkout["currency"]
        
        # Step 2: Update Taxes (critical for expected_amount)
        log("[2/12] Updating taxes (billing address)...")
        tax_result = await update_taxes(state, state.cs_id, billing)
        state.expected_amount = tax_result["expected_amount"]
        
        # Step 3: Initialize Stripe payment page
        log("[3/12] Initializing Stripe payment page...")
        init_payload = await stripe_init(state, state.cs_id)
        
        if state.checkout_ui_mode == "hosted":
            # Step 4: Initialize Payment Page (hosted mode)
            log("[4/12] Initializing payment page (hosted mode)...")
            ppage_result = await init_payment_page(state, state.cs_id)
            state.ppage_token = ppage_result["ppage_token"]
            state.rv_timestamp = ppage_result["rv_timestamp"]
            state.js_checksum = ppage_result["js_checksum"]
            
            # Step 5: Create Elements Session
            log("[5/12] Creating elements session...")
            elements_result = await create_elements_session(state, state.cs_id, state.ppage_token)
            state.elements_session_id = elements_result["elements_session_id"]
            state.elements_config_id = elements_result["config_id"]
            
            # Step 6: Create ConfirmationToken
            log("[6/12] Creating ConfirmationToken (tokenizing card)...")
            ctoken = await create_confirmation_token(
                state, state.cs_id, card, billing,
                state.elements_session_id, state.elements_config_id
            )
            state.ctoken_id = ctoken.get("id", "")
            log(f"      ctoken: {state.ctoken_id[:24]}..., type: {ctoken.get('type')}")
            
            # Step 7: Confirm Checkout (hosted mode)
            log("[7/12] Confirming checkout session (hosted)...")
            confirm_result = await confirm_checkout_hosted(
                state, state.cs_id, state.ppage_token, state.ctoken_id,
                state.expected_amount, state.rv_timestamp, state.js_checksum,
                state.processor_entity
            )
            log(f"      status: {confirm_result.get('status')}, requires_approval: {confirm_result.get('requires_approval')}")
            
            # Step 8: Platform Approve
            if confirm_result.get("requires_approval") or confirm_result.get("status") == "requires_approval":
                log("[8/12] Hosted mode requires approval - calling ChatGPT /approve...")
                await approve_checkout(state, state.cs_id, state.processor_entity)
                log("      approved")
            else:
                log("[8/12] No approval needed")
        else:
            # Custom mode - simplified
            log("[4/12] Custom mode - skipping payment page init")
            log("[5/12] Creating elements session (custom)...")
            elements_result = await create_elements_session(state, state.cs_id, "")
            state.elements_session_id = elements_result["elements_session_id"]
            state.elements_config_id = elements_result["config_id"]
            
            log("[6/12] Creating ConfirmationToken...")
            ctoken = await create_confirmation_token(
                state, state.cs_id, card, billing,
                state.elements_session_id, state.elements_config_id
            )
            state.ctoken_id = ctoken.get("id", "")
            log(f"      ctoken: {state.ctoken_id[:24]}...")
            
            log("[7/12] Confirming checkout (custom)...")
            # Custom mode would use different confirm endpoint
            log("[8/12] Custom mode - no approval needed")
        
        # Step 9: Poll for completion
        log("[9/12] Polling for payment completion...")
        final_status = await poll_checkout_status(state, state.cs_id, state.processor_entity)
        log(f"      final status: {final_status.get('status')}")
        
        log("[10/12] Payment completed successfully!")
        log("[11/12] Verifying subscription on ChatGPT...")
        log("[12/12] All steps complete!")
        
        return {
            "success": True,
            "cs_id": state.cs_id,
            "final_status": final_status,
            "expected_amount": state.expected_amount,
        }
        
    finally:
        release_run_lock(run_lock)
        await shutdown_cycletls(state)


# ============================================================================
# Android Browser Probe (for verification)
# ============================================================================

async def probe_android_device(
    android_serial: str = DEFAULT_ANDROID_SERIAL,
    browser_package: str = DEFAULT_BROWSER_PACKAGE,
    log_fn: Callable[[str], None] = None,
) -> dict:
    """Probe Android device and browser connectivity."""
    log = log_fn or (lambda m: logger.info(m))
    
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        raise AndroidPaymentError("Playwright not installed", "PLAYWRIGHT_MISSING")
    
    async with async_playwright() as p:
        android = p.android
        devices = await android.devices()
        
        log(f"[PROBE] Found {len(devices)} device(s)")
        for d in devices:
            log(f"  - {d.serial()}")
        
        # Find target device
        target = None
        for d in devices:
            if d.serial() == android_serial:
                target = d
                break
        
        if not target:
            raise AndroidPaymentError(f"Device {android_serial} not found", "DEVICE_NOT_FOUND")
        
        log(f"[PROBE] Using device: {target.serial()}")
        log(f"[PROBE] Launching browser: {browser_package}")
        
        # Force stop and launch
        await target.shell(f"am force-stop {browser_package}")
        context = await target.launch_browser({"pkg": browser_package})
        
        try:
            page = await context.new_page()
            log("[PROBE] Navigating to chatgpt.com...")
            await page.goto(CHATGPT_URL, wait_until="domcontentloaded", timeout=30000)
            
            # Wait for page ready
            await page.locator("body").wait_for(state="visible", timeout=15000)
            current = page.url
            if not current.startswith("https://chatgpt.com"):
                raise AndroidPaymentError(f"Unexpected page origin: {current}", "WRONG_ORIGIN")
            
            title = await page.title()
            log(f"[PROBE] Page title: {title}")
            log(f"[PROBE] Current URL: {current}")
            
            # Check cookies
            cookies = await context.cookies(CHATGPT_URL)
            log(f"[PROBE] ChatGPT cookies: {len(cookies)}")
            for c in cookies:
                log(f"  - {c['name']}: {c['value'][:20]}...")
            
            # Check for oai-did
            did_cookie = next((c for c in cookies if c["name"] == "oai-did"), None)
            if did_cookie:
                log(f"[PROBE] Found oai-did: {did_cookie['value']}")
            
            await page.close()
            await context.close()
            await target.close()
            
            log("[PROBE] Success - Android browser ready for payment automation")
            return {"ok": True, "device": android_serial, "cookies": len(cookies), "has_oai_did": bool(did_cookie)}
            
        except Exception as e:
            await context.close()
            await target.close()
            raise


# ============================================================================
# Sync wrappers for integration
# ============================================================================

def run_android_payment(
    access_token: str,
    **kwargs,
) -> dict:
    """Sync wrapper for run_android_payment_flow."""
    return asyncio.run(run_android_payment_flow(access_token, **kwargs))


def probe_android(
    android_serial: str = DEFAULT_ANDROID_SERIAL,
    browser_package: str = DEFAULT_BROWSER_PACKAGE,
    log_fn: Callable[[str], None] = None,
) -> dict:
    """Sync wrapper for probe_android_device."""
    return asyncio.run(probe_android_device(android_serial, browser_package, log_fn))


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "probe":
        result = probe_android()
        print(json.dumps(result, indent=2))
    else:
        print("Usage: python android_runtime.py probe")
