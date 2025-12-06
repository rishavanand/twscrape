import asyncio
import imaplib
import time
import random
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import bs4
import httpx
import pyotp
from curl_cffi import requests as curl_requests
from httpx import AsyncClient, Response
from x_client_transaction import ClientTransaction
from x_client_transaction.utils import generate_headers, get_ondemand_file_url

from .account import Account, TOKEN
from .imap import imap_get_email_code, imap_login
from .logger import logger
from .utils import utc


def _human_delay(min_sec: float = 0.5, max_sec: float = 1.5):
    """Add a random delay to simulate human behavior."""
    time.sleep(random.uniform(min_sec, max_sec))


async def _browser_login(acc: Account, cfg: "LoginConfig") -> Account:
    """Login using a real browser via Playwright - manual mode for anti-detection."""
    from playwright.async_api import async_playwright

    logger.info(f"Starting browser-based login for {acc.username}")
    logger.info("MANUAL LOGIN MODE: Please log in manually in the browser window that opens.")

    async with async_playwright() as p:
        # Use the system's Chrome/Chromium to avoid detection
        browser = await p.chromium.launch(
            headless=False,
            args=[
                "--disable-blink-features=AutomationControlled",
            ]
        )

        context = await browser.new_context(
            viewport={"width": 1280, "height": 720},
            locale="en-US",
        )
        page = await context.new_page()

        try:
            # Navigate to Twitter login
            logger.debug("Navigating to Twitter login page")
            await page.goto("https://x.com/i/flow/login", wait_until="load", timeout=60000)

            # Prompt user to log in manually
            print("\n" + "=" * 60)
            print("MANUAL LOGIN REQUIRED")
            print("=" * 60)
            print(f"Please log in to Twitter as: {acc.username}")
            print("The browser window should be open.")
            print("\nWaiting for you to complete login (will detect when you reach home page)...")
            print("=" * 60 + "\n")

            # Wait for user to complete login - detect when they reach home page
            # This will wait up to 5 minutes for manual login
            try:
                await page.wait_for_url("**/home**", timeout=300000)
                logger.info("Detected successful login - reached home page")
            except Exception:
                # Check if we got logged in but ended up somewhere else
                current_url = page.url
                if "x.com" in current_url and "login" not in current_url:
                    logger.info(f"Login appears successful - current URL: {current_url}")
                else:
                    raise ValueError(f"Login did not complete. Current URL: {current_url}")

            # Wait a moment for page to stabilize
            await asyncio.sleep(2)

            # Extract cookies
            cookies = await context.cookies()
            logger.debug(f"Got {len(cookies)} cookies from browser")

            # Convert to dict format
            cookies_dict = {}
            headers_dict = {}

            for cookie in cookies:
                cookies_dict[cookie["name"]] = cookie["value"]
                if cookie["name"] == "ct0":
                    headers_dict["x-csrf-token"] = cookie["value"]

            if "ct0" not in cookies_dict:
                # Take a screenshot for debugging
                await page.screenshot(path="login_debug.png")
                raise ValueError("Login failed - ct0 cookie not found. Check login_debug.png")

            # Set account as active with extracted cookies
            acc.active = True
            acc.cookies = cookies_dict
            acc.headers = {
                "authorization": TOKEN,
                "x-csrf-token": cookies_dict.get("ct0", ""),
                "x-twitter-auth-type": "OAuth2Session",
                "x-twitter-active-user": "yes",
                "x-twitter-client-language": "en",
            }

            logger.info(f"Browser login successful for {acc.username}")
            return acc

        except Exception as e:
            logger.error(f"Browser login failed: {e}")
            # Take screenshot for debugging
            try:
                await page.screenshot(path="login_error.png")
                logger.error("Screenshot saved to login_error.png")
            except Exception:
                pass
            raise

        finally:
            await browser.close()

# Thread pool for running curl_cffi synchronously
_executor = ThreadPoolExecutor(max_workers=4)

# Modern Chrome user agent - must match the impersonate version for TLS consistency
# Using Chrome 131 to match curl_cffi's chrome131 impersonation
CHROME_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

LOGIN_URL = "https://api.x.com/1.1/onboarding/task.json"


@dataclass
class LoginConfig:
    email_first: bool = False
    manual: bool = False


@dataclass
class TaskCtx:
    client: AsyncClient
    acc: Account
    cfg: LoginConfig
    prev: Any
    imap: None | imaplib.IMAP4_SSL


async def get_guest_token(client: AsyncClient):
    rep = await client.post("https://api.x.com/1.1/guest/activate.json")
    rep.raise_for_status()
    return rep.json()["guest_token"]


async def login_initiate(client: AsyncClient) -> Response:
    payload = {
        "input_flow_data": {
            "flow_context": {"debug_overrides": {}, "start_location": {"location": "unknown"}}
        },
        "subtask_versions": {},
    }

    rep = await client.post(LOGIN_URL, params={"flow_name": "login"}, json=payload)
    rep.raise_for_status()
    return rep


async def login_alternate_identifier(ctx: TaskCtx, *, username: str) -> Response:
    payload = {
        "flow_token": ctx.prev["flow_token"],
        "subtask_inputs": [
            {
                "subtask_id": "LoginEnterAlternateIdentifierSubtask",
                "enter_text": {"text": username, "link": "next_link"},
            }
        ],
    }

    rep = await ctx.client.post(LOGIN_URL, json=payload)
    rep.raise_for_status()
    return rep


async def login_instrumentation(ctx: TaskCtx) -> Response:
    payload = {
        "flow_token": ctx.prev["flow_token"],
        "subtask_inputs": [
            {
                "subtask_id": "LoginJsInstrumentationSubtask",
                "js_instrumentation": {"response": "{}", "link": "next_link"},
            }
        ],
    }

    rep = await ctx.client.post(LOGIN_URL, json=payload)
    rep.raise_for_status()
    return rep


async def login_enter_username(ctx: TaskCtx) -> Response:
    payload = {
        "flow_token": ctx.prev["flow_token"],
        "subtask_inputs": [
            {
                "subtask_id": "LoginEnterUserIdentifierSSO",
                "settings_list": {
                    "setting_responses": [
                        {
                            "key": "user_identifier",
                            "response_data": {"text_data": {"result": ctx.acc.username}},
                        }
                    ],
                    "link": "next_link",
                },
            }
        ],
    }

    rep = await ctx.client.post(LOGIN_URL, json=payload)
    rep.raise_for_status()
    return rep


async def login_enter_password(ctx: TaskCtx) -> Response:
    payload = {
        "flow_token": ctx.prev["flow_token"],
        "subtask_inputs": [
            {
                "subtask_id": "LoginEnterPassword",
                "enter_password": {"password": ctx.acc.password, "link": "next_link"},
            }
        ],
    }

    rep = await ctx.client.post(LOGIN_URL, json=payload)
    rep.raise_for_status()
    return rep


async def login_two_factor_auth_challenge(ctx: TaskCtx) -> Response:
    if ctx.acc.mfa_code is None:
        raise ValueError("MFA code is required")

    totp = pyotp.TOTP(ctx.acc.mfa_code)
    payload = {
        "flow_token": ctx.prev["flow_token"],
        "subtask_inputs": [
            {
                "subtask_id": "LoginTwoFactorAuthChallenge",
                "enter_text": {"text": totp.now(), "link": "next_link"},
            }
        ],
    }

    rep = await ctx.client.post(LOGIN_URL, json=payload)
    rep.raise_for_status()
    return rep


async def login_duplication_check(ctx: TaskCtx) -> Response:
    payload = {
        "flow_token": ctx.prev["flow_token"],
        "subtask_inputs": [
            {
                "subtask_id": "AccountDuplicationCheck",
                "check_logged_in_account": {"link": "AccountDuplicationCheck_false"},
            }
        ],
    }

    rep = await ctx.client.post(LOGIN_URL, json=payload)
    rep.raise_for_status()
    return rep


async def login_confirm_email(ctx: TaskCtx) -> Response:
    payload = {
        "flow_token": ctx.prev["flow_token"],
        "subtask_inputs": [
            {
                "subtask_id": "LoginAcid",
                "enter_text": {"text": ctx.acc.email, "link": "next_link"},
            }
        ],
    }

    rep = await ctx.client.post(LOGIN_URL, json=payload)
    rep.raise_for_status()
    return rep


async def login_confirm_email_code(ctx: TaskCtx):
    if ctx.cfg.manual:
        print(f"Enter email code for {ctx.acc.username} / {ctx.acc.email}")
        value = input("Code: ")
        value = value.strip()
    else:
        if not ctx.imap:
            ctx.imap = await imap_login(ctx.acc.email, ctx.acc.email_password)

        now_time = utc.now() - timedelta(seconds=30)
        value = await imap_get_email_code(ctx.imap, ctx.acc.email, now_time)

    payload = {
        "flow_token": ctx.prev["flow_token"],
        "subtask_inputs": [
            {
                "subtask_id": "LoginAcid",
                "enter_text": {"text": value, "link": "next_link"},
            }
        ],
    }

    rep = await ctx.client.post(LOGIN_URL, json=payload)
    rep.raise_for_status()
    return rep


async def login_success(ctx: TaskCtx) -> Response:
    payload = {
        "flow_token": ctx.prev["flow_token"],
        "subtask_inputs": [],
    }

    rep = await ctx.client.post(LOGIN_URL, json=payload)
    rep.raise_for_status()
    return rep


async def next_login_task(ctx: TaskCtx, rep: Response):
    ct0 = ctx.client.cookies.get("ct0", None)
    if ct0:
        ctx.client.headers["x-csrf-token"] = ct0
        ctx.client.headers["x-twitter-auth-type"] = "OAuth2Session"

    ctx.prev = rep.json()
    assert "flow_token" in ctx.prev, f"flow_token not in {rep.text}"

    for x in ctx.prev["subtasks"]:
        task_id = x["subtask_id"]

        try:
            if task_id == "LoginSuccessSubtask":
                return await login_success(ctx)
            if task_id == "LoginAcid":
                is_code = x["enter_text"]["hint_text"].lower() == "confirmation code"
                fn = login_confirm_email_code if is_code else login_confirm_email
                return await fn(ctx)
            if task_id == "AccountDuplicationCheck":
                return await login_duplication_check(ctx)
            if task_id == "LoginEnterPassword":
                return await login_enter_password(ctx)
            if task_id == "LoginTwoFactorAuthChallenge":
                return await login_two_factor_auth_challenge(ctx)
            if task_id == "LoginEnterUserIdentifierSSO":
                return await login_enter_username(ctx)
            if task_id == "LoginJsInstrumentationSubtask":
                return await login_instrumentation(ctx)
            if task_id == "LoginEnterAlternateIdentifierSubtask":
                return await login_alternate_identifier(ctx, username=ctx.acc.username)
        except Exception as e:
            ctx.acc.error_msg = f"login_step={task_id} err={e}"
            raise e

    return None

def _sync_gen_x_transaction_id() -> str:
    """Synchronous version using curl_cffi to bypass Cloudflare."""
    session = curl_requests.Session(impersonate="chrome131")
    headers = generate_headers()
    headers["User-Agent"] = CHROME_USER_AGENT
    session.headers.update(headers)

    home_page = session.get(url="https://x.com")
    home_page_response = bs4.BeautifulSoup(home_page.content, 'html.parser')

    ondemand_file_url = get_ondemand_file_url(response=home_page_response)
    ondemand_file = session.get(url=ondemand_file_url)
    ondemand_file_response = bs4.BeautifulSoup(ondemand_file.content, 'html.parser')

    ct = ClientTransaction(home_page_response, ondemand_file_response)
    return ct.generate_transaction_id(method="POST", path="/1.1/onboarding/task.json")


async def auto_gen_x_transaction_id() -> str:
    """Generate transaction ID using cloudscraper to bypass Cloudflare."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_executor, _sync_gen_x_transaction_id)


def _sync_login(acc: Account, cfg: LoginConfig) -> Account:
    """Synchronous login using curl_cffi to bypass Cloudflare."""
    # Use curl_cffi with Chrome 131 impersonation for modern TLS fingerprint
    session = curl_requests.Session(impersonate="chrome131")

    # Set comprehensive browser-like headers matching Chrome 131
    browser_headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Sec-Ch-Ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": CHROME_USER_AGENT,
    }
    session.headers.update(browser_headers)

    # First, solve Cloudflare challenge by visiting x.com
    # This will set cookies that allow subsequent API requests
    home_page = session.get("https://x.com")
    home_page_response = bs4.BeautifulSoup(home_page.content, 'html.parser')

    # Generate transaction ID from the same session
    ondemand_file_url = get_ondemand_file_url(response=home_page_response)
    ondemand_file = session.get(ondemand_file_url)
    ondemand_file_response = bs4.BeautifulSoup(ondemand_file.content, 'html.parser')

    ct = ClientTransaction(home_page_response, ondemand_file_response)
    client_transaction_id = ct.generate_transaction_id(method="POST", path="/1.1/onboarding/task.json")
    logger.debug(f"client_transaction_id: {client_transaction_id}")

    # Now set up headers for API requests (XHR-style headers)
    session.headers.update({
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "en-US,en;q=0.9",
        "Content-Type": "application/json",
        "Origin": "https://x.com",
        "Referer": "https://x.com/",
        "Sec-Ch-Ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
        "User-Agent": CHROME_USER_AGENT,
        "Authorization": TOKEN,
        "X-Twitter-Active-User": "yes",
        "X-Twitter-Client-Language": "en",
        "X-Client-Transaction-Id": client_transaction_id,
    })

    # Get guest token
    _human_delay(0.3, 0.8)
    rep = session.post("https://api.x.com/1.1/guest/activate.json")
    if rep.status_code != 200:
        logger.error(f"Guest token failed: {rep.status_code} - {rep.text[:500]}")
        rep.raise_for_status()
    guest_token = rep.json()["guest_token"]
    logger.debug(f"Got guest token: {guest_token}")
    session.headers["X-Guest-Token"] = guest_token

    # Check if ct0 cookie was set and update CSRF token
    ct0 = session.cookies.get("ct0")
    if ct0:
        session.headers["X-Csrf-Token"] = ct0

    # Login initiate
    _human_delay(0.5, 1.0)
    payload = {
        "input_flow_data": {
            "flow_context": {"debug_overrides": {}, "start_location": {"location": "unknown"}}
        },
        "subtask_versions": {},
    }
    logger.debug(f"Login initiate request headers: {dict(session.headers)}")
    rep = session.post(LOGIN_URL, params={"flow_name": "login"}, json=payload)
    logger.debug(f"Login initiate response: {rep.status_code} - {rep.text[:500] if rep.text else 'empty'}")
    if rep.status_code != 200:
        raise ValueError(f"Login initiate failed: {rep.status_code} - {rep.text[:1000]}")

    # Update CSRF token after login initiate
    ct0 = session.cookies.get("ct0")
    if ct0:
        session.headers["X-Csrf-Token"] = ct0

    # Set the att (authentication token) header from cookie - required per Nitter fix
    att = session.cookies.get("att")
    if att:
        session.headers["att"] = att
        logger.debug(f"Set att header: {att}")

    prev = rep.json()
    imap = None

    def update_csrf():
        ct0 = session.cookies.get("ct0")
        if ct0:
            session.headers["X-Csrf-Token"] = ct0
            session.headers["X-Twitter-Auth-Type"] = "OAuth2Session"

    # Process login tasks
    while True:
        update_csrf()
        assert "flow_token" in prev, f"flow_token not in response"
        flow_token = prev["flow_token"]

        task_completed = False
        for subtask in prev.get("subtasks", []):
            task_id = subtask["subtask_id"]

            try:
                if task_id == "LoginSuccessSubtask":
                    payload = {"flow_token": flow_token, "subtask_inputs": []}
                    rep = session.post(LOGIN_URL, json=payload)
                    rep.raise_for_status()
                    prev = rep.json()
                    task_completed = True
                    break

                elif task_id == "LoginJsInstrumentationSubtask":
                    _human_delay(0.5, 1.0)
                    payload = {
                        "flow_token": flow_token,
                        "subtask_inputs": [{
                            "subtask_id": "LoginJsInstrumentationSubtask",
                            "js_instrumentation": {"response": "{}", "link": "next_link"},
                        }],
                    }
                    rep = session.post(LOGIN_URL, json=payload)
                    logger.debug(f"LoginJsInstrumentation response: {rep.status_code} - {rep.text[:500] if rep.text else 'empty'}")
                    if rep.status_code != 200:
                        raise ValueError(f"LoginJsInstrumentation failed: {rep.status_code} - {rep.text[:1000]}")
                    update_csrf()
                    prev = rep.json()
                    task_completed = True
                    break

                elif task_id == "LoginEnterUserIdentifierSSO":
                    # Simulate user typing delay
                    _human_delay(1.0, 2.0)
                    payload = {
                        "flow_token": flow_token,
                        "subtask_inputs": [{
                            "subtask_id": "LoginEnterUserIdentifierSSO",
                            "settings_list": {
                                "setting_responses": [{
                                    "key": "user_identifier",
                                    "response_data": {"text_data": {"result": acc.username}},
                                }],
                                "link": "next_link",
                            },
                        }],
                    }
                    logger.debug(f"LoginEnterUserIdentifierSSO payload: {payload}")
                    # Get cookies safely handling multiple domains
                    try:
                        cookies_dict = {c.name: c.value for c in session.cookies.jar}
                        logger.debug(f"Current cookies: {cookies_dict}")
                    except Exception as e:
                        logger.debug(f"Could not log cookies: {e}")
                    rep = session.post(LOGIN_URL, json=payload)
                    logger.debug(f"LoginEnterUserIdentifierSSO response: {rep.status_code} - {rep.text[:500] if rep.text else 'empty'}")
                    if rep.status_code != 200:
                        raise ValueError(f"LoginEnterUserIdentifierSSO failed: {rep.status_code} - {rep.text[:1000]}")
                    update_csrf()
                    prev = rep.json()
                    task_completed = True
                    break

                elif task_id == "LoginEnterPassword":
                    payload = {
                        "flow_token": flow_token,
                        "subtask_inputs": [{
                            "subtask_id": "LoginEnterPassword",
                            "enter_password": {"password": acc.password, "link": "next_link"},
                        }],
                    }
                    rep = session.post(LOGIN_URL, json=payload)
                    rep.raise_for_status()
                    prev = rep.json()
                    task_completed = True
                    break

                elif task_id == "LoginTwoFactorAuthChallenge":
                    if acc.mfa_code is None:
                        raise ValueError("MFA code is required")
                    totp = pyotp.TOTP(acc.mfa_code)
                    payload = {
                        "flow_token": flow_token,
                        "subtask_inputs": [{
                            "subtask_id": "LoginTwoFactorAuthChallenge",
                            "enter_text": {"text": totp.now(), "link": "next_link"},
                        }],
                    }
                    rep = session.post(LOGIN_URL, json=payload)
                    rep.raise_for_status()
                    prev = rep.json()
                    task_completed = True
                    break

                elif task_id == "AccountDuplicationCheck":
                    payload = {
                        "flow_token": flow_token,
                        "subtask_inputs": [{
                            "subtask_id": "AccountDuplicationCheck",
                            "check_logged_in_account": {"link": "AccountDuplicationCheck_false"},
                        }],
                    }
                    rep = session.post(LOGIN_URL, json=payload)
                    rep.raise_for_status()
                    prev = rep.json()
                    task_completed = True
                    break

                elif task_id == "LoginAcid":
                    is_code = subtask.get("enter_text", {}).get("hint_text", "").lower() == "confirmation code"
                    if is_code:
                        if cfg.manual:
                            print(f"Enter email code for {acc.username} / {acc.email}")
                            value = input("Code: ").strip()
                        else:
                            if not imap:
                                # Note: imap_login is async, need to handle this
                                raise ValueError("Email verification required but IMAP not available in sync mode. Use --manual flag.")
                            raise ValueError("IMAP code retrieval not supported in sync mode. Use --manual flag.")
                    else:
                        value = acc.email

                    payload = {
                        "flow_token": flow_token,
                        "subtask_inputs": [{
                            "subtask_id": "LoginAcid",
                            "enter_text": {"text": value, "link": "next_link"},
                        }],
                    }
                    rep = session.post(LOGIN_URL, json=payload)
                    rep.raise_for_status()
                    prev = rep.json()
                    task_completed = True
                    break

                elif task_id == "LoginEnterAlternateIdentifierSubtask":
                    payload = {
                        "flow_token": flow_token,
                        "subtask_inputs": [{
                            "subtask_id": "LoginEnterAlternateIdentifierSubtask",
                            "enter_text": {"text": acc.username, "link": "next_link"},
                        }],
                    }
                    rep = session.post(LOGIN_URL, json=payload)
                    rep.raise_for_status()
                    prev = rep.json()
                    task_completed = True
                    break

            except Exception as e:
                acc.error_msg = f"login_step={task_id} err={e}"
                raise

        if not task_completed:
            break

    # Verify login success
    ct0 = session.cookies.get("ct0")
    if not ct0:
        raise ValueError("ct0 not in cookies (most likely IP ban or login failed)")

    # Save account state
    acc.active = True
    acc.headers = dict(session.headers)
    acc.cookies = dict(session.cookies)
    acc.headers["x-csrf-token"] = ct0
    acc.headers["x-twitter-auth-type"] = "OAuth2Session"

    return acc


async def login(acc: Account, cfg: LoginConfig | None = None) -> Account:
    log_id = f"{acc.username} - {acc.email}"
    if acc.active:
        logger.info(f"account already active {log_id}")
        return acc

    cfg = cfg or LoginConfig()

    # Use browser-based login to bypass Twitter's anti-automation
    return await _browser_login(acc, cfg)
