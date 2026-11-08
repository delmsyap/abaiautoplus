# Android Protocol Checkout Mode

Integration of Playwright + Android Chrome + CycleTLS for ChatGPT payments.

## Overview

This adds `android_protocol` as a new `checkout_mode` option in the ChatGPT platform plugin, calling the Node.js implementation from `stripe-protocol-payment-automation-deep-dive-2026/chatgpt-android-payment/`.

## Usage

### From Web UI (Payment Link Action)

Select **Checkout 后端模式** = `android_protocol`

Required parameters:
| Parameter | Description | Default |
|-----------|-------------|---------|
| `checkout_mode` | Must be `android_protocol` | - |
| `android_serial` | Android device serial | `emulator-5554` |
| `browser_package` | Android browser package | `com.android.chrome` |
| `card_number` | Test card number | `4242424242424242` |
| `card_exp_month` | Expiry month | `12` |
| `card_exp_year` | Expiry year | `2028` |
| `card_cvc` | CVC | `123` |
| `billing_country` | Billing country | `US` |
| `billing_name` | Name on card | `John Doe` |
| `billing_email` | Email | account email |
| `billing_line1` | Address line 1 | `123 Main St` |
| `billing_city` | City | `San Francisco` |
| `billing_state` | State | `CA` |
| `billing_postal` | Postal code | `94105` |

### From Python Code

```python
from platforms.chatgpt.plugin import ChatGPTPlatform

platform = ChatGPTPlatform(config, mailbox)

result = platform.execute_action("payment_link", account, {
    "checkout_mode": "android_protocol",
    "android_serial": "emulator-5554",
    "browser_package": "com.android.chrome",
    "plan": "plus",
    "country": "US",
    "auto_checkout": True,
    "payment_method": "paypal",
    "card_number": "4242424242424242",
    "card_exp_month": "12",
    "card_exp_year": "2028",
    "card_cvc": "123",
})
```

## How It Works

1. **Python** (`plugin.py:_handle_generate_link`):
   - Generates ChatGPT checkout URL
   - Calls `asyncio.run(run_android_payment_flow(...))` from `android_runtime.py`

2. **Python Wrapper** (`android_runtime.py`):
   - Imports Node.js `run_android_payment_flow` via subprocess or direct call
   - Passes credentials, card, billing, proxy, device config

3. **Node.js** (`chatgpt-android-payment/chatgpt-payment.js`):
   - Runs 12-step Stripe hosted mode flow
   - Uses Playwright to connect to Android Chrome on emulator-5554
   - Uses CycleTLS with Chrome 150 JA3 for all API calls
   - Returns success/failure with details

## Prerequisites

### Android
```bash
# Verify emulator running
adb devices
# emulator-5554  device
```

### Node.js Dependencies
```bash
cd /path/to/stripe-protocol-payment-automation-deep-dive-2026/chatgpt-android-payment
npm install
```

### Environment Variables (Node.js .env)
```bash
CHATGPT_ACCESS_TOKEN=<RS256 JWT from browser>
CHATGPT_CARD_NUMBER=4242424242424242
CHATGPT_CARD_EXP_MONTH=12
CHATGPT_CARD_EXP_YEAR=2028
CHATGPT_CARD_CVC=123
CHATGPT_BILLING_NAME=John Doe
CHATGPT_BILLING_EMAIL=test@example.com
CHATGPT_BILLING_LINE1=123 Main St
CHATGPT_BILLING_CITY=San Francisco
CHATGPT_BILLING_STATE=CA
CHATGPT_BILLING_POSTAL=94105
CHATGPT_BILLING_COUNTRY=US
CHATGPT_PLAN_NAME=chatgptplusplan
CHATGPT_STRIPE_PK=pk_live_51HOrSwC6h1nxGoI3lTAgRjYVrz4dU3fVOabyCcKR3pbEJguCVAlqCxdxCUvoRh1XWwRacViovU3kLKvpkjh7IqkW00iXQsjo3n
CHATGPT_ANDROID_SERIAL=emulator-5554
CHATGPT_BROWSER_PACKAGE=com.android.chrome
```

## Testing

### Test Android Connection
```bash
cd /path/to/chatgpt-android-payment
npm run probe
```

### Run Unit Tests
```bash
npm run pay:test
# 12/12 tests pass
```

### Dry Run
```bash
node dry-run.js
```

### REA Analysis
```bash
npm run rea:live
# Pulls ChatGPT APK, outputs JEB MCP commands
```

## Current Blocker

**"Unusual activity" 400** on checkout API - rate limit/anti-bot on account/session.

Fix: Use fresh account, rotate TLS fingerprint from `protocol-engine PAYMENT_FP_PROFILES`, add Turnstile token for approve step.

## Files

| File | Purpose |
|------|---------|
| `android_runtime.py` | Python wrapper calling Node.js |
| `plugin.py` | Added `android_protocol` mode handler |
| `../stripe-protocol-payment-automation-deep-dive-2026/chatgpt-android-payment/` | Node.js implementation |
