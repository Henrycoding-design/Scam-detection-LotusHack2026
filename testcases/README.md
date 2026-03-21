# ScamShield Testcases

This folder contains judge-ready demo pages for the ScamShield extension.

- `safe/` contains realistic pages that should stay safe when opened on `localhost`.
- `scam/` contains realistic scam pages that should look convincing in a demo and trigger the extension's heuristic scoring.

The custom hostname setup below is optional. It lets ScamShield evaluate suspicious-looking demo domains instead of only `localhost`, which makes the domain-name checks more obvious during a demo. If time is tight, you can skip the hosts-file setup and still run everything on `http://localhost:8000/...`.

## Hosts File Entries

Add these lines to `/etc/hosts` on Mac/Linux or `C:\Windows\System32\drivers\etc\hosts` on Windows:

```text
127.0.0.1 paypal-login-security-review-demo.xyz
127.0.0.1 microsoft-docs-session-check.top
127.0.0.1 netflix-account-billing-check.click
127.0.0.1 chase-secure-transfer-review.xyz
127.0.0.1 appleid-session-review.monster
127.0.0.1 eth-airdrop-bonus-claim.top
```

This optional setup makes it easier to demo the "check suspicious web name" style behavior on the scam pages.

## Mac Example

### Step 1 - Open hosts file

```sh
sudo nano /etc/hosts
```

### Step 2 - Add these lines

```text
127.0.0.1 paypal-login-security-review-demo.xyz
127.0.0.1 microsoft-docs-session-check.top
127.0.0.1 netflix-account-billing-check.click
127.0.0.1 chase-secure-transfer-review.xyz
127.0.0.1 appleid-session-review.monster
127.0.0.1 eth-airdrop-bonus-claim.top
```

### Step 3 - Save

- `Control + O`
- `Enter`
- `Control + X`

### Step 4 - Start local server

```sh
cd /Users/giakhang/Desktop/fix:/Scam-detection-LotusHack2026/testcases
python3 -m http.server 8000
```

### Step 5 - Open in Chrome

```text
http://paypal-login-security-review-demo.xyz:8000
http://paypal-login-security-review-demo.xyz:8000/scam/paypal-security-alert.html
```

## Linux Note

Linux uses the same hosts file path and same flow as Mac:

- Edit `/etc/hosts`
- Add the same 6 lines
- Save the file
- Start the local server from this folder

## Windows Note

On Windows, open `C:\Windows\System32\drivers\etc\hosts` as Administrator and add the same 6 lines:

```text
127.0.0.1 paypal-login-security-review-demo.xyz
127.0.0.1 microsoft-docs-session-check.top
127.0.0.1 netflix-account-billing-check.click
127.0.0.1 chase-secure-transfer-review.xyz
127.0.0.1 appleid-session-review.monster
127.0.0.1 eth-airdrop-bonus-claim.top
```

Then run:

```sh
cd /Users/giakhang/Desktop/fix:/Scam-detection-LotusHack2026/testcases
python3 -m http.server 8000
```

## Fast Demo Paths

- Safe pages: `http://localhost:8000/safe/...`
- Scam pages without hosts setup: `http://localhost:8000/scam/...`
- Scam pages with hostname checks: `http://paypal-login-security-review-demo.xyz:8000/scam/paypal-security-alert.html`

`file://` is not the intended path for these testcases. Use `http://localhost:8000/...` for the fast path, and use the mapped demo domains when you want the hostname-based scam checks to show up as part of the demo.

## Format:
http://the-registered-host-lines/scam/the-html
