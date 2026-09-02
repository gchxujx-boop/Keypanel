# KeyPanel

APK license key authentication panel — generate keys, verify them from your app,
manage devices/expiry from a dashboard.

## Local run
```
npm install
npm start
```
Open http://localhost:3000 — login with `admin` / `admin123` (change this before deploying, see below).

## Change the admin password
Set an environment variable instead of using the default:
```
ADMIN_USER=youradmin
ADMIN_PASS=your-strong-password
JWT_SECRET=some-long-random-string
```

## Verification endpoints (call these from your APK)
All of these do the same check — pick whichever path your app already expects:
- `/connect`
- `/connect.php`
- `/server`
- `/api/verify`
- `/verify`
- `/auth`

Send as GET query params or POST JSON/form body:
- `key` — the license key
- `device_id` — a unique ID for the device (e.g. Android ID)
- `app_version` — optional

Success:
```json
{"status":"success","message":"Key verified","expires_in_days":29,"device_limit":1,"devices_used":1}
```
Failure:
```json
{"status":"failed","message":"Invalid key"}
```

## Important: data storage note
Keys are stored in `db.json` on disk. On most **free** hosting tiers the filesystem
is wiped on every restart/redeploy — fine for testing, not safe for production.
For anything real, swap `db.json` to a free database (see hosting guide below).
