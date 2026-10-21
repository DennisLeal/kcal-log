# Kcal Log payment API

This Cloudflare Worker creates PayMongo Hosted Checkout sessions, grants lifetime access only after a verified paid-checkout webhook, and emails one-time codes for restoring that access. D1 stores purchase and recovery records. Meal logs remain in the user's browser and are not uploaded to this service.

## Prerequisites

- A Cloudflare account with Workers and D1 enabled.
- Node.js 22 or newer.
- A PayMongo account with test credentials and permission to configure webhooks.
- A Resend account and a verified sender domain for customer email delivery.

The Wrangler CLI is pinned in the npm scripts. You do not need to install it globally or add Worker dependencies to `node_modules`.

## Create and migrate the database

From this directory, authenticate Wrangler and create the D1 database:

```powershell
npx --yes wrangler@4.151.3 login
npx --yes wrangler@4.151.3 d1 create kcal-log-payments
```

Copy the database ID returned by Cloudflare into `wrangler.jsonc`, replacing `REPLACE_WITH_D1_DATABASE_ID`. Apply the schema to the local development database and the remote Cloudflare database:

```powershell
npx --yes wrangler@4.151.3 d1 migrations apply kcal-log-payments --local
npx --yes wrangler@4.151.3 d1 migrations apply kcal-log-payments --remote
```

Do not deploy while the placeholder database ID remains in the config.

## Configure secrets and email

In Resend, verify a domain you control and add the DNS records Resend provides. Choose a sender address on that verified domain. Do not use `onboarding@resend.dev` for customer delivery; it is intended for limited testing.

Set secrets directly in Wrangler's secure secret store. Do not put these values in source files, the PWA, GitHub Pages, or chat:

```powershell
npx --yes wrangler@4.151.3 secret put PAYMONGO_SECRET_KEY
npx --yes wrangler@4.151.3 secret put PAYMONGO_WEBHOOK_SECRET
npx --yes wrangler@4.151.3 secret put RESEND_API_KEY
npx --yes wrangler@4.151.3 secret put RESEND_FROM_EMAIL
```

The committed configuration uses `PAYMONGO_MODE=test`, and the API accepts only a test secret key in that mode. Keep test and live webhook secrets separate. For each PayMongo mode, register this HTTPS endpoint and subscribe to `checkout_session.payment.paid`:

```text
https://YOUR_WORKER_HOST/webhooks/paymongo
```

Copy the webhook signing secret into the matching `PAYMONGO_WEBHOOK_SECRET` Worker secret. Do not switch the mode or credentials to live until the entire test purchase and access recovery flow succeeds.

## Test and deploy

Run the built-in tests and start the local Worker:

```powershell
npm test
npm run dev
```

In another terminal, the local health endpoint should return `{"status":"ok"}` after the local D1 migration:

```powershell
Invoke-RestMethod http://localhost:8787/health
```

Local checkout and email delivery remain unavailable until test secrets and a sender address are configured. Deploy only after setting the real D1 ID, migrating the remote database, setting secrets, and configuring the PayMongo test webhook:

```powershell
npm run deploy
```

The deployment output includes the Worker HTTPS origin. Set `ACCESS_API_BASE_URL` in `../index.html` to that origin (without a trailing slash), then test a complete PayMongo test-mode purchase, confirmation emails, code redemption, and access restoration. Re-deploy the PWA after setting its API origin. Keep the PWA API origin empty until the Worker is deployed and configured.

## Payment and recovery behavior

- The server fixes the price at PHP 79.00 and requests GCash and QR Ph payment methods. It never accepts a price from the browser.
- Each checkout receives a random order reference. The browser's success redirect does not unlock the app.
- Webhooks are checked against the raw request body with PayMongo's HMAC-SHA256 signature. The Worker validates mode, timestamp, paid status, order reference, checkout session, amount, and currency, then deduplicates events.
- A purchase email is sent to the address entered before checkout. Recovery codes contain 24 random hexadecimal characters, expire after 10 minutes, and can be redeemed once. Only hashes of codes and access tokens are stored.
- The active access token stays separate from meal logs and is not included in JSON backups. After clearing browser data or changing devices, request another recovery code.
- The backend does not receive meal entries. Client-side trial and entitlement state can be modified by a determined user; this is not tamper-proof DRM.

## Important rollout notes

- `wrangler.jsonc` sets the app and allowed browser origin to the current GitHub Pages URL. Update both if the PWA is moved to another origin.
- `../index.html` deliberately ships with an empty API origin until the Worker is deployed.
- Review `../privacy.html` before launch. It identifies the app's local log storage, Cloudflare and D1 backend, PayMongo checkout, and Resend email processing.
- Use Cloudflare's dashboard to review Worker and D1 usage and configure backups/retention appropriate to purchase records. Do not store food logs or access codes in plaintext in D1.
- The old `backend/codes.json` and Express admin workflow are retired. Its current-version copy has been removed, but historic copies remain in the public Git history; no history rewrite has been authorized.

## Current scope and launch blockers

This backend is for web purchases by PWA users. It is not Google Play Billing, an Android APK, or an iOS App Store purchase flow. Store distribution and native billing need a separate product and platform decision. Trial download analytics are also not enabled; adding them would require a clear opt-in and corresponding privacy disclosure.

Before enabling real payments, confirm PayMongo live access, configure separate live credentials and webhook, confirm Resend domain delivery, and repeat purchase/recovery checks with production services. Never paste credentials into chat.
