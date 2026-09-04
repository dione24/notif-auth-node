# Notif Auth — Node.js SDK

Server-side WhatsApp authentication for [Notif Auth](https://auth.notif.ml). Generates OAuth authorization requests with PKCE S256, exchanges authorization codes, and verifies the signed profile using the issuer's public keys.

**Status:** public source, version 0.1.0. npm publication is planned; this package is not yet available from npm as part of this release.

## Install from source

Requires Node.js 22.12 or newer.

```bash
git clone https://github.com/dione24/notif-auth-node.git
cd notif-auth-node
npm ci
npm run check
npm pack

# From your application's directory:
npm install /path/to/notif-auth-node/spay-notif-auth-node-0.1.0.tgz
```

`npm install github:dione24/notif-auth-node#main` also builds the package from GitHub. Pin a reviewed commit instead of `main` for reproducible production installations.

## Configure your application

1. [Create a developer account](https://auth.notif.ml/register).
2. Create a Server application in the [dashboard](https://auth.notif.ml/dashboard). Verify your email to enable Live; Sandbox remains available.
3. Register the exact callback URL. Live callbacks require HTTPS. Save the client secret on your server.

```ts
import { NotifAuth } from '@spay/notif-auth-node';

const auth = new NotifAuth({
  clientId: process.env.NOTIF_CLIENT_ID!,
  clientSecret: process.env.NOTIF_CLIENT_SECRET!,
  redirectUri: process.env.NOTIF_REDIRECT_URI!,
  issuer: 'https://auth.notif.ml',
  allowSandbox: false, // Explicitly reject test identities in production.
});
```

### Start a login

```ts
const { url, transaction } = auth.begin();
// Save transaction in this browser's server-side session, expiring within
// 5 minutes, or in an authenticated HttpOnly cookie with a short lifetime.
// Then redirect this browser to url.
```

Never store one shared transaction for all users. The transaction contains `state`, the PKCE verifier and the callback URL. The SDK does not provide your application's session store.

### Handle the callback

```ts
// Read code/state from the callback query and retrieve this browser's transaction.
// Reject a missing/expired transaction, then consume it once in your session store.
const profile = await auth.complete(code, state, transaction);

// profile.subject identifies this user in the tenant/environment.
// Look up your own account and create your own secure application session.
```

`complete()` validates state before exchanging the code. `exchange(code, verifier, redirectUri?)` is available for integrations that validate state themselves, such as the React SDK flow. Do not skip that validation.

A profile contains `subject`, `phone_e164`, optional `display_name`, `mode`, `provider`, and the signed `token`. Token verification enforces the issuer, audience, RS256 signature and expiration. Decoding a JWT without verifying it is insufficient.

## Existing accounts

Link WhatsApp only from a session already authenticated to the destination account. Require recent reauthentication for sensitive linking or transfers. Do not automatically merge users by name, a supplied email, or a phone number. This SDK verifies a WhatsApp login; account linking, roles, recovery and sessions belong to your application.

## Sandbox

Test clients (`pk_test_…`) allow test profiles by default. Use `allowSandbox: true` explicitly for Sandbox integrations and `false` in production. A test profile has `mode: 'TEST'` and `provider: 'sandbox'`.

## API

- `begin(redirectUri?)` → `{ url, transaction }`
- `complete(code, state, transaction)` → verified profile
- `exchange(code, verifier, redirectUri?)` → verified profile (caller validates state)
- `verify(token)` → verified JWT claims and profile
- `NotifAuthError` exposes `code` and an optional `requestId`

## Development and support

```bash
npm ci
npm run check
npm pack --dry-run
```

Tests use a local mock issuer and synthetic identities; no live WhatsApp account is needed. See [SECURITY.md](SECURITY.md), [publication instructions](PUBLISHING.md), and the [React SDK](https://github.com/dione24/notif-auth-react).

Support: support@smsv.tech. License: [MIT](LICENSE).
