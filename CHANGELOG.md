# Changelog

## 0.2.0 — unreleased

- `sendOtp(phone, { endUserIp?, locale? })` and `verifyOtp(challengeId, code, { endUserIp? })` for the server-to-server OTP endpoints (`POST /server/otp/send`, `POST /server/otp/verify`, CONFIDENTIAL clients, Notif Auth 2026-10-12). `verifyOtp()` returns the same verified profile as `exchange()`.
- `NotifAuthError` now carries `status`, `retryAfterSeconds` (body `retry_after_seconds` or `Retry-After`) and `attemptsLeft` when the service returns them.
- A non-JSON response (gateway error page) or a network failure now raises `NotifAuthError` (`exchange_failed` / `network_error`, original error in `cause`) instead of a raw `SyntaxError`/`TypeError`.
- README: a login can legitimately take up to about 12 minutes in OTP mode (resends); keep the transaction for 15 minutes.

## 0.1.0 — 2026-09-04

- Initial standalone public SDK extracted from Notif Auth.
- TypeScript declarations and independent build configuration.
- Automated checks and a restricted npm package file list.
