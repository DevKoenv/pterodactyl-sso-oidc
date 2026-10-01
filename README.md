# Pterodactyl SSO - OIDC

A Blueprint extension for [Pterodactyl](https://pterodactyl.io) that adds
**OpenID Connect (OIDC) single sign-on login**, as an addition to the built-in
username/password login. Accounts are created just-in-time on first login and
matched to existing accounts by email on every single login — nothing about
that match is persisted, so it's re-decided fresh every time. 2FA is skipped
for SSO logins, since the second factor is the IdP's responsibility once
federated. An admin panel toggle can hide the native username/password form
entirely and redirect straight to the configured IdP.

## Features

- **OIDC Authorization Code Flow with PKCE** (S256) against any standard
  OIDC provider (tested against [authentik](https://goauthentik.io)).
- **Just-in-time account provisioning**: a new Pterodactyl account is
  created automatically on first SSO login, no admin action needed.
- **Just-in-time account updates**: email, username, first/last name and
  admin status are refreshed from the IdP's claims on **every** SSO login,
  for both new and pre-existing accounts.
- **Email-based account linking, decided fresh every login** — nothing is
  persisted as a "link"; if the email changes at the IdP, the next login
  simply resolves to a different (or new) account.
- **Admin status fully controlled by the IdP** via a configurable claim
  name/value (e.g. group membership) — see "How it works" below.
- **2FA (TOTP) is skipped for SSO logins** — the second factor becomes the
  IdP's responsibility once authentication is federated.
- **Optional "hide password login"** toggle: redirect straight to the IdP
  instead of showing the native login form, with a `?auto_sso=0` escape
  hatch to always be able to reach the classic form in an emergency.
- **RP-Initiated Logout**: logging out of Pterodactyl also ends the session
  at the IdP (both the client dashboard and admin panel logout buttons).
- **Back-Channel Logout** and **Front-Channel Logout**: logging out (or a
  session ending) *at the IdP* also ends the matching Pterodactyl session,
  even without the browser being involved.
- **ACR (requested) / AMR (enforced)** authentication-strength controls —
  optionally reject SSO logins that didn't use an expected authentication
  method (e.g. require MFA).
- **`access_token` revocation** and a **`userinfo_endpoint` fallback** for
  claims missing from the ID token, both automatic and transparent.
- **Client secret encrypted at rest** (Laravel's `Crypt`/`APP_KEY`), never
  echoed back into the admin form.
- **HTTPS enforced** for the whole SSO flow (localhost exempted for local
  development).
- **Clean install/update/remove**: reinstalling or removing the extension
  fully cleans up its database rows and tables — see "Why `remove.sh`
  cleans up the database itself" below.

## How it works

The OIDC authorization-code flow itself (`/redirect`, `/callback`) and a
public settings endpoint (`/config`) are implemented as plain Laravel
controllers/services under `app/`, bound via `requests.app` +
`requests.routers.web` in `conf.yml` (Blueprint's only unauthenticated
router type — needed since the browser has no panel session yet when the
IdP redirects back). Account provisioning talks to Pterodactyl's own `User`
model and `Auth` facade directly — Blueprint's `BlueprintExtensionLibrary`
only offers generic key-value storage (`dbGet`/`dbSet`), no user/auth
helpers.

Key design points:

- **PKCE (S256)** is used even though this is a confidential client, as a
  cheap extra layer against authorization-code interception.
- **AMR is enforced, ACR is only requested**: "Required AMR values" checks
  the id_token's `amr` claim and fails closed if absent; "Requested ACR
  values" is just a best-effort hint the provider may ignore.
- **`access_token` is revoked right after login** (after the redirect has
  been sent, so a slow revocation endpoint can't add latency to the login
  itself), and a **`userinfo_endpoint` fallback** fills in claims missing
  from the id_token.
- **No IdP subject (`sub`) is stored** — accounts are matched by email,
  freshly, on every login, matching the extension's re-decide-every-time
  design.
- **`root_admin` is fully IdP-controlled**: re-evaluated from the admin
  claim on every SSO login, for new and pre-existing accounts alike; an
  unresolvable claim means "not an admin", never "leave alone".
- **2FA is skipped for SSO logins** by calling the same guard login
  Pterodactyl's password flow uses, just without routing through the TOTP
  checkpoint branch.
- **Client secret is encrypted at rest** via Laravel's `Crypt`/`APP_KEY`
  (Blueprint's own storage only serializes, never encrypts), and never
  echoed back into the admin form — a blank field on save means "keep the
  current secret".
- **HTTPS is enforced** for the whole flow (`localhost` exempted for local
  dev).
- **`redirect_uri` is built from `app.url`**, not `url()`/`request()`,
  since a reverse-proxied panel without `TrustProxies` configured would
  otherwise generate a mismatched `http://` URL.
- **Logout is patched to reach the IdP too**: both the client dashboard's
  and admin panel's logout buttons are redirected to
  `/extensions/sso-oidc/logout`, which performs **RP-Initiated Logout**
  (`end_session_endpoint`, with `id_token_hint` sourced from a DB-backed
  reference token — a raw id_token was tried first but overflowed reverse
  proxy header buffers). **Back-Channel** and **Front-Channel Logout**
  handle sessions ending directly at the IdP (no browser involved),
  verifying a signed `logout_token` (Back-Channel) or an unsigned
  `iss`/`sid` iframe load (Front-Channel), and additionally rotate
  `remember_token` so a lingering "remember me" cookie can't silently
  re-authenticate the browser. Back-Channel is async (~30s delay via the
  IdP's task queue); Front-Channel is synchronous but has no signature and
  can be blocked by browser third-party-iframe restrictions or a
  restrictive `X-Frame-Options`/CSP.
- **`lcobucci/jwt` is reused** instead of adding a composer dependency
  (extensions can't add new ones) — including a hand-rolled JWK→PEM
  encoder, since it has no built-in JWK parser.
- **`remove.sh` cleans up the database itself**: `blueprint -remove` only
  deletes files, never runs migration rollbacks, so settings rows, the
  `sso-oidc_sessions` table and migration-tracking rows would otherwise
  linger forever after uninstall.

See the inline code comments and controller docblocks for the full
rationale and edge cases behind each of these.

## Configuration

All settings live under `Admin > Extensions > OIDC SSO Login`:

| Setting | Description |
|---|---|
| Enabled | Turns SSO login on/off globally |
| Hide password login | Skip the native form, redirect straight to the IdP |
| Button text | Text of the SSO button shown on the login page |
| Issuer URL | OIDC issuer; `{issuer}/.well-known/openid-configuration` is fetched automatically |
| Client ID / Client Secret | Confidential client credentials. The secret is stored encrypted and never shown again after saving - leave it blank on later saves to keep the current one. |
| Scopes | Defaults to `openid profile email` |
| Email / Username / First name / Last name claims | Claim names to read from the ID token |
| Admin claim / Admin claim value | A user is `root_admin` if this claim contains (or equals) this value. Evaluated fresh on **every** SSO login, for new *and* existing accounts alike - see "How it works" above before enabling SSO for an account that's already an admin. |
| Requested ACR values | Optional. Sent as `acr_values` in the authorization request - a hint the provider may ignore. Not enforcement, see "Requires AMR values" for that. |
| Required AMR values | Optional, comma-separated (e.g. `mfa,otp`). If set, login is rejected unless the id_token's `amr` claim contains at least one of these. Left empty, nothing is checked. |

## Setup

1. **Install the extension** — see "Installation" below.
2. **Register a confidential OIDC client** at your provider (authentik,
   Keycloak, Azure AD, ...). Open `/admin/extensions/sso_oidc` in Pterodactyl
   first to get the exact **Redirect / Callback URL** to register there.
3. **Fill in Issuer URL, Client ID and Client Secret** on the extension's
   admin page. The issuer's `.well-known/openid-configuration` is fetched
   automatically — no separate endpoint configuration needed.
4. **Check the Claim Mapping section** matches what your provider actually
   sends (defaults: `email`, `preferred_username`, `given_name`,
   `family_name`). Optionally set an Admin claim name/value if group
   membership at the IdP should control Pterodactyl's admin flag.
5. **Optional**: set the provider's logout callback ("Logout URI" /
   "Backchannel Logout URI" / "Frontchannel Logout URI", depending on what
   it supports) to the Back-/Front-Channel Logout URL shown on the same
   admin page, and set Requested ACR / Required AMR values if you want to
   enforce a specific authentication strength.
6. **Check "Enable SSO login"** and save. Optionally also check "Hide
   username/password login" to redirect straight to the IdP.
7. Test end-to-end: log in via the new SSO button (or the auto-redirect),
   confirm the account is created/matched correctly, then log out again and
   confirm it also ends the session at the IdP.

See the `## Configuration` table and the `## How it works` section above for
what each setting actually does and why it's built the way it is.

## Installation

1. Download the latest `sso_oidc.blueprint` file from the
   [Releases](https://github.com/DevKoenv/pterodactyl-sso-oidc/releases) page.
2. Upload it to your panel and run:

   ```bash
   blueprint -install sso_oidc.blueprint
   ```

After installing, set the callback URL shown on the extension's admin page as
the redirect URI at the OIDC provider, then fill in issuer/client
credentials and enable it. Optionally, also set the provider's "Logout URI"
/ "Backchannel Logout URI" (if it has one) to the backchannel-logout URL
shown on the same admin page - not required for normal login/logout, only
for Back-Channel Logout (see "How it works" above for the tradeoffs vs.
Front-Channel Logout).

## Uninstallation

```bash
blueprint -remove sso_oidc
```

`data/remove.sh` reverts the `NavigationBar.tsx` and `admin.blade.php`
logout patches exactly, explicitly cleans up the database (see "How it
works" above), and removal continues as usual: the admin page, routes and
login-page component are dropped. Accounts that were provisioned via SSO keep existing (with a
random, unusable password), so a password reset is needed if someone needs
to log into one of them without SSO afterwards.

## Compatibility

Last verified against:

- Pterodactyl Panel: `1.0-develop` branch — the admin view was confirmed to
  extend `layouts.admin` (not `admin.layout`), and `AdminFormRequest`
  already declares its own `normalize()`, so subclasses must not redeclare
  it under that name — both confirmed against a live panel (PHP 8.4.23,
  Laravel 11.47.0). The panel also needs `TrustProxies` configured (or
  `APP_URL` set correctly and its config cache rebuilt) when running behind
  a TLS-terminating reverse proxy — see "How it works" above.
- Blueprint Framework: `beta-2026-06` (current stable release, matching
  `info.target` in `conf.yml`).
- `lcobucci/jwt`: `5.6.0`, as actually installed by Pterodactyl's
  `composer.lock` (confirmed via `composer show lcobucci/jwt` on a live
  panel). `Configuration::forUnsecuredSigner()` doesn't exist in this
  version (only `forAsymmetricSigner`/`forSymmetricSigner` do), so reading
  the unverified `kid` header is done with a manual base64url + JSON decode
  instead (`OidcClientService::peekKid()`). `Lcobucci\Clock\SystemClock` is
  also not available - it lives in `lcobucci/clock`, which is only a *dev*
  dependency of `lcobucci/jwt` and isn't installed in production. The
  `LooseValidAt` constraint only needs a `Psr\Clock\ClockInterface`
  though (a real, non-dev dependency), so `OidcClientService::systemClock()`
  implements that interface directly with a one-line anonymous class
  instead of pulling in `SystemClock`.
- `resources/scripts/components/NavigationBar.tsx`: the patched line
  (`window.location = '/';` inside `onTriggerLogout`) was confirmed verbatim
  against the `develop` branch source. If a future panel version changes
  that file, `install.sh`/`update.sh` fail loudly (`FATAL`, non-zero exit)
  instead of silently skipping the patch.

Since ID-token verification relies on `lcobucci/jwt` already being a
Pterodactyl dependency, a future panel version dropping or majorly changing
that package's API would break signature verification again.

## Copyright

This project is a fork of [jw2702/pterodactyl-sso-oidc](https://github.com/jw2702/pterodactyl-sso-oidc).

Original work:
Copyright © 2026 jw2702

Modifications and additions in this fork:
Copyright © 2026 DevKoenv

The original project and this fork are licensed under the terms of the license included in the repository. All original copyright notices and license terms are retained.
