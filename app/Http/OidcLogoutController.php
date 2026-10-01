<?php

namespace Pterodactyl\BlueprintFramework\Extensions\sso_oidc\Http;

use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Pterodactyl\Http\Controllers\Controller;
use Pterodactyl\BlueprintFramework\Extensions\sso_oidc\Services\OidcDiscoveryService;
use Throwable;

/**
 * Reached after Pterodactyl's own logout button (client dashboard or admin
 * panel - see data/install.sh, both are patched) has already POSTed to
 * /auth/logout, redirecting here instead of straight to Pterodactyl.
 *
 * Only actually does anything for sessions that were established via SSO
 * (identified by the id_token_hint cookie reference - see
 * consumeIdTokenHint()); anyone who logged in with a plain username/password
 * just lands back on the panel like normal, since RP-Initiated Logout has
 * nothing to do with them. For an actual SSO session, without this the
 * IdP's own browser session (e.g. authentik) would stay alive, so hitting
 * the login page again - especially with hide_password_login enabled -
 * would silently sign the user straight back in. This performs OIDC
 * RP-Initiated Logout (using the discovery document's end_session_endpoint,
 * if the provider exposes one) so both sessions end together.
 */
class OidcLogoutController extends Controller
{
    use OidcSettingsProvider;

    public function __construct(private OidcDiscoveryService $discovery)
    {
    }

    public function index(): RedirectResponse
    {
        $settings = $this->oidcSettings();
        $fallback = $this->extensionUrl('/');

        $idTokenHint = $this->consumeIdTokenHint();

        // No tracked SSO session for this browser means this logout was
        // never an SSO login in the first place (plain username/password,
        // possibly with 2FA) - it has nothing to do with the IdP, so it
        // must never be redirected there. Without this check, *every*
        // logout redirected to the IdP whenever SSO was merely enabled,
        // regardless of how the user actually logged in.
        if (!$idTokenHint) {
            return redirect($fallback);
        }

        if ($settings['enabled'] !== '1' || !$settings['issuer']) {
            return redirect($fallback);
        }

        try {
            $document = $this->discovery->discover($settings['issuer']);
        } catch (Throwable) {
            // The IdP being unreachable must never block logging out of
            // the panel itself - the panel session is already gone by the
            // time this route is hit.
            return redirect($fallback);
        }

        $endSessionEndpoint = $document['end_session_endpoint'] ?? null;

        if (!$endSessionEndpoint) {
            return redirect($fallback);
        }

        $params = [
            'client_id' => $settings['client_id'],
            'post_logout_redirect_uri' => $fallback,
            // Recommended by the spec, and required by some (stricter)
            // providers before they'll honor post_logout_redirect_uri at
            // all. Always present here - we already returned above for
            // any logout that wasn't tied to a tracked SSO session.
            'id_token_hint' => $idTokenHint,
        ];

        return redirect($endSessionEndpoint . '?' . http_build_query($params));
    }

    /**
     * Reference-token pattern: the cookie set at login (OidcCallbackController)
     * only ever holds the (by-then-defunct) session_id, never the id_token
     * itself - looks the matching sso_oidc_sessions row up by it, and always
     * consumes both (cookie forgotten, row deleted) whether or not a row
     * was actually found. Read from the raw $_COOKIE superglobal, not
     * Laravel's $request->cookie(): the cookie is deliberately set via
     * plain setcookie() to keep it tiny and avoid
     * Pterodactyl\Http\Middleware\EncryptCookies - which would just fail to
     * "decrypt" an unencrypted value and return null.
     */
    private function consumeIdTokenHint(): ?string
    {
        $sessionId = $_COOKIE['sso_oidc_idth'] ?? null;

        setcookie('sso_oidc_idth', '', [
            'expires' => time() - 3600,
            'path' => '/',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);

        if (!$sessionId || !is_string($sessionId)) {
            return null;
        }

        $row = DB::table('sso_oidc_sessions')
            ->where('session_id', $sessionId)
            ->first();

        if (!$row) {
            return null;
        }

        // Consume the row regardless of whether token decryption succeeds.
        DB::table('sso_oidc_sessions')
            ->where('id', $row->id)
            ->delete();

        if (!is_string($row->id_token) || $row->id_token === '') {
            return null;
        }

        try {
            return Crypt::decryptString($row->id_token);
        } catch (Throwable) {
            // Never send an invalid or undecryptable token to the IdP.
            return null;
        }
    }
}
