<?php

namespace Pterodactyl\BlueprintFramework\Extensions\sso_oidc\Http;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Pterodactyl\Http\Controllers\Controller;
use Pterodactyl\Models\User;
use Pterodactyl\BlueprintFramework\Extensions\sso_oidc\Services\OidcClientService;
use Pterodactyl\BlueprintFramework\Extensions\sso_oidc\Services\OidcUserProvisioningService;
use RuntimeException;

class OidcCallbackController extends Controller
{
    use OidcSettingsProvider;

    public function __construct(private OidcClientService $client)
    {
    }

    public function index(Request $request): RedirectResponse
    {
        $settings = $this->oidcSettings();

        if ($settings['enabled'] !== '1') {
            throw new RuntimeException('SSO login is not enabled.');
        }

        $expectedState = $request->session()->pull('sso_oidc.state');
        $expectedNonce = $request->session()->pull('sso_oidc.nonce');
        $codeVerifier = $request->session()->pull('sso_oidc.code_verifier');
        $intended = $request->session()->pull('sso_oidc.intended', '/');

        $error = $request->query('error');
        if ($error) {
            throw new RuntimeException('OIDC provider returned an error: ' . $error);
        }

        $state = (string) $request->query('state');
        if (!$expectedState || !hash_equals((string) $expectedState, $state)) {
            throw new RuntimeException('Invalid or missing state parameter.');
        }

        $code = (string) $request->query('code');
        if (!$code) {
            throw new RuntimeException('Missing authorization code.');
        }

        if (!$codeVerifier) {
            throw new RuntimeException('Missing PKCE code verifier - the authorization flow was not started through /redirect.');
        }

        $redirectUri = $this->extensionUrl('/extensions/{identifier}/callback');

        $tokens = $this->client->exchangeCode($settings, $code, $redirectUri, (string) $codeVerifier);
        $claims = $this->client->verifyIdToken($settings, $tokens['id_token'], (string) $expectedNonce);

        $this->assertAmrSatisfied($settings, $claims);

        if (!empty($tokens['access_token'])) {
            $claims = $this->fillMissingClaimsFromUserInfo($settings, $claims, (string) $tokens['access_token']);
        }

        $provisioning = new OidcUserProvisioningService($settings);
        $user = $provisioning->resolve($claims);

        // Mirrors Pterodactyl's own AbstractLoginController::sendLoginResponse(),
        // minus the TOTP checkpoint branch: SSO logins intentionally skip 2FA,
        // since the second factor was already enforced (or not) by the IdP.
        $request->session()->regenerate();
        Auth::guard()->login($user, true);

        $sessionId = $request->session()->getId();
        $this->recordSession($claims, $user, $sessionId, (string) $tokens['id_token']);

        // Reference-token pattern (not the id_token itself) in the cookie:
        // OidcLogoutController runs *after* Pterodactyl's own /auth/logout
        // has already destroyed the Laravel session (see data/install.sh),
        // by which point session data is gone - but cookies aren't tied to
        // server-side session storage, so a small cookie holding just the
        // (now-defunct) session_id survives long enough to look the
        // matching sso_oidc_sessions row (and its stored id_token) back up
        // for use as `id_token_hint` on RP-Initiated Logout.
        //
        // Putting the full id_token directly in the cookie was the first
        // approach here, and it broke logins behind a reverse proxy: a JWT
        // can be a few hundred bytes to 1-2KB depending on how many
        // claims/groups the provider sends, and Laravel's
        // Pterodactyl\Http\Middleware\EncryptCookies AES-encrypts every
        // cookie by default on top of that - inflating it enough to push
        // the combined Set-Cookie headers past a reverse proxy's response
        // header buffer (confirmed against a live deploy behind Nginx
        // Proxy Manager: `502 upstream sent too big header`). A session_id
        // is a small, fixed-size opaque string regardless of how chatty
        // the provider's claims are, which sidesteps the problem entirely
        // rather than just working around Laravel's encryption overhead.
        setcookie('sso_oidc_idth', $sessionId, [
            'expires' => time() + ((int) config('session.lifetime', 720) * 60),
            'path' => '/',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);

        // We only ever needed the id_token's claims - revoke the now-unused
        // access_token rather than leave it valid at the provider for its
        // full lifetime. Deferred until *after* the response has already
        // been sent to the browser (via Laravel's terminate/afterResponse
        // mechanism) - this used to run inline here, and a slow-to-respond
        // revocation_endpoint added enough latency to push the whole
        // request past a reverse proxy's timeout. The proxy would then
        // return 503 to the browser even though the login itself had
        // already fully succeeded server-side - and a page reload after
        // that 503 replays the (already consumed) authorization code,
        // failing with a confusing invalid_grant. Revocation is cleanup,
        // not something the user should ever wait on.
        if (!empty($tokens['access_token'])) {
            $accessToken = (string) $tokens['access_token'];
            dispatch(function () use ($settings, $accessToken) {
                $this->client->revokeToken($settings, $accessToken);
            })->afterResponse();
        }

        return redirect($intended ?: '/');
    }

    /**
     * If "Required AMR values" is configured, rejects the login unless the
     * id_token's `amr` (Authentication Methods References, RFC 8176) claim
     * contains at least one of them - e.g. requiring "mfa" or "otp" so a
     * password-only IdP session can't silently satisfy the SSO login that
     * skips Pterodactyl's own 2FA. Providers vary in whether they send
     * `amr` at all; if required but absent, that's treated as not
     * satisfied (fail closed, not open).
     */
    private function assertAmrSatisfied(array $settings, array $claims): void
    {
        $required = array_filter(array_map('trim', explode(',', (string) ($settings['require_amr'] ?? ''))));

        if (empty($required)) {
            return;
        }

        $amr = array_map('strval', (array) ($claims['amr'] ?? []));

        if (empty(array_intersect($required, $amr))) {
            throw new RuntimeException(
                'The identity provider did not confirm one of the required authentication methods (' .
                implode(', ', $required) . ').'
            );
        }
    }

    /**
     * Fills in claims missing from the id_token (some providers/configs
     * don't put profile/group claims there) from the userinfo_endpoint.
     * id_token claims always win on conflict - they're signed, the
     * userinfo response merely rides on the access_token/TLS.
     */
    private function fillMissingClaimsFromUserInfo(array $settings, array $claims, string $accessToken): array
    {
        $watched = array_filter([
            $settings['claim_email'] ?? null,
            $settings['claim_username'] ?? null,
            $settings['claim_first_name'] ?? null,
            $settings['claim_last_name'] ?? null,
            $settings['claim_admin'] ?? null,
        ]);

        $missing = array_filter($watched, fn (string $claim) => !array_key_exists($claim, $claims));

        if (empty($missing)) {
            return $claims;
        }

        return $claims + $this->client->fetchUserInfo($settings, $accessToken);
    }

    /**
     * Remembers which Laravel session (and which user) this login produced,
     * keyed by the IdP's session id (sid) - or, if the provider doesn't
     * send one, by subject. This is what lets a Back-Channel Logout
     * notification (see OidcBackchannelLogoutController) find and kill the
     * right session(s), rotate that user's remember-me token, and (via the
     * stored id_token) supply `id_token_hint` for RP-Initiated Logout -
     * all without any browser involvement beyond a small session_id cookie.
     */
    private function recordSession(array $claims, User $user, string $sessionId, string $idToken): void
    {
        $subject = (string) ($claims['sub'] ?? '');

        if ($subject === '') {
            return;
        }

        DB::table('sso_oidc_sessions')->insert([
            'sid' => isset($claims['sid']) ? (string) $claims['sid'] : null,
            'subject' => $subject,
            'session_id' => $sessionId,
            'user_id' => $user->id,
            'id_token' => $idToken,
            'created_at' => now(),
        ]);
    }
}
