<?php

namespace Pterodactyl\BlueprintFramework\Extensions\ssooidc\Http;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Pterodactyl\Http\Controllers\Controller;
use Pterodactyl\Models\User;
use Pterodactyl\BlueprintFramework\Extensions\ssooidc\Services\OidcClientService;
use Pterodactyl\BlueprintFramework\Extensions\ssooidc\Services\OidcUserProvisioningService;
use RuntimeException;

class OidcCallbackController extends Controller
{
    use OidcSettingsProvider;
    use KillsSsoSessions;

    public function __construct(private OidcClientService $client)
    {
    }

    public function index(Request $request): RedirectResponse
    {
        $settings = $this->oidcSettings();

        if ($settings['enabled'] !== '1') {
            throw new RuntimeException('SSO login is not enabled.');
        }

        $state = (string) $request->query('state');

        if (!preg_match('/^[a-f0-9]{64}$/D', $state)) {
            throw new RuntimeException('Invalid OIDC state parameter.');
        }

        $attempts = $request->session()->get('ssooidc.attempts', []);

        if (!is_array($attempts)) {
            throw new RuntimeException('Invalid OIDC login session.');
        }

        $attempt = $attempts[$state] ?? null;

        // Consume the attempt immediately. Each state value is one-time use,
        // including when token exchange or claim validation fails.
        unset($attempts[$state]);
        $request->session()->put('ssooidc.attempts', $attempts);

        if (!is_array($attempt)) {
            throw new RuntimeException('Invalid or expired OIDC login attempt.');
        }

        $now = time();
        $expiresAt = $attempt['expires_at'] ?? 0;

        if (!is_int($expiresAt) || $expiresAt < $now) {
            throw new RuntimeException('OIDC login attempt has expired.');
        }

        $expectedNonce = $attempt['nonce'] ?? null;
        $codeVerifier = $attempt['code_verifier'] ?? null;
        $intended = $attempt['intended'] ?? '/';

        if (
            !is_string($expectedNonce)
            || $expectedNonce === ''
            || !is_string($codeVerifier)
            || $codeVerifier === ''
            || !is_string($intended)
        ) {
            throw new RuntimeException('OIDC login attempt is incomplete.');
        }

        $error = $request->query('error');

        if (is_string($error) && $error !== '') {
            throw new RuntimeException('OIDC provider returned an error: ' . $error);
        }

        $code = $request->query('code');

        if (!is_string($code) || $code === '') {
            throw new RuntimeException('Missing authorization code.');
        }

        $redirectUri = $this->extensionUrl('/extensions/{identifier}/callback');

        $tokens = $this->client->exchangeCode(
            $settings,
            $code,
            $redirectUri,
            $codeVerifier
        );

        $claims = $this->client->verifyIdToken(
            $settings,
            $tokens['id_token'],
            $expectedNonce
        );

        $this->assertAmrSatisfied($settings, $claims);

        if (!empty($tokens['access_token'])) {
            $claims = $this->fillMissingClaimsFromUserInfo(
                $settings,
                $claims,
                (string) $tokens['access_token']
            );
        }

        $provisioning = new OidcUserProvisioningService($settings);
        $user = $provisioning->resolve($claims);

        // Mirrors Pterodactyl's own login response, without the TOTP
        // checkpoint because authentication was handled by the IdP.
        $request->session()->regenerate();
        Auth::guard()->login($user, true);

        $sessionId = $request->session()->getId();
        $this->recordSession(
            $claims,
            $user,
            $sessionId,
            (string) $tokens['id_token']
        );

        $this->cleanupExpiredSsoSessions();

        setcookie('ssooidc_idth', $sessionId, [
            'expires' => time() + ((int) config('session.lifetime', 720) * 60),
            'path' => '/',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);

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

        DB::table('ssooidc_sessions')->insert([
            'sid' => isset($claims['sid']) ? (string) $claims['sid'] : null,
            'subject' => $subject,
            'session_id' => $sessionId,
            'user_id' => $user->id,
            'id_token' => Crypt::encryptString($idToken),
            'created_at' => now(),
        ]);
    }
}
