<?php

namespace Pterodactyl\BlueprintFramework\Extensions\ssooidc\Http;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Pterodactyl\Http\Controllers\Controller;
use Pterodactyl\BlueprintFramework\Extensions\ssooidc\Services\OidcClientService;
use RuntimeException;

class OidcRedirectController extends Controller
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

        $this->assertSecureContext();

        $state = bin2hex(random_bytes(32));
        $nonce = bin2hex(random_bytes(32));
        $codeVerifier = bin2hex(random_bytes(32));

        $now = time();
        $expiresAt = $now + 600; // 10 minutes

        $attempts = $request->session()->get('ssooidc.attempts', []);

        if (!is_array($attempts)) {
            $attempts = [];
        }

        // Remove malformed and expired attempts.
        $attempts = array_filter(
            $attempts,
            static fn (mixed $attempt): bool =>
                is_array($attempt)
                && is_int($attempt['expires_at'] ?? null)
                && $attempt['expires_at'] >= $now
        );

        // Keep at most three existing attempts before adding this one.
        // This limits session growth while allowing multiple browser tabs.
        if (count($attempts) >= 4) {
            uasort(
                $attempts,
                static fn (array $a, array $b): int =>
                    ($a['created_at'] ?? 0) <=> ($b['created_at'] ?? 0)
            );

            $attempts = array_slice($attempts, -3, null, true);
        }

        $loginHint = $request->query('login_hint');

        $attempts[$state] = [
            'nonce' => $nonce,
            'code_verifier' => $codeVerifier,
            'intended' => $this->safeRedirectPath($request->query('redirect_to')),
            'login_hint' => is_string($loginHint) ? $loginHint : null,
            'created_at' => $now,
            'expires_at' => $expiresAt,
        ];

        $request->session()->put('ssooidc.attempts', $attempts);

        $redirectUri = $this->extensionUrl('/extensions/{identifier}/callback');

        $authorizationUrl = $this->client->buildAuthorizationUrl(
            $settings,
            $redirectUri,
            $state,
            $nonce,
            $codeVerifier,
            is_string($loginHint) && $loginHint !== '' ? $loginHint : null
        );

        return redirect()->away($authorizationUrl);
    }

    private function safeRedirectPath(mixed $value): string
    {
        if (!is_string($value) || $value === '') {
            return '/';
        }

        // Only allow a local absolute path.
        if (!str_starts_with($value, '/')) {
            return '/';
        }

        // Reject protocol-relative URLs and backslash-based URL variants.
        if (
            str_starts_with($value, '//')
            || str_starts_with($value, '/\\')
            || str_contains($value, '\\')
        ) {
            return '/';
        }

        // Reject header-injection/control characters.
        if (preg_match('/[\x00-\x1F\x7F\r\n]/', $value)) {
            return '/';
        }

        return $value;
    }
}