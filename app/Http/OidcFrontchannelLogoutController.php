<?php

namespace Pterodactyl\BlueprintFramework\Extensions\sso_oidc\Http;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Log;
use Pterodactyl\Http\Controllers\Controller;
use Pterodactyl\BlueprintFramework\Extensions\sso_oidc\Services\OidcDiscoveryService;
use Throwable;

/**
 * OIDC Front-Channel Logout 1.0 endpoint: loaded as a hidden iframe on the
 * IdP's own logout page (GET, no body, no signature - the spec relies on
 * `iss`+`sid` query parameters alone). This is the synchronous sibling of
 * OidcBackchannelLogoutController: it fires the instant the IdP's logout
 * page renders rather than through an async task queue, but is inherently
 * less reliable - browsers increasingly restrict third-party iframes, and
 * some panel/proxy configurations send X-Frame-Options or a CSP
 * frame-ancestors policy that blocks this endpoint from being framed at
 * all (see the README for how to loosen that if needed).
 *
 * There's no signature to verify here, unlike Back-Channel Logout's
 * logout_token - so only `sid` is trusted for the lookup (a 64-character
 * SHA-256 hash, not realistically guessable), never `subject` alone, which
 * would be far weaker to trust from an unauthenticated GET request.
 */
class OidcFrontchannelLogoutController extends Controller
{
    use OidcSettingsProvider;
    use KillsSsoSessions;

    public function __construct(private OidcDiscoveryService $discovery)
    {
    }

    public function index(Request $request): Response
    {
        $response = new Response('', 200, [
            // Never cache this response, and never let it look like real
            // page content - it's meant to be an invisible iframe target.
            'Cache-Control' => 'no-cache, no-store',
            'Content-Type' => 'text/html',
        ]);

        $settings = $this->oidcSettings();

        if ($settings['enabled'] !== '1') {
            return $response;
        }

        $sid = $request->query('sid');
        if (!$sid) {
            return $response;
        }

        $iss = $request->query('iss');
        if ($iss && !$this->issuerMatches($settings, (string) $iss)) {
            return $response;
        }

        $matched = $this->killMatchingSessions((string) $sid, null);

        Log::info('sso_oidc frontchannel-logout received', [
            'issuer_present' => is_string($iss) && $iss !== '',
            'sid_present' => is_string($sid) && $sid !== '',
            'matched_rows' => $matched,
        ]);

        return $response;
    }

    /**
     * Best-effort sanity check, not real security (GET query params can be
     * set to anything by anyone) - just avoids acting on a request that
     * doesn't even claim to be from the configured provider.
     */
    private function issuerMatches(array $settings, string $iss): bool
    {
        try {
            $document = $this->discovery->discover($settings['issuer']);
        } catch (Throwable) {
            return false;
        }

        $expectedIssuer = $document['issuer'] ?? rtrim($settings['issuer'], '/');

        return hash_equals($expectedIssuer, $iss);
    }
}
