<?php

namespace Pterodactyl\BlueprintFramework\Extensions\sso_oidc\Http;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Pterodactyl\Http\Controllers\Controller;
use Pterodactyl\BlueprintFramework\Extensions\sso_oidc\Services\OidcClientService;
use Throwable;

/**
 * OIDC Back-Channel Logout 1.0 endpoint: the IdP calls this server-to-server
 * (no browser, no cookies) whenever a user's session ends somewhere that
 * isn't a normal Pterodactyl-initiated logout - an admin killing a session
 * in authentik, an account being deactivated, a session expiring, or the
 * user logging out of a different app sharing the same IdP session.
 *
 * This is the complement to OidcLogoutController's RP-Initiated Logout
 * (which handles the browser-driven direction): together they cover both
 * ways a session can end.
 */
class OidcBackchannelLogoutController extends Controller
{
    use OidcSettingsProvider;
    use KillsSsoSessions;

    public function __construct(private OidcClientService $client)
    {
    }

    public function index(Request $request): JsonResponse
    {
        $settings = $this->oidcSettings();

        if ($settings['enabled'] !== '1') {
            return new JsonResponse(['error' => 'invalid_request'], 400);
        }

        $logoutToken = (string) $request->input('logout_token', '');

        if ($logoutToken === '') {
            return new JsonResponse(['error' => 'invalid_request', 'error_description' => 'Missing logout_token.'], 400);
        }

        try {
            $claims = $this->client->verifyLogoutToken($settings, $logoutToken);
        } catch (Throwable $exception) {
            return new JsonResponse(['error' => 'invalid_request', 'error_description' => $exception->getMessage()], 400);
        }

        $sid = isset($claims['sid']) ? (string) $claims['sid'] : null;
        $subject = isset($claims['sub']) ? (string) $claims['sub'] : null;

        if ($sid === null && $subject === null) {
            // verifyLogoutToken() already guarantees at least one of these
            // is present, this is just belt-and-suspenders.
            return new JsonResponse(['error' => 'invalid_request'], 400);
        }

        $matched = $this->killMatchingSessions($sid, $subject);

        Log::info('sso_oidc backchannel-logout received', [
            'looked_up_by' => $sid !== null ? 'sid' : 'subject',
            'sid_present' => $sid !== null,
            'subject_present' => $subject !== null,
            'matched_rows' => $matched,
        ]);

        return new JsonResponse([], 200);
    }
}
