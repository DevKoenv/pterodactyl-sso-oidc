<?php

namespace Pterodactyl\BlueprintFramework\Extensions\ssooidc\Http;

use Illuminate\Http\JsonResponse;
use Pterodactyl\Http\Controllers\Controller;

/**
 * Unauthenticated endpoint consumed by the React login page. Only ever
 * exposes what's safe to hand to an unauthenticated browser - no secrets.
 */
class OidcPublicConfigController extends Controller
{
    use OidcSettingsProvider;

    public function index(): JsonResponse
    {
        $settings = $this->oidcSettings();

        return new JsonResponse([
            'enabled' => $settings['enabled'] === '1',
            'button_text' => $settings['button_text'] ?: 'Login with SSO',
            'hide_password_login' => $settings['hide_password_login'] === '1',
            'redirect_url' => $this->extensionUrl('/extensions/{identifier}/redirect'),
        ]);
    }
}
