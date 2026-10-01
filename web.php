<?php

use Illuminate\Support\Facades\Route;
use Pterodactyl\BlueprintFramework\Extensions\ssooidc\Http\OidcRedirectController;
use Pterodactyl\BlueprintFramework\Extensions\ssooidc\Http\OidcCallbackController;
use Pterodactyl\BlueprintFramework\Extensions\ssooidc\Http\OidcPublicConfigController;
use Pterodactyl\BlueprintFramework\Extensions\ssooidc\Http\OidcLogoutController;
use Pterodactyl\BlueprintFramework\Extensions\ssooidc\Http\OidcBackchannelLogoutController;
use Pterodactyl\BlueprintFramework\Extensions\ssooidc\Http\OidcFrontchannelLogoutController;
use Pterodactyl\Http\Middleware\VerifyCsrfToken;

// becomes /extensions/{identifier}/redirect - kicks the browser off to the
// configured OIDC provider's authorization endpoint.
Route::get('/redirect', [OidcRedirectController::class, 'index']);

// becomes /extensions/{identifier}/callback - the OIDC redirect_uri. Must
// stay unauthenticated, since the browser has no panel session yet.
Route::get('/callback', [OidcCallbackController::class, 'index']);

// becomes /extensions/{identifier}/config - public, secret-free settings
// consumed by the React login page component.
Route::get('/config', [OidcPublicConfigController::class, 'index']);

// becomes /extensions/{identifier}/logout - reached after Pterodactyl's own
// logout button already ended the panel session (see data/install.sh),
// additionally ends the IdP session via RP-Initiated Logout.
Route::get('/logout', [OidcLogoutController::class, 'index']);

// becomes /extensions/{identifier}/backchannel-logout - server-to-server
// OIDC Back-Channel Logout notification target. POSTed to directly by the
// IdP with no browser/session involved, so it can't carry a Pterodactyl
// CSRF token - Blueprint's web router still runs the full Laravel 'web'
// middleware group (including CSRF) despite having no auth of its own,
// confirmed the hard way (a live authentik instance got HTTP 419 back).
Route::post('/backchannel-logout', [OidcBackchannelLogoutController::class, 'index'])
    ->withoutMiddleware(VerifyCsrfToken::class);

// becomes /extensions/{identifier}/frontchannel-logout - loaded as a hidden
// iframe on the IdP's own logout page (GET, no body/signature - the spec
// relies on iss+sid query params only).
Route::get('/frontchannel-logout', [OidcFrontchannelLogoutController::class, 'index']);
