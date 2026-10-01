<?php

namespace Pterodactyl\BlueprintFramework\Extensions\ssooidc\Http;

use Illuminate\Support\Facades\Crypt;
use Pterodactyl\BlueprintFramework\Libraries\ExtensionLibrary\Admin\BlueprintAdminLibrary as BlueprintExtensionLibrary;
use RuntimeException;
use Throwable;

/**
 * Small shared helper so every OIDC controller reads settings the same way.
 * BlueprintExtensionLibrary's db* methods work outside of admin views too
 * (see the official migrations guide, which resolves it the same way from
 * a migration) - it's just named after its primary use case.
 */
trait OidcSettingsProvider
{
    protected function oidcSettings(): array
    {
        $blueprint = app(BlueprintExtensionLibrary::class);

        $settings = $blueprint->dbGetMany('{identifier}', [
            'enabled',
            'issuer',
            'client_id',
            'client_secret',
            'scopes',
            'button_text',
            'hide_password_login',
            'claim_email',
            'claim_username',
            'claim_first_name',
            'claim_last_name',
            'claim_admin',
            'claim_admin_value',
            'acr_values',
            'require_amr',
        ]);

        $settings['client_secret'] = $this->decryptClientSecret((string) ($settings['client_secret'] ?? ''));

        return $settings;
    }

    /**
     * client_secret is stored encrypted (via Laravel's APP_KEY-based
     * Crypt facade) since migration 2026_07_23_000004 - Blueprint's
     * dbSet()/dbGet() only serialize values, they don't encrypt them, so
     * without this a client_secret sits in the `settings` table in plain
     * text, readable by anyone with DB/backup access.
     *
     * Falls back to treating the value as already-plaintext if it doesn't
     * decrypt - covers the brief window between deploying this version and
     * the migration actually re-encrypting an existing plaintext value, and
     * fails safe rather than breaking login if that ever happens.
     */
    private function decryptClientSecret(string $value): string
    {
        if ($value === '') {
            return '';
        }

        try {
            return Crypt::decryptString($value);
        } catch (Throwable) {
            return $value;
        }
    }

    /**
     * Refuses to proceed if the panel isn't actually reachable over HTTPS
     * (localhost/127.0.0.1 exempted, for local development). OIDC is only
     * meaningfully secure over TLS - the authorization code and tokens
     * would otherwise cross the network in the clear - so this fails loudly
     * instead of quietly running an insecure flow.
     */
    protected function assertSecureContext(): void
    {
        $appUrl = (string) config('app.url');

        if (preg_match('#^https?://(localhost|127\.0\.0\.1)(:\d+)?(/|$)#i', $appUrl)) {
            return;
        }

        if (!str_starts_with($appUrl, 'https://')) {
            throw new RuntimeException(
                'SSO login refused: app.url (' . $appUrl . ') is not https://. ' .
                'OIDC must not run over an insecure connection.'
            );
        }
    }

    /**
     * Builds an absolute extension URL from the configured app.url, rather
     * than the global url()/request()-based helpers - those infer the
     * scheme from the current request, which is wrong (http instead of
     * https) whenever the panel sits behind a TLS-terminating reverse
     * proxy without Laravel's TrustProxies trusting it. The redirect_uri
     * sent to the OIDC provider must exactly match what's registered
     * there, so guessing wrong here breaks the whole login flow.
     */
    protected function extensionUrl(string $path): string
    {
        return rtrim(config('app.url'), '/') . $path;
    }
}
