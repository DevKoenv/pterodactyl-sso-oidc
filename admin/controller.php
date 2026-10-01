<?php

namespace Pterodactyl\Http\Controllers\Admin\Extensions\{identifier};

use Illuminate\View\View;
use Illuminate\View\Factory as ViewFactory;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Crypt;
use Pterodactyl\Http\Controllers\Controller;
use Pterodactyl\Http\Requests\Admin\AdminFormRequest;

use Pterodactyl\BlueprintFramework\Libraries\ExtensionLibrary\Admin\BlueprintAdminLibrary as BlueprintExtensionLibrary;

class {identifier}ExtensionController extends Controller
{
    /**
     * Settings keys managed by this extension, used both to load current
     * values for the view and to know what to persist on update().
     * client_secret is handled separately - see index()/update() - it's
     * stored encrypted and never echoed back into the form.
     */
    private const SETTINGS = [
        'enabled',
        'allow_registration',
        'issuer',
        'client_id',
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
    ];

    public function __construct(
        private ViewFactory $view,
        private BlueprintExtensionLibrary $blueprint,
    ) {
    }

    public function index(): View
    {
        $settings = $this->blueprint->dbGetMany('{identifier}', self::SETTINGS);

        return $this->view->make(
            'admin.extensions.{identifier}.index',
            array_merge($settings, [
                'root' => '/admin/extensions/{identifier}',
                'blueprint' => $this->blueprint,
                // Never echoed back - see update() for why.
                'hasClientSecret' => (bool) $this->blueprint->dbGet('{identifier}', 'client_secret'),
                // Built from app.url rather than url() - the latter infers
                // the scheme from the current request, which is wrong
                // (http) behind a TLS-terminating reverse proxy unless
                // TrustProxies is configured for it. This must exactly
                // match the redirect_uri sent to the OIDC provider in
                // OidcSettingsProvider::extensionUrl().
                'callbackUrl' => rtrim(config('app.url'), '/') . '/extensions/{identifier}/callback',
                'backchannelLogoutUrl' => rtrim(config('app.url'), '/') . '/extensions/{identifier}/backchannel-logout',
                'frontchannelLogoutUrl' => rtrim(config('app.url'), '/') . '/extensions/{identifier}/frontchannel-logout',
            ])
        );
    }

    public function update({identifier}SettingsFormRequest $request): RedirectResponse
    {
        $data = $request->settingsPayload();

        // Blueprint's dbSet()/dbGet() only serialize values, they don't
        // encrypt them - a client_secret would otherwise sit in the
        // `settings` table in plain text. An empty submission means "leave
        // the existing secret alone" (the form never echoes the real value
        // back, so there's nothing meaningful to resubmit unless the admin
        // is actively changing it).
        $clientSecret = $data['client_secret'] ?? '';
        unset($data['client_secret']);

        $willHaveSecret = $clientSecret !== '' || $this->blueprint->dbGet('{identifier}', 'client_secret');

        if (($data['enabled'] ?? '0') === '1' && (empty($data['issuer']) || empty($data['client_id']) || !$willHaveSecret)) {
            $this->blueprint->alert('danger', 'Could not enable SSO: Issuer URL, Client ID, and a Client Secret (newly entered or already stored) are required.');

            return redirect()->route('admin.extensions.{identifier}.index');
        }

        if ($clientSecret !== '') {
            $this->blueprint->dbSet('{identifier}', 'client_secret', Crypt::encryptString($clientSecret));
        }

        foreach ($data as $key => $value) {
            $this->blueprint->dbSet('{identifier}', $key, $value);
        }

        return redirect()->route('admin.extensions.{identifier}.index');
    }
}

class {identifier}SettingsFormRequest extends AdminFormRequest
{
    public function rules(): array
    {
        return [
            'enabled' => ['nullable', 'boolean'],
            'allow_registration' => ['nullable', 'boolean'],
            'issuer' => ['nullable', 'string', 'url'],
            'client_id' => ['nullable', 'string'],
            // Always optional at the validation level - blank means "keep
            // the existing secret", enforced as a real requirement (when
            // enabling SSO with none stored yet) in settingsPayload().
            'client_secret' => ['nullable', 'string'],
            'scopes' => ['required', 'string'],
            'button_text' => ['required', 'string', 'max:64'],
            'hide_password_login' => ['nullable', 'boolean'],
            'claim_email' => ['required', 'string'],
            'claim_username' => ['required', 'string'],
            'claim_first_name' => ['required', 'string'],
            'claim_last_name' => ['required', 'string'],
            'claim_admin' => ['nullable', 'string'],
            'claim_admin_value' => ['nullable', 'string'],
            'acr_values' => ['nullable', 'string'],
            'require_amr' => ['nullable', 'string'],
        ];
    }

    public function attributes(): array
    {
        return [
            'enabled' => 'Enabled',
            'allow_registration' => 'Allow Just-in-Time Account Creation',
            'issuer' => 'Issuer URL',
            'client_id' => 'Client ID',
            'client_secret' => 'Client Secret',
            'scopes' => 'Scopes',
            'button_text' => 'Button Text',
            'hide_password_login' => 'Hide Password Login',
            'claim_email' => 'Email Claim',
            'claim_username' => 'Username Claim',
            'claim_first_name' => 'First Name Claim',
            'claim_last_name' => 'Last Name Claim',
            'claim_admin' => 'Admin Claim',
            'claim_admin_value' => 'Admin Claim Value',
            'acr_values' => 'Requested ACR values',
            'require_amr' => 'Required AMR values',
        ];
    }

    /**
     * Normalizes checkbox fields (unchecked inputs are absent from the
     * request entirely) into explicit '0'/'1' strings for dbSet().
     *
     * Named settingsPayload() rather than normalize() because
     * AdminFormRequest already declares normalize(?array $only = null):
     * array, and a subclass can't redeclare it with an incompatible
     * signature.
     */
    public function settingsPayload(): array
    {
        $data = $this->validated();

        $data['enabled'] = $this->boolean('enabled') ? '1' : '0';
        $data['allow_registration'] = $this->boolean('allow_registration') ? '1' : '0';
        $data['hide_password_login'] = $this->boolean('hide_password_login') ? '1' : '0';

        return $data;
    }
}
