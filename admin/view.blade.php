{{--
    Deliberately bare content here - no @extends, no @section/@endsection.
    Confirmed straight from Blueprint's own install.sh
    (scripts/commands/extensions/install.sh): it builds
    resources/views/admin/extensions/ssooidc/index.blade.php by copying its
    OWN template first (@extends('layouts.admin'), the icon/name/version/
    GitHub-link/gear-icon header, then `@section('content')
    @yield('extension.config') @yield('extension.description')` - note:
    deliberately left *open*, no @endsection), then appends this file's raw
    content verbatim, and appends the closing `@endsection` itself
    (`echo -e "$(<admin_view)\n@endsection" >> "$AdminBladeConstructor"`).
    So this file's content becomes a continuation of Blueprint's
    already-open 'content' section - not a section of its own.

    Two earlier, wrong attempts at this file both caused real, confirmed
    breakage: (1) adding this file's own @extends('layouts.admin') made
    Blade render the entire admin layout twice (two full
    <div class="wrapper"> page copies stacked on top of each other,
    breaking the settings gear button since its id existed twice in the
    DOM); (2) wrapping this content in @section('extension.config') looked
    more "correct" but doesn't work either - by the time Blade's top-to-
    bottom execution reaches that @section (which is what actually stores
    the content), the @yield('extension.config') call earlier in the
    combined file has *already* executed and found nothing (only the
    @yield('extension.description') default text rendered - Blade's
    sections are populated top-to-bottom in a single pass, so a section
    can't be yielded before it's been defined further down the same file).
--}}
    <div class="row">
        <div class="col-xs-12">
            <div class="box box-primary">
                <div class="box-header with-border">
                    <h3 class="box-title">Redirect / Callback URL</h3>
                </div>
                <div class="box-body">
                    <p>Enter this URL at your OIDC provider as the "Redirect URI" / "Callback URL":</p>
                    <pre>{{ $callbackUrl }}</pre>
                    <p>Optional: for a "Logout URI", Back-Channel Logout is recommended if your provider supports it; Front-Channel Logout is the alternative if it doesn't.</p>
                    <pre>Back-Channel: {{ $backchannelLogoutUrl }}</pre>
                    <pre>Front-Channel: {{ $frontchannelLogoutUrl }}</pre>
                </div>
            </div>

            <form id="config-form" action="{{ $root }}" method="POST">
                {{ csrf_field() }}

                <div class="box box-primary">
                    <div class="box-header with-border">
                        <h3 class="box-title">General</h3>
                    </div>
                    <div class="box-body">
                        <div class="form-group">
                            <label>
                                <input type="checkbox" name="enabled" value="1" @if($enabled === '1') checked @endif />
                                Enable SSO login
                            </label>
                        </div>
                        <div class="form-group">
                            <label>
                                <input type="checkbox" name="hide_password_login" value="1" @if($hide_password_login === '1') checked @endif />
                                Hide username/password login (redirect straight to the provider)
                            </label>
                            <p class="text-muted small">Emergency access: append <code>?auto_sso=0</code> to the login page URL to disable the automatic redirect.</p>
                        </div>
                        <div class="form-group">
                            <label for="button_text">Button Text</label>
                            <input type="text" class="form-control" id="button_text" name="button_text" value="{{ $button_text }}" placeholder="Login with SSO" />
                        </div>
                    </div>
                </div>

                <div class="box box-primary">
                    <div class="box-header with-border">
                        <h3 class="box-title">OIDC Provider</h3>
                    </div>
                    <div class="box-body">
                        <div class="form-group">
                            <label for="issuer">Issuer URL</label>
                            <input type="text" class="form-control" id="issuer" name="issuer" value="{{ $issuer }}" placeholder="https://idp.example.com/realms/example" />
                            <p class="text-muted small">Blueprint fetches <code>{issuer}/.well-known/openid-configuration</code> automatically.</p>
                        </div>
                        <div class="form-group">
                            <label for="client_id">Client ID</label>
                            <input type="text" class="form-control" id="client_id" name="client_id" value="{{ $client_id }}" />
                        </div>
                        <div class="form-group">
                            <label for="client_secret">Client Secret</label>
                            <input type="password" class="form-control" id="client_secret" name="client_secret" value="" autocomplete="new-password" placeholder="{{ $hasClientSecret ? '•••••••• (set - leave blank to keep it)' : 'Enter client secret' }}" />
                            <p class="text-muted small">Stored encrypted and never shown again. Leave blank when saving to keep the current secret unchanged.</p>
                        </div>
                        <div class="form-group">
                            <label for="scopes">Scopes</label>
                            <input type="text" class="form-control" id="scopes" name="scopes" value="{{ $scopes }}" placeholder="openid profile email" />
                        </div>
                    </div>
                </div>

                <div class="box box-primary">
                    <div class="box-header with-border">
                        <h3 class="box-title">Claim Mapping</h3>
                    </div>
                    <div class="box-body">
                        <div class="form-group">
                            <label for="claim_email">Email Claim</label>
                            <input type="text" class="form-control" id="claim_email" name="claim_email" value="{{ $claim_email }}" placeholder="email" />
                        </div>
                        <div class="form-group">
                            <label for="claim_username">Username Claim</label>
                            <input type="text" class="form-control" id="claim_username" name="claim_username" value="{{ $claim_username }}" placeholder="preferred_username" />
                        </div>
                        <div class="form-group">
                            <label for="claim_first_name">First Name Claim</label>
                            <input type="text" class="form-control" id="claim_first_name" name="claim_first_name" value="{{ $claim_first_name }}" placeholder="given_name" />
                        </div>
                        <div class="form-group">
                            <label for="claim_last_name">Last Name Claim</label>
                            <input type="text" class="form-control" id="claim_last_name" name="claim_last_name" value="{{ $claim_last_name }}" placeholder="family_name" />
                        </div>
                        <div class="form-group">
                            <label for="claim_admin">Admin Claim (optional)</label>
                            <input type="text" class="form-control" id="claim_admin" name="claim_admin" value="{{ $claim_admin }}" placeholder="e.g. groups or roles" />
                        </div>
                        <div class="form-group">
                            <label for="claim_admin_value">Admin Claim Value (optional)</label>
                            <input type="text" class="form-control" id="claim_admin_value" name="claim_admin_value" value="{{ $claim_admin_value }}" placeholder="e.g. pterodactyl-admin" />
                            <p class="text-muted small">A user is marked as administrator if the admin claim contains (or equals) this value. Both fields are optional, but work together: if either is left empty, admin status is actively set to <strong>non-admin</strong> on every SSO login - not left unchanged.</p>
                        </div>
                    </div>
                </div>

                <div class="box box-primary">
                    <div class="box-header with-border">
                        <h3 class="box-title">Authentication Strength (optional)</h3>
                    </div>
                    <div class="box-body">
                        <div class="form-group">
                            <label for="acr_values">Requested ACR Values</label>
                            <input type="text" class="form-control" id="acr_values" name="acr_values" value="{{ $acr_values }}" placeholder="provider-specific value" />
                            <p class="text-muted small">Sent as the <code>acr_values</code> request parameter - a hint only, not enforced. Use "Required AMR Values" below for actual enforcement.</p>
                        </div>
                        <div class="form-group">
                            <label for="require_amr">Required AMR Values</label>
                            <input type="text" class="form-control" id="require_amr" name="require_amr" value="{{ $require_amr }}" placeholder="e.g. mfa,otp" />
                            <p class="text-muted small">Comma-separated. If set, login is rejected unless the id_token's <code>amr</code> claim contains at least one of these. Leave blank to skip this check.</p>
                        </div>
                    </div>
                    <div class="box-footer">
                        <button type="submit" name="_method" value="PATCH" class="btn btn-primary">Save</button>
                    </div>
                </div>
            </form>
        </div>
    </div>
