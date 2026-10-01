#!/bin/sh
set -e

FILE1="$PTERODACTYL_DIRECTORY/resources/scripts/components/NavigationBar.tsx"
ORIGINAL1="window.location = '/';"
PATCHED1="window.location = '/extensions/ssooidc/logout'; // blueprintframework:ssooidc"

FILE2="$PTERODACTYL_DIRECTORY/resources/views/layouts/admin.blade.php"
ORIGINAL2="window.location.href = '{{route('auth.login')}}';"
PATCHED2="window.location.href = '/extensions/ssooidc/logout'; // blueprintframework:ssooidc"

revert_one() {
    file="$1"
    original="$2"
    patched="$3"
    label="$4"

    if [ ! -f "$file" ]; then
        echo "ssooidc: $label not found at $file, nothing to revert."
        return 0
    fi

    if ! grep -qF "blueprintframework:ssooidc" "$file"; then
        echo "ssooidc: $label has no ssooidc marker, nothing to revert."
        return 0
    fi

    sed -i "s#${patched}#${original}#" "$file"

    if grep -qF "blueprintframework:ssooidc" "$file"; then
        echo "FATAL: ssooidc failed to fully revert the $label patch - marker still present." >&2
        exit 1
    fi

    if ! grep -qF "$original" "$file"; then
        echo "FATAL: ssooidc reverted the marker but the original logout redirect line is missing afterwards in $label." >&2
        exit 1
    fi

    echo "ssooidc: reverted $label logout redirect."
}

revert_one "$FILE1" "$ORIGINAL1" "$PATCHED1" "NavigationBar.tsx"
revert_one "$FILE2" "$ORIGINAL2" "$PATCHED2" "admin.blade.php"

# Blueprint's own removal process does not roll back an extension's
# database migrations (their down() methods are never invoked - confirmed
# by testing: after `blueprint -remove`, both the `settings` rows and the
# `migrations` tracking rows for ssooidc were still present). It only
# deletes files. So we do the database cleanup ourselves here, explicitly,
# instead of relying on a rollback that never happens.
MIGRATIONS="2026_07_23_000000_default_settings
2026_07_23_000001_create_ssooidc_sessions_table
2026_07_23_000002_add_user_id_to_ssooidc_sessions_table
2026_07_23_000003_add_acr_amr_settings
2026_07_23_000004_encrypt_client_secret
2026_07_23_000005_add_id_token_to_ssooidc_sessions_table"

MIGRATIONS_PHP_LIST=$(echo "$MIGRATIONS" | sed "s/^/'/;s/$/',/" | tr -d '\n' | sed 's/,$//')

(
    cd "$PTERODACTYL_DIRECTORY"
    # tinker's REPL (psysh) writes its config/history to $HOME/.config/psysh
    # on startup and aborts if that's not writable - which it isn't here
    # (confirmed: "Writing to directory /var/www/.config/psysh is not
    # allowed", the whole tinker call failed silently before our cleanup
    # code ever ran). Point HOME at a scratch dir just for this call so
    # psysh has somewhere writable, without touching the real environment.
    export HOME="$(mktemp -d)"
    php artisan tinker --execute="
        \$deleted = \Illuminate\Support\Facades\DB::table('settings')->where('key', 'like', 'ssooidc::%')->delete();
        echo \"ssooidc: removed \$deleted settings row(s).\n\";
        \Illuminate\Support\Facades\Schema::dropIfExists('ssooidc_sessions');
        echo \"ssooidc: dropped ssooidc_sessions table (if it existed).\n\";
        \$mig = \Illuminate\Support\Facades\DB::table('migrations')->whereIn('migration', [$MIGRATIONS_PHP_LIST])->delete();
        echo \"ssooidc: removed \$mig migration tracking row(s).\n\";
    "
    rm -rf "$HOME"
)

# Leftover migration .php files are likewise never removed by Blueprint.
for name in $MIGRATIONS; do
    mig_file="$PTERODACTYL_DIRECTORY/database/migrations/$name.php"
    if [ -f "$mig_file" ]; then
        rm -f "$mig_file"
        echo "ssooidc: removed leftover migration file $name.php."
    fi
done
