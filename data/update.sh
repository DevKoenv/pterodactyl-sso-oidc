#!/bin/sh
# Blueprint runs the *previously installed* version's update.sh, not the
# new one - keep this identical to install.sh's (idempotent) logic so it
# still works no matter which version of this script is on disk.
set -e

FILE1="$PTERODACTYL_DIRECTORY/resources/scripts/components/NavigationBar.tsx"
ORIGINAL1="window.location = '/';"
PATCHED1="window.location = '/extensions/ssooidc/logout'; // blueprintframework:ssooidc"

FILE2="$PTERODACTYL_DIRECTORY/resources/views/layouts/admin.blade.php"
ORIGINAL2="window.location.href = '{{route('auth.login')}}';"
PATCHED2="window.location.href = '/extensions/ssooidc/logout'; // blueprintframework:ssooidc"

patch_one() {
    file="$1"
    original="$2"
    patched="$3"
    label="$4"

    if [ ! -f "$file" ]; then
        echo "FATAL: ssooidc could not find $label at $file - Pterodactyl's directory layout may have changed. Aborting." >&2
        exit 1
    fi

    if grep -qF "blueprintframework:ssooidc" "$file"; then
        echo "ssooidc: $label is already patched, skipping."
        return 0
    fi

    if ! grep -qF "$original" "$file"; then
        echo "FATAL: ssooidc could not find the expected logout redirect line in $label (Pterodactyl's source may have changed since this extension was built). Aborting rather than risk a broken patch." >&2
        exit 1
    fi

    sed -i "s#${original}#${patched}#" "$file"

    if ! grep -qF "blueprintframework:ssooidc" "$file"; then
        echo "FATAL: ssooidc patched $label but the marker is missing afterwards - something went wrong. Aborting." >&2
        exit 1
    fi

    echo "ssooidc: patched $label logout redirect."
}

patch_one "$FILE1" "$ORIGINAL1" "$PATCHED1" "NavigationBar.tsx"
patch_one "$FILE2" "$ORIGINAL2" "$PATCHED2" "admin.blade.php"
