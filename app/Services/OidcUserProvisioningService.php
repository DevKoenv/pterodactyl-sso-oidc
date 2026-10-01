<?php

namespace Pterodactyl\BlueprintFramework\Extensions\ssooidc\Services;

use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Pterodactyl\Models\User;
use Ramsey\Uuid\Uuid;
use RuntimeException;

/**
 * Resolves an authenticated OIDC identity (claims) to a Pterodactyl User,
 * creating or just-in-time-updating the account as needed.
 *
 * Accounts are matched by email on every login. Nothing is persisted to
 * "link" an IdP identity to a panel account beyond the shared email
 * address - the decision is made fresh on every single login.
 */
class OidcUserProvisioningService
{
    public function __construct(private array $settings)
    {
    }

    public function resolve(array $claims): User
    {
        $email = $this->claim($claims, 'claim_email');

        if (!$email) {
            throw new RuntimeException('OIDC provider did not return an email claim.');
        }

        $desiredUsername = $this->deriveUsername($claims, $email);
        $firstName = $this->claim($claims, 'claim_first_name') ?: 'SSO';
        $lastName = $this->claim($claims, 'claim_last_name') ?: 'User';
        $isAdmin = $this->resolveIsAdmin($claims);

        /** @var User|null $user */
        $user = User::where('email', $email)->first();

        if ($user) {
            $user->name_first = $firstName;
            $user->name_last = $lastName;
            // The IdP is the source of truth for admin status on every
            // single SSO login, by design - if the admin claim isn't
            // configured (or doesn't match), that correctly means "not an
            // admin", full stop, even for an account that happened to be
            // root_admin before. Get this wrong on the IdP side (unset
            // claim, or the group missing from the token) and the very
            // next SSO login un-admins the account - see "Why root_admin
            // is fully IdP-controlled" in the README for how to avoid that.
            $user->root_admin = $isAdmin;

            // Only touch the username if the desired value is free (or
            // already belongs to this same user) - never break another
            // account's login by stealing its username.
            if ($desiredUsername !== $user->username && $this->usernameAvailable($desiredUsername, $user->id)) {
                $user->username = $desiredUsername;
            }

            $user->save();

            return $user;
        }

        $user = new User();
        $user->uuid = Uuid::uuid4()->toString();
        $user->email = $email;
        $user->username = $this->uniqueUsername($desiredUsername);
        $user->name_first = $firstName;
        $user->name_last = $lastName;
        $user->root_admin = $isAdmin;
        $user->language = 'en';
        // Password login is never used for JIT-provisioned SSO accounts;
        // a random, unguessable hash is stored because the column is
        // NOT NULL.
        $user->password = Hash::make(Str::random(40));
        $user->save();

        return $user;
    }

    private function claim(array $claims, string $settingsKey): ?string
    {
        $claimName = $this->settings[$settingsKey] ?? null;

        if (!$claimName || !array_key_exists($claimName, $claims)) {
            return null;
        }

        $value = $claims[$claimName];

        return is_array($value) ? null : (string) $value;
    }

    private function resolveIsAdmin(array $claims): bool
    {
        $claimName = $this->settings['claim_admin'] ?? null;
        $expected = $this->settings['claim_admin_value'] ?? null;

        if (!$claimName || $expected === null || $expected === '') {
            return false;
        }

        if (!array_key_exists($claimName, $claims)) {
            return false;
        }

        $value = $claims[$claimName];

        if (is_array($value)) {
            return in_array($expected, $value, true);
        }

        return (string) $value === (string) $expected;
    }

    private function deriveUsername(array $claims, string $email): string
    {
        $raw = $this->claim($claims, 'claim_username') ?: Str::before($email, '@');

        // Pterodactyl usernames are stored lowercase and limited to
        // alphanumeric characters plus a small set of symbols.
        $normalized = Str::of($raw)->lower()->replaceMatches('/[^a-z0-9_.-]/', '');

        return (string) ($normalized->isEmpty() ? Str::of('user')->append(Str::random(6)) : $normalized);
    }

    private function usernameAvailable(string $username, int $exceptUserId): bool
    {
        return !User::where('username', $username)->where('id', '!=', $exceptUserId)->exists();
    }

    private function uniqueUsername(string $desired): string
    {
        $username = $desired;
        $suffix = 1;

        while (User::where('username', $username)->exists()) {
            $username = $desired . $suffix;
            $suffix++;
        }

        return $username;
    }
}
