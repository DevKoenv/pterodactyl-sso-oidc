<?php

namespace Pterodactyl\BlueprintFramework\Extensions\sso_oidc\Http;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Pterodactyl\Models\User;

/**
 * Shared by OidcBackchannelLogoutController and OidcFrontchannelLogoutController -
 * both ultimately do the same thing (find tracked session(s) by IdP sid or
 * subject, destroy them, rotate the owning user's remember_token, clean up
 * the tracking rows), just triggered through different transports.
 */
trait KillsSsoSessions
{
    /**
     * Returns the number of sessions matched (and killed).
     */
    protected function killMatchingSessions(?string $sid, ?string $subject): int
    {
        $query = DB::table('sso_oidc_sessions');

        if ($sid !== null) {
            $query->where('sid', $sid);
        } elseif ($subject !== null) {
            $query->where('subject', $subject);
        } else {
            return 0;
        }

        $sessions = $query->get();

        $handler = app('session')->driver()->getHandler();

        foreach ($sessions as $session) {
            $handler->destroy($session->session_id);
        }

        // Killing the session row alone isn't a full logout: our SSO login
        // sets a "remember me" cookie (matching Pterodactyl's own behavior),
        // and a browser holding a still-valid one would otherwise silently
        // get a brand new, untracked session on its very next request.
        // Rotating remember_token invalidates that cookie too.
        $userIds = $sessions->pluck('user_id')->filter()->unique();
        if ($userIds->isNotEmpty()) {
            User::whereIn('id', $userIds)->update(['remember_token' => Str::random(60)]);
        }

        DB::table('sso_oidc_sessions')->whereIn('id', $sessions->pluck('id'))->delete();

        // Opportunistic cleanup: rows only ever get removed when consumed
        // here or (for the exact same session) at RP-Initiated Logout, so
        // sessions that just expire without an explicit logout event would
        // otherwise accumulate forever.
        $this->cleanupExpiredSsoSessions();

        return $sessions->count();
    }

    protected function cleanupExpiredSsoSessions(): int
    {
        return DB::table('sso_oidc_sessions')
            ->where('created_at', '<', now()->subDays(30))
            ->delete();
    }
}
