<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

/**
 * Needed so a Back-Channel Logout notification can rotate the affected
 * user's remember-me token, not just kill the session row - otherwise a
 * browser with a still-valid "remember me" cookie silently re-authenticates
 * with a brand new (untracked) session right after the old one is killed.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('ssooidc_sessions', function (Blueprint $table) {
            $table->unsignedInteger('user_id')->nullable()->index()->after('subject');
        });
    }

    public function down(): void
    {
        Schema::table('ssooidc_sessions', function (Blueprint $table) {
            $table->dropColumn('user_id');
        });
    }
};
