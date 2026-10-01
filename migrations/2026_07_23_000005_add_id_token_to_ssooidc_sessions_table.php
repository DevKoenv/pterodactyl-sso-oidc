<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

/**
 * Reference-token pattern: rather than putting the full id_token in a
 * cookie (a JWT can be a few hundred bytes to 1-2KB depending on how many
 * claims/groups the provider sends - confirmed to blow past a reverse
 * proxy's response header buffer even unencrypted), it's stored here,
 * keyed by session_id (already tracked in this table). The cookie only
 * ever holds the session_id itself (~40 bytes) as an opaque reference.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('ssooidc_sessions', function (Blueprint $table) {
            $table->text('id_token')->nullable()->after('user_id');
        });
    }

    public function down(): void
    {
        Schema::table('ssooidc_sessions', function (Blueprint $table) {
            $table->dropColumn('id_token');
        });
    }
};
