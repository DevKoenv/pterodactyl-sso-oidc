<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

/**
 * Maps an IdP session (sid, falling back to sub if the provider doesn't
 * send one) to the Laravel session it produced, so a Back-Channel Logout
 * notification can find and destroy the right Pterodactyl session(s)
 * without a browser being involved at all.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('ssooidc_sessions', function (Blueprint $table) {
            $table->id();
            $table->string('sid')->nullable()->index();
            $table->string('subject')->index();
            $table->string('session_id');
            $table->timestamp('created_at')->nullable();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('ssooidc_sessions');
    }
};
