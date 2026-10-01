<?php

use Illuminate\Support\Facades\DB;
use Illuminate\Database\Migrations\Migration;
use Pterodactyl\BlueprintFramework\Libraries\ExtensionLibrary\Admin\BlueprintAdminLibrary as BlueprintExtensionLibrary;

return new class extends Migration
{
    public function up(): void
    {
        $blueprint = app(BlueprintExtensionLibrary::class);

        $blueprint->dbSetMany('{identifier}', [
            'allow_registration' => '1',
        ]);
    }

    public function down(): void
    {
        DB::table('settings')
            ->where('key', '{identifier}::allow_registration')
            ->delete();
    }
};