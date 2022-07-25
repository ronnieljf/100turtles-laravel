<?php

namespace Database\Seeders;

use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
use App\Models\WalletKey;

class WalletSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
       // WalletKey::factory(20)->create();
        
       $walllet = new WalletKey;
       $walllet->user_id = "1";
       $walllet->email = "oschneider@example.net";
       $walllet->type = "google";
       $walllet->key = "gfdhfgjhgj";
       $walllet->save();

       $walllet = new WalletKey;
       $walllet->user_id = "2";
       $walllet->email = "kacey.bartell@example.net";
       $walllet->type = "google";
       $walllet->key = "vfdvniofdvjiof";
       $walllet->save();

       $walllet = new WalletKey;
       $walllet->user_id = "3";
       $walllet->email = "vonrueden.misael@example.net";
       $walllet->type = "google";
       $walllet->key = "fkofkgokof";
       $walllet->save();

       $walllet = new WalletKey;
       $walllet->user_id = "4";
       $walllet->email = "sibyl.connelly@example.net";
       $walllet->type = "google";
       $walllet->key = "dfkgkghokh";
       $walllet->save();

       $walllet = new WalletKey;
       $walllet->user_id = "5";
       $walllet->email = "christian58@example.com";
       $walllet->type = "google";
       $walllet->key = "hjhkjhkjl";
       $walllet->save();
    }
}
