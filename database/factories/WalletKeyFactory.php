<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;
use App\Models\User;


/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\WalletKey>
 */
class WalletKeyFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition()
    {
       return [
            'email' => User::inRandomOrder()->first()->email,
            'type' => fake()->sentence,
            'key' => Str::random(20),
            'user_id' => User::inRandomOrder()->first()->id,
        ];
    }
}
