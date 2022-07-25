<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Notifications\Notifiable;

class WalletKey extends Model
{
    use HasFactory, Notifiable;

    protected $fillable = [
        'email',
        'type',
        'key',
    ];

    //Relation One to Many (reverse)
    public function user(){
        return $this->belongsTo(User::class);
    }
    
}
