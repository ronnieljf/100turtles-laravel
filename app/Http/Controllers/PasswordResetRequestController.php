<?php

namespace App\Http\Controllers;
use Symfony\Component\HttpFoundation\Response;
use App\Models\User;
use App\Mail\SendMail;
use Illuminate\Support\Facades\Mail;
use Carbon\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

use Illuminate\Http\Request;

class PasswordResetRequestController extends Controller
{
    /**
     * @OA\POST(
     *      path="/reset-password-request",
     *      operationId="sendPasswordResetEmail",
     *      tags={"Reset Password Email"},
     *      summary="Sent a link to reset email",
     *      description="Returns a link email",
     *      @OA\Parameter(
     *          name="email",
     *          required=true,
     *          in="path",
     *          @OA\Schema(
     *              type="email"
     *          )
     *      ),
     *      @OA\Response(
     *          response=200,
     *          description="Check your inbox, we have sent a link to reset email",
     *       ),
     *      @OA\Response(
     *          response=404,
     *          description="Email does not exist"
     *      )
     * )
     */
    public function sendPasswordResetEmail(Request $request){
        // If email does not exist
        if(!$this->validEmail($request->email)) {
            return response()->json([
                'message' => 'Email does not exist.'
            ], Response::HTTP_NOT_FOUND);
        } else {
            // If email exists
            $this->sendMail($request->email);
            return response()->json([
                'message' => 'Check your inbox, we have sent a link to reset email.'
            ], Response::HTTP_OK);            
        }
    }

    public function sendMail($email){
        $token = $this->generateToken($email);
        Mail::to($email)->send(new SendMail($token));
    }
    public function validEmail($email) {
        return !!User::where('email', $email)->first();
    }
    public function generateToken($email){
        $isOtherToken = DB::table('password_resets')->where('email', $email)->first();
        if($isOtherToken) {
            return $isOtherToken->token;
        }
        $token = Str::random(80);;
        $this->storeToken($token, $email);
        return $token;
    }
    public function storeToken($token, $email){
        DB::table('password_resets')->insert([
            'email' => $email,
            'token' => $token,
            'created_at' => Carbon::now()            
        ]);
    }
}
