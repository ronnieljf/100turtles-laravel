<?php

namespace App\Http\Controllers;
use Illuminate\Http\Request;
use App\Http\Requests\UpdatePasswordRequest;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Support\Facades\DB;
use App\Models\User;

class ChangePasswordController extends Controller
{
    /**
     * @OA\POST(
     *      path="/api/auth/change-password",
     *      operationId="passwordResetProcess",
     *      tags={"Reset Password Email"},
     *      summary="Change password",
     *      description="Returns a message change password",
     *      @OA\Parameter(
     *          name="email",
     *          required=true,
     *          in="query",
     *          @OA\Schema(
     *              type="string"
     *          )
     *      ),
     *      @OA\Parameter(
     *          name="passwordToken",
     *          required=true,
     *          in="query",
     *          @OA\Schema(
     *              type="string"
     *          )
     *      ),
     *      @OA\Parameter(
     *          name="password",
     *          required=true,
     *          in="query",
     *          @OA\Schema(
     *              type="string",
     *              format="password"
     *          )
     *      ),
     *      @OA\Parameter(
     *          name="password_confirmation",
     *          required=true,
     *          in="query",
     *          @OA\Schema(
     *              type="string",
     *              format="password"
     *          )
     *      ),
     *      @OA\Response(
     *          response=200,
     *          description="Password has been updated",
     *          @OA\JsonContent(),
     *       ),
     *       @OA\Response(
     *          response=422,
     *          description="Either your email or token is wrong",
     *          @OA\JsonContent(),
     *       )
     * )
     */
    public function passwordResetProcess(UpdatePasswordRequest $request){
        return $this->updatePasswordRow($request)->count() > 0 ? $this->resetPassword($request) : $this->tokenNotFoundError();
    }
      // Verify if token is valid
    private function updatePasswordRow($request){
        return DB::table('password_resets')->where([
            'email' => $request->email,
            'token' => $request->passwordToken
        ]);
    }
      // Token not found response
    private function tokenNotFoundError() {
        return response()->json([
            'error' => 'Either your email or token is wrong.'
        ],Response::HTTP_UNPROCESSABLE_ENTITY);
    }
      // Reset password
    private function resetPassword($request) {
          // find email
        $userData = User::whereEmail($request->email)->first();
          // update password
        $userData->update([
            'password'=>bcrypt($request->password)
        ]);
          // remove verification data from db
        $this->updatePasswordRow($request)->delete();
          // reset password response
        return response()->json([
            'data'=>'Password has been updated.'
        ],Response::HTTP_CREATED);
    }    
}
