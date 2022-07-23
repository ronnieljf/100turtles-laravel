<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Models\User;
use App\Models\WalletKey;
use Validator;
use OpenApi\Annotations as OA;

    /**
 *
 * @OA\Info(
 *      version="v1",
 *      title="Core API",
 *      description="",
 *      @OA\Contact(
 *          email="***@***.com"
 *      )
 * )
 * @OA\Server(
 *      url= L5_SWAGGER_CONST_HOST,
 *      description="*** API Server"
 * )
 * @OA\SecurityScheme(
 *     type="http",
 *     description="API token is required to access this API",
 *     in="header",
 *     scheme="bearer",
 *     securityScheme="bearerAuth",
 * )
 *
 */

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct() {
        $this->middleware('auth:api', ['except' => ['login', 'register', 'loginWallet', 'saveKey']]);
    }
     /**
     * @OA\Post(
     *      path="/login",
     *      operationId="login",
     *      tags={"Login"},
     *      summary="Login User",
     *      description="Returns sesion",
     *      @OA\Response(
     *          response=200,
     *          description="Successful operation",
     *       ),
     *      @OA\Response(
     *          response=400,
     *          description="Bad Request"
     *      ),
     *      @OA\Response(
     *          response=401,
     *          description="Unauthenticated",
     *      ),
     *      @OA\Response(
     *          response=422,
     *          description="Fail"
     *      )
     * )
     */
   
    public function login(Request $request){
    	$validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string|min:6',
        ]);
        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }
        if (! $token = auth()->attempt($validator->validated())) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        return $this->createNewToken($token);
    }
    
    public function loginWallet(Request $request){
    	$validator = Validator::make($request->all(), [
            'key' => 'required|string',
            'type' => 'required|string|min:3',
            'email' => 'required|email',
        ]);
        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }
        $wallet = WalletKey::where('key', '=', $request->key)
                            ->where('type', '=', $request->type)
                            ->where('email', '=', $request->email)->first();
        if(empty($wallet)){
            return response()->json(['error' => 'User not exist'], 401);
        }
        $user = User::find($wallet->user_id);  
        if (! $token = auth()->fromUser($user)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        return $this->createNewToken($token);
    }
    /**
     * @OA\Post(
     *      path="/register",
     *      operationId="register",
     *      tags={"Register"},
     *      summary="Register User",
     *      description="Returns sesion", 
     *      @OA\Response(
     *          response=201,
     *          description="Successful operation",
     *       ),
     *      @OA\Response(
     *          response=400,
     *          description="Bad Request"
     *      ),
     *      @OA\Response(
     *          response=403,
     *          description="Forbidden"
     *      )
     * )
     */
    public function register(Request $request) {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|between:2,100',
            'email' => 'required|string|email|max:100|unique:users',
            'password' => 'required|string|confirmed|min:6',
        ]);
        if($validator->fails()){
            return response()->json($validator->errors()->toJson(), 400);
        }
        $user = User::create(array_merge(
                    $validator->validated(),
                    ['password' => bcrypt($request->password)]
                ));
        return response()->json([
            'message' => 'User successfully registered',
            'user' => $user
        ], 201);
    }

    public function saveKey(Request $request) {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email|max:100',
            'type' => 'required|string|between:2,100',
            'key' => 'required|string',
        ]);
        if($validator->fails()){
            return response()->json($validator->errors()->toJson(), 400);
        }
        $user = User::where('email', '=', $request->email)->first();
        if(empty($user)){
            return response()->json('User not exist', 401);
        }
        $walletsKeys = new WalletKey();
        $walletsKeys->user_id = $user->id;
        $walletsKeys->email = $request->email;
        $walletsKeys->type = $request->type;
        $walletsKeys->key = $request->key;
        $walletsKeys->save(); 
        return response()->json([
            'message' => 'Wallets Keys successfully registered',
            'walletsKeys' => $walletsKeys
        ], 201);
    }

        /**
     * @OA\Post(
     *      path="/logout",
     *      operationId="logout",
     *      tags={"Logout"},
     *      summary="User successfully signed out",
     *      @OA\Response(
     *          response=201,
     *          description="Successful operation",
     *       ),
     * 
     * )
     */
    public function logout() {
        auth()->logout();
        return response()->json(['message' => 'User successfully signed out']);
    }
    /**
     * @OA\Post(
     *      path="/refresh",
     *      operationId="refresh",
     *      tags={"Refresh"},
     *      summary="Refresh Token",
     *      @OA\Response(
     *          response=201,
     *          description="Successful operation"
     *      ),
     * )
     */
    public function refresh() {
        return $this->createNewToken(auth()->refresh());
    }
    /**
     * @OA\Get(
     *      path="user-profile",
     *      operationId="userProfile",
     *      summary="Get user information",
     *      description="Returns data",
     *      @OA\Parameter(
     *          name="id",
     *          required=true,
     *          in="path",
     *          @OA\Schema(
     *              type="integer"
     *          )
     *      ),
     *      @OA\Response(
     *          response=200,
     *          description="Successful operation",
     *       ),
     *      @OA\Response(
     *          response=400,
     *          description="Bad Request"
     *      ),
     *      @OA\Response(
     *          response=401,
     *          description="Unauthenticated",
     *      ),
     *      @OA\Response(
     *          response=403,
     *          description="Forbidden"
     *      )
     * )
     */
    public function userProfile() {
        return response()->json(auth()->user());
    }
    /**
     * @OA\Post(
     *      path="/createnewtoken",
     *      operationId="createNewToken",
     *      summary="Create new token",
     *      @OA\Response(
     *          response=201,
     *          description="Successful operation"
     *      ),
     * )
     */
    protected function createNewToken($token){
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60,
            'user' => auth()->user()
        ]);
    }
}