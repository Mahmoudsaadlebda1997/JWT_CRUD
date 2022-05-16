<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;
use App\Http\Controllers\Controller;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Models\User;
use Request;
use Validator;



class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login','register']]);
    }
    public function register(){
        $validator =validator()->make(request()->all(),[
            "name"   => "required|string|min:6",
            "email" => "required|email",
            "password" => "required|min:10|max:30|string",
            "phone"   => "required|numeric"
        ]);
        if($validator->fails()){
            return response()->json([
                'message' => 'Register Failed Due Validation '
            ]);
        }
        $user = User::create(['name'=>request()->get('name'),'email'=> request()->get('email'),'password'=> bcrypt(request()->get('password')),'phone'=> request()->get('phone')]);
    $user->save();
    // To Insert In The Pavot Table
    $countryID = request()->get('country_id');
    $user->countries()->attach([$countryID => ['user_id' =>$user->id]]);
        return response()->json([
            'message' => 'User Succefully Created',
            'user' => $user,
            'country'=>$countryID,
           'token' => $token = JWTAuth::fromUser($user)
        ]);
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login()
    {
        $credentials = request(['email', 'password']);

        if (! $token = JWTAuth::attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $this->respondWithToken($token);
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return response()->json(auth()->user());
    }
    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => config('jwt.ttl')
        ]);
    }
    public function index()
    {
        $users = User::with(['countries' => function($query) {
            $query->select(['name','id']);
        }])->get();
        $result = $users->makeHidden(['created_at','email_verified_at','updated_at','countries.id']);
        return response()->json($result);
    }
    public function show($id)
    {
        $result = User::with(['countries' => function($query) {
            $query->select(['name','id']);
        }])->find($id);
        return response()->json($result);
    }
    public function update(Request $request, $id){
        $user = User::find($id);
        if ($user) {
            $user->update($request->all());
            $response['status'] = 1;
            $response['message'] = 'User updated successfully';
            $response['code'] = 200;
        } else {
            $response['status'] = 0;
            $response['message'] = 'User not found';
            $response['code'] = 404;
        }
        $user->save();
        return response()->json($response);
    }
    public function destroy($id){

        $user = User::find($id);
        if ($user) {
            $user = User::destroy($id);
            $response['status'] = 1;
            $response['message'] = 'User Deleted successfully';
            $response['code'] = 200;
        } else {
            $response['status'] = 0;
            $response['message'] = 'User not found';
            $response['code'] = 404;
        }
        return response()->json($response);
    }
}
