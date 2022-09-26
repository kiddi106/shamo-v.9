<?php

namespace App\Http\Controllers\API;

use Exception;
use App\Models\User;
use Illuminate\Http\Request;
use App\Helpers\ResponseFormatter;
use Laravel\Fortify\Rules\Password;
use App\Http\Controllers\Controller;
use Facade\FlareClient\Http\Response;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class UserController extends Controller
{
    public function register(Request $request)
    {
        try {
            // $request->validate([
            //     'name' => ['required', 'string', 'max:255'],
            //     'username' => ['required', 'string', 'max:255', 'unique:users'],
            //     'email' => ['required','string','email','max:255','unique:users'],
            //     'phone' => ['required', 'string', 'max:255'],
            //     'password' => ['required','string', new Password],

            // ]);
            $validator = Validator::make($request->all(),
            [
                
            ]);
            User::create([
                'name' => $request->name,
                'username' => $request->username,
                'email' => $request->email,
                'phone' => $request->phone,
                'password' => Hash::make($request->password),
            ]);
            $user = User::where('email', $request->email)->first();
            
            $tokenResult = $user->createToken('authToken')->plainTextToken;

            return ResponseFormatter::success([
                'access_token' => $tokenResult,
                'token_type' => 'Bearer',
                'user' => $user
            ], 'User Registered');
        } catch (Exception $error){
            return ResponseFormatter::error([
                'message' => 'Something went wrong',
                'error' => $error
            ], 'Authentication Failed', 500);
        }

    }
    public function login(Request $request)
    {
       try {
        $validator = Validator::make($request->all(),[
               'email' => 'required|email',
               'password' => 'required' 
            ]);;
        // $credentials = $request(['email', 'password']);
        if ($validator->fails()) {
            return ResponseFormatter::error(['message' => 'Unauthozired'], 'Authentication Failed', 500);
        }
        $user = User::where('email', $request->email)->first();

        if (! Hash::check($request->password, $user->password, [])) {
            throw new \Exception("Invalid Credentials");
            
        }

        $tokenResult = $user->createToken('authToken')->plainTextToken;

        return ResponseFormatter::success([
            'access_token' => $tokenResult,
            'token_type' => 'Bearer',
            'user' => $user

        ], 'Authenticated');
       } catch (Exception $error) {
        return ResponseFormatter::error([
            'message' => 'Something went wrong',
            'error' => $error
        ], 'Authentication Failed', 500);
       }
    }
    public function fetch(Request $request)
    {
        return ResponseFormatter::success($request->user(), 'Data profile user berhasil diambil');
    }
    public function updateProfile(Request $request)
    {
        $data = $request->all();
        try {
            $validator = Validator::make($data,[
                   'name' => 'required',
                   'username' => 'required',
                   'email' => 'required|email',
                   'phone' => 'required',
                ]);;
            // $credentials = $request(['email', 'password']);
            if ($validator->fails()) {
                return ResponseFormatter::error(['message' => 'Updated must be required fill'], 'filled and required', 500);
            }
        $user = Auth::user();
        $user->update($data);

        return ResponseFormatter::success($user, 'Profile Updated');
        }catch (Exception $error) {
            return ResponseFormatter::error([
                'message' => 'Something went wrong',
                'error' => $error
            ], 'Updated Failed', 500);
           }
    }
    public function logout(Request $request)
    {
        $token = $request->user()->currentAccessToken()->delete();
        return ResponseFormatter::success($token, 'Token Revoked');

    }


}
