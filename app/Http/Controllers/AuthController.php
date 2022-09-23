<?php

namespace App\Http\Controllers;


use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;


class AuthController extends Controller
{
    public function register(Request $request){
        $fields = $request->validate([
            'name'=>'required|string',
            'email'=>'required|string|unique:users,email',
            'password'=>'required|string|confirmed',
        ]);
        
        // $fields['password']= bcrypt($fields['password']);
        
        //$user = User::create($fields);

        $user = User::create([
            'name'=> $fields['name'],
            'email'=> $fields['email'],
            'password'=> bcrypt($fields['password']),
        ]);

        $token=$user->createToken('myapptoken')->plainTextToken;

        $response=[
            'user'=>$user,
            'token'=>$token,
        ];

        return response($response,201);

    }

    //log in

    public function login(Request $request){
        $fields = $request->validate([
            'email'=>'required|string',
            'password'=>'required|string',
        ]);
        
        // check email
        $user=User::where('email',$fields['email'])->first();
        // check password
        if( !$user || !Hash::check($fields['password'], $user->password)){
            return response([
                'message'=>'Bad creds'
            ], 401);
        }

        $token=$user->createToken('myapptoken')->plainTextToken;

        $response=[
            'user'=>$user,
            'token'=>$token,
        ];

        return response($response,201);

    }

    //log out
    public function logout(Request $request){
        //Auth::user()->AauthAcessToken()->delete();
        $request->user()->tokens()->delete();

        return response()->json([
            'message'=>'Logged out'
        ]);
    } 
}
