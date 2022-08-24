<?php

class User {
/**
 * Function to test if user is logged in or not
 * Returns a boolean value of true or false depending on if a user is logged in or not
 */
public static function isLoggedIn($token, $db)
{
		$userid = $db->query('SELECT user_id FROM login_tokens WHERE token=:token', array(
			':token' => sha1($token)
		)) [0]['user_id'];
			//db check to see if the token is valid and also return id, either $userid returns the userid, or it returns false 
		//db check to see if the token is valid
		if ($userid) {
			//return user id
			return $userid;
		} 
	return false;	
}
    
    public static function getUsernameFromToken($token, $db)
    {
        //get the uid and verify token exists at the same time
        $uid = self::isLoggedIn($token, $db);
        //continue inside this condition if uid is found
        if($uid){
            //attempt to get username from uid
            $username = self::getUsernameFromUid($uid, $db);
            //continue inside this condition if username is found
            if($username){
                header((isset($_SERVER['SERVER_PROTOCOL']) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0') . ' ' . 200 . ' ' . 'Username: '.$username.'');
                echo '{ Username: "'.$username.'" }';
                http_response_code(200);
                die();
            } else {
                header((isset($_SERVER['SERVER_PROTOCOL']) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0') . ' ' . 404 . ' ' . 'Username does not exist');
                echo '{ Error: "Username does not exist" }';
                http_response_code(404);
                die();
            }
        } else {
            header((isset($_SERVER['SERVER_PROTOCOL']) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0') . ' ' . 401 . ' ' . 'Token is not valid');
        echo '{ Error: "Token is not valid" }';
        http_response_code(401);
        die();
    }
        }
    

    
        public static function getUsernameFromUid($uid, $db)
{
            $username = $db->query('SELECT username FROM users WHERE id=:userid', array(
                ':userid' => $uid
            )) [0]['username'];
                    //db check to see if the token is valid and also return id, either $userid returns the userid, or it returns false
                //db check to see if the token is valid
                if ($username) {
                    //return user id
                    return $username;
                }
            return false;
        }
        
    public static function changeUsernameFromToken($token, $username, $db)
{
    //get the uid and verify token exists at the same time
    $uid = self::isLoggedIn($token, $db);
    if($uid){
        
        if(!self::doesUsernameExist($username, $db)){
            $db->query('UPDATE users SET username=:username WHERE id=:userid', array(
                ':userid' => $uid, ':username'=>$username
            ));
                header((isset($_SERVER['SERVER_PROTOCOL']) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0') . ' ' . 200 . ' ' . 'Username has been set!');
                echo '{ Username: "'.$username.'" }';
                http_response_code(200);
                die();
            } else {
                header((isset($_SERVER['SERVER_PROTOCOL']) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0') . ' ' . 401 . ' ' . 'Username already taken!');
            echo '{ Error: "Username already taken" }';
            http_response_code(401);
            die();
            }
        }
    else {
        header((isset($_SERVER['SERVER_PROTOCOL']) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0') . ' ' . 401 . ' ' . 'Token is not valid');
    echo '{ Error: "Token is not valid" }';
    http_response_code(401);
    die();
    }
}
    
    
    public static function doesUsernameExist($username, $db)
    {
        //check if user exists
        if ($db->query('SELECT username FROM users WHERE username=:username', array(
            ':username' => $username
        )) [0]['username'])
        {
            return true;
        }
        else
        {
            return false;
        }
    }
    
    }
    
    
