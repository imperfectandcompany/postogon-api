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
                echo '{ Username: "'.$username.'" }';
                http_response_code(200);
                die();
            } else {
                echo '{ Error: "Username does not exist" }';
                http_response_code(400);
                die();
            }
        } else {
        echo '{ Error: "Token is not valid" }';
        http_response_code(400);
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
        
}
