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
    
    
    public static function confirmPasswordBelongsToUid($oldpassword, $uid, $db)
    {
        //check if password is valid
        if (password_verify($oldpassword, $db->query('SELECT password FROM users WHERE id=:uid', array(
            ':uid' => $uid
        )) [0]['password']))
        {
            return true;
        }
        else
        {
            return false;
        }
    }
    
    
    
    public static function changePassword($userToken, $oldpassword, $newpassword, $db)
{
    //get the uid and verify token exists at the same time
    $uid = self::isLoggedIn($userToken, $db);
    //token exists? OK! Continue...
    if($uid){
        //check and confirm the old password belongs to the user...
        if(self::confirmPasswordBelongsToUid($oldpassword, $uid, $db)){
            //since the old provided password does belong to user with that id, continue to update user with the newly provided password.
            $db->query('UPDATE users SET password=:password WHERE id=:userid', array(
                ':userid' => $uid, ':password'=>password_hash($newpassword, PASSWORD_BCRYPT)
            ));
                    //check to see if the NEW password is now the current password
                    if(self::confirmPasswordBelongsToUid($newpassword, $uid, $db)){
                        //if successful in updating password return success
                            header((isset($_SERVER['SERVER_PROTOCOL']) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0') . ' ' . 200 . ' ' . 'Password has been set!');
                            echo '{ Success: "Password changed to: '.$newpassword.'" }';
                            http_response_code(200);
                            die();
                        //throw error since current password was not updated to the intended new password...
                    } else {
                        header((isset($_SERVER['SERVER_PROTOCOL']) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0') . ' ' . 401 . ' ' . 'Password could not update');
                        echo '{ Error: "Password was not able to be changed to the new password for user." }';
                        http_response_code(401);
                        die();
                    }
            } else {
                header((isset($_SERVER['SERVER_PROTOCOL']) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0') . ' ' . 401 . ' ' . 'Password already belonged to user!');
            echo '{ Error: "Old password does not belong to user!" }';
            http_response_code(401);
            die();
            }
        }
    else {
        header((isset($_SERVER['SERVER_PROTOCOL']) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0') . ' ' . 401 . ' ' . 'Token is not valid');
    echo '{ Error: "User Token is not valid." }';
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
    
    
