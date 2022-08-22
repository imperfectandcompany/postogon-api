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
}