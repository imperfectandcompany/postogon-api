<?php

class posts {

public static function countPostLikes($postid){	
	if($db->query('SELECT count(*) as total from post_likes WHERE post_id=:postid', array(':postid'=>$postid))){
	return $db->query('SELECT count(*) as total from post_likes WHERE post_id=:postid"', array(':postid'=>$postid))[0]['total'];	
	}
}

public static function countPostComments($postid, $db){	
	if($db->query('SELECT count(*) as total from comments WHERE post_id=:postid', array(':postid'=>$postid))){
	return $db->query('SELECT count(*) as total from comments WHERE post_id=:postid', array(':postid'=>$postid))[0]['total'];	
	}
}

public static function isLiked($postid, $user_id, $db){
	if($db->query('SELECT user_id FROM post_likes WHERE post_id=:postid AND user_id=:userid', array(':postid'=>$postid,':userid'=>$user_id))){
	return "true";
	}
	return "false";
}



}
?>