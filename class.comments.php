<?php
class Comments {
/*
Function used to create a comment on a post
*/
    
public static function createComment($userId, $commentBody, $postId, $db){
            //check if the comment body length is greater than 160 and also less than one
            if (strlen($commentBody) > 180 || strlen($commentBody) < 1){
                die('incorrect length!');
            }
            //make sure post exists first off...
            if(!$db->query('SELECT id from posts where id=:postid', array(':postid'=>$postId))){
                die('invalid post id');
            }    else {
                $db->query('INSERT INTO comments (comment, user_id, post_id, posted_on) VALUES (:comment, :userid, :postid, UNIX_TIMESTAMP())', array(':comment'=>$commentBody,':userid'=>$userId,':postid'=>$postId));
            }
    }
    
private static function parse($text)
    {
        // Damn pesky carriage returns...
        $text = str_replace("\r\n", "\n", $text);
        $text = str_replace("\r", "\n", $text);

        // JSON requires new line characters be escaped
        $text = str_replace("\n", "\\n", $text);
        return $text;
    }
    
public static function fetch_Comments($postId, $order, $db){
    $result = $db->query('SELECT * FROM comments WHERE post_id=:postid ORDER BY posted_on '.$order, array(':postid'=>$postId));
//form json object
    $response="";
    $response .= "[";
    foreach ($result as $comment)
    {
        $response .= "{";
        $response .= '"CommentId": ' . $comment['ID'] . ",";
        $response .= '"CommentBody": "' . $comment['comment'] . "\",";
        $response .= '"CommentUserId": "' . $comment['user_id'] . "\",";
        $response .= '"PostId": ' . $comment['post_id'] . ",";
        $response .= '"PostedOn": ' . $comment['posted_on']  . "";
        $response .= "},";
    }
    $response = substr($response, 0, strlen($response) - 1);
    $response .= "]";

    $parsedResponse = str_replace("},]","}]",$response);

    return self::parse($parsedResponse);
}
    
}
?>
