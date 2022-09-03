<?php
require ('db.php');
require ('dbconf.php');
$db = new db($domain, $table, $user, $pass);
include ("./class.user.php");
include ("./class.posts.php");
include ("./class.passwordreset.php");

header('Access-Control-Allow-Origin: *');
header("Access-Control-Allow-Methods: HEAD, GET, POST, PUT, PATCH, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: X-API-KEY, Origin, X-Requested-With, Content-Type, Accept, Access-Control-Request-Method,Access-Control-Request-Headers, Authorization");
header('Content-Type: application/json');
$method = $_SERVER['REQUEST_METHOD'];
if ($method == "OPTIONS")
{
    header('Access-Control-Allow-Origin: *');
    header("Access-Control-Allow-Headers: X-API-KEY, Origin, X-Requested-With, Content-Type, Accept, Access-Control-Request-Method,Access-Control-Request-Headers, Authorization");
    header("HTTP/1.1 200 OK");
    die();
}

if ($_SERVER['REQUEST_METHOD'] == "GET")
{
    
    
    if ($_GET['url'] == "resetEmail")
    {

        if (isset($_GET['email']))
        {
           Passwordreset::reset($_GET['email'], $db);
        }
        else
        {
            echo '{ Error: "Email not provided" }';
            http_response_code(400);
            die();
        }
        
            echo '{ Error: "Malformed request" }';
            http_response_code(400);
                die();
    }

    if ($_GET['url'] == "verifyPasswordToken")
    {
        if (isset($_GET['token']))
        {
            if (Passwordreset::isTokenValid($_GET['token'], $db))
            {
                echo '{ Success: Password reset token is accepted} ';
                http_response_code(200);
                die();
            } else {
                echo '{ Error: Password reset token could not be found} ';
                http_response_code(404);
                die();
            }
        }
        else
        {
            echo '{ Error: "Token not provided" }';
            http_response_code(400);
            die();
        }
    }
    
    if ($_GET['url'] == "isUserAdmin")
    {
        if (isset($_GET['token']))
        {
            if (User::checkAdminStatus($_GET['token'], $db))
            {
                echo '{ Success: User is admin} ';
                http_response_code(200);
                die();
            } else {
                echo '{ Error: User is not admin } ';
                http_response_code(404);
                die();
            }
        }
        else
        {
            echo '{ Error: "Token not provided" }';
            http_response_code(400);
            die();
        }
    }
    
    if ($_GET['url'] == "isUserVerified")
    {
        if (isset($_GET['username']))
        {
            if (User::getUserVerified($_GET['username'], $db))
            {
                header((isset($_SERVER['SERVER_PROTOCOL']) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0') . ' ' . 200 . ' ' . 'User is verified');
                echo '{ Success: User is verified} ';
                http_response_code(200);
                die();
            } else {
                header((isset($_SERVER['SERVER_PROTOCOL']) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0') . ' ' . 401 . ' ' . 'User is not verified');
                echo '{ Error: User is not verified } ';
                http_response_code(401);
                die();
            }
        }
        else
        {
            header((isset($_SERVER['SERVER_PROTOCOL']) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0') . ' ' . 404 . ' ' . 'User not provided');
            echo '{ Error: "Username not provided" }';
            http_response_code(400);
            die();
        }
    }


    
    
    if ($_GET['url'] == "verifyToken")
    {
        //returns user id
        if (isset($_GET['token']))
        {
            //check if token is valid
            if ($db->query('SELECT token FROM login_tokens WHERE token=:token', array(
                ':token' => sha1($_GET['token'])
            )))
            {
                //get userid
                $userid = $db->query('SELECT user_id FROM login_tokens WHERE token=:token', array(
                    ':token' => sha1($_GET['token'])
                )) [0]['user_id'];
                //get email
                $email = $db->query('SELECT email FROM users WHERE id=:id', array(
                    ':id' => $userid
                )) [0]['email'];
                //get username
                $username = $db->query('SELECT username FROM users WHERE id=:id', array(
                    ':id' => $userid
                )) [0]['username'];
                echo '{ "Token": "' . $_GET['token'] . '", "Uid": "' . $userid . '", "Username": "' . $username . '", "Email": "' . $email . '" }';
                http_response_code(200);
            }
            else
            {
                echo '{ Error: "Invalid Token" }';
                http_response_code(400);
            }
        }
        else
        {
            echo '{ Error: "Malformed request" }';
            http_response_code(400);
        }
    }
    
    
    
    

    
    
    

    else if ($_GET['url'] == "auth")
    {
    }
    
    
    
    else if ($_GET['url'] == "user")
    {
        if (isset($_GET['username']))
        {
            //check if user exists
            if ($db->query('SELECT username FROM users WHERE username=:username', array(
                ':username' => $_GET['username']
            )) [0]['username'])
            {
                echo '{ Username: "True" }';
                http_response_code(200);
                die();
            }
            else
            {
                echo '{ Error: "Invalid Username" }';
                http_response_code(403);
                die();
            }
        }
        
        if (isset($_GET['token']))
        {
            //get the username of the user from token
            if($_GET['information'] == "username"){
                User::getUsernameFromToken($_GET['token'], $db);
            }
        }
        
        
        if (isset($_GET['contact']))
        {
            if (isset($_GET['token']))
            {
                $token = $_COOKIE['POSTOGON_ID'];
                //check if token exists and grab user's id
                if ($user_id = $db->query('SELECT user_id FROM login_tokens WHERE token=:token', array(
                    ':token' => sha1($_GET['token'])
                )) [0]['user_id'])
                {
                    $user_id = $db->query('SELECT user_id FROM login_tokens WHERE token=:token', array(
                        ':token' => sha1($_GET['token'])
                    )) [0]['user_id'];
                }
                else
                {
                    echo '{ Error: "Invalid Token" }';
                    http_response_code(400);
                    die();
                }
                //get userid
                $contact = $db->query('SELECT id FROM users WHERE username=:username', array(
                    ':username' => $_GET['contact']
                )) [0]['id'];
                if ($db->query('SELECT ID FROM contacts WHERE user_id=:userid AND contact_id=:contactid', array(
                    ':userid' => $user_id,
                    ':contactid' => $contact
                )))
                {
                    echo '{ Success: "User is a contact" }';
                    http_response_code(200);
                }
                else
                {
                    echo '{ Error: "User is not a contact" }';
                    http_response_code(400);
                    die();
                }
            }
            else
            {
                echo '{ Error: "You must provide a token" }';
                http_response_code(400);
                die();
            }
        }
    }
    
    
    
    else if ($_GET['url'] == "posts")
    {
        if (isset($_GET['token']))
        {
            $token = $_COOKIE['POSTOGON_ID'];
            //check if token exists and grab user's id
            if ($user_id = $db->query('SELECT user_id FROM login_tokens WHERE token=:token', array(
                ':token' => sha1($_GET['token'])
            )) [0]['user_id'])
            {
                $user_id = $db->query('SELECT user_id FROM login_tokens WHERE token=:token', array(
                    ':token' => sha1($_GET['token'])
                )) [0]['user_id'];
            }
            else
            {
                echo '{ Error: "Invalid Token" }';
                http_response_code(400);
                die();
            }
            if (isset($_GET['feed']))
            {
                if ($_GET['feed'] == "public")
                {
                    $feedoneposts = $db->query('SELECT DISTINCT posts.body, posts.user_id, users.`status`, posts.id, posts.likes, posts.posted_on, users.`username` FROM users, posts , followers
WHERE posts.user_id = followers.user_id
AND users.id = posts.user_id
AND to_whom = 1
AND follower_id = ' . $user_id . ' OR posts.user_id = ' . $user_id . ' AND users.id = posts.user_id AND to_whom = 1 ORDER BY posts.posted_on ' . $order);
                    $response .= "[";
                    foreach ($feedoneposts as $post)
                    {
                        $comments = posts::countPostComments($post['id'], $db);
                        $isLiked = posts::isLiked($post['id'], $user_id, $db);
                        $response .= "{";
                        $response .= '"PostId": ' . $post['id'] . ",";
                        $response .= '"PostBody": "' . $post['body'] . "\",";
                        $response .= '"PostedBy": "' . $post['username'] . "\",";
                        $response .= '"PostedOn": ' . $post['posted_on'] . ",";
                        $response .= '"Comments": ' . $comments . ",";
                        $response .= '"Likes": ' . $post['likes'] . ",";
                        $response .= '"IsLiked": ' . $isLiked . "";
                        $response .= "},";
                    }
                    $response = substr($response, 0, strlen($response) - 1);
                    $response .= "]";
                    function parse($text)
                    {
                        // Damn pesky carriage returns...
                        $text = str_replace("\r\n", "\n", $text);
                        $text = str_replace("\r", "\n", $text);

                        // JSON requires new line characters be escaped
                        $text = str_replace("\n", "\\n", $text);
                        return $text;
                    }
                    echo parse($response);
                }
                else if ($_GET['feed'] == "private")
                {
                    $feedtwoposts = $db->query('SELECT DISTINCT posts.body, posts.user_id, users.`status`, posts.id, posts.likes, posts.posted_on, users.`username` FROM users, posts , contacts
WHERE posts.user_id = contacts.contact_id
AND users.id = posts.user_id
AND to_whom = 2
AND contacts.user_id = ' . $user_id . ' OR posts.user_id = ' . $user_id . ' AND users.id = posts.user_id AND to_whom = 2 ORDER BY posts.posted_on ' . $order);
                    $response .= "[";
                    foreach ($feedtwoposts as $post)
                    {
                        $comments = posts::countPostComments($post['id'], $db);
                        $response .= "{";
                        $response .= '"PostId": ' . $post['id'] . ",";
                        $response .= '"PostBody": "' . $post['body'] . "\",";
                        $response .= '"PostedBy": "' . $post['username'] . "\",";
                        $response .= '"PostedOn": ' . $post['posted_on'] . ",";
                        $response .= '"Comments": ' . $comments . ",";
                        $response .= '"Likes": ' . $post['likes'] . "";
                        $response .= "},";
                    }
                    $response = substr($response, 0, strlen($response) - 1);
                    $response .= "]";
                    function parse($text)
                    {
                        // Damn pesky carriage returns...
                        $text = str_replace("\r\n", "\n", $text);
                        $text = str_replace("\r", "\n", $text);

                        // JSON requires new line characters be escaped
                        $text = str_replace("\n", "\\n", $text);
                        return $text;
                    }
                    echo parse($response);
                }
                else
                {
                    echo '{ Error: "Not a valid feed!" }';
                }
            }
            else
            {
                echo '{ Error: "Feed required!" }';
            }
        }
        else if (isset($_GET['id']))
        {
            if ($db->query('SELECT * FROM posts WHERE id=:id AND to_whom = 1', array(
                ':id' => $_GET['id']
            )))
            {
                $singlePost = $db->query('SELECT * FROM posts WHERE id=:id AND to_whom = 1', array(
                    ':id' => $_GET['id']
                ));
                $response .= "[";
                foreach ($singlePost as $post)
                {
                    $response .= "{";
                    $response .= '"PostId": ' . $post['id'] . ",";
                    $response .= '"PostBody": "' . $post['body'] . "\",";
                    //get username
                    $username = $db->query('SELECT username FROM users WHERE id=:id', array(
                        ':id' => $post['user_id']
                    )) [0]['username'];
                    $response .= '"PostedBy": "' . $username . "\",";
                    $response .= '"Likes": ' . $post['likes'] . "";
                    $response .= "},";
                }
                $response = substr($response, 0, strlen($response) - 1);
                $response .= "]";
                function parse($text)
                {
                    // Damn pesky carriage returns...
                    $text = str_replace("\r\n", "\n", $text);
                    $text = str_replace("\r", "\n", $text);

                    // JSON requires new line characters be escaped
                    $text = str_replace("\n", "\\n", $text);
                    return $text;
                }
                echo parse($response);
            }
            else
            {
                echo '{ Error: "Either Post is private or does not exist" }';
                http_response_code(400);
                die();
            }
        }
        else
        {
            echo '{ Error: "Malformed request" }';
            http_response_code(400);
            die();
        }

    }

    else if ($_GET['url'] == "profile")
    {
        if (isset($_GET['username']))
        {
            if (isset($_GET['feed']))
            {
                if ($_GET['feed'] == "public")
                {
                    //grab user id
                    $user_id = $db->query('SELECT id FROM users WHERE username=:username', array(
                        ':username' => $_GET['username']
                    )) [0]['id'];
                    $publicprofileposts = $db->query('SELECT * FROM posts WHERE user_id=:userid AND to_whom = 1', array(
                        ':userid' => $user_id
                    ));
                    $response .= "[";
                    foreach ($publicprofileposts as $post)
                    {
                        $response .= "{";
                        $response .= '"PostId": ' . $post['id'] . ",";
                        $response .= '"PostBody": "' . $post['body'] . "\",";
                        $response .= '"PostedBy": "' . $_GET['username'] . "\",";
                        $response .= '"Likes": ' . $post['likes'] . "";
                        $response .= "},";
                    }
                    $response = substr($response, 0, strlen($response) - 1);
                    $response .= "]";
                    function parse($text)
                    {
                        // Damn pesky carriage returns...
                        $text = str_replace("\r\n", "\n", $text);
                        $text = str_replace("\r", "\n", $text);

                        // JSON requires new line characters be escaped
                        $text = str_replace("\n", "\\n", $text);
                        return $text;
                    }
                    echo parse($response);
                }
                elseif ($_GET['feed'] == "private")
                {
                    //grab user id
                    $user_id = $db->query('SELECT id FROM users WHERE username=:username', array(
                        ':username' => $_GET['username']
                    )) [0]['id'];
                    $publicprofileposts = $db->query('SELECT * FROM posts WHERE user_id=:userid AND to_whom = 2', array(
                        ':userid' => $user_id
                    ));
                    $response .= "[";
                    foreach ($publicprofileposts as $post)
                    {
                        $response .= "{";
                        $response .= '"PostId": ' . $post['id'] . ",";
                        $response .= '"PostBody": "' . $post['body'] . "\",";
                        $response .= '"PostedBy": "' . $_GET['username'] . "\",";
                        $response .= '"Likes": ' . $post['likes'] . "";
                        $response .= "},";
                    }
                    $response = substr($response, 0, strlen($response) - 1);
                    $response .= "]";
                    function parse($text)
                    {
                        // Damn pesky carriage returns...
                        $text = str_replace("\r\n", "\n", $text);
                        $text = str_replace("\r", "\n", $text);

                        // JSON requires new line characters be escaped
                        $text = str_replace("\n", "\\n", $text);
                        return $text;
                    }
                    echo parse($response);
                   http_response_code(200);
                   die();
                }
                else
                {
                    echo '{ Error: "Not a valid feed!" }';
                   http_response_code(200);
                   die();
                }
            }
            else
            {
                echo '{ Error: "Feed required!" }';
               http_response_code(200);
               die();
            }
        }
        else
        {
            echo '{ Error: "username required!" }';
           http_response_code(200);
           die();
        }
    }
}
else if ($_SERVER['REQUEST_METHOD'] == "POST")
{

    if ($_GET['url'] == "logout")
    {
        $postBody = file_get_contents("php://input");
        $postBody = json_decode($postBody);
        $emailoruser = strtolower($postBody->username);
        $password = $postBody->password;
        //check if token exists
        if ($db->query('SELECT token FROM login_tokens WHERE token=:token', array(
            ':token' => sha1($_GET['token'])
        )))
        {

        }
    }
                            
                                               
       if ($_GET['url'] == "setNewPassword")
       {
                                               //If oldpassword is sent inside this receiving endpoint postbody then we will run the code necessary to change the password and assume user is logged in and in settings
                                               //otherwise, we will assume that the user is in the reset password recovery flow and not require the old password.
           $postBody = file_get_contents("php://input");
           $postBody = json_decode($postBody);
           $oldPassword = $postBody->oldpassword;
           $newPassword = $postBody->newpassword;
           $resetToken = strtolower($postBody->resettoken); //for recovery
           $userToken = strtolower($postBody->usertoken); //for settings
                                               //if user is in recovery
            if($resetToken && !$oldPassword && !$userToken){
                                               //check if user also provided a new password
                                               if($newPassword){
                                                   //check to ensure newpassword is filled in and not whitespace
                                                   if(trim($newPassword)=='')
                                                       {
                                                       echo '{ Error: "New password cannot be left empty!" }';
                                                       http_response_code(400);
                                                       die();
                                                       }
                                                       else
                                                       {
                                                       return passwordreset::setNewPassword($resetToken, $newPassword, $db);
                                                       }
                                               } else {
                                               echo '{ Error: "Malformed Request. New password was not provided in postbody!" }';
                                               http_response_code(400);
                                               die();
                                               }
                                               //if user is in settings
                   } elseif($oldPassword && !$resetToken && $newPassword && $userToken) {
                                               //check to see if oldpassword and newpassword are filled in values
                                               if(trim($oldPassword)=='' || trim($newPassword)=='')
                                               {
                                               echo '{ Error: "Old password and new password cannot be left empty!" }';
                                               http_response_code(400);
                                               die();
                                               }
                                               //make sure they don't match
                                               else if($oldPassword != $newPassword)
                                               {
                                               return user::changePassword($userToken, $oldPassword, $newPassword, $db);
                                               //throw this error if both password match
                                               } else {
                                               echo '{ Error: "Old and new password cannot match!" }';
                                               http_response_code(401);
                                               die();
                                               }
                                        }
                                             else {
                                               echo '{ Error: "Malformed Request. Old or new password was not provided" }';
                                               http_response_code(400);
                                               die();

                   }
                                               
                                               

                    
           //Passwordreset::setNewPassword($resetToken, $newpassword, $db);
            }
        
                                               
                                               
   if ($_GET['url'] == "changeusername")
   {
       $postBody = file_get_contents("php://input");
       $postBody = json_decode($postBody);
       $username = strtolower($postBody->username);
       $token = strtolower($postBody->token);
       User::changeUsernameFromToken($token, $username, $db);
   }
                                               
                                               

                                               

    if ($_GET['url'] == "token")
    {
        $postBody = file_get_contents("php://input");
        $postBody = json_decode($postBody);
        $token = strtolower($postBody->token);
        if (isset($token))
        {
            //check if token exists
            if ($db->query('SELECT token FROM login_tokens WHERE token=:token', array(
                ':token' => sha1($token)
            )))
            {
                //get userid
                $userid = $db->query('SELECT user_id FROM login_tokens WHERE token=:token', array(
                    ':token' => sha1($token)
                )) [0]['user_id'];
                //get email
                $email = $db->query('SELECT email FROM users WHERE id=:id', array(
                    ':id' => $userid
                )) [0]['email'];
                //get username
                $username = $db->query('SELECT username FROM users WHERE id=:id', array(
                    ':id' => $userid
                )) [0]['username'];
                echo '{ "Uid": "' . $userid . '", "Username": "' . $username . '", "Email": "' . $email . '" }';
                http_response_code(200);
            }
            else
            {
                echo '{ Error: "Invalid Token" }';
                http_response_code(400);
            }
        }
    }

    if ($_GET['url'] == "auth")
    {
        $postBody = file_get_contents("php://input");
        $postBody = json_decode($postBody);
        $emailoruser = strtolower($postBody->username);
        $password = $postBody->password;

        if (isset($_GET['token']))
        {
            //check if token exists
            if ($db->query('SELECT token FROM login_tokens WHERE token=:token', array(
                ':token' => sha1($_GET['token'])
            )))
            {
                //get userid
                $userid = $db->query('SELECT user_id FROM login_tokens WHERE token=:token', array(
                    ':token' => sha1($_GET['token'])
                )) [0]['user_id'];
                $cstrong = True;
                $token = bin2hex(openssl_random_pseudo_bytes(64, $cstrong));
                $db->query('INSERT INTO login_tokens (token, user_id) VALUES (:token, :user_id)', array(
                    ':token' => sha1($token) ,
                    ':user_id' => $userid
                ));
                echo '{ "Token": "' . $token . '" }';
                http_response_code(200);
            }
            else
            {
                echo '{ Error: "Invalid Token" }';
                http_response_code(400);
            }
        }

        //check if email exists
        else if ($db->query('SELECT email from users WHERE email=:email', array(
            ':email' => $emailoruser
        )))
        {
            //check if password is valid
            if (password_verify($password, $db->query('SELECT password from users WHERE email=:email', array(
                ':email' => $emailoruser
            )) [0]['password']))
            {
                $cstrong = True;
                $token = bin2hex(openssl_random_pseudo_bytes(64, $cstrong));
                $user_id = $db->query('SELECT id from users WHERE email=:email', array(
                    ':email' => $emailoruser
                )) [0]['id'];
                $db->query('INSERT INTO login_tokens (token, user_id) VALUES (:token, :user_id)', array(
                    ':token' => sha1($token) ,
                    ':user_id' => $user_id
                ));
                //get userid
                $userid = $db->query('SELECT user_id FROM login_tokens WHERE token=:token', array(
                    ':token' => sha1($token)
                )) [0]['user_id'];
                //get email
                $email = $db->query('SELECT email FROM users WHERE id=:id', array(
                    ':id' => $userid
                )) [0]['email'];
                //get username
                $username = $db->query('SELECT username FROM users WHERE id=:id', array(
                    ':id' => $userid
                )) [0]['username'];
                echo '{ "Token": "' . $token . '", "Uid": "' . $userid . '", "Username": "' . $username . '", "Email": "' . $email . '" }';
                http_response_code(200);
            }
            else
            {
                echo "Valid Email but wrong password";
                //set response code to unauthorized
                header((isset($_SERVER['SERVER_PROTOCOL']) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0') . ' ' . 401 . ' ' . 'Valid email but wrong password');
            }
        }
        else
        {
            //check if username exists (since email didn't pass through)
            if ($db->query('SELECT username from users WHERE username=:username', array(
                ':username' => $emailoruser
            )))
            {
                if (password_verify($password, $db->query('SELECT password from users WHERE username=:username', array(
                    ':username' => $emailoruser
                )) [0]['password']))
                {
                    $cstrong = True;
                    $token = bin2hex(openssl_random_pseudo_bytes(64, $cstrong));
                    $user_id = $db->query('SELECT id from users WHERE username=:username', array(
                        ':username' => $emailoruser
                    )) [0]['id'];
                    $db->query('INSERT INTO login_tokens (token, user_id) VALUES (:token, :user_id)', array(
                        ':token' => sha1($token) ,
                        ':user_id' => $user_id
                    ));
                    //get userid
                    $userid = $db->query('SELECT user_id FROM login_tokens WHERE token=:token', array(
                        ':token' => sha1($token)
                    )) [0]['user_id'];
                    //get email
                    $email = $db->query('SELECT email FROM users WHERE id=:id', array(
                        ':id' => $userid
                    )) [0]['email'];
                    //get username
                    $username = $db->query('SELECT username FROM users WHERE id=:id', array(
                        ':id' => $userid
                    )) [0]['username'];
                    echo '{ "Token": "' . $token . '", "Uid": "' . $userid . '", "Username": "' . $username . '", "Email": "' . $email . '" }';
                }
                else
                {
                    echo "Valid Username but wrong password";
                    //set response code to unauthorized
                    http_response_code(401);
                }
            }
            else
            {
                echo "Invalid username or email";
                //set response code to unauthorized
                http_response_code(401);
            }
        }
    }

    else if ($_GET['url'] == "post")
    {
        //get postbody
        $postBody = file_get_contents("php://input");
        $postBody = json_decode($postBody);
        //assign values
        $body = strtolower($postBody->body);
        $token = strtolower($postBody->token);
        //get userid if it exists
        $userid = user::isLoggedIn($token, $db);
        $to_whom = strtolower($postBody->to_whom);
        //check if user is logged in
        if ($userid)
        {
            //check if the postbody length is greater than 180 and also less than one
            if (strlen($body) < 180 && strlen($body) > 1)
            {
                $db->query('INSERT INTO posts (body, user_id, to_whom, likes, posted_on) VALUES (:body, :userid, :towhom, 0,  UNIX_TIMESTAMP())', array(
                    ':body' => $body,
                    ':userid' => $userid,
                    ':towhom' => $to_whom
                ));
                echo '{ "Success": "Post created successfully" }';
                http_response_code(201);
            }
            else
            {
                echo '{ "Error": "Text is longer than 180 characters" }';
                http_response_code(400);
                die();
            }

        } else {
                echo '{ "Error": "Token could not be authorized as a user!" }';
                http_response_code(401);
                die();
        }

    }
    
    else if ($_GET['url'] == "updatepostlike")
    {
        //get postbody
        $postBody = file_get_contents("php://input");
        $postBody = json_decode($postBody);
        //assign values
        $postId = strtolower($postBody->postId);

        $isLiked = strtolower($postBody->isLiked);
        $token = strtolower($postBody->token);
        //get userid if it exists
        $userid = user::isLoggedIn($token, $db);
        //check if user is logged in
        if ($userid)
        {
            switch($isLiked){
            case true:
         //check if the post is liked
if($db->query('SELECT user_id FROM post_likes WHERE post_id=:postid AND user_id=:userid', array(':postid'=>$postId,':userid'=>$userid))){
                $db->query('UPDATE posts SET likes=likes-1 WHERE id=:postid', array(
                    ':postid' => $postId
                ));
            $db->query('DELETE FROM post_likes WHERE post_id=:postid AND user_id=:userid', array(':postid'=>$postId, ':userid'=>$userid));
                echo '{ "Success": "Post unliked successfully." }';
                http_response_code(201);
            }
            else
            {
                echo '{ "Error": "Post could not be unliked because it is not liked." }';
                http_response_code(400);
                die();
            }
            break;
            case false:
        //check if the post is not already liked
if(!$db->query('SELECT user_id FROM post_likes WHERE post_id=:postid AND user_id=:userid', array(':postid'=>$postId,':userid'=>$userid))){
    //increment the count by one
                $db->query('UPDATE posts SET likes=likes+1 WHERE id=:postid', array(
                    ':postid' => $postId
                ));
                //"hard"-write into post_likes table
            $db->query('INSERT INTO post_likes (user_id, post_id) VALUES (:userid, :postid)', array(':userid'=>$userid, ':postid'=>$postId));
                echo '{ "Success": "Post liked successfully." }';
                http_response_code(201);
            }
            else
            {
                echo '{ "Error": "Post could not be liked because it is already liked." }';
                http_response_code(400);
                die();
            }
            break;
            }
        }
        else {
                echo '{ "Error": "Token could not be authorized as a user!" }';
                http_response_code(401);
                die();
        }
    }
    
    else if ($_GET['url'] == "unlikepost")
    {
        //get postbody
        $postBody = file_get_contents("php://input");
        $postBody = json_decode($postBody);
        //assign values
        $postId = strtolower($postBody->body);
        $token = strtolower($postBody->token);
        //get userid if it exists
        $userid = user::isLoggedIn($token, $db);
        //check if user is logged in
        if ($userid)
        {
        //check if the post is not already liked
if(!$db->query('SELECT user_id FROM post_likes WHERE post_id=:postid AND user_id=:userid', array(':postid'=>$postId,':userid'=>$userid))){
                $db->query('UPDATE posts SET likes=likes-1 WHERE id=:postid', array(
                    ':postid' => $postId
                ));
            $db->query('DELETE FROM post_likes WHERE post_id=:postid AND user_id=:userid', array(':postid'=>$postId, ':userid'=>$userid));
                echo '{ "Success": "Post unliked successfully." }';
                http_response_code(201);
            }
            else
            {
                echo '{ "Error": "Post could not be unliked because it is not liked." }';
                http_response_code(400);
                die();
            }

        } else {
                echo '{ "Error": "Token could not be authorized as a user!" }';
                http_response_code(401);
                die();
        }
    }

    else if ($_GET['url'] == "register")
    {
        $postBody = file_get_contents("php://input");
        $postBody = json_decode($postBody);
        $email = strtolower($postBody->email);
        $password = $postBody->password;
        if (filter_var($email, FILTER_VALIDATE_EMAIL))
        {
            if (strlen($password) >= 6 && strlen($password) <= 60)
            {
                if (!$db->query('SELECT email from users WHERE email=:email', array(
                    ':email' => $email
                )))
                {
                    $db->query('INSERT INTO users (email, password, verified) VALUES (:email, :password, :verified)', array(
                        ':email' => $email,
                        ':password' => password_hash($password, PASSWORD_BCRYPT) ,
                        ':verified' => 0
                    ));
                    echo "Success: Account Registered";
                    http_response_code(200);
                }
                else
                {
                    echo "Error: Email exists";
                    //set response code to unauthorized
                    http_response_code(401);
                }
            }
            else
            {
                echo "Error: Password must have at least 6 characters!";
                http_response_code(401);
            }
        }
        else
        {
            echo "Error: E-mail is not valid";
            http_response_code(401);
        }
    }
}

else if ($_SERVER['REQUEST_METHOD'] == "DELETE")
{
    if ($_GET['url'] == "deleteToken")
    {
        if (isset($_GET['token']))
        {
            if ($db->query('SELECT token FROM login_tokens WHERE token=:token', array(
                ':token' => sha1($_GET['token'])
            )))
            {
                $db->query('DELETE FROM login_tokens WHERE token=:token', array(
                    ':token' => sha1($_GET['token'])
                ));
                echo '{ Status: "Success" }';
                http_response_code(200);
            }
            else
            {
                echo '{ Error: "Invalid Token" }';
                http_response_code(400);
            }
        }
        else
        {
            echo '{ Error: "Malformed request" }';
            http_response_code(400);
        }
    }
}
else
{
    http_response_code(405);
}

?>
