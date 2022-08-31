<?php

class Passwordreset {

public static function reset($email, $db)
{
        //is email valid?
    if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
        //is email in database?
                    if (self::doesEmailExist($email, $db))
                    {
            //generate a random token for resetting
                $cstrong = True;
                $token = bin2hex(openssl_random_pseudo_bytes(64, $cstrong));
                        

               //gets the user id associated with the email
                $user_id = $db->query('SELECT id FROM users where email=:email', array(':email'=>$email))[0]['id'];
                //delete all prior reset tokens before generating a new one
                $db->query('DELETE FROM password_tokens WHERE user_id=:userid', array(
                    ':userid' => $user_id
                ));
                //insert the random generated token into the password_token and associate it with newly matched user id from the email
            $db->query('INSERT INTO password_tokens (token, user_id) VALUES (:token, :user_id)', array(':token'=>sha1($token), ':user_id'=>$user_id));

            $to = $email;
            $subject = "Password Reset - Postogon";
            $message = "
            <html>
            <head>
            <title>Postogon</title>
            </head>
            <body>
            <p>This email contains a special code necessary to reset your account's password!</p>
            <table>
            <tr>
            <th>Account Email</th>
            <th>Token</th>
            </tr>
            <tr>
            <td>".$email."</td>
            <td>".$token."</td>
            </tr>
            </table>
            </body>
            </html>
            ";
            // Always set content-type when sending HTML email
            $headers = "MIME-Version: 1.0" . "\r\n";
            $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";
            // More headers
            $headers .= 'From: <noreply@postogon.com>' . "\r\n";
            mail($to,$subject,$message,$headers);
    
            echo '{ Success: "Generated password reset token for email:'.$email.'" }';
            http_response_code(200);
            die();
            } else {
                echo '{ Error: "Email does not exist" }';
                http_response_code(400);
                die();
            }
        } else {
            echo '{ Error: "Email syntax is not valid!" }';
            http_response_code(400);
            die();
        }
    }

    public static function doesEmailExist($email, $db)
    {

            //check if user exists
            if ($db->query('SELECT email FROM users WHERE email=:email', array(
                ':email' => $email
            )) [0]['email'])
            {
               return true;
            }
            else
            {
                return false;
            }

    }

    public static function isTokenValid($token, $db)
    {
        if ($db->query('SELECT token FROM password_tokens WHERE token=:token', array(
            ':token' => sha1($token)
        )) [0]['token'])
        {
           return true;
        }
        else
        {
            return false;
        }

    }
    
    public static function getUidFromResetToken($resetToken, $db)
    {
            $userid = $db->query('SELECT user_id FROM password_tokens WHERE token=:token', array(
                ':token' => sha1($resetToken)
            )) [0]['user_id'];
                //db check to see if the token is valid and also return id, either $userid returns the userid, or it returns false
            //db check to see if the token is valid
            if ($userid) {
                //return user id
                return $userid;
            }
        return false;
    }
    
    
    public static function doesPasswordAlreadyBelongToUserWithId($newpassword, $uid, $db)
    {
        //check if password is valid
        if (password_verify($newpassword, $db->query('SELECT password FROM users WHERE id=:uid', array(
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
    
    
    public static function deletePasswordResetToken($resetToken, $db)
    {
                //check to see if token exists
                if ($db->query('SELECT token FROM password_tokens WHERE token=:token', array(
                    ':token' => sha1($resetToken)
                )))
                {
                    $db->query('DELETE FROM password_tokens WHERE token=:token', array(
                        ':token' => sha1($resetToken)
                    ));
                    //successful removal of passwordresettoken
                    return true;
                }
                else
                {
                    //could not find token so could not delete token
                    return false;
                }
    }
    
    public static function setNewPassword($resetToken, $newpassword, $db)
{
    //get the uid and verify password reset token exists at the same time
    $uid = self::getUidFromResetToken($resetToken, $db);
    if($uid){
        //check and see if the password is not already the users password (lol)
        if(!self::doesPasswordAlreadyBelongToUserWithId($newpassword, $uid, $db)){
            //since password does not already belong to user with that id, continue to update user with that password.
            $db->query('UPDATE users SET password=:password WHERE id=:userid', array(
                ':userid' => $uid, ':password'=>password_hash($newpassword, PASSWORD_BCRYPT)
            ));
                    //check to see if password is now the current password, if so remove reset token...
                    if(self::doesPasswordAlreadyBelongToUserWithId($newpassword, $uid, $db)){
                        //if successful in deleting reset token, return endpoint as succes.
                        if(self::deletePasswordResetToken($resetToken, $db)){
                            header((isset($_SERVER['SERVER_PROTOCOL']) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0') . ' ' . 200 . ' ' . 'Password has been set!');
                            echo '{ Success: "Password set to: '.$newpassword.' and password reset token removed." }';
                            http_response_code(200);
                            die();
                        } else {
                            //throw error since password token removal returned false
                            header((isset($_SERVER['SERVER_PROTOCOL']) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0') . ' ' . 401 . ' ' . 'Password reset token not found!');
                            echo '{ Error: "Password reset token could not be located in database and therefore was not removed." }';
                            http_response_code(404);
                            die();
                        }
                        //throw error since current password was not updated to the intended new password...
                    } else {
                        header((isset($_SERVER['SERVER_PROTOCOL']) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0') . ' ' . 401 . ' ' . 'Password could not update');
                        echo '{ Error: "Password was not able to be set for user." }';
                        http_response_code(401);
                        die();
                    }
            } else {
                header((isset($_SERVER['SERVER_PROTOCOL']) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0') . ' ' . 401 . ' ' . 'Password already belonged to user!');
            echo '{ Error: "Password already belongs to user!" }';
            http_response_code(401);
            die();
            }
        }
    else {
        header((isset($_SERVER['SERVER_PROTOCOL']) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0') . ' ' . 401 . ' ' . 'Token is not valid');
    echo '{ Error: "Password reset token is not valid." }';
    http_response_code(401);
    die();
    }
}
    
    
    

    }
