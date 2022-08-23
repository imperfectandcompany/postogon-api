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
            <p>This email contains a special code necessary for reset!</p>
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
        echo $email;

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
    }
