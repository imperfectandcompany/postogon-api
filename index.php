<?php
require ('db.php');
require ('dbconf.php');
$db = new db($domain, $table, $user, $pass);

  
header('Access-Control-Allow-Origin: *');
header("Access-Control-Allow-Methods: HEAD, GET, POST, PUT, PATCH, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: X-API-KEY, Origin, X-Requested-With, Content-Type, Accept, Access-Control-Request-Method,Access-Control-Request-Headers, Authorization");
header('Content-Type: application/json');
$method = $_SERVER['REQUEST_METHOD'];
if ($method == "OPTIONS") {
header('Access-Control-Allow-Origin: *');
header("Access-Control-Allow-Headers: X-API-KEY, Origin, X-Requested-With, Content-Type, Accept, Access-Control-Request-Method,Access-Control-Request-Headers, Authorization");
header("HTTP/1.1 200 OK");
die();
}


if ($_SERVER['REQUEST_METHOD'] == "GET")
{
    if ($_GET['url'] == "auth")
    {
        //returns user id
           if (isset($_GET['token'])){
                //check if token is valid
                if($db->query('SELECT token FROM login_tokens WHERE token=:token', array(':token'=>sha1($_GET['token'])))){
                        $userid = $db->query('SELECT user_id FROM login_tokens WHERE token=:token', array(':token'=>sha1($_GET['token'])))[0]['user_id'];                
                        echo '{ UserId: '.$userid.' }';
                        http_response_code(200);  
                } else {
                    echo '{ Error: "Invalid Token" }';
                    http_response_code(400);
                }               
                }
            else {
                echo '{ Error: "Malformed request" }';
                http_response_code(400);
            }        
    }
    else if ($_GET['url'] == "users")
    {

    }

}
else if ($_SERVER['REQUEST_METHOD'] == "POST")
{
    if ($_GET['url'] == "auth")
    {    
        $postBody = file_get_contents("php://input");
        $postBody = json_decode($postBody);
        $emailoruser = strtolower($postBody->username);
        $password = $postBody->password;

        if (isset($_GET['token'])){
            //check if token exists
            if($db->query('SELECT token FROM login_tokens WHERE token=:token', array(':token'=>sha1($_GET['token'])))){
            //get userid
            $userid = $db->query('SELECT user_id FROM login_tokens WHERE token=:token', array(':token'=>sha1($_GET['token'])))[0]['user_id'];                
            $cstrong = True;
            $token = bin2hex(openssl_random_pseudo_bytes(64, $cstrong));
            $db->query('INSERT INTO login_tokens (token, user_id) VALUES (:token, :user_id)', array(
                ':token' => sha1($token),
                ':user_id' => $userid
            ));
            echo '{ "Token": "' . $token . '" }';
            http_response_code(200);  
            } else {
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
                echo '{ "Token": "' . $token . '" }';
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
                    echo "Valid Username and Password";
                    echo '{ "Token": "' . $token . '" }';
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



else if ($_GET['url'] == "register")
{
    $postBody = file_get_contents("php://input");
    $postBody = json_decode($postBody);
    $email = strtolower($postBody->email);
    $password = $postBody->password;
    if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
        if (strlen($password) >= 6 && strlen($password) <= 60) {        
    if (!$db->query('SELECT email from users WHERE email=:email', array(
        ':email' => $email
    )))
    { 
       $db->query('INSERT INTO users (email, password, verified) VALUES (:email, :password, :verified)', array(
            ':email'=>$email, ':password'=>password_hash($password, PASSWORD_BCRYPT), ':verified'=>0
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
} else {
    echo "Error: Password must have at least 6 characters!";
    http_response_code(401);
} 
} else {
    echo "Error: E-mail is not valid";
    http_response_code(401);
}
}
}

else if ($_SERVER['REQUEST_METHOD'] == "DELETE")
{
    if ($_GET['url'] == "auth"){
        if (isset($_GET['token'])){
            if($db->query('SELECT token FROM login_tokens WHERE token=:token', array(':token'=>sha1($_GET['token'])))){
                $db->query('DELETE FROM login_tokens WHERE token=:token', array(':token'=>sha1($_GET['token'])));
                echo '{ Status: "Success" }';
                http_response_code(200);
            } else {
                echo '{ Error: "Invalid Token" }';
                http_response_code(400);
            }
        } else {
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