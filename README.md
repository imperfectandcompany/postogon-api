# postogon-api
GET

/verifytoken?token${token} 
returns token, uid, and username
//CHECKS IF TOKEN IS VALID FIRST

recovery (1)
/resetEmail?email={{$randomEmail}}
returns Success or Error with handling dependent on if email was provided or if email does not exist.
Then generates a token stored inside password_tokens matched with user_id reference to 'id' primary key from user table that is sent to the user's email to continue with recovery.
//note: wipes all existing recovery tokens for user belonging to inquired email before generating a new one

recovery (2)
/verifyPasswordToken?token={{$randomGeneratedTokenFromEmail}}
Returns success orerror based on if token exists and matches with a user or if token does not exist
This is used to confirm whether the user has the ability to update password or not. Gatekeeps recovery (3)

recovery (3)
(VIEW POST SECTION)

/user?token=${getToken()}&information=username
returns with the username of the user to confirm that the username is set (used to see if onboarding is finished or not)
//CHECKS IF TOKEN IS VALID FIRST

/isUserAdmin?token=${getToken()}
returns with the true or false based on if the username owning provided token (if that exists) is admin or not.
//CHECKS IF TOKEN IS VALID FIRST

/isUserVerified?username={{$userName}}
returns with true or false based on if username provided is verified within users table of the database or not.

/user?username={{$randomUserName}}
returns true or false depending if the username exists or not.
//USED TO SEE IF USERNAME IS TAKEN WHEN SETTING INITIALLY IN ONBOARDING OR WHEN UPDATING WITHIN SETTINGS PAGE

/user?username=${username}
returns boolean
//CHECKS IF USERNAME EXISTS

/user?contact=${username}&token={token}
returns boolean
//CHECKS IF USER (TOKEN) IS A CONTACT OF CONTACT (USERNAME)

/user/posts?token=${token}&feed=${feed}
returns user posts based on feed
//TAKES USER TOKEN TO IDENTIFY USER AND FEED PARAMETER ACCEPTS PUBLIC/PRIVATE

/user/posts?id=${id}
returns specific post based on postid
//ENDPOINT ONLY WORKS FOR FEED ONE POSTS

/profile?username=${username}&feed=${feed}
If user is contact then they have access to feed only works if user is a contaact

POST
/token
returns email, uid, and username
//requires user token

recovery (3)
/setNewPassword
takes json object of resettoken and desired newpassword, has proper validation and returns success or error based on necessary handling and conditions.
//ROBUST VALIDATION FINISHED, once done with setting new password, initial used password reset token is wiped from backend database.

Settings option (1) {username}
/setNewPassword
takes 3 values from postbody: usertoken, oldpassword, and newpassword
validation is set to confirm oldpassword matches currentpassword and newpassword doesn't equal oldpassword and also checks to ensure values are filled and trimmed with whitespace. after password is updated, validation is done to confirm newpassword is now user's current password before sending success. otherwise error.

/changeusername
returns success or error with handling.
//requires desired "username" and valid "token"
//IN FUTURE ADD VALIDATION TO SEE IF DESIRED USERNAME ALREADY BELONGS TO USER ***
//Validation: checks to see if username is already taken so it prevents redundant updating if user owns already but stil..

/auth
returns new token
//checks and verifies token then regenerates a new one 
//only called if POSTOGONID_ COOKIE does not exist in user's browser, refreshes expires time by regenerating a new token without the user knowing

/auth (without token in postbody)
returns success (200 OKIE DOKIE)
//takes user or email alongside pass to check if it is valid

/register
registers email and password

DELETE
/token
Removes token from backend, used when regenerating or logging out.
//takes token postbody
