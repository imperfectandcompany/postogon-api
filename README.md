# postogon-api
GET

/verifytoken?token${token} 
returns token, uid, and username
//CHECKS IF TOKEN IS VALID FIRST

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
