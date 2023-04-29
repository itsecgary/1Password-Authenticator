# 1password-Authenticator
A JavaScript utility script for authenticating to 1password in order to perform API testing. 1Password themselves created a [session analyzer tool/plugin](https://github.com/1Password/burp-1password-session-analyzer) for Burp Suite; I was just too lazy/poor to use Burp so I guess I made this script :)

*NOTE:* This script was made for the [1Password Bug Bounty CTF](https://bugcrowd.com/agilebits-ctf) which used `bugbounty-ctf.1password.com`. This script has not currently been tested/modified to work for other domains even though it should still work for them.

## Usage
Using this script requires filling out login information in `usersecrets.json`, which the script uses to authenticate:
```json
{
        "domain": "<subdomain>.1password.com",
        "email": "",
        "secret": "A3-...",
        "password": "",
        "accountID": "",
        "deviceUuid": "",
        "userUuid": ""
}
```

Install the following NodeJs dependencies:
```sh
npm install url-safe-base64 srpit node-fetch@2 crypto base64url
```

Run **auth.js**
```sh
node auth.js
```

*NOTE:* For some reason the authentication works ~80% of the time, so if `auth.js` doesn't print anything, give it another run.

*NOTE:* If authentication is not working, I have setup debug statements that will print if `authNotes = true`, which is defined at the beginning of the script.

## Authentication Details
*TODO* - I plan on adding my notes on 1Password's authentication here. 1Password has provided a [white paper](https://1passwordstatic.com/files/security/1password-white-paper.pdf) on how the security is designed.



