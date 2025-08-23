// Variables used by Scriptable.
// These must be at the very top of the file. Do not edit.
// icon-color: light-gray; icon-glyph: fingerprint;

//Possible Values for authType
const possibleAuthTypes = ["Web Application Flow", "PKCE"];

// A function to open the OAuth Authentication URL in Safari
// It also generated the code Verifier String and the code Challenge
function openAuthUrl(global) {
    const generateRandomString = (length) => {
        const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        const values = Array.from({
            length
        }, () => Math.floor(Math.random() * 256));
        return values.reduce((acc, x) => acc + possible[x % possible.length], "");
    }

    if (global.authType == "Web Application Flow") {

        // construct url with all the data
        const params = {
            response_type: 'code',
            client_id: global.clientId,
            scope: global.scope,
            redirect_uri: global.redirectUri,
            state: global.state
        }
        if (Object.keys(params).length > 0) {
            global.authEndpoint += '?' + Object.keys(params).map(key => `${key}=${params[key]}`).join('&');
        }

    } else {

        // Get the code verifier and save it
        const codeVerifier = generateRandomString(64);
        Keychain.set(`${global.app}_codeVerifier`, codeVerifier);

        // compute challenge with sha256 module by the jsSHA project
        const sha256 = importModule("sha256");
        const shaObj = new sha256('SHA-256', 'TEXT')
        shaObj.update(codeVerifier);

        const codeChallenge = shaObj.getHash('B64').replace(/=/g, '')
            .replace(/\+/g, '-')
            .replace(/\//g, '_');

        global.log(`Code Verifier: ${codeVerifier}`);

        //construct url with all the data
        const params = {
            response_type: 'code',
            client_id: global.clientId,
            scope: global.scope,
            code_challenge_method: 'S256',
            code_challenge: codeChallenge,
            redirect_uri: global.redirectUri,
        }

        if (Object.keys(params).length > 0) {
            global.authEndpoint += '?' + Object.keys(params).map(key => `${key}=${params[key]}`).join('&');
        }
    }

    // open url in Safari
    global.log(global.authEndpoint);
    Safari.open(global.authEndpoint);

    Script.complete();
}

//This function converts an Object into url params
function encodeParams(params) {
    // This function is a port of the standard encodeURIComponent function in most Web Browsers
    function myencodeURIComponent(str) {
        return encodeURIComponent(str).replace(/[!'()*]/g, function (c) {
            return '%' + c.charCodeAt(0).toString(16);
        });
    }

    return Object.keys(params).map(key => `${key}=${myencodeURIComponent(params[key])}`).join('&');
}

//Here is the token Management like refreshing the access token, or getting the tokens from the initial code
async function authManagement(global, code) {

    //This function gets the access and refresh tokens with the code provided by the oauth login
    async function getInitToken(code) {
        if (global.authType == "Web Application Flow") {
            const r = new Request(global.tokenEndpoint)
            r.method = "POST";
            r.headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
            };
            r.body = encodeParams({
                grant_type: 'authorization_code',
                code: code,
                client_id: global.clientId,
                client_secret: global.clientSecret,
                redirect_uri: global.redirectUri,
            });

            return await r.loadJSON();

        } else {
            const r = new Request(global.tokenEndpoint)
            r.method = "POST";
            r.headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
            };

            r.body = encodeParams({
                client_id: global.clientId,
                grant_type: 'authorization_code',
                code: code,
                redirect_uri: global.redirectUri,
                code_verifier: Keychain.get(`${global.app}_codeVerifier`),
            });
            return await r.loadJSON();
        }

    }

    // This function refreshes the access token with the refresh Token
    async function refreshToken(global) {
        const r = new Request(global.tokenEndpoint);
        r.method = "POST"
        r.headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        r.body = encodeParams({
            client_id: global.clientId,
            grant_type: 'refresh_token',
            refresh_token: global.currentToken.refresh_token
        })
        return await r.loadJSON();
    }

    // Here is the logic of when to do what with the tokens
    if (global.currentToken && (global.currentToken.expires && new Date(global.currentToken.expires) > new Date())) {
        // Token is still valid -> Do nothing
        global.log('Token is still valid');
    } else {
        global.log('Token is expired');
        // Token is expired! We have to do something
        if (global.currentToken.refresh_token) {
            global.log('Refreshing token');
            // If we have a refresh token, use it to get a new access token
            const response = await refreshToken(global);
            // Save the new access token
            global.currentToken = response;
            saveToken(global)
        } else {
            global.log('Requesting new token');
            // If we dont have a refresh Token, either have a login code from the login or we dont

            if (global.authType == "Web Application Flow") {

                if (!code) {

                    infoAlert("Your Access Token is expired, please reauthenticate in Safari");

                    openAuthUrl(global);
                    Script.complete();
                    return;
                }
            }
            else {
                if (!Keychain.contains(`${global.app}_codeVerifier`) || !code) {
                    // If we dont have one, something went wrong -> We ask the user again to sign in in Safari
                    errorAlert("No Code or codeVerifier found, please try again");

                    openAuthUrl(global);
                    Script.complete();
                    return;
                }
            }

            // If we do have the code we use it to get the tokens
            global.currentToken = await getInitToken(code);
            infoAlert(JSON.stringify(global.currentToken, null, 2));
            saveToken(global)
        }
    }
}

// This gets the current token from the Keychain if there is none we return {}
function getToken(global) {
    return Keychain.contains(`${global.app}_token`) ? JSON.parse(Keychain.get(`${global.app}_token`)) : {};
}

// This saves the current token to the Keychain and computes the exipiry date
function saveToken(global) {
    const token = global.currentToken;

    if (!token.access_token) {
        // If we have no access token, something went wrong! -> We try again by asking the user to sign in in Safari
        global.log(token)
        global.log('No access token in response, automaticly requesting new OAuth confirmation.');

        errorAlert("No access token found, please try again");
        openAuthUrl(global);
        Script.complete();
        return;
    }

    // We compute the absolute Expiry date from the relative one in the token response
    const now = new Date();
    const expiry = new Date(now.getTime() + (token.expires_in * 1000));

    // We add the absolute expiry date to the token
    const data = JSON.stringify({
        ...token,
        expires: expiry
    });

    // We save the token in the Keychain
    Keychain.set(`${global.app}_token`, data);
}


function errorAlert(message) {
    let alert = new Alert();
    alert.title = "Error";
    alert.message = message;
    alert.addAction("OK");
    alert.present();
}
function infoAlert(message) {
    let alert = new Alert();
    alert.title = "Info";
    alert.message = message;
    alert.addAction("OK");
    alert.present();
}

// This is the auth function exposed in the module which parses the config and returns the final access token
async function auth(config) {

    // Setup Logging according to the config
    function logging(data) {
        if (config.logging == true) {
            if (typeof data == "string") {
                console.log("OAuth: " + data)
            } else {
                console.log("OAuth: " + JSON.stringify(data))
            }
        }
    }

    if (config.authType == null) {
        errorAlert("No authType provided");
        return;
    }
    if (!possibleAuthTypes.includes(config.authType)) {
        errorAlert("Invalid authType provided");
        return;
    }

    // Save all config data in the global Object, as we can not have global variables in Modules in Scriptable
    let global = {
        ...config,
        log: logging
    }

    // get the old config to see if something changed
    const old_config = Keychain.contains(`${global.app}_config`) ? JSON.parse(Keychain.get(`${global.app}_config`)) : null;

    function compare(key) {
        return old_config[key] != global[key];
    }

    if (old_config != null) {
        if (compare("clientId") || compare("redirectUri") || compare("tokenEndpoint") || compare("authEndpoint") || compare("scope")) {
            global.log("The Scope changed, reauthing user")
            // But first change the new config
            Keychain.set(`${global.app}_config`, JSON.stringify(global));
            errorAlert("The Scope changed, please reauthenticate");
            openAuthUrl(global);
            return;
        }
    }

    // Save the config in the Keychain because the callback from login needs some of this data to get the access token from the code
    Keychain.set(`${global.app}_config`, JSON.stringify(global));

    // Load tokens from Keychain
    global.currentToken = getToken(global);

    // Call auth Management to take action if required
    await authManagement(global)

    // return the valid access token
    return global.currentToken.access_token;
}

// This function called from the OAuthCode Script with the inital login Code and app name
module.exports.codeReturn = async (code, app) => {
    if (code) {
        let global = JSON.parse(Keychain.get(`${app}_config`));

        global.currentToken = {}
        global.log = console.log

        await authManagement(global, code);
        return;
    }
}

// Expose the auth function to other Scripts
module.exports.auth = auth;