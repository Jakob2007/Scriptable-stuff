// Variables used by Scriptable.
// These must be at the very top of the file. Do not edit.
// icon-color: light-gray; icon-glyph: fingerprint;

// This verion of OAuth will open a WebView in Scriptable where the user can authenticate. When successful the redirect back will be intercepted thereby getting the code. This became nesseccary since using the scriptable uri scriptable:///run/OAuthCode is nolonger permited in this context

// Arbitrary port for redirection -> Port will never be reached because it is intercepted
const PORT = 8888;

//Possible Values for authType
const possibleAuthTypes = ["Web Application Flow", "PKCE"];

const wv = new WebView();

// Success Page that will be loaded since webview cannot be closed directly
const successPage = `
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
<style>
  * {
    box-sizing: border-box;
  }

  body {
    margin: 0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", sans-serif;
    background: #ffffff;
    color: #111111;
  }

  .container {
    text-align: center;
    padding: 32px;
    max-width: 340px;
  }

  .icon {
    width: 78px;
    height: 78px;
    margin: 0 auto 22px;
    border-radius: 50%;
    background: #34c759;
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: 0 8px 25px rgba(52, 199, 89, 0.25);
  }

  .check {
    color: white;
    font-size: 43px;
    font-weight: 600;
    line-height: 1;
    transform: translateY(-2px);
  }

  h1 {
    margin: 0 0 10px;
    font-size: 28px;
    font-weight: 700;
    letter-spacing: -0.6px;
  }

  p {
    margin: 0;
    color: #777777;
    font-size: 16px;
    line-height: 1.45;
  }
</style>
</head>

<body>
  <div class="container">
    <div class="icon">
      <div class="check">✓</div>
    </div>

    <h1>Success</h1>
    <p>Please close the WebView in the top right to continue.</p>
  </div>
</body>
</html>
`;

// A function to open the OAuth Authentication URL in Safari
// It also generated the code Verifier String and the code Challenge
async function openAuthUrl(global) {
    // Generate a random TCP port for the loopback redirect.
    // Nothing actually listens on this port: the WebView intercepts
    // the navigation before it reaches the network.
    const redirectUri = `http://127.0.0.1:${PORT}/callback`;

    global.redirectUri = redirectUri;

    // Generate PKCE verifier.
    const generateRandomString = (length) => {
        const possible =
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';

        const values = Array.from(
            { length },
            () => Math.floor(Math.random() * 256)
        );

        return values
            .map(x => possible[x % possible.length])
            .join('');
    };

    // Generate and store PKCE verifier.
    const codeVerifier = generateRandomString(64);
    Keychain.set(`${global.app}_codeVerifier`, codeVerifier);

    // Generate PKCE challenge.
    const sha256 = importModule("sha256");
    const shaObj = new sha256('SHA-256', 'TEXT');
    shaObj.update(codeVerifier);

    const codeChallenge = shaObj
        .getHash('B64')
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');

    // Generate state.
    const state = generateRandomString(32);

    Keychain.set(`${global.app}_oauthState`, state);

    // Build the Spotify authorization URL.
    const params = {
        response_type: 'code',
        client_id: global.clientId,
        scope: global.scope,
        code_challenge_method: 'S256',
        code_challenge: codeChallenge,
        redirect_uri: redirectUri,
        state: state
    };

    const query = Object.keys(params)
        .map(key => `${encodeURIComponent(key)}=${encodeURIComponent(params[key])}`)
        .join('&');

    const authUrl = `${global.authEndpoint}?${query}`;

    global.log(`Redirect URI: ${redirectUri}`);
    global.log(`Authorization URL: ${authUrl}`);

    // Variable populated when the WebView attempts to navigate
    // to our loopback callback.
    let callbackUrl = null;

    const webView = new WebView();

    webView.shouldAllowRequest = request => {
        const url = request.url;

        global.log(`WebView request: ${url}`);

        // Only intercept the exact loopback endpoint we created.
        if (url.startsWith(`${redirectUri}?`) ||
            url === redirectUri) {

            global.log(`OAuth callback intercepted: ${url}`);

            callbackUrl = url;

            webView.loadHTML(successPage);

            // IMPORTANT:
            // Do not actually make the request to 127.0.0.1.
            return false;
        }

        return true;
    };

    // Load url.
    await webView.loadURL(authUrl);

    // Present the WebView.
    //
    // The user closes it after the callback is intercepted.
    await webView.present(true);

    if (!callbackUrl) {
        throw new Error("OAuth authentication was cancelled.");
    }

    // Parse the intercepted callback.
    const queryString = callbackUrl.split("?")[1] || "";
    const queryParameters = {};

    for (const parameter of queryString.split("&")) {
        if (!parameter) continue;

        const [key, ...valueParts] = parameter.split("=");

        const value = valueParts.join("=");

        queryParameters[decodeURIComponent(key)] =
            decodeURIComponent(value.replace(/\+/g, " "));
    }

    const code = queryParameters.code;
    const returnedState = queryParameters.state;
    const error = queryParameters.error;

    if (error) {
        throw new Error(`OAuth error: ${error}`);
    }

    if (!code) {
        throw new Error("The service did not return an authorization code.");
    }

    // Verify state.
    const expectedState = Keychain.get(`${global.app}_oauthState`);

    if (!returnedState || returnedState !== expectedState) {
        throw new Error("OAuth state validation failed.");
    }

    // State is single-use.
    Keychain.remove(`${global.app}_oauthState`);

    global.log(`Authorization code received.`);

    return code;
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

async function authManagement(global, code) {

    async function getInitToken(code) {
        if (global.authType == "Web Application Flow") {

            const r = new Request(global.tokenEndpoint);

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

            const r = new Request(global.tokenEndpoint);

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

    async function refreshToken(global) {

        const r = new Request(global.tokenEndpoint);

        r.method = "POST";

        r.headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        };

        r.body = encodeParams({
            client_id: global.clientId,
            grant_type: 'refresh_token',
            refresh_token: global.currentToken.refresh_token
        });

        return await r.loadJSON();
    }

    // Existing token is still valid.
    if (
        global.currentToken &&
        global.currentToken.expires &&
        new Date(global.currentToken.expires) > new Date()
    ) {
        global.log('Token is still valid');
        return;
    }

    global.log('Token is expired or missing.');

    // Try refresh token first.
    if (global.currentToken && global.currentToken.refresh_token) {

        global.log('Refreshing token');

        const response = await refreshToken(global);

        global.currentToken = {
            ...response,
            refresh_token:
                response.refresh_token ||
                global.currentToken.refresh_token
        };

        saveToken(global);
        return;
    }

    // If we already have an authorization code, exchange it.
    if (code) {

        global.log('Exchanging authorization code');

        global.currentToken = await getInitToken(code);

        saveToken(global);
        return;
    }

    // No token and no code -> start interactive OAuth.
    global.log('Starting OAuth authentication.');

    if (global.authType === "PKCE") {

        const authorizationCode = await openAuthUrl(global);

        global.currentToken = await getInitToken(authorizationCode);

        saveToken(global);

        // PKCE verifier has now served its purpose.
        if (Keychain.contains(`${global.app}_codeVerifier`)) {
            Keychain.remove(`${global.app}_codeVerifier`);
        }

        return;
    }

    // Web Application Flow still needs its own handling.
    if (global.authType === "Web Application Flow") {

        const authorizationCode = await openAuthUrl(global);

        global.currentToken = await getInitToken(authorizationCode);

        saveToken(global);

        return;
    }
}

// This gets the current token from the Keychain if there is none we return {}
function getToken(global) {
    return Keychain.contains(`${global.app}_token`) ? JSON.parse(Keychain.get(`${global.app}_token`)) : {};
}

// This saves the current token to the Keychain and computes the exipiry date
function saveToken(global) {
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
        if (compare("clientId") || compare("tokenEndpoint") || compare("authEndpoint") || compare("scope")) {
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

// Expose the auth function to other Scripts
module.exports.auth = auth;