// Variables used by Scriptable.
// These must be at the very top of the file. Do not edit.
// icon-color: gray; icon-glyph: code;
// This script is used as a callback for OAuth applications, they call this script using IOSs X-Callback-Urls with the login code and this script calls the main OAuth script to get and save the access and refresh token

const oauth = importModule("OAuth")

// Parse code and app from the callback arguments
const code = args.queryParameters.code || args.queryParameters.authCode || args.queryParameters.access_token;
const app = args.queryParameters.app;

infoAlert = new Alert();
infoAlert.title = "Arguments";
infoAlert.message = JSON.stringify(args.queryParameters, null, 2);
infoAlert.addAction("OK");
infoAlert.present();

// construct an Alert if one of the Arguments isnt found
let alert = new Alert();
if (!code || !app) {
    alert.message = "Couldn't find the Argument";
    if (!code && !app) {
        alert.message += "s "
    } else {
        alert.message += " "
    }
    if (!code) {
        alert.message += "'code'"
    }
    if (!code && !app) {
        alert.message += " and "
    }
    if (!app) {
        alert.message += "'app'"
    }

    alert.present();
}

// Call the codeReturn function in the main OAuth script to get the access and refresh tokens
await oauth.codeReturn(code, app);