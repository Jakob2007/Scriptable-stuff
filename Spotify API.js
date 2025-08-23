// Variables used by Scriptable.
// These must be at the very top of the file. Do not edit.
// icon-color: deep-green; icon-glyph: music;
const oauth = importModule("OAuth");

app_config = {
    authType: "PKCE",
    app: "spotify",
    clientId: "", //make a spotify app in the developer dashboard
    redirectUri: "scriptable:///run/OAuthCode?app=spotify",
    tokenEndpoint: "https://accounts.spotify.com/api/token",
    authEndpoint: "https://accounts.spotify.com/authorize",
    scope: "user-read-private user-read-email playlist-modify-public playlist-modify-private user-modify-playback-state",
    logging: true
};

const access_token = await oauth.auth(app_config);

async function request(endpoint, method, body) {
    const r = new Request("https://api.spotify.com/v1"+endpoint)
    r.method = method;
    r.headers = {
        'Authorization': `Bearer ${access_token}`
    };
    if (method != "GET") {
        r.body = JSON.stringify(body);
    }
    return await r.loadJSON();
}

async function searchSpotify(query, type = "track", market = "DE", limit = 1, offset = 0) {
    return await request(
        `/search?q=${query}&type=${type}&market=${market}&limit=${limit}&offset=${offset}`,
        "GET")
}

async function addTrackToPlaylist(playlistId, trackUri) {
    return await request(`/playlists/${playlistId}/tracks?uris=${trackUri}`, "POST")
}

async function getUserData() {
    return await request('/me', "GET")
}

async function playPlaylist(playlistURI, device) {
    if (device) {
        return await request(`/me/player/play?device_id=${device}`, "PUT", {context_uri: playlistURI})
    }
    else {
        return await request(`/me/player/play`, "PUT", {context_uri: playlistURI})   
    }
}

async function setPlaybackShuffle(state) {
    return await request(`/me/player/shuffle?state=${state}`, "PUT")
}

if (!access_token) {
    Script.setShortcutOutput({
        "code": -1,
        "error": "Couldnt get a access token"
    })
}

const parameter = args.shortcutParameter;

if (parameter) {
    if (parameter.action == "addSearchToPlaylist") {
        const id = parameter.playlistId;
        const query = parameter.query;

    const searchResult = await searchSpotify(query);
    if (!searchResult || !searchResult.tracks || !searchResult.tracks.items || !searchResult.tracks.items[0]) {
        Script.setShortcutOutput({
            "code": 404,
            "error": "track was not found",
            "Shortcut Parameters": parameter,
            "search result": searchResult
        })
        Script.complete();
        return;
    }
    const trackId = searchResult.tracks.items[0].uri;
    console.log(trackId)

    await addTrackToPlaylist(id, trackId);
    Script.setShortcutOutput({
        "code": 0,
        "error": "Success"
    })
    
    Script.complete();
    return;
	}    
    else if (parameter.action == "playPlaylist") {
        const random = parameter.random == "true" ? "true" : "false";
        const id = "spotify:playlist:"+parameter.id;
        const device = parameter.device;
        
        setPlaybackShuffle(random)
    	playPlaylist(id, device);
     	
        Script.setShortcutOutput({
        "code": 0,
        "error": "Success"
    		})
        
        Script.complete();
        return;
    }
}

if (config.runsInApp) {
    const data = await getUserData();
    console.log(`You are logged in as "${data.display_name}"`)
}