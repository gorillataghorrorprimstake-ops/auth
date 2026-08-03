// api/photon/authenticate.js
//
// Vercel serverless function. Deployed URL will be something like:
//   https://your-project.vercel.app/api/photon/authenticate
// Point Photon's Custom Server Provider -> Authentication URL at that.
//
// Env vars to set in Vercel Project Settings -> Environment Variables:
//   PLAYFAB_TITLE_ID     e.g. "8388D"
//   PLAYFAB_SECRET_KEY   Server Secret Key from Game Manager -> Settings -> Secret Keys
//
// Note: this is a stateless function - every invocation may run on a fresh
// instance, so there's no reliable shared in-memory cache like the Express
// version had. If you want to cut down on PlayFab API calls for reconnect
// bursts, use Vercel KV / Upstash Redis instead of an in-memory Map.

const axios = require("axios");

const TITLE_ID = process.env.PLAYFAB_TITLE_ID;
const SECRET_KEY = process.env.PLAYFAB_SECRET_KEY;
const PLAYFAB_BASE = `https://${TITLE_ID}.playfabapi.com`;

async function playfabServerPost(path, body) {
    const resp = await axios.post(`${PLAYFAB_BASE}/Server/${path}`, body, {
        headers: {
            "Content-Type": "application/json",
            "X-SecretKey": SECRET_KEY
        },
        timeout: 5000
    });
    return resp.data;
}

async function isBanned(playFabId) {
    try {
        // GetUserAccountInfo doesn't reliably surface ban status in every SDK
        // response shape - swap to GetUserBans if this comes back undefined
        // for you in testing.
        const data = await playfabServerPost("GetUserAccountInfo", { PlayFabId: playFabId });
        const banned = data && data.data && data.data.UserInfo && data.data.UserInfo.PrivateInfo &&
            data.data.UserInfo.PrivateInfo.BannedUntil;
        return !!banned;
    } catch (e) {
        console.error("[isBanned] lookup failed:", e.message);
        return true; // fail closed
    }
}

async function hasValidAntiUnityPass(playFabId) {
    try {
        const data = await playfabServerPost("GetUserInternalData", {
            PlayFabId: playFabId,
            Keys: ["AntiUnityAuthPass"]
        });

        const raw = data && data.data && data.data.Data && data.data.Data.AntiUnityAuthPass &&
            data.data.Data.AntiUnityAuthPass.Value;

        if (!raw) return false;

        const record = JSON.parse(raw);
        const MAX_AGE_MS = 12 * 60 * 60 * 1000; // keep in sync with CloudScript
        return record.passed === true && (Date.now() - record.timestamp) < MAX_AGE_MS;
    } catch (e) {
        console.error("[hasValidAntiUnityPass] lookup failed:", e.message);
        return false; // fail closed
    }
}

// Photon's Custom Authentication contract only recognizes three ResultCode
// values (this is distinct from Photon's separate room "Webhooks" feature,
// which does use 0 for success/ack - easy to mix the two up):
//   1 = auth OK        (must include UserId)
//   2 = auth failed
//   3 = invalid/missing parameters
// Anything else (including 0) isn't a code Photon's Custom Auth handler
// understands, and can cause it to misbehave on the client's next connect
// attempt rather than cleanly reporting OnCustomAuthenticationFailed.
function reject(res, message, resultCode = 2) {
    return res.status(200).json({ ResultCode: resultCode, Message: message });
}

module.exports = async function handler(req, res) {
    if (!TITLE_ID || !SECRET_KEY) {
        console.error("Missing PLAYFAB_TITLE_ID or PLAYFAB_SECRET_KEY env vars.");
        return reject(res, "Server misconfigured.", 2);
    }

    const playFabId = req.query.username;
    const photonToken = req.query.token;

    if (!playFabId || !photonToken) {
        return reject(res, "Missing username/token parameters.", 3);
    }

    // Step 1: confirm the Photon token is legit via PlayFab's real endpoint.
    let playfabResult;
    try {
        const upstream = await axios.get(`${PLAYFAB_BASE}/photon/authenticate`, {
            params: { username: playFabId, token: photonToken },
            timeout: 5000
        });
        playfabResult = upstream.data;
    } catch (e) {
        // axios throws on non-2xx by default, so a PlayFab-side error (4xx/5xx)
        // lands here too, not just network failures. Log status + body if present.
        if (e.response) {
            console.error(
                `[gateway] PlayFab upstream call returned ${e.response.status}:`,
                JSON.stringify(e.response.data)
            );
        } else {
            console.error("[gateway] PlayFab upstream call failed:", e.message);
        }
        return reject(res, "Upstream auth service unavailable.", 2);
    }

    // NOTE: PlayFab's /photon/authenticate response uses lowercase keys
    // (resultCode, userId, nickname) - NOT the PascalCase (ResultCode, UserId)
    // used by Photon's Custom Auth contract that THIS gateway returns to Photon.
    // Those are two different schemas; don't assume they match casing.
    if (!playfabResult || playfabResult.resultCode !== 1) {
        // Don't forward PlayFab's full error object - it can carry extra fields
        // that push past Photon's response size cap. Short reason only.
        console.error("[gateway] PlayFab rejected auth:", JSON.stringify(playfabResult));
        return reject(res, "PlayFab auth failed.", 2);
    }

    // Step 2: our own extra gate.
    const [banned, hasPass] = await Promise.all([
        isBanned(playFabId),
        hasValidAntiUnityPass(playFabId)
    ]);

    if (banned) {
        return reject(res, "Player is banned.", 2);
    }

    if (!hasPass) {
        return reject(res, "No valid AntiUnity ticket - device check must pass before Photon.", 2);
    }

    // Everything checked out. Return ONLY what Photon's Custom Auth contract
    // actually needs - not PlayFab's full response object, which can include
    // a Data/EntityToken blob large enough to trip Photon's response size cap
    // ("http response max size exceeded").
    const minimalResponse = {
        ResultCode: 1,
        UserId: playfabResult.userId || playFabId
    };
    if (playfabResult.nickname) {
        minimalResponse.Nickname = playfabResult.nickname;
    }

    return res.status(200).json(minimalResponse);
};
