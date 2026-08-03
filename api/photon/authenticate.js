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

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

// Mirrors the retry pattern CloudScript's checkAntiUnityPass() already uses
// (ANTIUNITY_READ_RETRY_COUNT / ANTIUNITY_READ_RETRY_DELAY_MS) - the client's
// AntiUnity device-check write can lag a few seconds behind login, so a single
// immediate read here was rejecting legitimate players who just hadn't had
// their AntiUnityAuthPass key written yet. Delay is shorter than CloudScript's
// 5s since this runs inline in Photon's connect path, not a background sweep.
const ANTIUNITY_READ_RETRY_COUNT = 2;
const ANTIUNITY_READ_RETRY_DELAY_MS = 1500;
const ANTIUNITY_MAX_AGE_MS = 12 * 60 * 60 * 1000; // keep in sync with CloudScript

async function readAntiUnityPassRaw(playFabId) {
    const data = await playfabServerPost("GetUserInternalData", {
        PlayFabId: playFabId,
        Keys: ["AntiUnityAuthPass"]
    });

    return data && data.data && data.data.Data && data.data.Data.AntiUnityAuthPass &&
        data.data.Data.AntiUnityAuthPass.Value;
}

async function hasValidAntiUnityPass(playFabId) {
    for (let attempt = 0; attempt <= ANTIUNITY_READ_RETRY_COUNT; attempt++) {
        try {
            const raw = await readAntiUnityPassRaw(playFabId);

            if (raw) {
                const record = JSON.parse(raw);
                return record.passed === true && (Date.now() - record.timestamp) < ANTIUNITY_MAX_AGE_MS;
            }
        } catch (e) {
            console.error("[hasValidAntiUnityPass] lookup failed (attempt " + attempt + "):", e.message);
        }

        if (attempt < ANTIUNITY_READ_RETRY_COUNT) {
            await sleep(ANTIUNITY_READ_RETRY_DELAY_MS);
        }
    }

    return false; // still fail closed after retries
}

function reject(res, message) {
    // Photon expects HTTP 200 with ResultCode 0 for an auth failure - a 4xx/5xx
    // gets treated as "auth service unavailable", a different failure mode.
    return res.status(200).json({ ResultCode: 0, Message: message });
}

module.exports = async function handler(req, res) {
    if (!TITLE_ID || !SECRET_KEY) {
        console.error("Missing PLAYFAB_TITLE_ID or PLAYFAB_SECRET_KEY env vars.");
        return reject(res, "Server misconfigured.");
    }

    const playFabId = req.query.username;
    const photonToken = req.query.token;

    if (!playFabId || !photonToken) {
        return reject(res, "Missing username/token parameters.");
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
        console.error("[gateway] PlayFab upstream call failed:", e.message);
        return reject(res, "Upstream auth service unavailable.");
    }

    if (!playfabResult || playfabResult.ResultCode !== 1) {
        // Don't forward PlayFab's full error object - it can carry extra fields
        // that push past Photon's response size cap. Short reason only.
        return reject(res, "PlayFab auth failed.");
    }

    // Step 2: our own extra gate.
    const [banned, hasPass] = await Promise.all([
        isBanned(playFabId),
        hasValidAntiUnityPass(playFabId)
    ]);

    if (banned) {
        return reject(res, "Player is banned.");
    }

    if (!hasPass) {
        return reject(res, "No valid AntiUnity ticket - device check must pass before Photon.");
    }

    // Everything checked out. Return ONLY what Photon's Custom Auth contract
    // actually needs - not PlayFab's full response object, which can include
    // a Data/EntityToken blob large enough to trip Photon's response size cap
    // ("http response max size exceeded").
    const minimalResponse = {
        ResultCode: 1,
        UserId: playfabResult.UserId || playFabId
    };
    if (playfabResult.Nickname) {
        minimalResponse.Nickname = playfabResult.Nickname;
    }

    return res.status(200).json(minimalResponse);
};
