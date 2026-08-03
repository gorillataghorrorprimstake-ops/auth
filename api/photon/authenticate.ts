// FUCK YOU YOU DEAD WIFE HAVING BITCH
import crypto from "crypto";

const TITLE_ID = "8388D";
const TITLE_SECRET_KEY = process.env.PLAYFAB_TITLE_SECRET_KEY!; 
const CLEARANCE_SECRET = "THISANAUTH738X9KEY";

export default async function handler(req, res) {
  const { UserId, AppId, Token } = req.query as {
    UserId?: string;
    AppId?: string;
    Token?: string;
  };

  if (!UserId || !Token) {
    return res.json({ ResultCode: 0, Message: "missing credentials" });
  }

  // 1. Confirm the token is a real PlayFab-issued Photon token
  const pfResp = await fetch(
    `https://${TITLE_ID}.playfabapi.com/photon/authenticate?UserId=${encodeURIComponent(
      UserId
    )}&AppId=${encodeURIComponent(AppId ?? "")}&Token=${encodeURIComponent(Token)}`
  );
  const pfResult = await pfResp.json();
  if (pfResult.ResultCode !== 1) {
    return res.json({ ResultCode: 0, Message: "invalid photon token" });
  }

  const dataResp = await fetch(`https://${TITLE_ID}.playfabapi.com/Server/GetUserInternalData`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-SecretKey": TITLE_SECRET_KEY },
    body: JSON.stringify({ PlayFabId: UserId, Keys: ["PhotonClearance"] }),
  });
  const dataResult = await dataResp.json();
  const raw = dataResult?.data?.Data?.PhotonClearance?.Value;

  if (!raw) {
    return res.json({ ResultCode: 0, Message: "no clearance on file" });
  }

  let clearance: { exp: number; nonce: string; sig: string };
  try {
    clearance = JSON.parse(raw);
  } catch {
    return res.json({ ResultCode: 0, Message: "malformed clearance" });
  }

  const now = Date.now();
  if (now > clearance.exp) {
    return res.json({ ResultCode: 0, Message: "clearance expired" });
  }

  const expectedSig = crypto
    .createHmac("sha256", CLEARANCE_SECRET)
    .update(`${UserId}|${clearance.exp}|${clearance.nonce}`)
    .digest("hex");

  if (expectedSig !== clearance.sig) {
    return res.json({ ResultCode: 0, Message: "clearance signature mismatch" });
  }

  await fetch(`https://${TITLE_ID}.playfabapi.com/Server/UpdateUserInternalData`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-SecretKey": TITLE_SECRET_KEY },
    body: JSON.stringify({ PlayFabId: UserId, KeysToRemove: ["PhotonClearance"] }),
  });

  return res.json({ ResultCode: 1, UserId: UserId, Nickname: UserId });
}
