// api/photon/sign-clearance.ts ts too easy fr

import crypto from "crypto";

const CLEARANCE_SECRET = "THISANAUTH738X9KEY";

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "method not allowed" });
  }

  const suppliedSecret = req.headers["x-clearance-secret"];
  if (suppliedSecret !== CLEARANCE_SECRET) {
    return res.status(401).json({ error: "unauthorized" });
  }

  const { playerId, exp, nonce } = req.body || {};
  if (!playerId || !exp || !nonce) {
    return res.status(400).json({ error: "missing fields" });
  }

  const sig = crypto
    .createHmac("sha256", CLEARANCE_SECRET)
    .update(`${playerId}|${exp}|${nonce}`)
    .digest("hex");

  return res.status(200).json({ sig });
}
