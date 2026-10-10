import { db } from "hatchable";

export const access = "user";
export const methods = ["GET", "PATCH"];

const ROLES = ["Admin","Submitter","Reviewer","Approving Officer","Implementation Officer"];

export default async function (req, res) {
  const user = req.user;
  const { rows: mine } = await db.query("SELECT role FROM app_profiles WHERE user_id = $1", [user.id]);
  if (mine[0]?.role !== "Admin") return res.status(403).json({ error: "Administrator access required." });
  if (req.method === "GET") {
    const { rows } = await db.query("SELECT user_id,email,display_name,role,created_at FROM app_profiles ORDER BY created_at ASC LIMIT 250");
    return res.json({ users: rows });
  }
  const body = req.body || {};
  if (!body.user_id || !ROLES.includes(body.role)) return res.status(400).json({ error: "Choose a valid user and role." });
  if (body.user_id === user.id && body.role !== "Admin") return res.status(409).json({ error: "You cannot remove your own administrator role." });
  const { rows } = await db.query("UPDATE app_profiles SET role = $2 WHERE user_id = $1 RETURNING user_id,email,display_name,role,created_at", [String(body.user_id),body.role]);
  if (!rows.length) return res.status(404).json({ error: "User not found." });
  res.json({ user: rows[0] });
}