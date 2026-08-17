/**
 * Early-access signups, static-export friendly.
 *
 * Three modes, decided by public env vars at build time:
 *  - Supabase configured  -> insert the signup via PostgREST (anon key,
 *    RLS insert-only; see supabase/early_access.sql).
 *  - Launcher URL configured -> after a stored signup, the caller may
 *    start the real download.
 *  - Nothing configured   -> caller falls back to the mailto flow.
 */

export interface SignupPayload {
  name: string;
  email: string;
  role_company: string;
  os: string;
  workflow: string;
  tools: string;
  model_provider: string;
  feedback_call: string;
  locale: string;
}

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
export const LAUNCHER_URL = process.env.NEXT_PUBLIC_LAUNCHER_URL || "";

export const isSignupBackendConfigured = Boolean(
  SUPABASE_URL && SUPABASE_ANON_KEY
);

export async function submitSignup(payload: SignupPayload): Promise<void> {
  if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
    throw new Error("Signup backend is not configured");
  }
  const response = await fetch(
    `${SUPABASE_URL}/rest/v1/early_access_signups`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        apikey: SUPABASE_ANON_KEY,
        Authorization: `Bearer ${SUPABASE_ANON_KEY}`,
        Prefer: "return=minimal",
      },
      body: JSON.stringify(payload),
    }
  );
  if (!response.ok) {
    const detail = await response.text().catch(() => "");
    throw new Error(
      `Signup failed (${response.status}): ${detail.slice(0, 200)}`
    );
  }
}
