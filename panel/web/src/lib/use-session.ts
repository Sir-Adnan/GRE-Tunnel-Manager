import { useCallback, useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { Session } from "@/lib/api";

const signedOut: Session = {
  authenticated: false,
  session: { csrf: "", username: "", expires: "" },
  demo: false,
};

/** Signing out keeps the server's demo flag, so the demo sign-in hint stays visible. */
const signOut = (current?: Session): Session => ({
  ...signedOut,
  demo: current?.demo ?? false,
});

/** The signed-in session; any 401 from the API (the gtm:unauthorized event) signs the page out. */
export function useSession() {
  const [session, setSession] = useState<Session>();
  const [error, setError] = useState("");
  useEffect(() => {
    api<Session>("session")
      .then(setSession)
      .catch((reason) => setError(String(reason)));
  }, []);
  useEffect(() => {
    const expired = () => setSession(signOut);
    window.addEventListener("gtm:unauthorized", expired);
    return () => window.removeEventListener("gtm:unauthorized", expired);
  }, []);
  const logout = useCallback(async () => {
    await api("logout", {});
    setSession(signOut);
  }, []);
  return { session, setSession, error, logout };
}
