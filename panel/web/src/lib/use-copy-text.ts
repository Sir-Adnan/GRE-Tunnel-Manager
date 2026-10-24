import { useEffect, useState } from "react";
import { copyText } from "./clipboard";

export function useCopyText(text: string) {
  const [result, setResult] = useState<{ text: string; ok: boolean }>();
  useEffect(() => {
    if (!result) return;
    const timer = window.setTimeout(() => setResult(undefined), 4000);
    return () => window.clearTimeout(timer);
  }, [result]);
  const status =
    result?.text === text ? (result.ok ? "copied" : "copyFailed") : "";
  async function copy() {
    const ok = await copyText(text);
    setResult({ text, ok });
    return ok;
  }
  return { status, copy };
}
