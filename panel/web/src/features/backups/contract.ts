export type BackupInput = {
  password: string;
  archive?: string;
  include_traffic: boolean;
  addresses?: Record<string, string>;
  interfaces?: Record<string, string>;
  revision?: string;
};
export type BackupReview = {
  created: string;
  host: string;
  version: string;
  revision: string;
  items: { id: string; name: string; engine: string; summary: string }[];
  addresses: string[];
  interfaces: string[];
  certificates: string[];
  traffic: boolean;
  blockers: string[];
};
export const maxBackupBytes = 28 * 1024 * 1024;

// Download data is already encrypted by the broker. Never put recovery contents
// or passwords in localStorage, routes or a persistent frontend cache.
export function downloadBackup(filename: string, archive: string) {
  const url = URL.createObjectURL(
    new Blob([archive], { type: "application/json" }),
  );
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export function migrationValues(values: Record<string, string>) {
  return Object.fromEntries(
    Object.entries(values)
      .filter(([from, to]) => to.trim() && to.trim() !== from)
      .map(([from, to]) => [from, to.trim()]),
  );
}
