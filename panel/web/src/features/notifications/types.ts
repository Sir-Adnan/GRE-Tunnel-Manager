export type NotifySeverity = "info" | "warning" | "critical";

export type NotifyEvent = {
  id: number;
  time: string;
  kind: string;
  severity: NotifySeverity;
  owner?: string;
  name?: string;
  detail?: string;
  /** Values of a localized detail (seconds, names, counts). */
  args?: Record<string, string>;
  read: boolean;
  /** pending, sent, failed or limited; empty when no channel took it. */
  delivery?: string;
};

export type NotifySettingsView = {
  kinds: string[];
  language: "en" | "fa";
  webhook: {
    enabled: boolean;
    url_set: boolean;
    host?: string;
    secret_set: boolean;
  };
  telegram: {
    enabled: boolean;
    token_set: boolean;
    chat?: string;
    api?: string;
  };
};

export type NotifyView = {
  settings: NotifySettingsView;
  revision: number;
  unread: number;
  events: NotifyEvent[];
  kinds: string[];
};

/** What the settings form sends; empty secrets keep the stored ones. */
export type NotifySettingsInput = {
  kinds: string[];
  language: "en" | "fa";
  webhook: { enabled: boolean; url?: string; secret?: string; forget?: boolean };
  telegram: {
    enabled: boolean;
    token?: string;
    chat?: string;
    api?: string;
    forget?: boolean;
  };
};
