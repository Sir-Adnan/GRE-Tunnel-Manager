// Browser-local interface preferences. Framework-free so the parsing and migration rules are unit-tested.
export type Locale = "fa" | "en";
export type ModePreference = "light" | "dark" | "system";
export type Preferences = {
  locale: Locale;
  style: string;
  mode: ModePreference;
  refresh: boolean;
};

export const preferencesKey = "gtm.preferences.v2";
/** v1 always stored the style, chosen or not, so its value cannot tell a choice from the old default. */
const legacyKey = "gtm.preferences.v1";
const legacyDefaultStyle = "nettinx";

export const defaultPreferences: Preferences = {
  locale: "fa",
  style: "signal",
  mode: "dark",
  refresh: false,
};

/** Validates every field; anything unknown falls back to the default instead of reaching the DOM. */
export function parsePreferences(
  raw: unknown,
  styles: readonly string[],
  fallback: Preferences = defaultPreferences,
): Preferences {
  const value = (raw && typeof raw === "object" ? raw : {}) as Record<
    string,
    unknown
  >;
  return {
    locale:
      value.locale === "en"
        ? "en"
        : value.locale === "fa"
          ? "fa"
          : fallback.locale,
    style:
      typeof value.style === "string" && styles.includes(value.style)
        ? value.style
        : fallback.style,
    mode: ["light", "dark", "system"].includes(value.mode as string)
      ? (value.mode as ModePreference)
      : fallback.mode,
    refresh: value.refresh === true,
  };
}

/** Moves v1 settings forward once; its stored old default style becomes the current default. */
export function migrateLegacy(
  raw: unknown,
  styles: readonly string[],
): Preferences {
  const value = (raw && typeof raw === "object" ? raw : {}) as Record<
    string,
    unknown
  >;
  const { style, ...rest } = value;
  return parsePreferences(style === legacyDefaultStyle ? rest : value, styles);
}

function read(storage: Storage, key: string): unknown {
  const text = storage.getItem(key);
  return text ? JSON.parse(text) : undefined;
}

export function loadPreferences(
  storage: Storage | undefined,
  styles: readonly string[],
): Preferences {
  try {
    if (!storage) return defaultPreferences;
    const current = read(storage, preferencesKey);
    if (current !== undefined) return parsePreferences(current, styles);
    const legacy = read(storage, legacyKey);
    return legacy === undefined
      ? defaultPreferences
      : migrateLegacy(legacy, styles);
  } catch {
    return defaultPreferences;
  }
}

export function savePreferences(
  storage: Storage | undefined,
  value: Preferences,
) {
  try {
    storage?.setItem(preferencesKey, JSON.stringify(value));
    storage?.removeItem(legacyKey);
  } catch {
    /* private mode or blocked storage: preferences last for this page only */
  }
}
