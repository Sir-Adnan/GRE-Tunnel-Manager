import defaults from "../../../internal/model/creation_defaults.json";

/** Only for a new draft; editing saved connections must retain old semantics. */
export function creationOptions(engine: string): Record<string, string> {
  return { ...(defaults as Record<string, Record<string, string>>)[engine] };
}
