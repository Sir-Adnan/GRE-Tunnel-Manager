// Prevents a flash of the wrong style, mode or axis values in client-rendered apps. With SSR, prefer resolving
// on the server (cookie or session) and rendering experienceAttributes() on <html> directly; use this script
// only as a fallback. Under a strict CSP, serve it as a file or allow it by hash/nonce, never "unsafe-inline".
//
// The script embeds an allowlist generated from the registry, so a tampered storage value can only select a
// registered style or axis value, never inject a selector, class name, or URL. Precedence mirrors resolve.ts.
import type { GeneratedRegistry, ModePreference } from "./types";

export interface NoFlashOptions {
  registry: GeneratedRegistry;
  surface: string;
  /** localStorage key holding a PersistedSelection JSON (user preference cache). */
  storageKey: string;
  /** Server-published defaults for this surface, rendered into the page. */
  defaults: {
    styleId: string;
    packId: string;
    mode?: ModePreference;
    axes?: Readonly<Record<string, string>>;
  };
  allowUserStyle?: boolean;
  /** Same meaning as ResolveInput.userMay.axes. */
  allowUserAxes?: boolean | readonly string[];
}

export function createNoFlashScript(o: NoFlashOptions): string {
  const pack = o.registry.packs[o.defaults.packId];
  const allowed = (pack?.compatibleStyleIds ?? []).filter((id) =>
    o.registry.styles[id]?.surfaces.includes(o.surface),
  );
  const modesByStyle = Object.fromEntries(
    allowed.map((id) => [id, o.registry.styles[id].modes]),
  );
  const styleAxes = Object.fromEntries(
    allowed.map((id) => [id, o.registry.styles[id].axes ?? {}]),
  );
  const aliases = Object.fromEntries(
    Object.entries(o.registry.aliases?.styles ?? {}).filter(([, to]) =>
      allowed.includes(to),
    ),
  );
  const axes = Object.values(o.registry.axes ?? {})
    .filter((a) => !a.surfaces || a.surfaces.includes(o.surface))
    .map((a) => ({ i: a.id, v: a.values, d: a.default, o: a.overridableBy }));
  const config = {
    k: o.storageKey,
    s: o.surface,
    p: o.defaults.packId,
    d: o.registry.aliases?.styles[o.defaults.styleId] ?? o.defaults.styleId,
    m: o.defaults.mode ?? "system",
    a: modesByStyle,
    u: !!o.allowUserStyle,
    al: aliases,
    x: axes,
    sa: styleAxes,
    sx: o.defaults.axes ?? {},
    ua: o.allowUserAxes ?? false,
  };
  // JSON is escaped so "</script>" can never terminate the inline script.
  const json = JSON.stringify(config).replace(/</g, "\\u003c");
  return `(function(){try{var c=${json};var has=function(o,k){return Object.prototype.hasOwnProperty.call(o,k)};var sel={};try{var raw=JSON.parse(localStorage.getItem(c.k)||"null");sel=(raw&&raw.surfaces&&raw.surfaces[c.s])||{};}catch(e){}
var want=typeof sel.styleId==="string"&&has(c.al,sel.styleId)?c.al[sel.styleId]:sel.styleId;
var style=(c.u&&typeof want==="string"&&has(c.a,want))?want:c.d;
var pref=(sel.mode==="light"||sel.mode==="dark"||sel.mode==="system")?sel.mode:c.m;
var mode=pref==="system"?(window.matchMedia("(prefers-color-scheme: dark)").matches?"dark":"light"):pref;
var modes=c.a[style]||["light"];if(modes.indexOf(mode)<0)mode=modes[0];
var el=document.documentElement;el.setAttribute("data-surface",c.s);el.setAttribute("data-pack",c.p);el.setAttribute("data-style",style);el.setAttribute("data-mode",mode);el.setAttribute("data-mode-preference",pref);el.style.colorScheme=mode;
var mine=(sel.axes&&typeof sel.axes==="object")?sel.axes:{};
for(var i=0;i<c.x.length;i++){var a=c.x[i],v=a.d,ok=function(x){return typeof x==="string"&&a.v.indexOf(x)>=0};
var sp=(c.sa[style]||{})[a.i];if(ok(sp))v=sp;
if(a.o!=="none"&&ok(c.sx[a.i]))v=c.sx[a.i];
if(a.o==="user"&&(c.ua===true||(c.ua&&c.ua.indexOf&&c.ua.indexOf(a.i)>=0))&&ok(mine[a.i]))v=mine[a.i];
el.setAttribute("data-"+a.i,v);}}catch(e){}})();`;
}
