// Connection templates: ready starting points for common setups.
import type { Messages } from "./types";

export const templates = {
  tmplStart: ["Start from a template", "شروع با یک قالب آماده"],
  tmpl_vpn: ["VPN to a foreign server", "تونل VPN به سرور خارج"],
  tmplHelp_vpn: [
    "TCP and UDP on one port, forwarded in the kernel: the fastest path.",
    "TCP و UDP روی یک پورت، با عبور در کرنل؛ سریع‌ترین مسیر.",
  ],
  tmpl_web: ["HTTPS / TLS relay", "رله‌ی HTTPS / TLS"],
  tmplHelp_web: [
    "TCP 443 through HAProxy, with health checks and graceful reloads.",
    "TCP 443 از طریق HAProxy، همراه با بررسی سلامت و بارگذاری بدون قطعی.",
  ],
  tmpl_range: ["A range of ports", "بازه‌ای از پورت‌ها"],
  tmplHelp_range: [
    "Many ports to the same port numbers in one kernel rule.",
    "چندین پورت به همان شماره‌پورت‌ها، با یک قانون کرنل.",
  ],
  tmpl_balance: ["Several foreign servers", "چند سرور خارج"],
  tmplHelp_balance: [
    "Shares clients between servers and skips one that stops answering.",
    "کاربران را بین سرورها تقسیم می‌کند و سروری را که پاسخ نمی‌دهد کنار می‌گذارد.",
  ],
  tmpl_gre: ["Through a GRE tunnel", "از طریق تونل GRE"],
  tmplHelp_gre: [
    "Sends traffic to the far end of an existing GRE tunnel.",
    "ترافیک را به سمت دیگر یک تونل GRE موجود می‌فرستد.",
  ],
} satisfies Messages;
