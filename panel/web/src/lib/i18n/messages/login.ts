// Sign-in page.
import type { Messages } from "./types";

export const login = {
  headline: ["Your network. Under control.", "شبکهٔ شما، تحت کنترل."],
  quietDesc: [
    "Traffic runs through your selected engines. The panel only manages them.",
    "ترافیک از موتورهای انتخابی عبور می‌کند؛ پنل فقط آن‌ها را مدیریت می‌کند.",
  ],
  loginTitle: ["Welcome back.", "خوش آمدید."],
  loginDesc: [
    "Sign in to manage your server connections.",
    "برای مدیریت اتصال‌های سرور وارد شوید.",
  ],
  username: ["Username", "نام کاربری"],
  signIn: ["Sign in", "ورود"],
  httpAccess: ["HTTP · Unencrypted connection", "اتصال HTTP · بدون رمزگذاری"],
  demoLogin: [
    "Demo login: demo / demo-panel-12345",
    "ورود نمایشی: demo / demo-panel-12345",
  ],
} satisfies Messages;
