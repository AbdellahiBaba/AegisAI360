import { createRoot } from "react-dom/client";
import App from "./App";
import "./index.css";
import "./i18n";
import { registerServiceWorker } from "./lib/serviceWorker";

let deferredInstallPrompt: any = null;
window.addEventListener("beforeinstallprompt", (e) => {
  e.preventDefault();
  deferredInstallPrompt = e;
});
export { deferredInstallPrompt };

const CURRENT_CACHE = "aegisai360-v8.2.1";

async function clearStaleCachesAndBoot() {
  if ("caches" in window) {
    try {
      const cacheNames = await caches.keys();
      const stale = cacheNames.filter((n) => n !== CURRENT_CACHE);
      if (stale.length > 0) {
        await Promise.all(stale.map((n) => caches.delete(n)));
        if ("serviceWorker" in navigator) {
          const regs = await navigator.serviceWorker.getRegistrations();
          await Promise.all(regs.map((r) => r.unregister()));
        }
        window.location.reload();
        return;
      }
    } catch (_) {}
  }

  createRoot(document.getElementById("root")!).render(<App />);
  registerServiceWorker();
}

clearStaleCachesAndBoot();
