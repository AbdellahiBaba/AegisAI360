import { apiRequest } from "./queryClient";

let swRegistration: ServiceWorkerRegistration | null = null;

export async function registerServiceWorker(): Promise<ServiceWorkerRegistration | null> {
  if (!("serviceWorker" in navigator)) return null;

  try {
    const reg = await navigator.serviceWorker.register("/sw.js", { scope: "/" });
    swRegistration = reg;

    reg.addEventListener("updatefound", () => {
      const newWorker = reg.installing;
      if (newWorker) {
        newWorker.addEventListener("statechange", () => {
          if (newWorker.state === "activated") {
            window.dispatchEvent(new CustomEvent("sw-status-change"));
          }
        });
      }
    });

    navigator.serviceWorker.addEventListener("message", (event) => {
      window.dispatchEvent(new CustomEvent("sw-message", { detail: event.data }));
    });

    return reg;
  } catch (err) {
    console.error("SW registration failed:", err);
    return null;
  }
}

export function getRegistration(): ServiceWorkerRegistration | null {
  return swRegistration;
}

export async function getSwStatus(): Promise<{
  installed: boolean;
  active: boolean;
  waiting: boolean;
  scope: string;
  state: string;
}> {
  const reg = swRegistration;
  if (!reg) {
    return { installed: false, active: false, waiting: false, scope: "", state: "not-installed" };
  }
  return {
    installed: true,
    active: !!reg.active,
    waiting: !!reg.waiting,
    scope: reg.scope,
    state: reg.active?.state || "unknown",
  };
}

export async function requestNotificationPermission(): Promise<NotificationPermission> {
  if (!("Notification" in window)) return "denied";
  if (Notification.permission !== "default") return Notification.permission;
  return await Notification.requestPermission();
}

export async function subscribeToPush(): Promise<PushSubscription | null> {
  const reg = swRegistration;
  if (!reg) return null;

  try {
    const response = await fetch("/api/push/vapid-key");
    const { publicKey } = await response.json();
    if (!publicKey) return null;

    const sub = await reg.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: urlBase64ToUint8Array(publicKey),
    });

    await apiRequest("POST", "/api/push/subscribe", {
      endpoint: sub.endpoint,
      keys: {
        p256dh: arrayBufferToBase64(sub.getKey("p256dh")!),
        auth: arrayBufferToBase64(sub.getKey("auth")!),
      },
    });

    return sub;
  } catch (err) {
    console.error("Push subscription failed:", err);
    return null;
  }
}

export async function unsubscribeFromPush(): Promise<boolean> {
  const reg = swRegistration;
  if (!reg) return false;

  try {
    const sub = await reg.pushManager.getSubscription();
    if (!sub) return true;

    await apiRequest("POST", "/api/push/unsubscribe", { endpoint: sub.endpoint });
    await sub.unsubscribe();
    return true;
  } catch (err) {
    console.error("Push unsubscribe failed:", err);
    return false;
  }
}

export async function getPushSubscriptionStatus(): Promise<{ subscribed: boolean; endpoint?: string }> {
  const reg = swRegistration;
  if (!reg) return { subscribed: false };

  try {
    const sub = await reg.pushManager.getSubscription();
    return sub ? { subscribed: true, endpoint: sub.endpoint } : { subscribed: false };
  } catch {
    return { subscribed: false };
  }
}

export async function triggerBackgroundSync(tag: string = "aegis-telemetry-sync"): Promise<boolean> {
  const reg = swRegistration;
  if (!reg) return false;

  try {
    await (reg as any).sync.register(tag);
    return true;
  } catch {
    return false;
  }
}

export async function sendSwMessage(msg: any): Promise<any> {
  const reg = swRegistration;
  if (!reg?.active) return null;

  return new Promise((resolve) => {
    const channel = new MessageChannel();
    channel.port1.onmessage = (e) => resolve(e.data);
    reg.active!.postMessage(msg, [channel.port2]);
    setTimeout(() => resolve(null), 3000);
  });
}

export async function getCacheStatus(): Promise<{ names: string[]; estimatedSize?: number }> {
  try {
    const names = await caches.keys();
    let estimatedSize: number | undefined;
    if ("storage" in navigator && "estimate" in navigator.storage) {
      const est = await navigator.storage.estimate();
      estimatedSize = est.usage;
    }
    return { names, estimatedSize };
  } catch {
    return { names: [] };
  }
}

function urlBase64ToUint8Array(base64String: string): Uint8Array {
  const padding = "=".repeat((4 - (base64String.length % 4)) % 4);
  const base64 = (base64String + padding).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(base64);
  const arr = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
  return arr;
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}
