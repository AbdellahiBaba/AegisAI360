import { malwareBazaarLookup } from "./services/threatIntel/malwareBazaar";

interface TrojanFamily {
  name: string;
  aliases: string[];
  category: "RAT" | "Banking" | "Stealer" | "Mobile" | "Cryptominer" | "C2" | "Loader" | "Ransomware" | "Wiper";
  description: string;
  firstSeen: string;
  lastActive: string;
  mitreTechniques: Array<{ id: string; name: string; tactic: string }>;
  c2Ports: number[];
  mutexPatterns: string[];
  registryKeys: string[];
  filePaths: string[];
  networkSignatures: string[];
  knownHashes: string[];
  knownDomains: string[];
  knownIPs: string[];
  behaviorProfile: {
    persistence: string[];
    discovery: string[];
    lateralMovement: string[];
    exfiltration: string[];
    commandAndControl: string[];
    execution: string[];
  };
  yaraStrings: string[];
  yaraHex: string[];
  processNames: string[];
  commandLines: string[];
  riskScore: number;
}

const TROJAN_KNOWLEDGE_BASE: TrojanFamily[] = [
  {
    name: "AsyncRAT",
    aliases: ["AsyncRAT", "Async Remote Access Trojan"],
    category: "RAT",
    description: "Open-source remote access trojan written in C#. Features keylogging, screen capture, file management, and reverse proxy capabilities.",
    firstSeen: "2019-01",
    lastActive: "2024-12",
    mitreTechniques: [
      { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
      { id: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: "Persistence" },
      { id: "T1055", name: "Process Injection", tactic: "Defense Evasion" },
      { id: "T1056.001", name: "Keylogging", tactic: "Collection" },
      { id: "T1113", name: "Screen Capture", tactic: "Collection" },
      { id: "T1571", name: "Non-Standard Port", tactic: "Command and Control" },
      { id: "T1573.001", name: "Symmetric Cryptography", tactic: "Command and Control" },
    ],
    c2Ports: [6606, 7707, 8808, 4449, 5552, 6666, 7777, 8888],
    mutexPatterns: ["AsyncMutex_6SI8OkPnk", "AsyncMutex_*", "\\Sessions\\*\\BaseNamedObjects\\AsyncMutex"],
    registryKeys: [
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\AsyncRAT",
      "HKCU\\Environment\\SEE_MASK_NOZONECHECKS",
      "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*",
    ],
    filePaths: [
      "%AppData%\\AsyncRAT\\",
      "%Temp%\\AsyncRAT\\",
      "%AppData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\AsyncRAT.lnk",
      "%AppData%\\stub.exe",
    ],
    networkSignatures: [
      "POST /rat HTTP/1.1",
      "Content-Type: application/octet-stream",
      "X-AsyncRAT: true",
    ],
    knownHashes: [
      "e4a0c09c2e8a3e3c54d9b4e6f5c1a2b3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9",
    ],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Registry Run key modification", "Startup folder shortcut creation", "Scheduled task creation"],
      discovery: ["System information gathering via WMI", "Network configuration enumeration", "Running process enumeration"],
      lateralMovement: [],
      exfiltration: ["Keylogger data exfiltration over C2", "Screen capture exfiltration"],
      commandAndControl: ["TCP socket connection to C2", "AES-256 encrypted communication", "Certificate pinning"],
      execution: ["PowerShell script execution", "Process hollowing", ".NET assembly loading"],
    },
    yaraStrings: ["AsyncMutex", "AsyncRAT", "stub.exe", "Async_RAT", "ABORIFHJAOSDHFOIUAHSF"],
    yaraHex: ["41 73 79 6E 63 4D 75 74 65 78"],
    processNames: ["AsyncRAT.exe", "stub.exe"],
    commandLines: ["powershell -ExecutionPolicy Bypass -File", "schtasks /create /tn AsyncRAT"],
    riskScore: 85,
  },
  {
    name: "DarkComet",
    aliases: ["DarkComet RAT", "Fynloski", "Breut"],
    category: "RAT",
    description: "Legacy remote access trojan developed by DarkCoderSc. Widely used in targeted attacks with full system control capabilities.",
    firstSeen: "2008-06",
    lastActive: "2023-06",
    mitreTechniques: [
      { id: "T1059.003", name: "Windows Command Shell", tactic: "Execution" },
      { id: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: "Persistence" },
      { id: "T1056.001", name: "Keylogging", tactic: "Collection" },
      { id: "T1123", name: "Audio Capture", tactic: "Collection" },
      { id: "T1125", name: "Video Capture", tactic: "Collection" },
      { id: "T1571", name: "Non-Standard Port", tactic: "Command and Control" },
    ],
    c2Ports: [1604, 1337, 4444, 5555, 8080],
    mutexPatterns: ["DC_MUTEX-*", "DarkComet-*", "DCPERSFWBP"],
    registryKeys: [
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\MicroUpdate",
      "HKCU\\Software\\DC3_FEXEC",
      "HKLM\\SYSTEM\\CurrentControlSet\\Services\\DarkComet",
    ],
    filePaths: [
      "%AppData%\\dclogs\\",
      "%System32%\\msdcsc.exe",
      "%Temp%\\dclogs\\",
      "%AppData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\MicroUpdate.exe",
    ],
    networkSignatures: [
      "IDTYPE",
      "GetSIN",
      "GetPCInfo",
      "DCPERSFWBP",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Registry Run key (MicroUpdate)", "Startup folder executable", "Service installation"],
      discovery: ["System info collection (OS, CPU, RAM)", "Webcam enumeration", "Installed AV detection"],
      lateralMovement: [],
      exfiltration: ["Keylog file upload", "Webcam/audio stream to C2"],
      commandAndControl: ["Custom TCP protocol", "RC4 encrypted payloads"],
      execution: ["cmd.exe command execution", "File download and execute"],
    },
    yaraStrings: ["DarkComet", "DC_MUTEX", "dclogs", "DCPERSFWBP", "msdcsc", "DarkCoderSc"],
    yaraHex: ["44 43 5F 4D 55 54 45 58"],
    processNames: ["msdcsc.exe", "MicroUpdate.exe"],
    commandLines: ["msdcsc.exe", "reg add HKCU\\Software\\DC3_FEXEC"],
    riskScore: 80,
  },
  {
    name: "njRAT",
    aliases: ["Bladabindi", "njw0rm"],
    category: "RAT",
    description: "Prolific .NET remote access trojan originating from the Middle East. Supports keylogging, screen capture, file management, and plugin extensibility.",
    firstSeen: "2012-11",
    lastActive: "2024-12",
    mitreTechniques: [
      { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
      { id: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: "Persistence" },
      { id: "T1056.001", name: "Keylogging", tactic: "Collection" },
      { id: "T1113", name: "Screen Capture", tactic: "Collection" },
      { id: "T1571", name: "Non-Standard Port", tactic: "Command and Control" },
      { id: "T1095", name: "Non-Application Layer Protocol", tactic: "Command and Control" },
    ],
    c2Ports: [5552, 1177, 4444, 5555, 7777],
    mutexPatterns: ["njRAT*", "njq8*", "Bladabindi*"],
    registryKeys: [
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
      "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
      "HKCU\\di",
      "HKCU\\Software\\*\\njq8",
    ],
    filePaths: [
      "%AppData%\\server.exe",
      "%Temp%\\server.exe",
      "%UserProfile%\\server.exe",
      "%AppData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\server.lnk",
    ],
    networkSignatures: [
      "ll|'|'|",
      "kl|'|'|",
      "inf|'|'|",
      "proc|'|'|",
      "rss|'|'|",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Registry Run key auto-start", "Startup folder shortcut", "Copy self to AppData"],
      discovery: ["WMI queries for system info", "Network adapter enumeration", "AV product detection"],
      lateralMovement: ["USB worm propagation", "Network share spreading"],
      exfiltration: ["Keylogger data over TCP", "Browser credential theft"],
      commandAndControl: ["Custom TCP protocol with | delimiter", "Base64 encoded commands"],
      execution: ["Process creation via cmd.exe", "DLL plugin loading"],
    },
    yaraStrings: ["njRAT", "njq8", "Bladabindi", "server.exe", "|'|'|"],
    yaraHex: ["6E 6A 52 41 54", "7C 27 7C 27 7C"],
    processNames: ["server.exe", "svchost.exe"],
    commandLines: ["netsh firewall add allowedprogram", "reg add HKCU\\di"],
    riskScore: 82,
  },
  {
    name: "Remcos",
    aliases: ["Remcos RAT", "RemcosRAT"],
    category: "RAT",
    description: "Commercial remote administration tool frequently abused as a RAT. Features surveillance, keylogging, and remote desktop capabilities.",
    firstSeen: "2016-07",
    lastActive: "2024-12",
    mitreTechniques: [
      { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
      { id: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: "Persistence" },
      { id: "T1056.001", name: "Keylogging", tactic: "Collection" },
      { id: "T1113", name: "Screen Capture", tactic: "Collection" },
      { id: "T1055.012", name: "Process Hollowing", tactic: "Defense Evasion" },
      { id: "T1573.001", name: "Symmetric Cryptography", tactic: "Command and Control" },
      { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control" },
    ],
    c2Ports: [2404, 2560, 8080, 443, 80, 4782],
    mutexPatterns: ["Remcos_Mutex_*", "Remcos-*", "RmC-*"],
    registryKeys: [
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Remcos",
      "HKCU\\Software\\Remcos-*",
      "HKLM\\SOFTWARE\\Remcos\\",
    ],
    filePaths: [
      "%AppData%\\Remcos\\",
      "%AppData%\\remcos\\logs.dat",
      "%ProgramData%\\Remcos\\",
      "%Temp%\\remcos\\",
    ],
    networkSignatures: [
      "Remcos_",
      "Breaking-Security.Net",
      "POST /gate.php",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Registry Run keys", "Startup folder", "Scheduled tasks"],
      discovery: ["System fingerprinting", "Installed software enumeration", "Screen resolution query"],
      lateralMovement: [],
      exfiltration: ["Keylogger logs upload", "Screen/webcam capture upload", "Clipboard monitoring"],
      commandAndControl: ["TLS encrypted C2 channel", "RC4 stream cipher", "Custom binary protocol"],
      execution: ["Process hollowing into legitimate processes", "PowerShell download cradle"],
    },
    yaraStrings: ["Remcos", "Breaking-Security", "remcos_mutex", "logs.dat", "Remcos_Mutex"],
    yaraHex: ["52 65 6D 63 6F 73 5F 4D 75 74 65 78"],
    processNames: ["remcos.exe"],
    commandLines: ["schtasks /create /tn Remcos", "reg add HKCU\\Software\\Remcos"],
    riskScore: 88,
  },
  {
    name: "QuasarRAT",
    aliases: ["Quasar", "CinaRAT", "Yggdrasil"],
    category: "RAT",
    description: "Open-source .NET remote administration tool. Features remote desktop, file manager, keylogger, and reverse proxy.",
    firstSeen: "2014-07",
    lastActive: "2024-12",
    mitreTechniques: [
      { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
      { id: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: "Persistence" },
      { id: "T1056.001", name: "Keylogging", tactic: "Collection" },
      { id: "T1113", name: "Screen Capture", tactic: "Collection" },
      { id: "T1090", name: "Proxy", tactic: "Command and Control" },
      { id: "T1573.002", name: "Asymmetric Cryptography", tactic: "Command and Control" },
    ],
    c2Ports: [4782, 4783, 1604, 8080, 443],
    mutexPatterns: ["QSR_MUTEX_*", "Quasar_*"],
    registryKeys: [
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Quasar Client Startup",
      "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Quasar",
    ],
    filePaths: [
      "%AppData%\\SubDir\\Client.exe",
      "%AppData%\\Quasar\\",
      "%Temp%\\Quasar\\",
    ],
    networkSignatures: [
      "X509Certificate",
      "QuasarRAT",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Registry Run key", "Startup folder shortcut", "Scheduled task"],
      discovery: ["System info via WMI", "Geolocation via IP API", "Network configuration"],
      lateralMovement: [],
      exfiltration: ["Keylogger data", "Password recovery data"],
      commandAndControl: ["TLS encrypted TCP", "X509 certificate validation", "AES-128 data encryption"],
      execution: [".NET assembly execution", "Shell command execution"],
    },
    yaraStrings: ["QuasarRAT", "QSR_MUTEX", "Quasar Client", "SubDir\\Client.exe"],
    yaraHex: ["51 53 52 5F 4D 55 54 45 58"],
    processNames: ["Client.exe"],
    commandLines: ["schtasks /create /tn Quasar"],
    riskScore: 83,
  },
  {
    name: "NetWire",
    aliases: ["NetWireRC", "NetWire RC", "Recam"],
    category: "RAT",
    description: "Multi-platform remote access trojan with credential stealing, keylogging, and remote desktop capabilities. Originally marketed as a legitimate tool.",
    firstSeen: "2012-01",
    lastActive: "2024-06",
    mitreTechniques: [
      { id: "T1059.003", name: "Windows Command Shell", tactic: "Execution" },
      { id: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: "Persistence" },
      { id: "T1056.001", name: "Keylogging", tactic: "Collection" },
      { id: "T1555.003", name: "Credentials from Web Browsers", tactic: "Credential Access" },
      { id: "T1573.001", name: "Symmetric Cryptography", tactic: "Command and Control" },
    ],
    c2Ports: [3360, 3364, 1604, 4444, 80],
    mutexPatterns: ["NetWireRC_Mutex*", "OPe-*"],
    registryKeys: [
      "HKCU\\Software\\NetWire\\",
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\NetWire",
    ],
    filePaths: [
      "%AppData%\\Install\\Host.exe",
      "%AppData%\\NetWire\\",
      "%Temp%\\NetWire\\Logs\\",
    ],
    networkSignatures: [
      "NetWire",
      "3c 17 20 25",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Registry Run key", "Startup folder copy"],
      discovery: ["System info collection", "Credential store enumeration"],
      lateralMovement: [],
      exfiltration: ["Browser credential theft", "Keylogger data upload"],
      commandAndControl: ["AES encrypted TCP", "Custom handshake protocol"],
      execution: ["cmd.exe execution", "File download and execute"],
    },
    yaraStrings: ["NetWire", "NetWireRC", "Host.exe", "Logs\\Day"],
    yaraHex: ["4E 65 74 57 69 72 65"],
    processNames: ["Host.exe", "NetWire.exe"],
    commandLines: [],
    riskScore: 81,
  },
  {
    name: "Gh0stRAT",
    aliases: ["Gh0st", "Gh0st RAT", "Moudoor", "Mongall"],
    category: "RAT",
    description: "Chinese-origin remote access trojan widely used in APT campaigns. Open-source with many variants. Features remote shell, keylogger, and file management.",
    firstSeen: "2008-01",
    lastActive: "2024-12",
    mitreTechniques: [
      { id: "T1059.003", name: "Windows Command Shell", tactic: "Execution" },
      { id: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: "Persistence" },
      { id: "T1056.001", name: "Keylogging", tactic: "Collection" },
      { id: "T1113", name: "Screen Capture", tactic: "Collection" },
      { id: "T1095", name: "Non-Application Layer Protocol", tactic: "Command and Control" },
      { id: "T1132.001", name: "Standard Encoding", tactic: "Command and Control" },
    ],
    c2Ports: [8000, 8080, 443, 80, 53, 9999],
    mutexPatterns: ["Gh0st*", "YOURPASSWORD*", "YOURMARKHERE*"],
    registryKeys: [
      "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Gh0st",
      "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Gh0st",
    ],
    filePaths: [
      "%System32%\\drivers\\svchost.exe",
      "%Temp%\\Gh0st\\",
      "%System32%\\Gh0st.dll",
    ],
    networkSignatures: [
      "Gh0st",
      "\\x47\\x68\\x30\\x73\\x74",
      "YOURPASSWORD",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Windows service installation", "Registry Run key", "DLL side-loading"],
      discovery: ["System enumeration", "Drive listing", "Process listing"],
      lateralMovement: ["Network share propagation"],
      exfiltration: ["Screen capture upload", "Keylogger data", "File exfiltration"],
      commandAndControl: ["Custom TCP protocol with magic bytes", "Zlib compressed payloads", "DNS tunneling (variants)"],
      execution: ["Remote shell access", "DLL injection", "Service DLL execution"],
    },
    yaraStrings: ["Gh0st", "Gh0stRAT", "YOURPASSWORD", "Gh0st Update"],
    yaraHex: ["47 68 30 73 74"],
    processNames: ["svchost.exe"],
    commandLines: ["sc create Gh0st", "net start Gh0st"],
    riskScore: 84,
  },
  {
    name: "Zeus",
    aliases: ["Zbot", "ZeuS", "Terdot", "DELoader"],
    category: "Banking",
    description: "Infamous banking trojan targeting financial credentials via web injection. Source code leaked in 2011, spawning numerous variants (Citadel, ICE IX, KINS).",
    firstSeen: "2007-06",
    lastActive: "2024-06",
    mitreTechniques: [
      { id: "T1185", name: "Browser Session Hijacking", tactic: "Collection" },
      { id: "T1055.001", name: "Dynamic-link Library Injection", tactic: "Defense Evasion" },
      { id: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: "Persistence" },
      { id: "T1056.004", name: "Credential API Hooking", tactic: "Collection" },
      { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control" },
      { id: "T1573.001", name: "Symmetric Cryptography", tactic: "Command and Control" },
    ],
    c2Ports: [80, 443, 8080],
    mutexPatterns: ["_AVIRA_*", "__SYSTEM__*", "_ZONE*"],
    registryKeys: [
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
      "HKCU\\Software\\Microsoft\\*\\random",
    ],
    filePaths: [
      "%AppData%\\random\\random.exe",
      "%Temp%\\tmp*.tmp",
      "%AppData%\\Microsoft\\random.exe",
    ],
    networkSignatures: [
      "POST /gate.php",
      "POST /config.bin",
      "POST /bot.php",
      "Content-Type: multipart/form-data",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Registry Run key with random name", "AppInit_DLLs modification"],
      discovery: ["Browser process monitoring", "Banking site detection"],
      lateralMovement: [],
      exfiltration: ["Form grabbing via browser hooks", "Web injection data theft", "FTP credential theft"],
      commandAndControl: ["HTTP POST to gate.php", "RC4 encrypted config file", "Domain generation algorithm (DGA)"],
      execution: ["DLL injection into browser processes", "API hooking via inline patches"],
    },
    yaraStrings: ["Zeus", "gate.php", "config.bin", "bot_version", "botid"],
    yaraHex: ["67 61 74 65 2E 70 68 70"],
    processNames: [],
    commandLines: [],
    riskScore: 90,
  },
  {
    name: "TrickBot",
    aliases: ["Trickster", "TheTrick", "TrickLoader"],
    category: "Banking",
    description: "Modular banking trojan evolved from Dyre. Functions as a malware distribution platform with modules for credential theft, lateral movement, and ransomware delivery.",
    firstSeen: "2016-09",
    lastActive: "2024-03",
    mitreTechniques: [
      { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
      { id: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: "Persistence" },
      { id: "T1053.005", name: "Scheduled Task", tactic: "Persistence" },
      { id: "T1055.012", name: "Process Hollowing", tactic: "Defense Evasion" },
      { id: "T1185", name: "Browser Session Hijacking", tactic: "Collection" },
      { id: "T1210", name: "Exploitation of Remote Services", tactic: "Lateral Movement" },
      { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control" },
    ],
    c2Ports: [443, 447, 449, 8082],
    mutexPatterns: ["Global\\TrickBot*"],
    registryKeys: [
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit",
    ],
    filePaths: [
      "%AppData%\\winapp\\",
      "%AppData%\\cloudapp\\",
      "%ProgramData%\\*\\client_id",
      "%ProgramData%\\*\\group_tag",
    ],
    networkSignatures: [
      "POST /*/81/",
      "POST /*/83/",
      "POST /*/90/",
      "gtag=",
      "client_id=",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Scheduled task with random name", "Registry Run key", "Service installation"],
      discovery: ["Domain trust enumeration", "Network topology mapping", "AD reconnaissance (shareDll module)"],
      lateralMovement: ["EternalBlue exploitation (wormDll)", "LDAP/SMB spreading (tabDll)", "RDP brute force (rdpScanDll)"],
      exfiltration: ["Web inject banking data", "Email credential harvesting", "Cookie theft"],
      commandAndControl: ["HTTPS C2 with ECC encryption", "Tor hidden service fallback", "Proxy module for network pivoting"],
      execution: ["Process hollowing", "Module download and load (DLL plugins)", "PowerShell execution"],
    },
    yaraStrings: ["TrickBot", "trickbot", "client_id", "group_tag", "tabDll", "wormDll", "shareDll", "rdpScanDll"],
    yaraHex: [],
    processNames: ["svchost.exe"],
    commandLines: ["schtasks /create /tn TrickBot"],
    riskScore: 92,
  },
  {
    name: "Emotet",
    aliases: ["Heodo", "Geodo", "Mealybug"],
    category: "Banking",
    description: "Originally a banking trojan, evolved into a major malware-as-a-service botnet. Primary loader for TrickBot, QBot, and ransomware. Spreads via malicious email attachments.",
    firstSeen: "2014-06",
    lastActive: "2024-03",
    mitreTechniques: [
      { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
      { id: "T1059.005", name: "Visual Basic", tactic: "Execution" },
      { id: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: "Persistence" },
      { id: "T1053.005", name: "Scheduled Task", tactic: "Persistence" },
      { id: "T1027", name: "Obfuscated Files or Information", tactic: "Defense Evasion" },
      { id: "T1566.001", name: "Spearphishing Attachment", tactic: "Initial Access" },
      { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control" },
    ],
    c2Ports: [80, 443, 7080, 8080, 50000],
    mutexPatterns: ["PEM*", "PEMFD8*", "Global\\I*", "Global\\M*"],
    registryKeys: [
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
      "HKLM\\SYSTEM\\CurrentControlSet\\Services\\*",
    ],
    filePaths: [
      "%LocalAppData%\\random\\random.exe",
      "%SystemRoot%\\SysWOW64\\random\\random.exe",
      "%Temp%\\*.exe",
    ],
    networkSignatures: [
      "POST / HTTP/1.1",
      "Cookie: *=*",
      "Content-Type: multipart/form-data",
      "DNT: 1",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Windows service with random name", "Registry Run key", "Scheduled task"],
      discovery: ["Email harvesting from Outlook", "Network share enumeration"],
      lateralMovement: ["Email thread hijacking", "SMB/Admin$ exploitation", "Brute force credentials"],
      exfiltration: ["Email credential theft", "Contact list exfiltration"],
      commandAndControl: ["HTTP POST with encrypted body", "Multiple C2 tiers (Epoch 1/2/3)", "Self-signed TLS certificates"],
      execution: ["Macro-enabled document execution", "PowerShell download cradle", "Rundll32 execution"],
    },
    yaraStrings: ["Emotet", "PEM", "PEMFD8"],
    yaraHex: [],
    processNames: ["rundll32.exe"],
    commandLines: ["powershell -e", "rundll32.exe shell32.dll,Control_RunDLL"],
    riskScore: 95,
  },
  {
    name: "Dridex",
    aliases: ["Bugat", "Cridex", "Feodo"],
    category: "Banking",
    description: "Banking trojan evolved from Bugat/Cridex. Uses web injection to steal banking credentials. Distributed via malspam with macro-enabled documents.",
    firstSeen: "2014-06",
    lastActive: "2024-03",
    mitreTechniques: [
      { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
      { id: "T1059.005", name: "Visual Basic", tactic: "Execution" },
      { id: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: "Persistence" },
      { id: "T1185", name: "Browser Session Hijacking", tactic: "Collection" },
      { id: "T1055.001", name: "Dynamic-link Library Injection", tactic: "Defense Evasion" },
      { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control" },
    ],
    c2Ports: [443, 4443, 8443],
    mutexPatterns: ["Global\\*"],
    registryKeys: [
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
    ],
    filePaths: [
      "%AppData%\\random.exe",
      "%Temp%\\*.tmp",
    ],
    networkSignatures: [
      "POST / HTTP/1.1",
      "User-Agent: Mozilla/",
      "Content-Type: application/x-www-form-urlencoded",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Registry Run key", "Scheduled task"],
      discovery: ["Banking site detection via web injection config"],
      lateralMovement: [],
      exfiltration: ["Web injection form grabbing", "Man-in-the-browser attacks"],
      commandAndControl: ["HTTPS P2P C2 infrastructure", "XML-based configuration", "Binary protocol over HTTPS"],
      execution: ["Macro execution from Office docs", "PowerShell download", "Rundll32 execution"],
    },
    yaraStrings: ["Dridex", "Bugat", "bot_id"],
    yaraHex: [],
    processNames: ["explorer.exe"],
    commandLines: ["rundll32.exe", "regsvr32.exe /s"],
    riskScore: 88,
  },
  {
    name: "QBot",
    aliases: ["Qakbot", "QuakBot", "Pinkslipbot"],
    category: "Banking",
    description: "Banking trojan and botnet with worm capabilities. Evolved into a major initial access broker, delivering ransomware. Taken down by FBI in Aug 2023 but has re-emerged.",
    firstSeen: "2008-01",
    lastActive: "2024-12",
    mitreTechniques: [
      { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
      { id: "T1053.005", name: "Scheduled Task", tactic: "Persistence" },
      { id: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: "Persistence" },
      { id: "T1055.012", name: "Process Hollowing", tactic: "Defense Evasion" },
      { id: "T1185", name: "Browser Session Hijacking", tactic: "Collection" },
      { id: "T1210", name: "Exploitation of Remote Services", tactic: "Lateral Movement" },
      { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control" },
    ],
    c2Ports: [443, 995, 2222, 2078, 32101],
    mutexPatterns: ["qbot_*"],
    registryKeys: [
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
    ],
    filePaths: [
      "%AppData%\\Microsoft\\*\\*.dll",
      "%Temp%\\*.dll",
    ],
    networkSignatures: [
      "POST / HTTP/1.1",
      "Content-Type: application/x-www-form-urlencoded",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Scheduled task", "Registry Run key", "Service creation"],
      discovery: ["Domain enumeration", "Network mapping", "Installed software inventory"],
      lateralMovement: ["SMB/ADMIN$ spreading", "Email thread hijacking"],
      exfiltration: ["Banking credential theft", "Email harvesting", "Browser cookie theft"],
      commandAndControl: ["HTTPS C2", "Signed C2 communication", "P2P backup C2"],
      execution: ["Process hollowing into wermgr.exe", "DLL execution via regsvr32", "Scheduled task execution"],
    },
    yaraStrings: ["Qakbot", "QBot", "Pinkslipbot", "qbot"],
    yaraHex: [],
    processNames: ["wermgr.exe", "explorer.exe"],
    commandLines: ["regsvr32.exe -s", "schtasks /create"],
    riskScore: 91,
  },
  {
    name: "IcedID",
    aliases: ["BokBot"],
    category: "Banking",
    description: "Banking trojan that also serves as a loader for other malware including ransomware. Uses web injection and proxy-based man-in-the-browser attacks.",
    firstSeen: "2017-09",
    lastActive: "2024-06",
    mitreTechniques: [
      { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
      { id: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: "Persistence" },
      { id: "T1053.005", name: "Scheduled Task", tactic: "Persistence" },
      { id: "T1185", name: "Browser Session Hijacking", tactic: "Collection" },
      { id: "T1055", name: "Process Injection", tactic: "Defense Evasion" },
      { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control" },
    ],
    c2Ports: [443, 8080],
    mutexPatterns: [],
    registryKeys: [
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
    ],
    filePaths: [
      "%LocalAppData%\\*.dll",
      "%Temp%\\*.tmp",
      "%AppData%\\*\\license.dat",
    ],
    networkSignatures: [
      "GET /image/",
      "Cookie: __gads=",
      "Cookie: _u=",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Scheduled task", "Registry Run key"],
      discovery: ["AD enumeration", "Domain trust mapping"],
      lateralMovement: ["Cobalt Strike beacon delivery"],
      exfiltration: ["Web injection banking data", "Browser credential theft"],
      commandAndControl: ["HTTPS with fake cookie C2", "SSL certificate impersonation"],
      execution: ["Rundll32 DLL execution", "Process injection"],
    },
    yaraStrings: ["IcedID", "BokBot", "license.dat"],
    yaraHex: [],
    processNames: ["rundll32.exe", "msiexec.exe"],
    commandLines: ["rundll32.exe", "msiexec /i"],
    riskScore: 87,
  },
  {
    name: "AgentTesla",
    aliases: ["Agent Tesla", "AgenTesla", "Negasteal"],
    category: "Stealer",
    description: ".NET-based information stealer and keylogger sold as MaaS. Exfiltrates credentials, keystrokes, screenshots, and clipboard data via SMTP, FTP, or HTTP.",
    firstSeen: "2014-12",
    lastActive: "2024-12",
    mitreTechniques: [
      { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
      { id: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: "Persistence" },
      { id: "T1056.001", name: "Keylogging", tactic: "Collection" },
      { id: "T1113", name: "Screen Capture", tactic: "Collection" },
      { id: "T1555.003", name: "Credentials from Web Browsers", tactic: "Credential Access" },
      { id: "T1555", name: "Credentials from Password Stores", tactic: "Credential Access" },
      { id: "T1048.003", name: "Exfiltration Over Unencrypted Non-C2 Protocol", tactic: "Exfiltration" },
    ],
    c2Ports: [587, 465, 25, 21, 443, 80],
    mutexPatterns: ["AgentTesla_*", "AKV_MUTEX_*"],
    registryKeys: [
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run\\*",
    ],
    filePaths: [
      "%AppData%\\*.exe",
      "%Temp%\\*.exe",
      "%UserProfile%\\AppData\\Roaming\\*.exe",
    ],
    networkSignatures: [
      "SMTP EHLO",
      "Subject: PW_",
      "Subject: KL_",
      "Subject: SC_",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Registry Run key", "Startup folder", "Scheduled task"],
      discovery: ["Installed browser enumeration", "Email client detection", "FTP client detection"],
      lateralMovement: [],
      exfiltration: ["SMTP exfiltration with Base64 attachments", "FTP upload", "HTTP POST to panel", "Telegram bot API"],
      commandAndControl: ["SMTP-based C2", "HTTP panel", "FTP drop"],
      execution: ["PowerShell download cradle", ".NET execution", "Process injection"],
    },
    yaraStrings: ["AgentTesla", "Agent Tesla", "PW_", "KL_", "SC_", "Negasteal"],
    yaraHex: [],
    processNames: ["RegAsm.exe", "InstallUtil.exe"],
    commandLines: ["RegAsm.exe", "InstallUtil.exe /LogFile="],
    riskScore: 78,
  },
  {
    name: "RedLine",
    aliases: ["RedLine Stealer"],
    category: "Stealer",
    description: "Popular information stealer sold on underground forums. Targets browser credentials, cryptocurrency wallets, VPN clients, and system information.",
    firstSeen: "2020-02",
    lastActive: "2024-12",
    mitreTechniques: [
      { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
      { id: "T1555.003", name: "Credentials from Web Browsers", tactic: "Credential Access" },
      { id: "T1539", name: "Steal Web Session Cookie", tactic: "Credential Access" },
      { id: "T1005", name: "Data from Local System", tactic: "Collection" },
      { id: "T1113", name: "Screen Capture", tactic: "Collection" },
      { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control" },
    ],
    c2Ports: [443, 80, 8080, 6677],
    mutexPatterns: ["RedLine_*"],
    registryKeys: [],
    filePaths: [
      "%Temp%\\*.exe",
      "%LocalAppData%\\*.exe",
    ],
    networkSignatures: [
      "SOAP action",
      "Content-Type: text/xml",
      "POST /",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Usually none — smash-and-grab stealer"],
      discovery: ["Browser profile enumeration", "Crypto wallet file search", "VPN config file search", "System hardware info (GPU for crypto)"],
      lateralMovement: [],
      exfiltration: ["SOAP/XML over HTTPS", "Zip archive of stolen data"],
      commandAndControl: ["SOAP-based C2", "HTTPS POST"],
      execution: [".NET assembly execution", "PowerShell download"],
    },
    yaraStrings: ["RedLine", "RedLine Stealer", "StringDecrypt", "ScanningArgs"],
    yaraHex: [],
    processNames: [],
    commandLines: [],
    riskScore: 76,
  },
  {
    name: "Raccoon",
    aliases: ["Raccoon Stealer", "RecordBreaker"],
    category: "Stealer",
    description: "MaaS information stealer targeting browser data, crypto wallets, and email clients. Version 2.0 (RecordBreaker) rebuilt in C/C++ for improved performance.",
    firstSeen: "2019-04",
    lastActive: "2024-12",
    mitreTechniques: [
      { id: "T1555.003", name: "Credentials from Web Browsers", tactic: "Credential Access" },
      { id: "T1539", name: "Steal Web Session Cookie", tactic: "Credential Access" },
      { id: "T1005", name: "Data from Local System", tactic: "Collection" },
      { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control" },
    ],
    c2Ports: [80, 443],
    mutexPatterns: ["raccoon_*"],
    registryKeys: [],
    filePaths: [
      "%Temp%\\*.exe",
      "%Temp%\\*.dll",
    ],
    networkSignatures: [
      "POST /",
      "machineId=",
      "configId=",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Usually none — smash-and-grab"],
      discovery: ["Browser profile search", "Crypto wallet search", "Email client search"],
      lateralMovement: [],
      exfiltration: ["HTTP POST with stolen data archive"],
      commandAndControl: ["HTTP-based C2 with config download"],
      execution: ["Direct execution", "Loader DLL injection"],
    },
    yaraStrings: ["Raccoon", "RecordBreaker", "machineId", "configId"],
    yaraHex: [],
    processNames: [],
    commandLines: [],
    riskScore: 74,
  },
  {
    name: "Vidar",
    aliases: ["Vidar Stealer"],
    category: "Stealer",
    description: "Information stealer forked from Arkei. Targets browser data, crypto wallets, 2FA apps, and takes screenshots. Distributed via malvertising and cracked software.",
    firstSeen: "2018-10",
    lastActive: "2024-12",
    mitreTechniques: [
      { id: "T1555.003", name: "Credentials from Web Browsers", tactic: "Credential Access" },
      { id: "T1539", name: "Steal Web Session Cookie", tactic: "Credential Access" },
      { id: "T1005", name: "Data from Local System", tactic: "Collection" },
      { id: "T1113", name: "Screen Capture", tactic: "Collection" },
      { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control" },
    ],
    c2Ports: [80, 443],
    mutexPatterns: [],
    registryKeys: [],
    filePaths: [
      "%ProgramData%\\*.exe",
      "%Temp%\\*.exe",
    ],
    networkSignatures: [
      "POST /",
      "Content-Type: multipart/form-data",
      "hwid=",
      "os=",
      "platform=",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Usually none"],
      discovery: ["Browser enumeration", "2FA app search (Authy, Google Authenticator)", "Crypto wallet search"],
      lateralMovement: [],
      exfiltration: ["Multipart HTTP POST with zip archive", "Screenshots and files"],
      commandAndControl: ["HTTP C2 with dead drop resolvers (Steam, Telegram)"],
      execution: ["Direct PE execution", "Self-deletion after exfil"],
    },
    yaraStrings: ["Vidar", "hwid", "Arkei"],
    yaraHex: [],
    processNames: [],
    commandLines: [],
    riskScore: 73,
  },
  {
    name: "FormBook",
    aliases: ["Formbook", "xLoader"],
    category: "Stealer",
    description: "Information stealer and form grabber. xLoader is the macOS variant. Uses process injection and anti-analysis techniques extensively.",
    firstSeen: "2016-01",
    lastActive: "2024-12",
    mitreTechniques: [
      { id: "T1055.012", name: "Process Hollowing", tactic: "Defense Evasion" },
      { id: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: "Persistence" },
      { id: "T1056.001", name: "Keylogging", tactic: "Collection" },
      { id: "T1113", name: "Screen Capture", tactic: "Collection" },
      { id: "T1555.003", name: "Credentials from Web Browsers", tactic: "Credential Access" },
      { id: "T1185", name: "Browser Session Hijacking", tactic: "Collection" },
      { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control" },
    ],
    c2Ports: [80, 443],
    mutexPatterns: ["formbook_*", "xloader_*"],
    registryKeys: [
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\*",
    ],
    filePaths: [
      "%AppData%\\*\\*.exe",
      "%Temp%\\*.exe",
      "%UserProfile%\\AppData\\Local\\Temp\\*",
    ],
    networkSignatures: [
      "GET /form*",
      "POST /form*",
      "User-Agent: Mozilla/5.0",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Registry Run key", "Random delay execution", "Process injection persistence"],
      discovery: ["Browser enumeration", "Email client detection", "Installed application inventory"],
      lateralMovement: [],
      exfiltration: ["HTTP POST to C2 panel", "Form data interception"],
      commandAndControl: ["HTTP-based C2 with decoy URLs", "Multiple C2 domain fallback", "RC4 encrypted payloads"],
      execution: ["Process hollowing into explorer.exe", "ntdll unhooking", "Anti-sandbox detection"],
    },
    yaraStrings: ["FormBook", "xLoader", "formbook"],
    yaraHex: [],
    processNames: ["explorer.exe"],
    commandLines: [],
    riskScore: 80,
  },
  {
    name: "Cerberus",
    aliases: ["Cerberus Android"],
    category: "Mobile",
    description: "Android banking trojan with overlay attack capabilities. Targets banking apps, cryptocurrency wallets, and social media. Source code leaked in 2020.",
    firstSeen: "2019-06",
    lastActive: "2024-06",
    mitreTechniques: [
      { id: "T1417.002", name: "GUI Input Capture: Phishing Overlay", tactic: "Collection" },
      { id: "T1411", name: "Input Prompt", tactic: "Collection" },
      { id: "T1418", name: "Software Discovery", tactic: "Discovery" },
      { id: "T1646", name: "Exfiltration Over C2 Channel", tactic: "Exfiltration" },
      { id: "T1517", name: "Access Notifications", tactic: "Collection" },
    ],
    c2Ports: [443, 80],
    mutexPatterns: [],
    registryKeys: [],
    filePaths: [
      "/data/data/com.*/",
      "/sdcard/.*/",
    ],
    networkSignatures: [
      "POST /gate.php",
      "POST /api/",
      "bot_id=",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Accessibility Service abuse", "Device Admin registration", "Auto-start on boot"],
      discovery: ["Installed app enumeration", "SMS interception", "Contact list access"],
      lateralMovement: ["SMS spreading"],
      exfiltration: ["Overlay phishing data", "SMS logs", "2FA codes", "Contact lists"],
      commandAndControl: ["HTTP/HTTPS to C2 panel", "Firebase Cloud Messaging", "Telegram bot fallback"],
      execution: ["APK sideloading", "Accessibility Service automation", "Screen recording"],
    },
    yaraStrings: ["Cerberus", "gate.php", "bot_id", "accessibility"],
    yaraHex: [],
    processNames: [],
    commandLines: [],
    riskScore: 86,
  },
  {
    name: "Anubis",
    aliases: ["Anubis Android", "BankBot Anubis"],
    category: "Mobile",
    description: "Android banking trojan with extensive capabilities including overlay attacks, keylogging, file encryption (ransomware), and screen recording.",
    firstSeen: "2017-12",
    lastActive: "2024-06",
    mitreTechniques: [
      { id: "T1417.002", name: "GUI Input Capture: Phishing Overlay", tactic: "Collection" },
      { id: "T1418", name: "Software Discovery", tactic: "Discovery" },
      { id: "T1646", name: "Exfiltration Over C2 Channel", tactic: "Exfiltration" },
      { id: "T1471", name: "Data Encrypted for Impact", tactic: "Impact" },
      { id: "T1517", name: "Access Notifications", tactic: "Collection" },
    ],
    c2Ports: [443, 80],
    mutexPatterns: [],
    registryKeys: [],
    filePaths: [
      "/data/data/com.*/",
    ],
    networkSignatures: [
      "POST /o1o/a*",
      "POST /gp/",
      "type=WEB",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Accessibility Service abuse", "Device Admin", "Anti-uninstall"],
      discovery: ["App list enumeration", "Country code detection"],
      lateralMovement: [],
      exfiltration: ["Overlay phishing credentials", "SMS interception", "Keylogger data"],
      commandAndControl: ["HTTPS to C2", "Twitter/Telegram fallback C2"],
      execution: ["APK installation", "Accessibility automation", "File encryption (ransomware module)"],
    },
    yaraStrings: ["Anubis", "BankBot", "/o1o/a", "WEB_INJECT"],
    yaraHex: [],
    processNames: [],
    commandLines: [],
    riskScore: 88,
  },
  {
    name: "FluBot",
    aliases: ["FluBot", "Cabassous", "FedEx SMS"],
    category: "Mobile",
    description: "Android banking trojan spread via SMS phishing (smishing). Disguised as delivery tracking apps. Targets banking credentials via overlay attacks.",
    firstSeen: "2020-12",
    lastActive: "2023-06",
    mitreTechniques: [
      { id: "T1417.002", name: "GUI Input Capture: Phishing Overlay", tactic: "Collection" },
      { id: "T1418", name: "Software Discovery", tactic: "Discovery" },
      { id: "T1646", name: "Exfiltration Over C2 Channel", tactic: "Exfiltration" },
      { id: "T1582", name: "SMS Control", tactic: "Impact" },
    ],
    c2Ports: [443, 80],
    mutexPatterns: [],
    registryKeys: [],
    filePaths: [],
    networkSignatures: [
      "POST /poll",
      "POST /submit",
      "DGA domain pattern",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Accessibility Service", "Default SMS app replacement"],
      discovery: ["Contact list harvesting", "Installed banking app detection"],
      lateralMovement: ["SMS worm spreading to contacts"],
      exfiltration: ["Overlay phishing data", "SMS messages", "Contact lists"],
      commandAndControl: ["HTTPS with DGA", "DNS-over-HTTPS for domain resolution"],
      execution: ["APK sideload via smishing link"],
    },
    yaraStrings: ["FluBot", "Cabassous"],
    yaraHex: [],
    processNames: [],
    commandLines: [],
    riskScore: 82,
  },
  {
    name: "SharkBot",
    aliases: ["SharkBot Android"],
    category: "Mobile",
    description: "Android banking trojan that uses Automatic Transfer System (ATS) to bypass multi-factor authentication and automate money transfers.",
    firstSeen: "2021-10",
    lastActive: "2024-06",
    mitreTechniques: [
      { id: "T1417.002", name: "GUI Input Capture: Phishing Overlay", tactic: "Collection" },
      { id: "T1418", name: "Software Discovery", tactic: "Discovery" },
      { id: "T1646", name: "Exfiltration Over C2 Channel", tactic: "Exfiltration" },
    ],
    c2Ports: [443],
    mutexPatterns: [],
    registryKeys: [],
    filePaths: [],
    networkSignatures: [
      "POST /api/",
      "Content-Type: application/json",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Accessibility Service abuse"],
      discovery: ["Banking app detection", "Country/language detection"],
      lateralMovement: [],
      exfiltration: ["ATS-based automated transfers", "Overlay credential theft", "2FA code interception"],
      commandAndControl: ["HTTPS JSON API"],
      execution: ["Dropper from Google Play Store", "Modular payload download"],
    },
    yaraStrings: ["SharkBot"],
    yaraHex: [],
    processNames: [],
    commandLines: [],
    riskScore: 85,
  },
  {
    name: "Hydra",
    aliases: ["BianLian", "Hydra Android"],
    category: "Mobile",
    description: "Android banking trojan with VNC capabilities for remote device control. Targets banking apps with overlay attacks and supports screen streaming.",
    firstSeen: "2019-01",
    lastActive: "2024-06",
    mitreTechniques: [
      { id: "T1417.002", name: "GUI Input Capture: Phishing Overlay", tactic: "Collection" },
      { id: "T1418", name: "Software Discovery", tactic: "Discovery" },
      { id: "T1646", name: "Exfiltration Over C2 Channel", tactic: "Exfiltration" },
    ],
    c2Ports: [443, 80],
    mutexPatterns: [],
    registryKeys: [],
    filePaths: [],
    networkSignatures: [
      "POST /gate",
      "POST /check",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Accessibility Service", "Device Admin"],
      discovery: ["Installed app enumeration", "Device info collection"],
      lateralMovement: [],
      exfiltration: ["Overlay phishing data", "Screen streaming via VNC", "SMS interception"],
      commandAndControl: ["HTTPS C2", "WebSocket for VNC"],
      execution: ["APK dropper", "Accessibility automation"],
    },
    yaraStrings: ["Hydra", "BianLian"],
    yaraHex: [],
    processNames: [],
    commandLines: [],
    riskScore: 84,
  },
  {
    name: "BRATA",
    aliases: ["BRATA Android", "AmexTroll"],
    category: "Mobile",
    description: "Brazilian Android RAT initially targeting Brazilian banks, expanded to European targets. Capable of factory reset after stealing data to destroy evidence.",
    firstSeen: "2019-01",
    lastActive: "2024-03",
    mitreTechniques: [
      { id: "T1417.002", name: "GUI Input Capture: Phishing Overlay", tactic: "Collection" },
      { id: "T1418", name: "Software Discovery", tactic: "Discovery" },
      { id: "T1646", name: "Exfiltration Over C2 Channel", tactic: "Exfiltration" },
      { id: "T1471", name: "Data Encrypted for Impact", tactic: "Impact" },
    ],
    c2Ports: [443],
    mutexPatterns: [],
    registryKeys: [],
    filePaths: [],
    networkSignatures: [
      "POST /api/",
      "WebSocket upgrade",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Accessibility Service", "Device Admin"],
      discovery: ["Banking app detection", "GPS location tracking"],
      lateralMovement: [],
      exfiltration: ["Screen capture", "Keylogger data", "Banking credentials via overlay"],
      commandAndControl: ["HTTPS REST API", "WebSocket for real-time control"],
      execution: ["APK sideload", "Factory reset after theft (anti-forensics)"],
    },
    yaraStrings: ["BRATA", "AmexTroll"],
    yaraHex: [],
    processNames: [],
    commandLines: [],
    riskScore: 87,
  },
  {
    name: "Joker",
    aliases: ["Bread", "Joker Android"],
    category: "Mobile",
    description: "Android malware focused on premium SMS fraud and subscription scams. Frequently found on Google Play Store disguised as utility apps.",
    firstSeen: "2017-06",
    lastActive: "2024-12",
    mitreTechniques: [
      { id: "T1418", name: "Software Discovery", tactic: "Discovery" },
      { id: "T1582", name: "SMS Control", tactic: "Impact" },
      { id: "T1646", name: "Exfiltration Over C2 Channel", tactic: "Exfiltration" },
    ],
    c2Ports: [443, 80],
    mutexPatterns: [],
    registryKeys: [],
    filePaths: [],
    networkSignatures: [
      "POST /sub",
      "POST /click",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Auto-start on boot", "Background service"],
      discovery: ["SIM card info", "Carrier detection"],
      lateralMovement: [],
      exfiltration: ["Contact list theft", "SMS message theft"],
      commandAndControl: ["HTTPS C2"],
      execution: ["Dynamic code loading from Play Store dropper", "DEX file download"],
    },
    yaraStrings: ["Joker", "Bread"],
    yaraHex: [],
    processNames: [],
    commandLines: [],
    riskScore: 65,
  },
  {
    name: "XMRig",
    aliases: ["XMRig Miner", "XMR Miner"],
    category: "Cryptominer",
    description: "Open-source Monero (XMR) cryptocurrency miner frequently deployed by malware for cryptojacking. Legitimate tool weaponized for unauthorized mining.",
    firstSeen: "2017-05",
    lastActive: "2024-12",
    mitreTechniques: [
      { id: "T1496", name: "Resource Hijacking", tactic: "Impact" },
      { id: "T1053.005", name: "Scheduled Task", tactic: "Persistence" },
      { id: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: "Persistence" },
      { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
      { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control" },
    ],
    c2Ports: [3333, 5555, 7777, 8888, 14433, 14444, 45700],
    mutexPatterns: ["xmrig_*"],
    registryKeys: [
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\XMRig",
      "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemService",
    ],
    filePaths: [
      "%Temp%\\xmrig.exe",
      "%ProgramData%\\xmrig\\",
      "%AppData%\\xmrig\\config.json",
      "/tmp/xmrig",
      "/opt/xmrig/",
    ],
    networkSignatures: [
      '{"jsonrpc":"2.0"',
      '"method":"login"',
      '"method":"submit"',
      "stratum+tcp://",
      "stratum+ssl://",
    ],
    knownHashes: [],
    knownDomains: ["pool.minexmr.com", "xmr.pool.minergate.com", "pool.supportxmr.com"],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Scheduled task", "Registry Run key", "Crontab entry (Linux)", "Systemd service (Linux)"],
      discovery: ["CPU count detection", "GPU enumeration"],
      lateralMovement: [],
      exfiltration: [],
      commandAndControl: ["Stratum mining protocol (JSON-RPC)", "TLS-encrypted mining pool connection"],
      execution: ["Direct execution", "PowerShell download and execute", "Bash script dropper"],
    },
    yaraStrings: ["xmrig", "XMRig", "stratum+tcp", "stratum+ssl", "pool.minexmr", "donate-level"],
    yaraHex: ["78 6D 72 69 67"],
    processNames: ["xmrig.exe", "xmrig", "svchost.exe"],
    commandLines: ["xmrig.exe -o pool", "xmrig --url stratum+tcp"],
    riskScore: 60,
  },
  {
    name: "CoinHive",
    aliases: ["Coinhive", "CoinHive Miner"],
    category: "Cryptominer",
    description: "JavaScript-based Monero miner designed for in-browser mining. Shut down in 2019 but clones still active. Frequently injected into compromised websites.",
    firstSeen: "2017-09",
    lastActive: "2023-12",
    mitreTechniques: [
      { id: "T1496", name: "Resource Hijacking", tactic: "Impact" },
      { id: "T1059.007", name: "JavaScript", tactic: "Execution" },
    ],
    c2Ports: [443, 80],
    mutexPatterns: [],
    registryKeys: [],
    filePaths: [],
    networkSignatures: [
      "coinhive.min.js",
      "CoinHive.Anonymous",
      "authedmine.com",
    ],
    knownHashes: [],
    knownDomains: ["coinhive.com", "authedmine.com", "coin-hive.com"],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Injected script in web page", "Service worker persistence"],
      discovery: [],
      lateralMovement: [],
      exfiltration: [],
      commandAndControl: ["WebSocket to mining proxy"],
      execution: ["JavaScript execution in browser", "WebAssembly CryptoNight implementation"],
    },
    yaraStrings: ["CoinHive", "coinhive", "CoinHive.Anonymous", "authedmine"],
    yaraHex: [],
    processNames: [],
    commandLines: [],
    riskScore: 45,
  },
  {
    name: "CobaltStrike",
    aliases: ["Cobalt Strike", "Beacon", "CS Beacon"],
    category: "C2",
    description: "Commercial adversary simulation framework widely abused by threat actors. Beacon implant provides extensive post-exploitation capabilities.",
    firstSeen: "2012-01",
    lastActive: "2024-12",
    mitreTechniques: [
      { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
      { id: "T1055.012", name: "Process Hollowing", tactic: "Defense Evasion" },
      { id: "T1055.001", name: "Dynamic-link Library Injection", tactic: "Defense Evasion" },
      { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control" },
      { id: "T1071.004", name: "DNS", tactic: "Command and Control" },
      { id: "T1573.001", name: "Symmetric Cryptography", tactic: "Command and Control" },
      { id: "T1090.001", name: "Internal Proxy", tactic: "Command and Control" },
      { id: "T1021.002", name: "SMB/Windows Admin Shares", tactic: "Lateral Movement" },
      { id: "T1558.003", name: "Kerberoasting", tactic: "Credential Access" },
    ],
    c2Ports: [80, 443, 8080, 8443, 50050],
    mutexPatterns: ["MSCTF.Asm.*"],
    registryKeys: [],
    filePaths: [
      "%Temp%\\beacon.exe",
      "%Temp%\\*.dll",
    ],
    networkSignatures: [
      "GET /cx",
      "GET /pixel.gif",
      "GET /dpixel",
      "GET /ptj",
      "GET /activity",
      "POST /submit.php",
      "Cookie: SESSIONID=",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Service installation", "Registry Run key", "Scheduled task", "COM object hijacking"],
      discovery: ["Network enumeration", "Domain trust mapping", "Kerberos ticket enumeration"],
      lateralMovement: ["PsExec", "WMI lateral movement", "WinRM", "SMB named pipe", "SSH"],
      exfiltration: ["Data staging and exfil over C2", "Chunked HTTP exfiltration"],
      commandAndControl: ["HTTP/HTTPS malleable C2 profiles", "DNS beacon", "SMB named pipe beacon", "TCP reverse beacon"],
      execution: ["PowerShell execution", "Process injection (spawn and inject)", ".NET assembly inline execution", "BOF (Beacon Object Files)"],
    },
    yaraStrings: ["Cobalt Strike", "beacon.dll", "beacon.x64.dll", "ReflectiveLoader", "%%POSTEX%%", "sleeptime"],
    yaraHex: ["4D 5A 52 45"],
    processNames: ["rundll32.exe", "dllhost.exe", "gpupdate.exe"],
    commandLines: ["powershell -nop -w hidden -encodedcommand", "rundll32.exe"],
    riskScore: 95,
  },
  {
    name: "Meterpreter",
    aliases: ["Metasploit Meterpreter", "MSF Meterpreter"],
    category: "C2",
    description: "Post-exploitation payload from the Metasploit Framework. Provides in-memory execution, file system access, network pivoting, and privilege escalation.",
    firstSeen: "2004-01",
    lastActive: "2024-12",
    mitreTechniques: [
      { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
      { id: "T1055.001", name: "Dynamic-link Library Injection", tactic: "Defense Evasion" },
      { id: "T1090.001", name: "Internal Proxy", tactic: "Command and Control" },
      { id: "T1573.001", name: "Symmetric Cryptography", tactic: "Command and Control" },
      { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control" },
    ],
    c2Ports: [4444, 4443, 8080, 8443, 443, 80],
    mutexPatterns: [],
    registryKeys: [],
    filePaths: [
      "%Temp%\\*.exe",
      "%Temp%\\*.dll",
    ],
    networkSignatures: [
      "MZ header in network stream",
      "metsrv.dll",
      "stdapi",
      "priv",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Registry Run key (persistence module)", "Service creation", "Scheduled task"],
      discovery: ["System enumeration (sysinfo)", "Network interface listing", "Route table", "ARP cache"],
      lateralMovement: ["Port forwarding (portfwd)", "Proxy pivoting (autoroute)", "PsExec module"],
      exfiltration: ["File download over C2 channel"],
      commandAndControl: ["Reverse TCP", "Reverse HTTPS", "Bind TCP", "Reverse DNS", "Named pipe transport"],
      execution: ["In-memory DLL injection", "Reflective DLL loading", "Shell command execution", "Ruby script execution"],
    },
    yaraStrings: ["metsrv", "Meterpreter", "stdapi", "ReflectiveDLL", "meterpreter"],
    yaraHex: ["6D 65 74 73 72 76"],
    processNames: ["notepad.exe", "svchost.exe"],
    commandLines: ["msfvenom", "msfconsole"],
    riskScore: 90,
  },
  {
    name: "Sliver",
    aliases: ["Sliver C2", "BishopFox Sliver"],
    category: "C2",
    description: "Open-source C2 framework by BishopFox. Cross-platform implants with mutual TLS, WireGuard, HTTP(S), and DNS C2 channels. Growing alternative to Cobalt Strike.",
    firstSeen: "2019-01",
    lastActive: "2024-12",
    mitreTechniques: [
      { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
      { id: "T1055", name: "Process Injection", tactic: "Defense Evasion" },
      { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control" },
      { id: "T1071.004", name: "DNS", tactic: "Command and Control" },
      { id: "T1573.002", name: "Asymmetric Cryptography", tactic: "Command and Control" },
      { id: "T1090.001", name: "Internal Proxy", tactic: "Command and Control" },
    ],
    c2Ports: [443, 8888, 31337, 53],
    mutexPatterns: [],
    registryKeys: [],
    filePaths: [
      "%Temp%\\*.exe",
      "/tmp/sliver-*",
    ],
    networkSignatures: [
      "mTLS handshake",
      "WireGuard protocol",
      "Protobuf encoded payloads",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Service creation", "Crontab (Linux)", "Registry Run key"],
      discovery: ["Process listing", "Network enumeration", "File system traversal"],
      lateralMovement: ["SSH pivoting", "WireGuard tunneling", "SOCKS5 proxy"],
      exfiltration: ["File download over C2"],
      commandAndControl: ["Mutual TLS (mTLS)", "HTTPS", "DNS", "WireGuard", "Named pipe (Windows)"],
      execution: ["Shellcode injection", "DLL injection", "Execute assembly (.NET)"],
    },
    yaraStrings: ["Sliver", "sliver", "bishopfox"],
    yaraHex: [],
    processNames: [],
    commandLines: ["sliver-server", "sliver-client"],
    riskScore: 88,
  },
  {
    name: "Havoc",
    aliases: ["Havoc C2", "Havoc Framework"],
    category: "C2",
    description: "Modern open-source C2 framework with advanced evasion capabilities. Features include indirect syscalls, sleep obfuscation, and module execution.",
    firstSeen: "2022-06",
    lastActive: "2024-12",
    mitreTechniques: [
      { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
      { id: "T1055", name: "Process Injection", tactic: "Defense Evasion" },
      { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control" },
      { id: "T1573.001", name: "Symmetric Cryptography", tactic: "Command and Control" },
      { id: "T1497", name: "Virtualization/Sandbox Evasion", tactic: "Defense Evasion" },
    ],
    c2Ports: [443, 8443, 40056],
    mutexPatterns: [],
    registryKeys: [],
    filePaths: [
      "%Temp%\\*.exe",
    ],
    networkSignatures: [
      "POST /Demon",
      "User-Agent: Havoc",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Service creation", "Registry Run key"],
      discovery: ["Process listing", "Token enumeration"],
      lateralMovement: ["SMB lateral movement"],
      exfiltration: ["File download over C2"],
      commandAndControl: ["HTTPS with AES encrypted payloads", "SMB named pipes", "Custom binary protocol"],
      execution: ["Indirect syscalls", "Sleep obfuscation (Ekko, Foliage)", "Shellcode injection", "BOF execution", ".NET inline execution"],
    },
    yaraStrings: ["Havoc", "HavocFramework", "Demon", "DemonLoader"],
    yaraHex: [],
    processNames: [],
    commandLines: [],
    riskScore: 87,
  },
  {
    name: "LockBit",
    aliases: ["LockBit 2.0", "LockBit 3.0", "LockBit Black"],
    category: "Ransomware",
    description: "Ransomware-as-a-Service (RaaS) operation. One of the most prolific ransomware families with fast encryption, data exfiltration, and affiliate program.",
    firstSeen: "2019-09",
    lastActive: "2024-06",
    mitreTechniques: [
      { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact" },
      { id: "T1490", name: "Inhibit System Recovery", tactic: "Impact" },
      { id: "T1489", name: "Service Stop", tactic: "Impact" },
      { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
      { id: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: "Persistence" },
      { id: "T1021.002", name: "SMB/Windows Admin Shares", tactic: "Lateral Movement" },
    ],
    c2Ports: [443, 80],
    mutexPatterns: ["Global\\LockBit*"],
    registryKeys: [
      "HKCU\\Software\\LockBit\\",
    ],
    filePaths: [
      "%Desktop%\\Restore-My-Files.txt",
      "*.lockbit",
    ],
    networkSignatures: [
      "POST /upload",
      "Tor .onion domain",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Group Policy modification for deployment"],
      discovery: ["Network share enumeration", "Domain controller discovery", "File system traversal"],
      lateralMovement: ["PsExec deployment", "GPO deployment", "SMB propagation"],
      exfiltration: ["StealBit tool for data exfiltration", "Cloud storage upload"],
      commandAndControl: ["Tor-based leak site", "HTTPS C2"],
      execution: ["Multi-threaded encryption", "Volume shadow copy deletion", "Service stopping", "AV/EDR termination"],
    },
    yaraStrings: ["LockBit", "Restore-My-Files", ".lockbit", "lockbit3"],
    yaraHex: [],
    processNames: ["lockbit.exe"],
    commandLines: ["vssadmin delete shadows /all", "bcdedit /set {default} recoveryenabled No", "wmic shadowcopy delete"],
    riskScore: 98,
  },
  {
    name: "BlackCat",
    aliases: ["ALPHV", "Noberus", "BlackCat Ransomware"],
    category: "Ransomware",
    description: "Rust-based RaaS operation. First major ransomware written in Rust. Features cross-platform capabilities (Windows, Linux, VMware ESXi).",
    firstSeen: "2021-11",
    lastActive: "2024-03",
    mitreTechniques: [
      { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact" },
      { id: "T1490", name: "Inhibit System Recovery", tactic: "Impact" },
      { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
      { id: "T1021.002", name: "SMB/Windows Admin Shares", tactic: "Lateral Movement" },
    ],
    c2Ports: [443],
    mutexPatterns: [],
    registryKeys: [],
    filePaths: [
      "RECOVER-*-FILES.txt",
    ],
    networkSignatures: [
      "Tor .onion domain",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: [],
      discovery: ["UUID-based victim identification", "Network enumeration"],
      lateralMovement: ["PsExec", "WMI", "SSH (Linux)"],
      exfiltration: ["ExMatter tool", "Custom exfiltration"],
      commandAndControl: ["Tor-based communication"],
      execution: ["Rust binary execution", "ESXi VM encryption", "AES + RSA encryption"],
    },
    yaraStrings: ["ALPHV", "BlackCat", "RECOVER-", "access-key"],
    yaraHex: [],
    processNames: [],
    commandLines: ["esxcli vm process kill", "vssadmin delete shadows"],
    riskScore: 96,
  },
  {
    name: "Conti",
    aliases: ["Conti Ransomware", "Ryuk successor"],
    category: "Ransomware",
    description: "Major RaaS operation and successor to Ryuk. Known for targeting healthcare and critical infrastructure. Source code leaked in 2022.",
    firstSeen: "2020-05",
    lastActive: "2023-06",
    mitreTechniques: [
      { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact" },
      { id: "T1490", name: "Inhibit System Recovery", tactic: "Impact" },
      { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
      { id: "T1021.002", name: "SMB/Windows Admin Shares", tactic: "Lateral Movement" },
      { id: "T1489", name: "Service Stop", tactic: "Impact" },
    ],
    c2Ports: [443, 80],
    mutexPatterns: ["CONTI_*", "hsfjuukjz*"],
    registryKeys: [],
    filePaths: [
      "readme.txt",
      "*.CONTI",
    ],
    networkSignatures: [
      "Tor .onion domain",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: [],
      discovery: ["Network share enumeration", "ARP scanning", "Domain controller identification"],
      lateralMovement: ["SMB spreading", "PsExec", "Cobalt Strike beacons"],
      exfiltration: ["Rclone to cloud storage", "Custom exfiltration tools"],
      commandAndControl: ["Tor-based leak site"],
      execution: ["Multi-threaded AES-256 encryption", "32 concurrent threads", "Volume shadow deletion"],
    },
    yaraStrings: ["CONTI", "conti_v3", "readme.txt"],
    yaraHex: [],
    processNames: ["conti.exe"],
    commandLines: ["vssadmin delete shadows", "wmic shadowcopy delete"],
    riskScore: 95,
  },
  {
    name: "REvil",
    aliases: ["Sodinokibi", "REvil Ransomware"],
    category: "Ransomware",
    description: "Major RaaS operation known for high-profile supply chain attacks (Kaseya). Successor to GandCrab. Disrupted by law enforcement in 2022.",
    firstSeen: "2019-04",
    lastActive: "2023-01",
    mitreTechniques: [
      { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact" },
      { id: "T1490", name: "Inhibit System Recovery", tactic: "Impact" },
      { id: "T1195.002", name: "Supply Chain Compromise: Software Supply Chain", tactic: "Initial Access" },
    ],
    c2Ports: [443],
    mutexPatterns: ["Global\\{*}"],
    registryKeys: [
      "HKLM\\SOFTWARE\\BlackLivesMatter\\",
      "HKLM\\SOFTWARE\\recfg\\",
    ],
    filePaths: [
      "*-readme.txt",
      "*.sodinokibi",
    ],
    networkSignatures: [
      "Tor .onion domain",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: [],
      discovery: ["Language/keyboard check (CIS exclusion)", "System info collection"],
      lateralMovement: ["RDP", "PsExec", "Supply chain exploitation"],
      exfiltration: ["Data theft before encryption"],
      commandAndControl: ["Tor-based negotiation"],
      execution: ["Salsa20 + Curve25519 encryption", "Volume shadow deletion", "Safe mode boot for encryption"],
    },
    yaraStrings: ["Sodinokibi", "REvil", "BlackLivesMatter", "expand 32-byte k"],
    yaraHex: [],
    processNames: [],
    commandLines: ["bcdedit /set safeboot minimal", "vssadmin delete shadows"],
    riskScore: 94,
  },
  {
    name: "PlugX",
    aliases: ["Korplug", "DestroyRAT", "THOR"],
    category: "RAT",
    description: "Modular RAT widely used by Chinese APT groups. Employs DLL side-loading for execution. Features file management, keylogging, and network tunneling.",
    firstSeen: "2008-01",
    lastActive: "2024-12",
    mitreTechniques: [
      { id: "T1574.002", name: "DLL Side-Loading", tactic: "Persistence" },
      { id: "T1055.001", name: "Dynamic-link Library Injection", tactic: "Defense Evasion" },
      { id: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: "Persistence" },
      { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control" },
      { id: "T1573.001", name: "Symmetric Cryptography", tactic: "Command and Control" },
    ],
    c2Ports: [80, 443, 8080, 53],
    mutexPatterns: ["PlugX*", "Global\\PlugX*"],
    registryKeys: [
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
      "HKLM\\SYSTEM\\CurrentControlSet\\Services\\*",
    ],
    filePaths: [
      "%ProgramData%\\*\\*.exe",
      "%ProgramData%\\*\\*.dll",
      "%ProgramData%\\*\\*.dat",
    ],
    networkSignatures: [
      "POST /update",
      "MZ header with XOR key",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["DLL side-loading via legitimate signed executable", "Service creation", "Registry Run key"],
      discovery: ["System info collection", "Drive enumeration", "Network config"],
      lateralMovement: ["Network share access", "USB worm propagation"],
      exfiltration: ["File collection and upload", "Keylogger data"],
      commandAndControl: ["Custom binary protocol over HTTP/TCP/UDP/DNS", "XOR encrypted payloads"],
      execution: ["DLL side-loading triad (EXE + DLL + DAT)", "Shellcode injection"],
    },
    yaraStrings: ["PlugX", "Korplug", "PLUG", "XV"],
    yaraHex: ["58 56 00 00"],
    processNames: [],
    commandLines: [],
    riskScore: 89,
  },
  {
    name: "ShadowPad",
    aliases: ["ShadowPad", "POISONPLUG"],
    category: "RAT",
    description: "Modular backdoor shared among Chinese APT groups. Successor to PlugX with more advanced obfuscation. Used in supply chain attacks.",
    firstSeen: "2017-07",
    lastActive: "2024-12",
    mitreTechniques: [
      { id: "T1574.002", name: "DLL Side-Loading", tactic: "Persistence" },
      { id: "T1055", name: "Process Injection", tactic: "Defense Evasion" },
      { id: "T1071.004", name: "DNS", tactic: "Command and Control" },
      { id: "T1573.001", name: "Symmetric Cryptography", tactic: "Command and Control" },
      { id: "T1195.002", name: "Supply Chain Compromise: Software Supply Chain", tactic: "Initial Access" },
    ],
    c2Ports: [80, 443, 53, 8080],
    mutexPatterns: [],
    registryKeys: [
      "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
      "HKLM\\SYSTEM\\CurrentControlSet\\Services\\*",
    ],
    filePaths: [
      "%ProgramData%\\*\\*.dll",
      "%System32%\\*.dll",
    ],
    networkSignatures: [
      "DNS TXT query",
      "Custom encoded HTTP",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["DLL side-loading", "Service DLL", "Registry modification"],
      discovery: ["Network enumeration", "Active Directory recon"],
      lateralMovement: ["SMB lateral movement", "WMI execution"],
      exfiltration: ["Encrypted data exfiltration over C2"],
      commandAndControl: ["DNS tunneling", "HTTP/HTTPS C2", "UDP C2", "Modular plugin system"],
      execution: ["DLL side-loading", "In-memory module execution", "Shellcode-based plugin loading"],
    },
    yaraStrings: ["ShadowPad", "POISONPLUG"],
    yaraHex: [],
    processNames: [],
    commandLines: [],
    riskScore: 92,
  },
  {
    name: "BumbleBee",
    aliases: ["BumbleBee Loader", "Bumblebee"],
    category: "Loader",
    description: "Malware loader used as initial access broker. Replaced BazarLoader as a primary delivery mechanism for ransomware and post-exploitation frameworks.",
    firstSeen: "2022-03",
    lastActive: "2024-06",
    mitreTechniques: [
      { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
      { id: "T1055.012", name: "Process Hollowing", tactic: "Defense Evasion" },
      { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control" },
      { id: "T1027", name: "Obfuscated Files or Information", tactic: "Defense Evasion" },
    ],
    c2Ports: [443],
    mutexPatterns: [],
    registryKeys: [
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
    ],
    filePaths: [
      "%LocalAppData%\\*.dll",
      "%Temp%\\*.dll",
    ],
    networkSignatures: [
      "POST /gates",
      "Content-Type: application/x-www-form-urlencoded",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Scheduled task", "COM object hijacking"],
      discovery: ["Domain enumeration", "Whoami", "Network config"],
      lateralMovement: [],
      exfiltration: [],
      commandAndControl: ["HTTPS C2 with WebSocket upgrade", "Custom encrypted protocol"],
      execution: ["ISO/VHD delivery", "DLL execution via rundll32", "Process injection", "Cobalt Strike delivery"],
    },
    yaraStrings: ["BumbleBee", "bumblebee"],
    yaraHex: [],
    processNames: ["rundll32.exe", "wermgr.exe"],
    commandLines: ["rundll32.exe *.dll,IternalJob", "odbcconf.exe /A"],
    riskScore: 83,
  },
  {
    name: "SystemBC",
    aliases: ["SystemBC Proxy", "Coroxy"],
    category: "C2",
    description: "Proxy bot and backdoor used to establish SOCKS5 proxy connections for other malware. Frequently used alongside ransomware for persistent access.",
    firstSeen: "2019-06",
    lastActive: "2024-12",
    mitreTechniques: [
      { id: "T1090.003", name: "Multi-hop Proxy", tactic: "Command and Control" },
      { id: "T1573.001", name: "Symmetric Cryptography", tactic: "Command and Control" },
      { id: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: "Persistence" },
    ],
    c2Ports: [4001, 4002, 443],
    mutexPatterns: [],
    registryKeys: [
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
    ],
    filePaths: [
      "%ProgramData%\\*.exe",
      "%Temp%\\*.exe",
    ],
    networkSignatures: [
      "SOCKS5 handshake",
      "XOR encrypted beacon",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Registry Run key", "Scheduled task", "Service creation"],
      discovery: [],
      lateralMovement: ["SOCKS5 proxy for lateral movement"],
      exfiltration: ["Proxy tunnel for data exfiltration"],
      commandAndControl: ["Tor SOCKS5 proxy", "XOR encrypted C2", "Custom binary protocol"],
      execution: ["Direct PE execution", "Scheduled task execution"],
    },
    yaraStrings: ["SystemBC", "Coroxy"],
    yaraHex: [],
    processNames: [],
    commandLines: [],
    riskScore: 78,
  },
  {
    name: "Amadey",
    aliases: ["Amadey Bot"],
    category: "Loader",
    description: "Simple but effective malware loader sold on underground forums. Used to download and execute additional payloads including stealers and ransomware.",
    firstSeen: "2018-10",
    lastActive: "2024-12",
    mitreTechniques: [
      { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
      { id: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: "Persistence" },
      { id: "T1053.005", name: "Scheduled Task", tactic: "Persistence" },
      { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control" },
    ],
    c2Ports: [80, 443],
    mutexPatterns: [],
    registryKeys: [
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
    ],
    filePaths: [
      "%Temp%\\*.exe",
      "%AppData%\\*.exe",
    ],
    networkSignatures: [
      "POST /Zu7JuNko/index.php",
      "id=",
      "vs=",
      "sd=",
      "os=",
      "bi=",
      "ar=",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Registry Run key", "Scheduled task"],
      discovery: ["System info collection", "Installed AV detection", "Screenshot capture"],
      lateralMovement: [],
      exfiltration: ["System info upload", "Screenshot upload"],
      commandAndControl: ["HTTP POST to PHP panel"],
      execution: ["Download and execute payloads", "Plugin loading"],
    },
    yaraStrings: ["Amadey", "Zu7JuNko", "index.php"],
    yaraHex: [],
    processNames: [],
    commandLines: [],
    riskScore: 70,
  },
  {
    name: "SmokeLoader",
    aliases: ["Smoke Loader", "Dofoil"],
    category: "Loader",
    description: "Modular malware loader active since 2011. Provides backdoor capabilities and delivers additional payloads. Known for advanced anti-analysis techniques.",
    firstSeen: "2011-06",
    lastActive: "2024-12",
    mitreTechniques: [
      { id: "T1055.012", name: "Process Hollowing", tactic: "Defense Evasion" },
      { id: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: "Persistence" },
      { id: "T1027", name: "Obfuscated Files or Information", tactic: "Defense Evasion" },
      { id: "T1497", name: "Virtualization/Sandbox Evasion", tactic: "Defense Evasion" },
      { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control" },
    ],
    c2Ports: [80, 443],
    mutexPatterns: [],
    registryKeys: [
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
    ],
    filePaths: [
      "%AppData%\\*.exe",
      "%Temp%\\*.exe",
    ],
    networkSignatures: [
      "POST / HTTP/1.1",
      "Content-Type: application/x-www-form-urlencoded",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Registry Run key", "Explorer.exe injection"],
      discovery: ["Anti-VM checks", "Anti-debug checks", "Sandbox detection"],
      lateralMovement: [],
      exfiltration: ["Plugin-based data theft"],
      commandAndControl: ["HTTP POST C2", "RC4 encrypted communication", "Multiple C2 fallback"],
      execution: ["Process hollowing", "Process injection into explorer.exe", "Plugin DLL loading"],
    },
    yaraStrings: ["SmokeLoader", "Dofoil"],
    yaraHex: [],
    processNames: ["explorer.exe"],
    commandLines: [],
    riskScore: 79,
  },
  {
    name: "Gootloader",
    aliases: ["GootLoader", "Gootkit Loader"],
    category: "Loader",
    description: "JavaScript-based loader that uses SEO poisoning to deliver payloads. Associated with the Gootkit banking trojan family. Delivers Cobalt Strike and ransomware.",
    firstSeen: "2020-11",
    lastActive: "2024-12",
    mitreTechniques: [
      { id: "T1059.007", name: "JavaScript", tactic: "Execution" },
      { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
      { id: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: "Persistence" },
      { id: "T1053.005", name: "Scheduled Task", tactic: "Persistence" },
      { id: "T1027", name: "Obfuscated Files or Information", tactic: "Defense Evasion" },
    ],
    c2Ports: [443, 80],
    mutexPatterns: [],
    registryKeys: [
      "HKCU\\Software\\Microsoft\\*\\random_key",
    ],
    filePaths: [
      "%Temp%\\*.js",
      "%AppData%\\*.js",
    ],
    networkSignatures: [
      "GET /search?q=",
      "JavaScript download from compromised site",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Registry key with encoded payload", "Scheduled task"],
      discovery: ["Domain enumeration", "User context detection"],
      lateralMovement: [],
      exfiltration: [],
      commandAndControl: ["HTTPS to compromised legitimate websites"],
      execution: ["Obfuscated JavaScript execution", "PowerShell decode and execute", "Cobalt Strike beacon delivery"],
    },
    yaraStrings: ["GootLoader", "Gootkit"],
    yaraHex: [],
    processNames: ["wscript.exe", "cscript.exe", "powershell.exe"],
    commandLines: ["wscript.exe *.js", "powershell -encodedcommand"],
    riskScore: 77,
  },
  {
    name: "Grandoreiro",
    aliases: ["Grandoreiro Banking Trojan"],
    category: "Banking",
    description: "Latin American banking trojan targeting Spanish and Portuguese-speaking countries. Uses large MSI files to evade analysis. Features overlay attacks and remote access.",
    firstSeen: "2016-01",
    lastActive: "2024-12",
    mitreTechniques: [
      { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
      { id: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: "Persistence" },
      { id: "T1185", name: "Browser Session Hijacking", tactic: "Collection" },
      { id: "T1056.001", name: "Keylogging", tactic: "Collection" },
      { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control" },
    ],
    c2Ports: [443, 80, 8080],
    mutexPatterns: [],
    registryKeys: [
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
    ],
    filePaths: [
      "%ProgramData%\\*.exe",
      "%AppData%\\*.msi",
    ],
    networkSignatures: [
      "POST /gate",
      "DGA domains",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Registry Run key", "Startup folder"],
      discovery: ["Banking site detection", "Country/language check"],
      lateralMovement: [],
      exfiltration: ["Overlay phishing data", "Keylogger data"],
      commandAndControl: ["HTTPS C2", "DGA for C2 resolution", "Google Cloud/Azure abuse"],
      execution: ["MSI installer execution", "Delphi binary execution", "DLL side-loading"],
    },
    yaraStrings: ["Grandoreiro"],
    yaraHex: [],
    processNames: [],
    commandLines: ["msiexec /i"],
    riskScore: 80,
  },
  {
    name: "Ursnif",
    aliases: ["Gozi", "ISFB", "Dreambot", "Gozi ISFB"],
    category: "Banking",
    description: "Long-running banking trojan with web injection capabilities. Source code leaked multiple times, leading to many variants. Also known as Gozi ISFB.",
    firstSeen: "2007-01",
    lastActive: "2024-06",
    mitreTechniques: [
      { id: "T1185", name: "Browser Session Hijacking", tactic: "Collection" },
      { id: "T1055.001", name: "Dynamic-link Library Injection", tactic: "Defense Evasion" },
      { id: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: "Persistence" },
      { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control" },
      { id: "T1132.002", name: "Non-Standard Encoding", tactic: "Command and Control" },
    ],
    c2Ports: [80, 443],
    mutexPatterns: [],
    registryKeys: [
      "HKCU\\Software\\AppDataLow\\Software\\Microsoft\\*",
    ],
    filePaths: [
      "%AppData%\\Microsoft\\*.dll",
      "%Temp%\\*.bin",
    ],
    networkSignatures: [
      "GET /images/",
      "serpent encrypted",
      "XTEA encrypted",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Registry AppDataLow key", "Scheduled task"],
      discovery: ["System info via WMI", "Browser enumeration"],
      lateralMovement: [],
      exfiltration: ["Web injection form grabbing", "Video recording of sessions"],
      commandAndControl: ["HTTP C2 with Serpent/XTEA encryption", "DGA domains"],
      execution: ["DLL injection into explorer.exe", "PowerShell download", "Macro execution"],
    },
    yaraStrings: ["Ursnif", "Gozi", "ISFB", "serpent_cbc"],
    yaraHex: [],
    processNames: ["explorer.exe"],
    commandLines: [],
    riskScore: 82,
  },
  {
    name: "Pikabot",
    aliases: ["PikaBot"],
    category: "Loader",
    description: "Modular malware loader that emerged as a replacement for QBot. Features anti-analysis, process injection, and delivers secondary payloads including Cobalt Strike.",
    firstSeen: "2023-02",
    lastActive: "2024-12",
    mitreTechniques: [
      { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
      { id: "T1055.012", name: "Process Hollowing", tactic: "Defense Evasion" },
      { id: "T1497", name: "Virtualization/Sandbox Evasion", tactic: "Defense Evasion" },
      { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control" },
    ],
    c2Ports: [443, 2967, 13720],
    mutexPatterns: [],
    registryKeys: [],
    filePaths: [
      "%AppData%\\*.dll",
      "%Temp%\\*.dll",
    ],
    networkSignatures: [
      "POST /api/",
      "HTTPS with custom TLS fingerprint",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Scheduled task"],
      discovery: ["Anti-VM checks", "Language/locale checks", "Domain controller detection"],
      lateralMovement: [],
      exfiltration: [],
      commandAndControl: ["HTTPS C2 with custom protocol", "Multiple C2 servers"],
      execution: ["DLL injection", "Process hollowing", "Cobalt Strike delivery", "Shellcode execution"],
    },
    yaraStrings: ["PikaBot", "Pikabot"],
    yaraHex: [],
    processNames: ["SearchProtocolHost.exe"],
    commandLines: ["rundll32.exe *.dll,*"],
    riskScore: 81,
  },
  {
    name: "DanaBot",
    aliases: ["DanaBot Banking Trojan"],
    category: "Banking",
    description: "Modular banking trojan operating as MaaS. Features web injection, VNC, and information stealing. Known for targeting Australian and European banks.",
    firstSeen: "2018-05",
    lastActive: "2024-12",
    mitreTechniques: [
      { id: "T1185", name: "Browser Session Hijacking", tactic: "Collection" },
      { id: "T1055", name: "Process Injection", tactic: "Defense Evasion" },
      { id: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: "Persistence" },
      { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control" },
    ],
    c2Ports: [443, 4443, 8443],
    mutexPatterns: [],
    registryKeys: [
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
    ],
    filePaths: [
      "%AppData%\\*.dll",
      "%Temp%\\*.dll",
    ],
    networkSignatures: [
      "POST /",
      "Danabot beacon",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Registry Run key", "Service creation"],
      discovery: ["Banking site detection", "System info"],
      lateralMovement: [],
      exfiltration: ["Web injection data", "VNC screenshots", "Credential theft"],
      commandAndControl: ["HTTPS C2", "Custom binary protocol"],
      execution: ["DLL injection", "VNC module", "Stealer module", "Proxy module"],
    },
    yaraStrings: ["DanaBot"],
    yaraHex: [],
    processNames: [],
    commandLines: [],
    riskScore: 83,
  },
  {
    name: "LummaC2",
    aliases: ["Lumma Stealer", "LummaC2 Stealer"],
    category: "Stealer",
    description: "Information stealer sold as MaaS targeting browser data, cryptocurrency wallets, and 2FA extensions. Written in C and highly configurable.",
    firstSeen: "2022-08",
    lastActive: "2024-12",
    mitreTechniques: [
      { id: "T1555.003", name: "Credentials from Web Browsers", tactic: "Credential Access" },
      { id: "T1539", name: "Steal Web Session Cookie", tactic: "Credential Access" },
      { id: "T1005", name: "Data from Local System", tactic: "Collection" },
      { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control" },
    ],
    c2Ports: [443, 80],
    mutexPatterns: [],
    registryKeys: [],
    filePaths: [
      "%Temp%\\*.exe",
      "%LocalAppData%\\*.exe",
    ],
    networkSignatures: [
      "POST /api",
      "POST /c2conf",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Usually none — smash-and-grab"],
      discovery: ["Browser profile enumeration", "Crypto wallet extension detection", "2FA app detection"],
      lateralMovement: [],
      exfiltration: ["HTTPS POST with stolen data zip", "Encrypted data upload"],
      commandAndControl: ["HTTPS C2 with encrypted config", "Cloudflare protection"],
      execution: ["Direct PE execution", "Self-deletion after exfil"],
    },
    yaraStrings: ["LummaC2", "Lumma"],
    yaraHex: [],
    processNames: [],
    commandLines: [],
    riskScore: 75,
  },
  {
    name: "StealC",
    aliases: ["StealC Stealer"],
    category: "Stealer",
    description: "Information stealer heavily inspired by Vidar and Raccoon. Targets browser data, crypto wallets, and messaging apps. Sold on underground forums.",
    firstSeen: "2023-01",
    lastActive: "2024-12",
    mitreTechniques: [
      { id: "T1555.003", name: "Credentials from Web Browsers", tactic: "Credential Access" },
      { id: "T1539", name: "Steal Web Session Cookie", tactic: "Credential Access" },
      { id: "T1005", name: "Data from Local System", tactic: "Collection" },
      { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control" },
    ],
    c2Ports: [80, 443],
    mutexPatterns: [],
    registryKeys: [],
    filePaths: [
      "%Temp%\\*.exe",
    ],
    networkSignatures: [
      "POST /",
      "hwid=",
      "build=",
    ],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Usually none"],
      discovery: ["Browser enumeration", "Crypto wallet file search", "Messaging app search (Telegram, Discord)"],
      lateralMovement: [],
      exfiltration: ["HTTP POST multipart upload"],
      commandAndControl: ["HTTP C2 panel with config download"],
      execution: ["Direct execution", "Self-deletion"],
    },
    yaraStrings: ["StealC"],
    yaraHex: [],
    processNames: [],
    commandLines: [],
    riskScore: 72,
  },
  {
    name: "Remcos",
    aliases: ["Remcos RAT"],
    category: "RAT",
    description: "Remote control and surveillance tool marketed as legitimate. Widely abused by cybercriminals.",
    firstSeen: "2016-07",
    lastActive: "2024-12",
    mitreTechniques: [
      { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
      { id: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: "Persistence" },
    ],
    c2Ports: [2404, 2560, 4782],
    mutexPatterns: ["Remcos_Mutex_*"],
    registryKeys: ["HKCU\\Software\\Remcos\\"],
    filePaths: ["%AppData%\\Remcos\\"],
    networkSignatures: ["Remcos_"],
    knownHashes: [],
    knownDomains: [],
    knownIPs: [],
    behaviorProfile: {
      persistence: ["Registry Run keys"],
      discovery: ["System fingerprinting"],
      lateralMovement: [],
      exfiltration: ["Keylogger logs upload"],
      commandAndControl: ["TLS encrypted C2"],
      execution: ["Process hollowing"],
    },
    yaraStrings: ["Remcos", "Breaking-Security"],
    yaraHex: [],
    processNames: ["remcos.exe"],
    commandLines: [],
    riskScore: 88,
  },
];

const uniqueFamilies = new Map<string, TrojanFamily>();
for (const family of TROJAN_KNOWLEDGE_BASE) {
  if (!uniqueFamilies.has(family.name)) {
    uniqueFamilies.set(family.name, family);
  }
}
const UNIQUE_FAMILIES = Array.from(uniqueFamilies.values());

interface ThreatActorInfo {
  name: string;
  aliases: string[];
  origin: string;
  targetSectors: string[];
  activeSince: string;
  description: string;
}

const THREAT_ACTOR_MAP: Record<string, ThreatActorInfo> = {
  Emotet: { name: "Mummy Spider", aliases: ["TA542", "MealyBug", "Gold Crestwood"], origin: "Eastern Europe", targetSectors: ["Financial", "Government", "Healthcare", "Education", "Manufacturing"], activeSince: "2014", description: "Prolific cybercrime group operating Emotet as a malware-as-a-service botnet, primarily distributing banking trojans and ransomware." },
  TrickBot: { name: "Wizard Spider", aliases: ["UNC1878", "Gold Blackburn", "ITG23"], origin: "Russia", targetSectors: ["Healthcare", "Financial", "Government", "Technology", "Legal"], activeSince: "2016", description: "Russian-speaking cybercrime syndicate operating TrickBot and Conti ransomware operations." },
  Conti: { name: "Wizard Spider", aliases: ["UNC1878", "Gold Blackburn", "ITG23"], origin: "Russia", targetSectors: ["Healthcare", "Critical Infrastructure", "Government", "Financial"], activeSince: "2020", description: "Ransomware operation run by Wizard Spider, known for targeting healthcare during COVID-19 pandemic." },
  Dridex: { name: "Evil Corp", aliases: ["Indrik Spider", "UNC2165", "Gold Drake"], origin: "Russia", targetSectors: ["Financial", "Government", "Manufacturing"], activeSince: "2014", description: "Russian cybercrime group sanctioned by US Treasury, operating Dridex banking trojan and BitPaymer/WastedLocker ransomware." },
  Zeus: { name: "Slavik", aliases: ["Evgeniy Bogachev", "lucky12345"], origin: "Russia/Ukraine", targetSectors: ["Financial", "Banking"], activeSince: "2007", description: "One of the most wanted cybercriminals, creator of Zeus banking trojan. $3M FBI bounty." },
  Gh0stRAT: { name: "APT1 / Comment Crew", aliases: ["Unit 61398", "Comment Panda", "TG-8223"], origin: "China", targetSectors: ["Defense", "Government", "Technology", "Telecommunications", "Energy"], activeSince: "2006", description: "Chinese military-linked APT group using Gh0st RAT variants in espionage campaigns." },
  CobaltStrike: { name: "Multiple Threat Actors", aliases: ["Various APTs", "FIN groups", "Ransomware affiliates"], origin: "Global", targetSectors: ["All sectors"], activeSince: "2012", description: "Commercially available C2 framework abused by numerous APT groups and ransomware operators worldwide." },
  LockBit: { name: "LockBit Gang", aliases: ["Gold Mystic", "Bitwise Spider"], origin: "Russia", targetSectors: ["Healthcare", "Education", "Government", "Manufacturing", "Critical Infrastructure"], activeSince: "2019", description: "Most prolific RaaS operation with extensive affiliate program. Disrupted by law enforcement in 2024." },
  BlackCat: { name: "BlackCat/ALPHV", aliases: ["Scattered Spider (affiliate)", "UNC3944"], origin: "Russia", targetSectors: ["Healthcare", "Financial", "Technology", "Government"], activeSince: "2021", description: "Rust-based RaaS with cross-platform capabilities. Associated with former DarkSide/BlackMatter operators." },
  REvil: { name: "Gold Southfield", aliases: ["Pinchy Spider", "REvil Gang"], origin: "Russia", targetSectors: ["Manufacturing", "Legal", "Technology", "MSPs", "Government"], activeSince: "2019", description: "High-profile RaaS operation responsible for Kaseya supply chain attack. Members arrested in 2022." },
  Remcos: { name: "Breaking Security", aliases: ["Commercial RAT vendor"], origin: "Germany (marketed)", targetSectors: ["Government", "Financial", "Defense"], activeSince: "2016", description: "Commercial surveillance tool marketed as legitimate but widely abused in targeted attacks." },
  AsyncRAT: { name: "Various Actors", aliases: ["Open-source RAT users"], origin: "Global", targetSectors: ["SMB", "Government", "Education"], activeSince: "2019", description: "Open-source RAT used by various low-to-mid tier threat actors in phishing campaigns." },
  njRAT: { name: "Various Middle Eastern Actors", aliases: ["njRAT operators"], origin: "Middle East", targetSectors: ["Government", "Military", "Telecommunications"], activeSince: "2012", description: "Widely used RAT originating from the Middle East, popular among less sophisticated threat actors." },
  QBot: { name: "Gold Lagoon", aliases: ["QakBot operators", "TA570"], origin: "Eastern Europe", targetSectors: ["Financial", "Healthcare", "Government", "Manufacturing"], activeSince: "2007", description: "Long-running banking trojan evolved into a major malware distribution platform." },
  DarkComet: { name: "DarkCoderSc", aliases: ["Jean-Pierre Lesueur"], origin: "France", targetSectors: ["Government", "Activists", "Dissidents"], activeSince: "2008", description: "RAT notably used against Syrian dissidents. Developer ceased development in 2012." },
  AgentTesla: { name: "Various Actors", aliases: ["AgentTesla operators"], origin: "Global (Turkey-linked MaaS)", targetSectors: ["Financial", "Energy", "Manufacturing", "Government"], activeSince: "2014", description: ".NET-based info stealer sold as MaaS, widely used in Business Email Compromise (BEC) campaigns." },
  FormBook: { name: "Various Actors", aliases: ["XLoader operators"], origin: "Global", targetSectors: ["Manufacturing", "Financial", "Government", "Defense"], activeSince: "2016", description: "Info stealer sold as MaaS with XLoader variant targeting macOS." },
  Sliver: { name: "Multiple APTs", aliases: ["Various"], origin: "Global", targetSectors: ["Government", "Technology", "Critical Infrastructure"], activeSince: "2019", description: "Open-source C2 framework increasingly adopted by APT groups as alternative to Cobalt Strike." },
};

interface KillChainPhase {
  phase: string;
  order: number;
  description: string;
  active: boolean;
  techniques: string[];
}

const KILL_CHAIN_PHASES = [
  "Reconnaissance",
  "Weaponization",
  "Delivery",
  "Exploitation",
  "Installation",
  "Command & Control",
  "Actions on Objectives",
] as const;

function mapToKillChain(family: TrojanFamily): KillChainPhase[] {
  const bp = family.behaviorProfile;
  const phases: KillChainPhase[] = [
    {
      phase: "Reconnaissance",
      order: 1,
      description: "Gathering information about targets",
      active: bp.discovery.length > 0,
      techniques: bp.discovery.slice(0, 3),
    },
    {
      phase: "Weaponization",
      order: 2,
      description: "Creating malicious payload",
      active: family.yaraStrings.length > 0 || family.category === "Loader",
      techniques: family.category === "Loader" ? ["Payload packaging", "Dropper creation"] : ["Malware compilation", "Payload obfuscation"],
    },
    {
      phase: "Delivery",
      order: 3,
      description: "Transmitting payload to target",
      active: family.mitreTechniques.some(t => t.tactic === "Initial Access") || bp.execution.some(e => e.toLowerCase().includes("phishing") || e.toLowerCase().includes("download") || e.toLowerCase().includes("dropper") || e.toLowerCase().includes("macro") || e.toLowerCase().includes("sideload")),
      techniques: bp.execution.filter(e => e.toLowerCase().includes("phishing") || e.toLowerCase().includes("download") || e.toLowerCase().includes("macro") || e.toLowerCase().includes("sideload") || e.toLowerCase().includes("dropper")).slice(0, 3),
    },
    {
      phase: "Exploitation",
      order: 4,
      description: "Exploiting vulnerability to execute",
      active: bp.execution.length > 0,
      techniques: bp.execution.filter(e => !e.toLowerCase().includes("phishing") && !e.toLowerCase().includes("download")).slice(0, 3),
    },
    {
      phase: "Installation",
      order: 5,
      description: "Installing persistent access",
      active: bp.persistence.length > 0,
      techniques: bp.persistence.slice(0, 3),
    },
    {
      phase: "Command & Control",
      order: 6,
      description: "Establishing C2 communication",
      active: bp.commandAndControl.length > 0,
      techniques: bp.commandAndControl.slice(0, 3),
    },
    {
      phase: "Actions on Objectives",
      order: 7,
      description: "Achieving mission goals",
      active: bp.exfiltration.length > 0 || bp.lateralMovement.length > 0,
      techniques: [...bp.exfiltration.slice(0, 2), ...bp.lateralMovement.slice(0, 2)],
    },
  ];
  if (phases[2].techniques.length === 0 && phases[2].active) {
    phases[2].techniques = ["Malicious payload delivery"];
  }
  if (phases[3].techniques.length === 0 && phases[3].active) {
    phases[3].techniques = bp.execution.slice(0, 3);
  }
  return phases;
}

const MITRE_TACTICS_ORDER = [
  "Reconnaissance", "Resource Development", "Initial Access", "Execution",
  "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
  "Discovery", "Lateral Movement", "Collection", "Command and Control",
  "Exfiltration", "Impact",
];

function generateMitreHeatmap(family: TrojanFamily): {
  tactics: Array<{
    tactic: string;
    techniques: Array<{ id: string; name: string }>;
    coverage: number;
  }>;
  totalTechniques: number;
  coveredTactics: number;
  totalTactics: number;
} {
  const tacticMap = new Map<string, Array<{ id: string; name: string }>>();
  for (const tactic of MITRE_TACTICS_ORDER) {
    tacticMap.set(tactic, []);
  }

  for (const tech of family.mitreTechniques) {
    const existing = tacticMap.get(tech.tactic) || [];
    existing.push({ id: tech.id, name: tech.name });
    tacticMap.set(tech.tactic, existing);
  }

  const tactics = MITRE_TACTICS_ORDER.map(tactic => {
    const techniques = tacticMap.get(tactic) || [];
    return {
      tactic,
      techniques,
      coverage: techniques.length > 0 ? Math.min(100, techniques.length * 33) : 0,
    };
  });

  const coveredTactics = tactics.filter(t => t.techniques.length > 0).length;

  return {
    tactics,
    totalTechniques: family.mitreTechniques.length,
    coveredTactics,
    totalTactics: MITRE_TACTICS_ORDER.length,
  };
}

export function extractIOCsFromText(text: string): {
  ips: string[];
  domains: string[];
  urls: string[];
  emails: string[];
  filePaths: string[];
  registryKeys: string[];
  mutexNames: string[];
  hashes: { md5: string[]; sha1: string[]; sha256: string[] };
} {
  const ipRegex = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
  const domainRegex = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|xyz|top|info|biz|cc|tk|ml|ga|cf|gq|ru|cn|de|uk|fr|nl|onion)\b/gi;
  const urlRegex = /https?:\/\/[^\s"'<>\]]+/gi;
  const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
  const filePathWinRegex = /(?:[A-Z]:\\|%[A-Za-z]+%)(?:[^\s"'<>|*?]+)/gi;
  const filePathUnixRegex = /(?:\/(?:tmp|opt|var|etc|usr|home|root)\/[^\s"'<>|*?]+)/gi;
  const registryRegex = /HK(?:LM|CU|CR|U|CC)\\[^\s"'<>]+/gi;
  const mutexRegex = /(?:Global\\|Local\\|Sessions\\)[^\s"'<>]+/gi;
  const md5Regex = /\b[a-fA-F0-9]{32}\b/g;
  const sha1Regex = /\b[a-fA-F0-9]{40}\b/g;
  const sha256Regex = /\b[a-fA-F0-9]{64}\b/g;

  const unique = (arr: string[]) => Array.from(new Set(arr));

  const ips = unique((text.match(ipRegex) || []).filter(ip => !ip.startsWith("0.") && !ip.startsWith("255.")));
  const urls = unique(text.match(urlRegex) || []);
  const urlDomains = new Set(urls.map(u => { try { return new URL(u).hostname; } catch { return ""; } }).filter(Boolean));
  const allDomains = unique((text.match(domainRegex) || []).filter(d => !urlDomains.has(d) && d.length > 4));
  const emails = unique(text.match(emailRegex) || []);
  const filePathsWin: string[] = text.match(filePathWinRegex) || [];
  const filePathsUnix: string[] = text.match(filePathUnixRegex) || [];
  const filePaths = unique(filePathsWin.concat(filePathsUnix));
  const registryKeys = unique(text.match(registryRegex) || []);

  const mutexCandidates: string[] = text.match(mutexRegex) || [];
  const mutexFromContext: string[] = [];
  const mutexKeywords = /mutex[:\s=]+["']?([^\s"']+)/gi;
  let mx;
  while ((mx = mutexKeywords.exec(text)) !== null) {
    mutexFromContext.push(mx[1]);
  }
  const mutexNames = unique(mutexCandidates.concat(mutexFromContext));

  const sha256 = unique(text.match(sha256Regex) || []);
  const sha256Arr = sha256;
  const sha1 = unique((text.match(sha1Regex) || []).filter(h => sha256Arr.indexOf(h) === -1 && !sha256Arr.some(s => s.includes(h))));
  const sha1Arr = sha1;
  const md5 = unique((text.match(md5Regex) || []).filter(h => sha1Arr.indexOf(h) === -1 && sha256Arr.indexOf(h) === -1 && !sha1Arr.some(s => s.includes(h)) && !sha256Arr.some(s => s.includes(h))));

  return { ips, domains: allDomains, urls, emails, filePaths, registryKeys, mutexNames, hashes: { md5, sha1, sha256 } };
}

export function getThreatActor(familyName: string): ThreatActorInfo | null {
  const family = UNIQUE_FAMILIES.find(f => f.name.toLowerCase() === familyName.toLowerCase() || f.aliases.some(a => a.toLowerCase() === familyName.toLowerCase()));
  if (!family) return null;
  return THREAT_ACTOR_MAP[family.name] || null;
}

export function getKillChain(familyName: string): { family: string; phases: KillChainPhase[] } | null {
  const family = UNIQUE_FAMILIES.find(f => f.name.toLowerCase() === familyName.toLowerCase() || f.aliases.some(a => a.toLowerCase() === familyName.toLowerCase()));
  if (!family) return null;
  return { family: family.name, phases: mapToKillChain(family) };
}

export function getMitreHeatmap(familyName: string): {
  family: string;
  heatmap: ReturnType<typeof generateMitreHeatmap>;
} | null {
  const family = UNIQUE_FAMILIES.find(f => f.name.toLowerCase() === familyName.toLowerCase() || f.aliases.some(a => a.toLowerCase() === familyName.toLowerCase()));
  if (!family) return null;
  return { family: family.name, heatmap: generateMitreHeatmap(family) };
}

export async function lookupHash(hash: string): Promise<{
  hash: string;
  malwareBazaarResult: any;
  knowledgeBaseMatches: Array<{
    family: string;
    category: string;
    riskScore: number;
    description: string;
    mitreTechniques: Array<{ id: string; name: string; tactic: string }>;
    behaviorProfile: any;
  }>;
  combined: {
    isMalicious: boolean;
    confidence: number;
    primaryFamily: string | null;
    category: string | null;
    riskScore: number;
    firstSeen: string | null;
    lastActive: string | null;
    detectionSources: string[];
  };
}> {
  const cleanHash = hash.trim().toLowerCase();

  const malwareBazaarResult = await malwareBazaarLookup(cleanHash);

  const knowledgeBaseMatches: Array<{
    family: string;
    category: string;
    riskScore: number;
    description: string;
    mitreTechniques: Array<{ id: string; name: string; tactic: string }>;
    behaviorProfile: any;
  }> = [];

  let detectedFamily: string | null = null;
  if (malwareBazaarResult?.data?.data && Array.isArray(malwareBazaarResult.data.data) && malwareBazaarResult.data.data.length > 0) {
    const mbData = malwareBazaarResult.data.data[0];
    const mbFamily = (mbData.signature || mbData.tags?.[0] || "").toLowerCase();

    for (const family of UNIQUE_FAMILIES) {
      const familyLower = family.name.toLowerCase();
      const aliasesLower = family.aliases.map((a: string) => a.toLowerCase());

      if (mbFamily.includes(familyLower) || aliasesLower.some((a: string) => mbFamily.includes(a))) {
        detectedFamily = family.name;
        knowledgeBaseMatches.push({
          family: family.name,
          category: family.category,
          riskScore: family.riskScore,
          description: family.description,
          mitreTechniques: family.mitreTechniques,
          behaviorProfile: family.behaviorProfile,
        });
      }
    }
  }

  for (const family of UNIQUE_FAMILIES) {
    if (family.knownHashes.includes(cleanHash)) {
      if (!knowledgeBaseMatches.find(m => m.family === family.name)) {
        detectedFamily = detectedFamily || family.name;
        knowledgeBaseMatches.push({
          family: family.name,
          category: family.category,
          riskScore: family.riskScore,
          description: family.description,
          mitreTechniques: family.mitreTechniques,
          behaviorProfile: family.behaviorProfile,
        });
      }
    }
  }

  const isMalicious = malwareBazaarResult?.data?.query_status === "ok" || knowledgeBaseMatches.length > 0;
  const mbMatch = malwareBazaarResult?.data?.data?.[0];

  return {
    hash: cleanHash,
    malwareBazaarResult: malwareBazaarResult?.data || null,
    knowledgeBaseMatches,
    combined: {
      isMalicious,
      confidence: isMalicious ? (knowledgeBaseMatches.length > 0 && mbMatch ? 95 : knowledgeBaseMatches.length > 0 ? 80 : 70) : 0,
      primaryFamily: detectedFamily || (mbMatch?.signature || null),
      category: knowledgeBaseMatches[0]?.category || (mbMatch ? "Unknown" : null),
      riskScore: knowledgeBaseMatches[0]?.riskScore || (mbMatch ? 75 : 0),
      firstSeen: mbMatch?.first_seen || null,
      lastActive: mbMatch?.last_seen || null,
      detectionSources: [
        ...(mbMatch ? ["MalwareBazaar"] : []),
        ...(knowledgeBaseMatches.length > 0 ? ["AegisAI360 Knowledge Base"] : []),
      ],
    },
  };
}

export function classifyBehavior(indicators: {
  networkConnections?: string[];
  registryModifications?: string[];
  filePaths?: string[];
  processNames?: string[];
  mutexNames?: string[];
}): Array<{
  family: string;
  category: string;
  confidence: number;
  matchedIndicators: {
    network: string[];
    registry: string[];
    files: string[];
    processes: string[];
    mutexes: string[];
  };
  riskScore: number;
  description: string;
  mitreTechniques: Array<{ id: string; name: string; tactic: string }>;
}> {
  const results: Array<{
    family: string;
    category: string;
    confidence: number;
    matchedIndicators: {
      network: string[];
      registry: string[];
      files: string[];
      processes: string[];
      mutexes: string[];
    };
    riskScore: number;
    description: string;
    mitreTechniques: Array<{ id: string; name: string; tactic: string }>;
  }> = [];

  for (const family of UNIQUE_FAMILIES) {
    const matched = {
      network: [] as string[],
      registry: [] as string[],
      files: [] as string[],
      processes: [] as string[],
      mutexes: [] as string[],
    };
    let score = 0;
    const weights = { network: 15, registry: 20, files: 15, processes: 25, mutexes: 30 };

    if (indicators.networkConnections) {
      for (const conn of indicators.networkConnections) {
        const connLower = conn.toLowerCase();
        for (const sig of family.networkSignatures) {
          if (connLower.includes(sig.toLowerCase())) {
            matched.network.push(conn);
            score += weights.network;
          }
        }
        for (const port of family.c2Ports) {
          if (connLower.includes(`:${port}`) || connLower.includes(`port ${port}`)) {
            matched.network.push(conn);
            score += weights.network / 2;
          }
        }
      }
    }

    if (indicators.registryModifications) {
      for (const reg of indicators.registryModifications) {
        const regLower = reg.toLowerCase();
        for (const key of family.registryKeys) {
          const keyPattern = key.replace(/\*/g, "").toLowerCase();
          if (regLower.includes(keyPattern) || keyPattern.includes(regLower)) {
            matched.registry.push(reg);
            score += weights.registry;
          }
        }
      }
    }

    if (indicators.filePaths) {
      for (const fp of indicators.filePaths) {
        const fpLower = fp.toLowerCase();
        for (const kfp of family.filePaths) {
          const pattern = kfp.replace(/%[^%]+%/g, "").replace(/\*/g, "").toLowerCase();
          if (pattern.length > 2 && fpLower.includes(pattern)) {
            matched.files.push(fp);
            score += weights.files;
          }
        }
      }
    }

    if (indicators.processNames) {
      for (const proc of indicators.processNames) {
        const procLower = proc.toLowerCase();
        for (const kproc of family.processNames) {
          if (procLower === kproc.toLowerCase() || procLower.includes(kproc.toLowerCase())) {
            matched.processes.push(proc);
            score += weights.processes;
          }
        }
      }
    }

    if (indicators.mutexNames) {
      for (const mutex of indicators.mutexNames) {
        const mutexLower = mutex.toLowerCase();
        for (const pattern of family.mutexPatterns) {
          const cleanPattern = pattern.replace(/\*/g, "").toLowerCase();
          if (cleanPattern.length > 2 && mutexLower.includes(cleanPattern)) {
            matched.mutexes.push(mutex);
            score += weights.mutexes;
          }
        }
      }
    }

    if (score > 0) {
      const totalMatched = matched.network.length + matched.registry.length + matched.files.length + matched.processes.length + matched.mutexes.length;
      const confidence = Math.min(99, Math.round(score / (totalMatched > 3 ? 1 : totalMatched > 1 ? 1.5 : 2)));

      results.push({
        family: family.name,
        category: family.category,
        confidence,
        matchedIndicators: matched,
        riskScore: family.riskScore,
        description: family.description,
        mitreTechniques: family.mitreTechniques,
      });
    }
  }

  results.sort((a, b) => b.confidence - a.confidence);
  return results.slice(0, 10);
}

export function generateYARARule(familyName: string): { rule: string; family: string } | null {
  const family = UNIQUE_FAMILIES.find(f => f.name.toLowerCase() === familyName.toLowerCase() || f.aliases.some(a => a.toLowerCase() === familyName.toLowerCase()));
  if (!family) return null;

  const safeName = family.name.replace(/[^a-zA-Z0-9_]/g, "_");
  const strings: string[] = [];
  let idx = 0;

  for (const s of family.yaraStrings) {
    strings.push(`        $s${idx} = "${s}" ascii wide nocase`);
    idx++;
  }

  for (const h of family.yaraHex) {
    strings.push(`        $h${idx} = { ${h} }`);
    idx++;
  }

  for (const proc of family.processNames) {
    strings.push(`        $p${idx} = "${proc}" ascii wide nocase`);
    idx++;
  }

  for (const cmd of family.commandLines.slice(0, 3)) {
    const escaped = cmd.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
    strings.push(`        $c${idx} = "${escaped}" ascii wide nocase`);
    idx++;
  }

  for (const mutex of family.mutexPatterns.slice(0, 3)) {
    const clean = mutex.replace(/\*/g, "").replace(/\\/g, "\\\\").replace(/"/g, '\\"');
    if (clean.length > 2) {
      strings.push(`        $m${idx} = "${clean}" ascii wide nocase`);
      idx++;
    }
  }

  for (const reg of family.registryKeys.slice(0, 2)) {
    const cleanReg = reg.replace(/\*/g, "").replace(/\\/g, "\\\\").replace(/"/g, '\\"');
    if (cleanReg.length > 4) {
      strings.push(`        $r${idx} = "${cleanReg}" ascii wide nocase`);
      idx++;
    }
  }

  for (const fp of family.filePaths.slice(0, 2)) {
    const cleanFp = fp.replace(/%[^%]+%/g, "").replace(/\*/g, "").replace(/\\/g, "\\\\").replace(/"/g, '\\"');
    if (cleanFp.length > 3) {
      strings.push(`        $f${idx} = "${cleanFp}" ascii wide nocase`);
      idx++;
    }
  }

  const conditionParts = [];
  if (idx <= 5) {
    conditionParts.push(`2 of them`);
  } else if (idx <= 10) {
    conditionParts.push(`3 of them`);
  } else {
    conditionParts.push(`4 of them`);
  }

  const fileSizeLimit = family.category === "Ransomware" ? "100MB" : family.category === "Mobile" ? "20MB" : "50MB";

  const rule = `rule ${safeName}_Detector
{
    meta:
        description = "Detects ${family.name} - ${family.description.substring(0, 100)}"
        author = "AegisAI360 Threat Intelligence"
        category = "${family.category}"
        risk_score = ${family.riskScore}
        severity = "${family.riskScore >= 90 ? "critical" : family.riskScore >= 75 ? "high" : family.riskScore >= 50 ? "medium" : "low"}"
        first_seen = "${family.firstSeen}"
        last_active = "${family.lastActive}"
        reference = "AegisAI360 Trojan Knowledge Base"
        hash_count = ${family.knownHashes.length}
${family.mitreTechniques.slice(0, 5).map((t, i) => `        mitre_${i} = "${t.id} - ${t.name}"`).join("\n")}

    strings:
${strings.join("\n")}

    condition:
        (
            (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) or
            uint32(0) == 0x464C457F or
            uint32(0) == 0xBEBAFECA or
            uint16(0) == 0x6152 or
            uint32(0) == 0x04034B50
        ) and
        filesize < ${fileSizeLimit} and
        ${conditionParts.join(" and ")}
}

rule ${safeName}_Memory_Detector
{
    meta:
        description = "Memory-based detection for ${family.name}"
        author = "AegisAI360 Threat Intelligence"
        category = "${family.category}"
        scan_context = "memory"

    strings:
${family.yaraStrings.slice(0, 5).map((s, i) => `        $mem${i} = "${s}" ascii wide nocase`).join("\n")}
${family.mutexPatterns.slice(0, 3).map((m, i) => {
    const clean = m.replace(/\*/g, "").replace(/\\/g, "\\\\").replace(/"/g, '\\"');
    return clean.length > 2 ? `        $mx${i} = "${clean}" ascii wide` : "";
  }).filter(Boolean).join("\n")}

    condition:
        2 of them
}`;

  return { rule, family: family.name };
}

export function generateSigmaRule(familyName: string): { rule: string; family: string } | null {
  const family = UNIQUE_FAMILIES.find(f => f.name.toLowerCase() === familyName.toLowerCase() || f.aliases.some(a => a.toLowerCase() === familyName.toLowerCase()));
  if (!family) return null;

  const rules: string[] = [];

  if (family.processNames.length > 0 || family.commandLines.length > 0) {
    const processRule = `title: ${family.name} Process Activity Detection
id: ${generateUUID(family.name + "_process")}
status: experimental
description: Detects ${family.name} (${family.category}) process execution patterns
author: AegisAI360 Threat Intelligence
date: ${new Date().toISOString().split("T")[0]}
references:
    - https://attack.mitre.org/software/
tags:
${family.mitreTechniques.slice(0, 5).map(t => `    - attack.${t.tactic.toLowerCase().replace(/ /g, "_")}`).join("\n")}
${family.mitreTechniques.slice(0, 5).map(t => `    - attack.${t.id.toLowerCase()}`).join("\n")}
logsource:
    category: process_creation
    product: windows
detection:
    selection_process:
${family.processNames.length > 0 ? `        Image|endswith:\n${family.processNames.map(p => `            - '\\\\${p}'`).join("\n")}` : "        Image|endswith: []"}
${family.commandLines.length > 0 ? `    selection_cmdline:\n        CommandLine|contains:\n${family.commandLines.map(c => `            - '${c.replace(/'/g, "''")}'`).join("\n")}` : ""}
    condition: selection_process${family.commandLines.length > 0 ? " or selection_cmdline" : ""}
falsepositives:
    - Legitimate administrative tools
    - Software with similar process names
level: high`;
    rules.push(processRule);
  }

  if (family.registryKeys.length > 0) {
    const regRule = `
---
title: ${family.name} Registry Modification Detection
id: ${generateUUID(family.name + "_registry")}
status: experimental
description: Detects ${family.name} registry persistence indicators
author: AegisAI360 Threat Intelligence
date: ${new Date().toISOString().split("T")[0]}
tags:
    - attack.persistence
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains:
${family.registryKeys.filter(k => !k.includes("*")).map(k => `            - '${k}'`).join("\n") || `            - '${family.registryKeys[0].replace(/\*/g, "")}'`}
    condition: selection
falsepositives:
    - Legitimate software using similar registry paths
level: medium`;
    rules.push(regRule);
  }

  if (family.networkSignatures.length > 0 || family.c2Ports.length > 0) {
    const netRule = `
---
title: ${family.name} Network Communication Detection
id: ${generateUUID(family.name + "_network")}
status: experimental
description: Detects ${family.name} C2 communication patterns
author: AegisAI360 Threat Intelligence
date: ${new Date().toISOString().split("T")[0]}
tags:
    - attack.command_and_control
logsource:
    category: firewall
detection:
    selection_ports:
        dst_port:
${family.c2Ports.slice(0, 10).map(p => `            - ${p}`).join("\n")}
${family.knownDomains.length > 0 ? `    selection_domains:\n        query|contains:\n${family.knownDomains.map(d => `            - '${d}'`).join("\n")}` : ""}
    condition: selection_ports${family.knownDomains.length > 0 ? " or selection_domains" : ""}
falsepositives:
    - Legitimate services using these ports
level: medium`;
    rules.push(netRule);
  }

  if (family.mutexPatterns.length > 0) {
    const mutexRule = `
---
title: ${family.name} Mutex Creation Detection
id: ${generateUUID(family.name + "_mutex")}
status: experimental
description: Detects ${family.name} mutex creation patterns
author: AegisAI360 Threat Intelligence
date: ${new Date().toISOString().split("T")[0]}
tags:
    - attack.execution
logsource:
    category: create_mutex
    product: windows
detection:
    selection:
        MutexName|contains:
${family.mutexPatterns.map(m => `            - '${m.replace(/\*/g, "")}'`).join("\n")}
    condition: selection
falsepositives:
    - Unlikely
level: high`;
    rules.push(mutexRule);
  }

  if (family.knownDomains.length > 0) {
    const dnsRule = `
---
title: ${family.name} DNS Query Detection
id: ${generateUUID(family.name + "_dns")}
status: experimental
description: Detects DNS queries to known ${family.name} infrastructure
author: AegisAI360 Threat Intelligence
date: ${new Date().toISOString().split("T")[0]}
tags:
    - attack.command_and_control
logsource:
    category: dns_query
    product: windows
detection:
    selection:
        QueryName|contains:
${family.knownDomains.map(d => `            - '${d}'`).join("\n")}
    condition: selection
falsepositives:
    - Unlikely
level: critical`;
    rules.push(dnsRule);
  }

  if (family.filePaths.length > 0) {
    const fileRule = `
---
title: ${family.name} File Creation Detection
id: ${generateUUID(family.name + "_file")}
status: experimental
description: Detects ${family.name} file creation in known paths
author: AegisAI360 Threat Intelligence
date: ${new Date().toISOString().split("T")[0]}
tags:
    - attack.persistence
    - attack.t1547.001
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains:
${family.filePaths.filter(f => !f.includes("*")).slice(0, 8).map(f => `            - '${f.replace(/%[^%]+%/g, "").replace(/'/g, "''")}'`).join("\n") || `            - '${family.filePaths[0].replace(/%[^%]+%/g, "").replace(/\*/g, "").replace(/'/g, "''")}'`}
    condition: selection
falsepositives:
    - Legitimate software using similar paths
level: medium`;
    rules.push(fileRule);
  }

  const hasScheduledTask = family.behaviorProfile.persistence.some(p => p.toLowerCase().includes("scheduled task")) || family.commandLines.some(c => c.toLowerCase().includes("schtasks"));
  if (hasScheduledTask) {
    const taskRule = `
---
title: ${family.name} Scheduled Task Creation
id: ${generateUUID(family.name + "_schtask")}
status: experimental
description: Detects ${family.name} scheduled task creation for persistence
author: AegisAI360 Threat Intelligence
date: ${new Date().toISOString().split("T")[0]}
tags:
    - attack.persistence
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\schtasks.exe'
        CommandLine|contains:
            - '${family.name}'
${family.commandLines.filter(c => c.toLowerCase().includes("schtasks")).map(c => `            - '${c.replace(/'/g, "''")}'`).join("\n")}
    condition: selection
falsepositives:
    - Legitimate scheduled task creation
level: high`;
    rules.push(taskRule);
  }

  return { rule: rules.join("\n"), family: family.name };
}

export function extractIOCs(familyName: string): {
  family: string;
  category: string;
  iocs: {
    ips: string[];
    domains: string[];
    hashes: string[];
    mutexes: string[];
    registryKeys: string[];
    filePaths: string[];
    networkSignatures: string[];
    c2Ports: number[];
    processNames: string[];
    commandLines: string[];
  };
  mitreTechniques: Array<{ id: string; name: string; tactic: string }>;
  behaviorProfile: any;
} | null {
  const family = UNIQUE_FAMILIES.find(f => f.name.toLowerCase() === familyName.toLowerCase() || f.aliases.some(a => a.toLowerCase() === familyName.toLowerCase()));
  if (!family) return null;

  return {
    family: family.name,
    category: family.category,
    iocs: {
      ips: family.knownIPs,
      domains: family.knownDomains,
      hashes: family.knownHashes,
      mutexes: family.mutexPatterns,
      registryKeys: family.registryKeys,
      filePaths: family.filePaths,
      networkSignatures: family.networkSignatures,
      c2Ports: family.c2Ports,
      processNames: family.processNames,
      commandLines: family.commandLines,
    },
    mitreTechniques: family.mitreTechniques,
    behaviorProfile: family.behaviorProfile,
  };
}

export function listFamilies(): Array<{
  name: string;
  aliases: string[];
  category: string;
  description: string;
  riskScore: number;
  firstSeen: string;
  lastActive: string;
}> {
  return UNIQUE_FAMILIES.map(f => ({
    name: f.name,
    aliases: f.aliases,
    category: f.category,
    description: f.description,
    riskScore: f.riskScore,
    firstSeen: f.firstSeen,
    lastActive: f.lastActive,
  }));
}

function generateUUID(seed: string): string {
  let hash = 0;
  for (let i = 0; i < seed.length; i++) {
    const char = seed.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  const hex = Math.abs(hash).toString(16).padStart(8, "0");
  return `${hex.slice(0, 8)}-${hex.slice(0, 4)}-4${hex.slice(1, 4)}-a${hex.slice(1, 4)}-${hex.padEnd(12, "0").slice(0, 12)}`;
}
