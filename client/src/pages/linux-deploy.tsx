import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";
import {
  Copy, Download, Terminal, CheckCircle, Server, Shield,
  Database, Settings, Package, Zap, ChevronRight, Info,
} from "lucide-react";
import { SiUbuntu, SiDebian } from "react-icons/si";
import { FaRedhat } from "react-icons/fa";

// ─── Code block component ─────────────────────────────────────────────────────

function CodeBlock({ code, label }: { code: string; label?: string }) {
  const { toast } = useToast();
  const copy = () => {
    navigator.clipboard.writeText(code.trim());
    toast({ title: "Copied to clipboard" });
  };
  return (
    <div className="relative group">
      {label && <p className="text-[10px] text-muted-foreground mb-1 font-mono uppercase tracking-wider">{label}</p>}
      <div className="bg-black/60 border border-border/40 rounded-md p-3 pr-10 font-mono text-xs text-green-300 whitespace-pre overflow-x-auto leading-relaxed">
        {code.trim()}
      </div>
      <Button
        size="icon"
        variant="ghost"
        className="absolute top-1.5 right-1.5 h-6 w-6 opacity-0 group-hover:opacity-100 transition-opacity"
        onClick={copy}
        data-testid="button-copy-code"
      >
        <Copy className="w-3 h-3" />
      </Button>
    </div>
  );
}

// ─── Step component ───────────────────────────────────────────────────────────

function Step({ n, title, children }: { n: number; title: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-3">
      <div className="flex-shrink-0 w-6 h-6 rounded-full bg-primary/20 border border-primary/40 flex items-center justify-center text-[10px] font-bold text-primary mt-0.5">
        {n}
      </div>
      <div className="flex-1 space-y-2">
        <p className="text-sm font-semibold">{title}</p>
        {children}
      </div>
    </div>
  );
}

// ─── Req badge ────────────────────────────────────────────────────────────────

function Req({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center gap-2 text-xs">
      <CheckCircle className="w-3.5 h-3.5 text-green-400 flex-shrink-0" />
      <span className="text-muted-foreground">{label}:</span>
      <span className="font-mono text-foreground">{value}</span>
    </div>
  );
}

// ─── Shared install script fragments ─────────────────────────────────────────

const SYSTEMD_UNIT = `[Unit]
Description=AegisAI360 SOC Platform
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=aegis
WorkingDirectory=/opt/aegisai360
EnvironmentFile=/opt/aegisai360/.env
ExecStart=/usr/bin/node dist/index.js
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aegisai360

[Install]
WantedBy=multi-user.target`;

const ENV_TEMPLATE = `DATABASE_URL=postgresql://aegis:CHANGE_ME@localhost:5432/aegisai360
SESSION_SECRET=CHANGE_THIS_TO_A_LONG_RANDOM_STRING
NODE_ENV=production
PORT=5000`;

const VERIFY_CMDS = `# Check service status
sudo systemctl status aegisai360

# View live logs
sudo journalctl -u aegisai360 -f

# Test the API
curl -s http://localhost:5000/api/health | jq .

# Check open port
ss -tlnp | grep 5000`;

// ─── Ubuntu tab ───────────────────────────────────────────────────────────────

function UbuntuTab() {
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <SiUbuntu className="w-8 h-8 text-orange-400" />
        <div>
          <p className="font-semibold">Ubuntu 20.04 / 22.04 / 24.04 LTS</p>
          <p className="text-xs text-muted-foreground">Tested on Ubuntu Server (amd64 / arm64)</p>
        </div>
        <Badge className="ml-auto bg-green-500/10 text-green-400 border-green-500/30">Recommended</Badge>
      </div>

      <Card className="border-border/40">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2"><Info className="w-4 h-4" />System Requirements</CardTitle>
        </CardHeader>
        <CardContent className="space-y-1.5">
          <Req label="OS" value="Ubuntu 20.04 LTS or later" />
          <Req label="CPU" value="2+ cores (4 recommended)" />
          <Req label="RAM" value="4 GB minimum (8 GB recommended)" />
          <Req label="Disk" value="20 GB free" />
          <Req label="Network" value="Static IP or FQDN" />
          <Req label="Ports" value="5000 (API), 443 (HTTPS via reverse proxy)" />
        </CardContent>
      </Card>

      <div className="space-y-4">
        <Step n={1} title="One-line quick install">
          <p className="text-xs text-muted-foreground">Runs the full automated installer — fetches dependencies, configures PostgreSQL, creates a system user, and registers the systemd service.</p>
          <CodeBlock label="Run as root or with sudo" code={`curl -fsSL https://aegisai360.com/install/ubuntu.sh | sudo bash`} />
          <p className="text-[10px] text-amber-400 flex items-center gap-1 mt-1">
            <Info className="w-3 h-3" /> Always review scripts before piping to bash. The manual steps below do the same thing.
          </p>
        </Step>

        <div className="border-l-2 border-border/30 pl-4 space-y-4">
          <p className="text-xs text-muted-foreground font-semibold uppercase tracking-wider">— OR manual install —</p>

          <Step n={2} title="Install Node.js 20 + PostgreSQL">
            <CodeBlock code={`sudo apt-get update
sudo apt-get install -y curl gnupg2 build-essential

# Node.js 20 via NodeSource
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# PostgreSQL 16
sudo apt-get install -y postgresql postgresql-contrib
sudo systemctl enable --now postgresql`} />
          </Step>

          <Step n={3} title="Create database and user">
            <CodeBlock code={`sudo -u postgres psql <<'SQL'
CREATE USER aegis WITH PASSWORD 'CHANGE_ME';
CREATE DATABASE aegisai360 OWNER aegis;
GRANT ALL PRIVILEGES ON DATABASE aegisai360 TO aegis;
SQL`} />
          </Step>

          <Step n={4} title="Create system user and deploy app">
            <CodeBlock code={`# Create a dedicated system user
sudo useradd -r -s /usr/sbin/nologin -d /opt/aegisai360 aegis

# Create app directory
sudo mkdir -p /opt/aegisai360
sudo chown aegis:aegis /opt/aegisai360

# Copy or clone the application
# If you have the release archive:
sudo tar -xzf aegisai360-latest.tar.gz -C /opt/aegisai360 --strip-components=1

# Install production dependencies
sudo -u aegis bash -c "cd /opt/aegisai360 && npm ci --omit=dev"

# Build frontend assets
sudo -u aegis bash -c "cd /opt/aegisai360 && npm run build"`} />
          </Step>

          <Step n={5} title="Configure environment">
            <p className="text-xs text-muted-foreground">Create <code className="text-amber-400">/opt/aegisai360/.env</code> with your settings:</p>
            <CodeBlock label="/opt/aegisai360/.env" code={ENV_TEMPLATE} />
            <CodeBlock code={`sudo chmod 600 /opt/aegisai360/.env
sudo chown aegis:aegis /opt/aegisai360/.env`} />
          </Step>

          <Step n={6} title="Run database migrations">
            <CodeBlock code={`sudo -u aegis bash -c "cd /opt/aegisai360 && npm run db:push"`} />
          </Step>

          <Step n={7} title="Install and start the systemd service">
            <CodeBlock label="/etc/systemd/system/aegisai360.service" code={SYSTEMD_UNIT} />
            <CodeBlock code={`sudo systemctl daemon-reload
sudo systemctl enable --now aegisai360
sudo systemctl status aegisai360`} />
          </Step>

          <Step n={8} title="Configure UFW firewall">
            <CodeBlock code={`sudo ufw allow 22/tcp    # SSH
sudo ufw allow 5000/tcp  # AegisAI360 API (or 443 if behind Nginx)
sudo ufw --force enable
sudo ufw status`} />
          </Step>
        </div>

        <Step n={9} title="Verify installation">
          <CodeBlock code={VERIFY_CMDS} />
        </Step>
      </div>

      <div className="flex gap-2">
        <Button
          variant="outline"
          className="gap-2"
          data-testid="button-download-ubuntu-script"
          onClick={() => { window.location.href = "/api/deploy/script/ubuntu"; }}
        >
          <Download className="w-4 h-4" />
          Download ubuntu.sh
        </Button>
        <Button
          variant="ghost"
          className="gap-2 text-xs"
          data-testid="button-download-ubuntu-env"
          onClick={() => {
            const b = new Blob([ENV_TEMPLATE], { type: "text/plain" });
            const a = document.createElement("a"); a.href = URL.createObjectURL(b);
            a.download = ".env.example"; a.click();
          }}
        >
          <Download className="w-3 h-3" /> .env template
        </Button>
      </div>
    </div>
  );
}

// ─── CentOS / RHEL tab ────────────────────────────────────────────────────────

function CentOSTab() {
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <FaRedhat className="w-8 h-8 text-red-500" />
        <div>
          <p className="font-semibold">CentOS Stream 9 / RHEL 9 / AlmaLinux / Rocky Linux</p>
          <p className="text-xs text-muted-foreground">Compatible with all RHEL 8/9 derivatives (amd64)</p>
        </div>
      </div>

      <Card className="border-border/40">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2"><Info className="w-4 h-4" />System Requirements</CardTitle>
        </CardHeader>
        <CardContent className="space-y-1.5">
          <Req label="OS" value="CentOS Stream 9 / RHEL 8+ / AlmaLinux 9 / Rocky Linux 9" />
          <Req label="CPU" value="2+ cores (4 recommended)" />
          <Req label="RAM" value="4 GB minimum (8 GB recommended)" />
          <Req label="Disk" value="20 GB free" />
          <Req label="Ports" value="5000 (API), 443 via Nginx" />
          <Req label="SELinux" value="Permissive or policy adjusted (see step 6)" />
        </CardContent>
      </Card>

      <div className="space-y-4">
        <Step n={1} title="One-line quick install">
          <CodeBlock label="Run as root or with sudo" code={`curl -fsSL https://aegisai360.com/install/centos.sh | sudo bash`} />
        </Step>

        <div className="border-l-2 border-border/30 pl-4 space-y-4">
          <p className="text-xs text-muted-foreground font-semibold uppercase tracking-wider">— OR manual install —</p>

          <Step n={2} title="Install Node.js 20 + PostgreSQL">
            <CodeBlock code={`# Enable EPEL + NodeSource
sudo dnf install -y epel-release curl
curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -
sudo dnf install -y nodejs

# PostgreSQL 16
sudo dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-9-x86_64/pgdg-redhat-repo-latest.noarch.rpm
sudo dnf -qy module disable postgresql
sudo dnf install -y postgresql16-server postgresql16
sudo /usr/pgsql-16/bin/postgresql-16-setup initdb
sudo systemctl enable --now postgresql-16`} />
          </Step>

          <Step n={3} title="Create database and user">
            <CodeBlock code={`sudo -u postgres psql <<'SQL'
CREATE USER aegis WITH PASSWORD 'CHANGE_ME';
CREATE DATABASE aegisai360 OWNER aegis;
GRANT ALL PRIVILEGES ON DATABASE aegisai360 TO aegis;
SQL`} />
          </Step>

          <Step n={4} title="Create system user and deploy app">
            <CodeBlock code={`sudo useradd -r -s /sbin/nologin -d /opt/aegisai360 aegis
sudo mkdir -p /opt/aegisai360
sudo chown aegis:aegis /opt/aegisai360

# Extract release archive
sudo tar -xzf aegisai360-latest.tar.gz -C /opt/aegisai360 --strip-components=1
sudo -u aegis bash -c "cd /opt/aegisai360 && npm ci --omit=dev"
sudo -u aegis bash -c "cd /opt/aegisai360 && npm run build"`} />
          </Step>

          <Step n={5} title="Configure environment">
            <CodeBlock label="/opt/aegisai360/.env" code={ENV_TEMPLATE} />
            <CodeBlock code={`sudo chmod 600 /opt/aegisai360/.env
sudo chown aegis:aegis /opt/aegisai360/.env`} />
          </Step>

          <Step n={6} title="SELinux — allow Node.js to bind port 5000">
            <CodeBlock code={`# Option A: allow network connect (preferred)
sudo setsebool -P httpd_can_network_connect 1

# Option B: set permissive mode (less secure)
sudo setenforce 0
sudo sed -i 's/^SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config`} />
          </Step>

          <Step n={7} title="Run migrations and install service">
            <CodeBlock code={`sudo -u aegis bash -c "cd /opt/aegisai360 && npm run db:push"`} />
            <CodeBlock label="/etc/systemd/system/aegisai360.service" code={SYSTEMD_UNIT} />
            <CodeBlock code={`sudo systemctl daemon-reload
sudo systemctl enable --now aegisai360`} />
          </Step>

          <Step n={8} title="Configure firewalld">
            <CodeBlock code={`sudo firewall-cmd --permanent --add-port=5000/tcp
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
sudo firewall-cmd --list-all`} />
          </Step>
        </div>

        <Step n={9} title="Verify installation">
          <CodeBlock code={VERIFY_CMDS} />
        </Step>
      </div>

      <div className="flex gap-2">
        <Button
          variant="outline"
          className="gap-2"
          data-testid="button-download-centos-script"
          onClick={() => { window.location.href = "/api/deploy/script/centos"; }}
        >
          <Download className="w-4 h-4" />
          Download centos.sh
        </Button>
        <Button
          variant="ghost"
          className="gap-2 text-xs"
          onClick={() => {
            const b = new Blob([ENV_TEMPLATE], { type: "text/plain" });
            const a = document.createElement("a"); a.href = URL.createObjectURL(b);
            a.download = ".env.example"; a.click();
          }}
        >
          <Download className="w-3 h-3" /> .env template
        </Button>
      </div>
    </div>
  );
}

// ─── Debian tab ───────────────────────────────────────────────────────────────

function DebianTab() {
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <SiDebian className="w-8 h-8 text-red-400" />
        <div>
          <p className="font-semibold">Debian 11 (Bullseye) / 12 (Bookworm)</p>
          <p className="text-xs text-muted-foreground">Tested on Debian Server minimal (amd64 / arm64)</p>
        </div>
      </div>

      <Card className="border-border/40">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2"><Info className="w-4 h-4" />System Requirements</CardTitle>
        </CardHeader>
        <CardContent className="space-y-1.5">
          <Req label="OS" value="Debian 11 (Bullseye) or Debian 12 (Bookworm)" />
          <Req label="CPU" value="2+ cores (4 recommended)" />
          <Req label="RAM" value="4 GB minimum (8 GB recommended)" />
          <Req label="Disk" value="20 GB free" />
          <Req label="Network" value="Static IP or FQDN" />
          <Req label="Ports" value="5000 (API), 443 via Nginx reverse proxy" />
        </CardContent>
      </Card>

      <div className="space-y-4">
        <Step n={1} title="One-line quick install">
          <CodeBlock label="Run as root or with sudo" code={`curl -fsSL https://aegisai360.com/install/debian.sh | sudo bash`} />
        </Step>

        <div className="border-l-2 border-border/30 pl-4 space-y-4">
          <p className="text-xs text-muted-foreground font-semibold uppercase tracking-wider">— OR manual install —</p>

          <Step n={2} title="Install Node.js 20 + PostgreSQL">
            <CodeBlock code={`sudo apt-get update
sudo apt-get install -y curl gnupg2 apt-transport-https ca-certificates build-essential

# Node.js 20 via NodeSource
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# PostgreSQL (official PGDG repo for latest version)
sudo sh -c 'echo "deb https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list'
curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/postgresql.gpg
sudo apt-get update
sudo apt-get install -y postgresql-16 postgresql-contrib-16
sudo systemctl enable --now postgresql`} />
          </Step>

          <Step n={3} title="Create database and user">
            <CodeBlock code={`sudo -u postgres psql <<'SQL'
CREATE USER aegis WITH PASSWORD 'CHANGE_ME';
CREATE DATABASE aegisai360 OWNER aegis;
GRANT ALL PRIVILEGES ON DATABASE aegisai360 TO aegis;
SQL`} />
          </Step>

          <Step n={4} title="Create system user and deploy app">
            <CodeBlock code={`sudo useradd -r -s /usr/sbin/nologin -d /opt/aegisai360 aegis
sudo mkdir -p /opt/aegisai360
sudo chown aegis:aegis /opt/aegisai360

# Extract release archive
sudo tar -xzf aegisai360-latest.tar.gz -C /opt/aegisai360 --strip-components=1
sudo -u aegis bash -c "cd /opt/aegisai360 && npm ci --omit=dev"
sudo -u aegis bash -c "cd /opt/aegisai360 && npm run build"`} />
          </Step>

          <Step n={5} title="Configure environment">
            <CodeBlock label="/opt/aegisai360/.env" code={ENV_TEMPLATE} />
            <CodeBlock code={`sudo chmod 600 /opt/aegisai360/.env
sudo chown aegis:aegis /opt/aegisai360/.env`} />
          </Step>

          <Step n={6} title="Run database migrations">
            <CodeBlock code={`sudo -u aegis bash -c "cd /opt/aegisai360 && npm run db:push"`} />
          </Step>

          <Step n={7} title="Install and start systemd service">
            <CodeBlock label="/etc/systemd/system/aegisai360.service" code={SYSTEMD_UNIT} />
            <CodeBlock code={`sudo systemctl daemon-reload
sudo systemctl enable --now aegisai360
sudo systemctl status aegisai360`} />
          </Step>

          <Step n={8} title="Configure nftables / iptables firewall">
            <CodeBlock code={`# Using nftables (Debian 12 default)
sudo nft add rule inet filter input tcp dport 5000 accept
sudo nft add rule inet filter input tcp dport 443 accept

# Or using iptables (older systems)
sudo iptables -I INPUT -p tcp --dport 5000 -j ACCEPT
sudo iptables -I INPUT -p tcp --dport 443 -j ACCEPT
sudo iptables-save | sudo tee /etc/iptables/rules.v4`} />
          </Step>
        </div>

        <Step n={9} title="Verify installation">
          <CodeBlock code={VERIFY_CMDS} />
        </Step>
      </div>

      <div className="flex gap-2">
        <Button
          variant="outline"
          className="gap-2"
          data-testid="button-download-debian-script"
          onClick={() => { window.location.href = "/api/deploy/script/debian"; }}
        >
          <Download className="w-4 h-4" />
          Download debian.sh
        </Button>
        <Button
          variant="ghost"
          className="gap-2 text-xs"
          onClick={() => {
            const b = new Blob([ENV_TEMPLATE], { type: "text/plain" });
            const a = document.createElement("a"); a.href = URL.createObjectURL(b);
            a.download = ".env.example"; a.click();
          }}
        >
          <Download className="w-3 h-3" /> .env template
        </Button>
      </div>
    </div>
  );
}

// ─── Nginx reverse proxy card ─────────────────────────────────────────────────

function NginxCard() {
  const conf = `server {
    listen 80;
    server_name YOUR_DOMAIN.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name YOUR_DOMAIN.com;

    ssl_certificate     /etc/letsencrypt/live/YOUR_DOMAIN.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/YOUR_DOMAIN.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass         http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade $http_upgrade;
        proxy_set_header   Connection "upgrade";
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400;
    }
}`;

  return (
    <Card className="border-border/40">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm flex items-center gap-2">
          <Server className="w-4 h-4" /> Nginx Reverse Proxy + TLS (recommended)
        </CardTitle>
        <CardDescription className="text-xs">Run AegisAI360 behind Nginx with Let's Encrypt for HTTPS</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <CodeBlock label="Install Nginx + Certbot" code={`# Ubuntu / Debian
sudo apt-get install -y nginx certbot python3-certbot-nginx

# CentOS / RHEL
sudo dnf install -y nginx certbot python3-certbot-nginx`} />
        <CodeBlock label="/etc/nginx/sites-available/aegisai360" code={conf} />
        <CodeBlock code={`sudo ln -s /etc/nginx/sites-available/aegisai360 /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
sudo certbot --nginx -d YOUR_DOMAIN.com`} />
      </CardContent>
    </Card>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function LinuxDeployPage() {
  useDocumentTitle("Linux Deployment | AegisAI360");

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Terminal className="w-5 h-5 text-primary" />
            <h1 className="text-xl font-bold">Linux Self-Hosted Deployment</h1>
          </div>
          <p className="text-sm text-muted-foreground">
            Deploy AegisAI360 on your own infrastructure — full control, no cloud dependency. Supports Ubuntu, CentOS/RHEL, and Debian.
          </p>
        </div>
        <div className="flex gap-2 flex-shrink-0">
          <Badge variant="outline" className="text-[10px] border-green-500/30 text-green-400">
            <CheckCircle className="w-2.5 h-2.5 mr-1" /> Node.js 20
          </Badge>
          <Badge variant="outline" className="text-[10px] border-blue-500/30 text-blue-400">
            <Database className="w-2.5 h-2.5 mr-1" /> PostgreSQL 16
          </Badge>
        </div>
      </div>

      {/* Quick overview cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { icon: Package, label: "Runtime", value: "Node.js 20 LTS" },
          { icon: Database, label: "Database", value: "PostgreSQL 16" },
          { icon: Shield, label: "Service", value: "systemd managed" },
          { icon: Zap, label: "Port", value: "5000 (proxied)" },
        ].map(({ icon: Icon, label, value }) => (
          <Card key={label} className="border-border/40">
            <CardContent className="p-3 flex items-center gap-2">
              <Icon className="w-4 h-4 text-primary flex-shrink-0" />
              <div>
                <p className="text-[10px] text-muted-foreground">{label}</p>
                <p className="text-xs font-mono font-semibold">{value}</p>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Per-distro tabs */}
      <Tabs defaultValue="ubuntu">
        <TabsList className="grid grid-cols-3 w-full max-w-md">
          <TabsTrigger value="ubuntu" className="gap-1.5 text-xs" data-testid="tab-ubuntu">
            <SiUbuntu className="w-3.5 h-3.5" /> Ubuntu
          </TabsTrigger>
          <TabsTrigger value="centos" className="gap-1.5 text-xs" data-testid="tab-centos">
            <FaRedhat className="w-3.5 h-3.5" /> CentOS / RHEL
          </TabsTrigger>
          <TabsTrigger value="debian" className="gap-1.5 text-xs" data-testid="tab-debian">
            <SiDebian className="w-3.5 h-3.5" /> Debian
          </TabsTrigger>
        </TabsList>

        <div className="mt-4">
          <TabsContent value="ubuntu"><UbuntuTab /></TabsContent>
          <TabsContent value="centos"><CentOSTab /></TabsContent>
          <TabsContent value="debian"><DebianTab /></TabsContent>
        </div>
      </Tabs>

      {/* Nginx section */}
      <NginxCard />

      {/* Post-install checklist */}
      <Card className="border-border/40">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <CheckCircle className="w-4 h-4 text-green-400" /> Post-Install Security Checklist
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {[
              "Change default SESSION_SECRET to a 64-char random string",
              "Change database password from CHANGE_ME",
              "Enable HTTPS via Nginx + Certbot (Let's Encrypt)",
              "Restrict PostgreSQL to localhost only (pg_hba.conf)",
              "Create your first superadmin account via /register",
              "Configure SMTP for alert email notifications",
              "Enable automatic security updates (unattended-upgrades)",
              "Set up log rotation for journald / application logs",
              "Configure backup for the PostgreSQL database",
              "Review firewall rules — only expose required ports",
            ].map((item) => (
              <div key={item} className="flex items-start gap-2 text-xs">
                <ChevronRight className="w-3 h-3 text-primary mt-0.5 flex-shrink-0" />
                <span className="text-muted-foreground">{item}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Update instructions */}
      <Card className="border-border/40">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <Settings className="w-4 h-4" /> Updating AegisAI360
          </CardTitle>
        </CardHeader>
        <CardContent>
          <CodeBlock code={`# Stop the service
sudo systemctl stop aegisai360

# Replace app files
sudo tar -xzf aegisai360-NEW.tar.gz -C /opt/aegisai360 --strip-components=1

# Install new dependencies + rebuild
sudo -u aegis bash -c "cd /opt/aegisai360 && npm ci --omit=dev && npm run build"

# Run any new migrations
sudo -u aegis bash -c "cd /opt/aegisai360 && npm run db:push"

# Restart the service
sudo systemctl start aegisai360
sudo systemctl status aegisai360`} />
        </CardContent>
      </Card>
    </div>
  );
}
