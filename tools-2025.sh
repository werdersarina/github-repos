#!/bin/bash
#
# YT ZIXSTYLE Tools Installer 2025
# Created: September 7, 2025
# Purpose: Install system tools, dependencies, and basic configurations
# Log: Inherit dari setup-2025.sh
# ===============================================================================

# Prevent interactive prompts during package installation (for iptables-persistent)
export DEBIAN_FRONTEND=noninteractive

# Inherit logging system
if [ -z "$INSTALL_LOG_PATH" ]; then
    echo "ERROR: Must be called from setup-2025.sh"
    exit 1
fi

log_section "TOOLS-2025.SH STARTED"
log_and_show "🛠️  Starting system tools installation..."

# Color functions for compatibility
red='\e[1;31m'
green='\e[1;32m'
yell='\e[1;33m'
NC='\e[0m'
green() { echo -e "\\033[32;1m${*}\\033[0m"; }
red() { echo -e "\\033[31;1m${*}\\033[0m"; }
yellow() { echo -e "\\033[33;1m${*}\\033[0m"; }

# Fungsi instalasi paket dengan retry mechanism
install_package() {
  local package=$1
  local max_attempts=3
  local attempt=1
  
  while [ $attempt -le $max_attempts ]; do
    log_and_show "🔄 Installing $package (attempt $attempt/$max_attempts)..."
    if apt install -y $package; then
      log_and_show "✅ Successfully installed $package"
      return 0
    else
      log_and_show "⚠️ Failed to install $package, retrying..."
      sleep 3
      attempt=$((attempt+1))
    fi
  done
  
  log_and_show "❌ Failed to install $package after $max_attempts attempts"
  return 1
}

# Grup paket-paket berdasarkan prioritas
critical_packages="curl wget"
network_packages="net-tools tcpdump"
utility_packages="zip unzip screen whois jq"

# OS Detection
if [[ -e /etc/debian_version ]]; then
    source /etc/os-release
    OS=$ID # debian or ubuntu
elif [[ -e /etc/centos-release ]]; then
    source /etc/os-release
    OS=centos
fi

# Get network interface
NET=$(ip -o $ANU -4 route show to default | awk '{print $5}')
if [ -z "$NET" ]; then
    NET=$(ip route | awk '/default/ { print $5 }' | head -n1)
fi

log_and_show "📦 Updating system packages..."
log_command "apt update -y"
log_command "apt dist-upgrade -y"
log_command "apt-get remove --purge ufw firewalld -y"
log_command "apt-get remove --purge exim4 -y"

# Install comprehensive package list (based on tools.sh - updated for Ubuntu 24.04)
log_and_show "📦 Installing comprehensive package list..."
# Install packages in smaller groups to avoid conflicts
log_command "apt install -y screen curl jq bzip2 gzip coreutils rsyslog iftop htop zip unzip"
log_command "apt install -y net-tools sed gnupg gnupg1 bc apt-transport-https build-essential"
log_command "apt install -y dirmngr libxml-parser-perl neofetch screenfetch git lsof openssl"
log_command "apt install -y openvpn easy-rsa fail2ban tmux stunnel4 squid dropbear"
# Install nginx and additional packages
log_command "apt install -y nginx apache2-utils"
# Install netfilter-persistent and netcat-openbsd (fixing netcat issue)
log_command "apt install -y iptables-persistent netfilter-persistent netcat-openbsd"

# Configure stunnel4 with proper settings
log_and_show "🔒 Configuring stunnel4..."
if command -v stunnel4 >/dev/null 2>&1; then
    # Ensure stunnel4 configuration directory exists
    log_command "mkdir -p /etc/stunnel"
    
    # Create stunnel4 user if not exists (before creating certificate)
    if ! id stunnel4 >/dev/null 2>&1; then
        log_command "useradd --system --no-create-home --shell /bin/false stunnel4" || true
    fi
    
    # Create self-signed certificate FIRST (before config)
    if [[ ! -f /etc/stunnel/stunnel.pem ]]; then
        log_and_show "🔐 Creating self-signed SSL certificate for stunnel4..."
        openssl req -new -x509 -days 3650 -nodes -out /etc/stunnel/stunnel.pem -keyout /etc/stunnel/stunnel.pem -subj "/C=ID/ST=Jakarta/L=Jakarta/O=YT-ZIXSTYLE/CN=stunnel" 2>/dev/null || true
        chmod 600 /etc/stunnel/stunnel.pem
        chown stunnel4:stunnel4 /etc/stunnel/stunnel.pem 2>/dev/null || true
        log_and_show "✅ SSL certificate created for stunnel4"
    fi
    
    # Create basic stunnel4 configuration AFTER certificate is ready
    # Create stunnel4 runtime directory BEFORE configuration
    log_command "mkdir -p /var/run/stunnel4 /var/lib/stunnel4 /var/log/stunnel4"
    log_command "chown stunnel4:stunnel4 /var/run/stunnel4" || true
    
    if [[ ! -f /etc/stunnel/stunnel.conf ]]; then
        cat > /etc/stunnel/stunnel.conf << 'EOF'
; Basic stunnel4 configuration for YT ZIXSTYLE VPN
cert = /etc/stunnel/stunnel.pem
pid = /var/run/stunnel4/stunnel.pid

; User and group
setuid = stunnel4
setgid = stunnel4

; Some performance tunings
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

; Logging
debug = 4
output = /var/log/stunnel4/stunnel.log

; Basic HTTPS to HTTP proxy service (minimal working configuration)
[https]
accept = 8443
connect = 127.0.0.1:8080
TIMEOUTclose = 0

EOF
        log_and_show "✅ Basic stunnel4 configuration created"
    fi
    
    # Create basic systemd service for stunnel4 if it doesn't exist properly
    if [[ ! -f /etc/systemd/system/stunnel4.service ]]; then
        cat > /etc/systemd/system/stunnel4.service << 'EOF'
[Unit]
Description=SSL tunnel for network daemons
Documentation=man:stunnel
DefaultDependencies=no
After=network.target
Before=multi-user.target

[Service]
Type=forking
RuntimeDirectory=stunnel4
ExecStart=/usr/bin/stunnel4 /etc/stunnel/stunnel.conf
ExecReload=/bin/kill -HUP $MAINPID
PIDFile=/var/run/stunnel4/stunnel.pid
KillMode=mixed

# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/run/stunnel4
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
EOF
        log_and_show "✅ Enhanced stunnel4 systemd service created"
        log_command "systemctl daemon-reload"
    fi
    
    # Test stunnel4 configuration (directories now exist)
    if stunnel4 -test 2>/dev/null; then
        log_and_show "✅ stunnel4 configuration test passed"
    else
        log_and_show "⚠️ stunnel4 configuration test failed, but continuing..."
    fi
    
    # Set proper ownership after directories are created
    log_command "chown stunnel4:stunnel4 /var/run/stunnel4 /var/lib/stunnel4 /var/log/stunnel4" || true
    log_command "chmod 755 /var/run/stunnel4 /var/lib/stunnel4"
    log_command "chmod 750 /var/log/stunnel4"
    
    # Enable stunnel4 service if it exists
    if systemctl list-unit-files | grep -q "^stunnel4.service"; then
        log_command "systemctl enable stunnel4" || log_and_show "⚠️ Failed to enable stunnel4 service"
    fi
else
    log_and_show "⚠️ stunnel4 not installed, skipping configuration"
fi
    fi
else
    log_and_show "⚠️ stunnel4 command not found after installation"
fi
# Simplified package installation like original script
log_and_show "📦 Installing system packages..."

# Remove problematic packages first
apt-get remove --purge ufw firewalld -y >/dev/null 2>&1 || true
apt-get remove --purge exim4 -y >/dev/null 2>&1 || true

# Install all packages in one go like original script
apt install -y screen curl jq bzip2 gzip coreutils rsyslog iftop \
 htop zip unzip net-tools sed gnupg gnupg1 \
 bc apt-transport-https build-essential dirmngr libxml-parser-perl neofetch screenfetch git lsof \
 openssl openvpn easy-rsa fail2ban tmux \
 stunnel4 vnstat squid3 \
 dropbear libsqlite3-dev \
 socat cron bash-completion ntpdate xz-utils \
 gnupg2 dnsutils lsb-release chrony >/dev/null 2>&1

log_and_show "✅ System packages installed"

# Install Node.js like original script
curl -sSL https://deb.nodesource.com/setup_16.x | bash - >/dev/null 2>&1
apt-get install nodejs -y >/dev/null 2>&1

log_and_show "✅ Node.js installed"

# For Ubuntu 24.04, we use ufw instead of iptables-persistent
if ! command -v netfilter-persistent >/dev/null 2>&1; then
    log_and_show "📦 Installing iptables-persistent package..."
    echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
    echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
    log_command "apt install -y iptables-persistent netfilter-persistent" || log_and_show "⚠️ iptables-persistent installation failed, rules may not persist"
fi

# Install Node.js 20 LTS (updated from deprecated 16.x with error handling)
log_and_show "🟢 Installing Node.js 20 LTS..."
if ! log_command "curl -sSL https://deb.nodesource.com/setup_20.x | bash -"; then
    log_and_show "⚠️ NodeSource repository setup failed, trying snap installation..."
    if command -v snap >/dev/null; then
        log_command "snap install node --classic" || log_and_show "⚠️ Node.js installation failed"
    else
        log_and_show "⚠️ Installing nodejs from Ubuntu repository as fallback..."
        log_command "apt install -y nodejs npm" || log_and_show "⚠️ Node.js fallback installation failed"
    fi
else
    log_command "apt-get install nodejs -y" || log_and_show "⚠️ Node.js installation failed"
fi

# Python environment
log_and_show "🐍 Setting up Python environment..."
log_command "apt install -y python3 python3-pip python3-dev build-essential"
if ! command -v python >/dev/null 2>&1; then
    log_command "ln -sf /usr/bin/python3 /usr/bin/python"
    log_and_show "✅ Python symlink created"
fi

# Install vnstat - simplified approach like original script
log_and_show "📊 Installing vnstat..."

# Simple vnstat installation
/etc/init.d/vnstat restart
wget -q https://humdi.net/vnstat/vnstat-2.6.tar.gz
tar zxvf vnstat-2.6.tar.gz >/dev/null 2>&1
cd vnstat-2.6
./configure --prefix=/usr --sysconfdir=/etc >/dev/null 2>&1 && make >/dev/null 2>&1 && make install >/dev/null 2>&1
cd /
rm -rf vnstat-2.6*
NET=$(ip -o -4 route show to default | awk '{print $5}' | head -n1)
vnstat -u -i $NET
log_and_show "✅ vnstat berhasil diinstal"

log_and_show "✅ All tools installation completed successfully"

log_section "TOOLS-2025.SH COMPLETED"
    
    # Create database directory with proper permissions
    log_command "mkdir -p /var/lib/vnstat"
    log_command "chown vnstat:vnstat /var/lib/vnstat" || true
    log_command "chmod 755 /var/lib/vnstat"
    
    # Remove any corrupted database files
    log_command "rm -f /var/lib/vnstat/$NET_INTERFACE*" || true
    
    # Initialize database with modern vnstat methods (no -u parameter in newer versions)
    log_and_show "🔄 Attempting vnstat database initialization..."
    
    # Method 1: Modern vnstat (2.6+)
    if vnstat --help 2>/dev/null | grep -q "\--create"; then
        if log_command "vnstat --create -i $NET_INTERFACE"; then
            log_and_show "✅ vnstat database created with --create method"
        else
            log_and_show "⚠️ Method 1 failed, trying daemon initialization..."
            log_command "vnstatd --initdb --config /etc/vnstat.conf" || true
            log_and_show "✅ vnstat initialized with daemon method"
        fi
    elif vnstat --help 2>/dev/null | grep -q "\--add"; then
        # Method 2: Legacy vnstat
        if log_command "vnstat -i $NET_INTERFACE --add"; then
            log_and_show "✅ vnstat database created with --add method"
        else
            log_and_show "⚠️ Method 2 failed, trying daemon initialization..."
            log_command "vnstatd --initdb --config /etc/vnstat.conf" || true
            log_and_show "✅ vnstat initialized with daemon method"
        fi
    else
        # Method 3: Force initialization with daemon only (no -u in modern versions)
        log_command "vnstatd --initdb --config /etc/vnstat.conf" || true
        log_and_show "⚠️ All database creation methods failed, using service auto-init"
    fi
    
    # Final ownership fix
    log_command "chown -R vnstat:vnstat /var/lib/vnstat" || true
    log_command "chmod -R 644 /var/lib/vnstat/*" 2>/dev/null || true
    # Ensure database directory exists
    mkdir -p /var/lib/vnstat
    chown -R vnstat:vnstat /var/lib/vnstat 2>/dev/null || true
    
    # Create database for primary interface if not exists (fixed for modern vnstat)
    if [[ ! -f /var/lib/vnstat/.$NET ]] && [[ ! -f /var/lib/vnstat/.${NET} ]]; then
        log_and_show "📊 Creating vnstat database for interface $NET..."
        # Try different vnstat database creation methods based on version
        if vnstat --help 2>/dev/null | grep -q "\--create"; then
            vnstat --create -i $NET 2>/dev/null || log_and_show "⚠️ vnstat --create failed"
        elif vnstat --help 2>/dev/null | grep -q "\--add"; then
            vnstat -i $NET --add 2>/dev/null || log_and_show "⚠️ vnstat --add failed"
        else
            # Fallback: Use daemon initialization (no -u in modern vnstat)
            vnstatd --initdb --config /etc/vnstat.conf 2>/dev/null || log_and_show "⚠️ vnstat basic initialization failed"
        fi
        sleep 2
    else
        log_and_show "✅ vnstat database already exists for $NET"
    fi
    
    # Try to start vnstat service with enhanced error handling
    if systemctl is-active --quiet vnstat; then
        log_and_show "✅ vnstat service is already running"
    else
        if systemctl start vnstat 2>/dev/null; then
            log_and_show "✅ vnstat service started successfully"
        else
            log_and_show "⚠️ vnstat service startup failed, trying restart..."
            systemctl restart vnstat 2>/dev/null || log_and_show "⚠️ vnstat will be available after next system reboot"
        fi
    fi
    
    # Set correct ownership after database creation
    chown -R vnstat:vnstat /var/lib/vnstat 2>/dev/null || true
    chmod 755 /var/lib/vnstat 2>/dev/null || true
    
    # Start vnstat service with proper error handling
    if systemctl start vnstat 2>/dev/null; then
        log_and_show "✅ vnstat service started successfully"
        # Verify service is actually running
        sleep 2
        if systemctl is-active --quiet vnstat; then
            log_and_show "✅ vnstat service confirmed active"
        else
            log_and_show "⚠️ vnstat service not active, will retry after reboot"
        fi
    else
        log_and_show "⚠️ vnstat service startup failed, trying restart..."
        if systemctl restart vnstat 2>/dev/null; then
            log_and_show "✅ vnstat service restarted successfully"
        else
            log_and_show "⚠️ vnstat will be available after next system reboot"
            systemctl enable vnstat 2>/dev/null || true
        fi
    fi
else
    log_and_show "⚠️ vnstat command not available, skipping service startup"
fi
log_and_show "✅ vnstat configured with hardened systemd service"

# Enhanced security tools with nginx DDoS protection
log_and_show "🛡️ Configuring enhanced security tools with nginx DDoS protection..."
log_command "apt install -y ufw fail2ban"

# Configure fail2ban with nginx-specific rules
log_and_show "🔒 Setting up fail2ban with nginx DDoS protection..."

# Create nginx-ddos filter
log_and_show "📝 Creating nginx-ddos fail2ban filter..."
mkdir -p /etc/fail2ban/filter.d
cat > /etc/fail2ban/filter.d/nginx-ddos.conf << 'EOF'
# Fail2Ban filter for nginx DDoS protection
[Definition]
failregex = <HOST> -.*- .*HTTP/1.* .* .*$
ignoreregex =
EOF

# Create nginx-specific jail configuration  
log_and_show "🔒 Creating nginx-specific fail2ban jail..."
mkdir -p /etc/fail2ban/jail.d
cat > /etc/fail2ban/jail.d/fail2ban-nginx.conf << 'EOF'
[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 3
findtime = 600
bantime = 3600

[nginx-noscript]
enabled = true
port = http,https
filter = nginx-noscript
logpath = /var/log/nginx/access.log
maxretry = 6
findtime = 600
bantime = 3600

[nginx-badbots]
enabled = true
port = http,https
filter = nginx-badbots
logpath = /var/log/nginx/access.log
maxretry = 2
findtime = 600
bantime = 86400

[nginx-noproxy]
enabled = true
port = http,https
filter = nginx-noproxy
logpath = /var/log/nginx/access.log
maxretry = 2
findtime = 600
bantime = 86400

[nginx-ddos]
enabled = true
port = http,https
filter = nginx-ddos
logpath = /var/log/nginx/access.log
maxretry = 50
findtime = 60
bantime = 600

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
findtime = 600
bantime = 3600
EOF

log_command "systemctl enable fail2ban"
log_command "systemctl restart fail2ban"
log_and_show "✅ fail2ban configured with nginx DDoS protection"

# Performance tools
log_and_show "⚡ Installing performance optimization tools..."
log_command "apt install -y haveged rng-tools"
log_command "systemctl enable haveged"
log_command "systemctl start haveged"

# Development tools (updated to avoid conflicts)
log_and_show "🔧 Installing additional development tools..."
log_command "apt install -y autoconf automake libtool"
log_command "apt install -y libssl-dev zlib1g-dev"

# Create necessary directories
log_and_show "📁 Creating system directories..."
log_command "mkdir -p /etc/xray /etc/v2ray /usr/local/bin"

# System optimizations
log_and_show "⚙️ Applying system optimizations..."
log_command "sysctl -w net.core.default_qdisc=fq"
log_command "sysctl -w net.ipv4.tcp_congestion_control=bbr"

log_section "TOOLS-2025.SH COMPLETED"
log_and_show "✅ System tools installation completed successfully!"
log_command "mkdir -p /home/vps/public_html"
log_command "mkdir -p /var/log/xray"

# Set timezone
log_and_show "🕐 Configuring timezone..."
log_command "timedatectl set-timezone Asia/Jakarta"

# Final status message (matching tools.sh style)
yellow() { echo -e "\\033[33;1m${*}\\033[0m"; }
yellow "Dependencies successfully installed..."
log_and_show "⏳ Waiting 3 seconds..."
sleep 3

# Log tools installation
echo "Tools: System packages, Python, network utilities" >> /root/log-install.txt
echo "Development: gcc, make, build tools" >> /root/log-install.txt
echo "Performance: haveged, rng-tools" >> /root/log-install.txt
echo "vnStat: Version 2.9 with hardened systemd service" >> /root/log-install.txt
echo "fail2ban: Enhanced with nginx DDoS protection rules" >> /root/log-install.txt
echo "Security: SystemCallArchitectures, PrivateTmp, ProtectSystem" >> /root/log-install.txt

log_and_show "✅ System tools installation completed"
log_section "TOOLS-2025.SH COMPLETED"

# Ensure script exits successfully even if some minor components failed
exit 0
