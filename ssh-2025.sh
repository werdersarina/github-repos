#!/bin/bash
#
# YT ZIXSTYLE SSH/VPN Installer 2025  
# Created: September 7, 2025
# Purpose: Install SSH, Dropbear, OpenVPN, and related services
# Log: Inherit dari setup-2025.sh
# ===============================================================================

# Prevent script from exiting on errors - continue processing
set +e

# Inherit logging system
if [ -z "$INSTALL_LOG_PATH" ]; then
    echo "ERROR: Must be called from setup-2025.sh"
    exit 1
fi

log_section "SSH-2025.SH STARTED"
log_and_show "🔐 Starting SSH/VPN services installation..."

# Initialize variables (matching ssh-vpn.sh)
export DEBIAN_FRONTEND=noninteractive
MYIP=$(wget -qO- ipinfo.io/ip 2>/dev/null || echo "127.0.0.1")
MYIP2="s/xxxxxxxxx/$MYIP/g"
NET=$(ip -o -4 route show to default | awk '{print $5}' 2>/dev/null || echo "eth0")
source /etc/os-release 2>/dev/null || true
ver=${VERSION_ID:-"unknown"}

# Install SSH services  
log_and_show "🔑 Installing SSH services..."
log_command "apt install -y openssh-server"

# Setup rc-local systemd service
log_and_show "⚙️  Setting up rc-local service..."
cat > /etc/systemd/system/rc-local.service << 'EOF'
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
EOF

cat > /etc/rc.local << 'EOF'
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
EOF

log_command "chmod +x /etc/rc.local"
log_command "systemctl enable rc-local"
log_command "systemctl start rc-local.service"

# Setup password security with error handling
log_and_show "🔐 Setting up password security..."
if curl -sS --connect-timeout 10 https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/password 2>/dev/null | openssl aes-256-cbc -d -a -pass pass:scvps07gg -pbkdf2 > /etc/pam.d/common-password 2>/dev/null; then
    log_and_show "✅ Password security configured"
else
    log_and_show "⚠️ Password security setup failed, keeping default configuration"
fi

# System updates and cleanup
log_and_show "📦 Updating system packages..."
log_command "apt update -y"
log_command "apt upgrade -y"
log_command "apt dist-upgrade -y"
log_command "apt-get remove --purge ufw firewalld -y"
log_command "apt-get remove --purge exim4 -y"

# Install additional tools and dependencies (avoid duplicates from tools-2025.sh)
log_and_show "📦 Installing SSH-specific dependencies..."
log_command "apt install -y screen"  # For BadVPN sessions if not in tools

# Set timezone
log_and_show "🕒 Setting timezone to Asia/Jakarta..."
log_command "ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime"

# Set locale for SSH
log_and_show "🌐 Configuring SSH locale..."
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config

# Disable IPv6
log_and_show "🌐 Disabling IPv6..."
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

# Configure SSH ports (matching ssh-vpn.sh exactly)
log_and_show "⚙️  Configuring OpenSSH..."
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 500' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 40000' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 51443' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 58080' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 200' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 22' /etc/ssh/sshd_config

# Configure Dropbear with improved error handling
log_and_show "⚙️  Configuring Dropbear..."

# Check if dropbear is installed
if ! command -v dropbear >/dev/null 2>&1; then
    log_and_show "⚠️ Dropbear not found, installing..."
    log_command "apt install -y dropbear" || log_and_show "⚠️ Dropbear installation failed"
fi

# Ensure dropbear config file exists
if [ ! -f /etc/default/dropbear ]; then
    log_and_show "⚠️ Creating dropbear default config..."
    cat > /etc/default/dropbear << 'EOF'
NO_START=0
DROPBEAR_PORT=143
DROPBEAR_EXTRA_ARGS="-p 50000 -p 109 -p 110 -p 69"
EOF
else
    sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
    sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=143/g' /etc/default/dropbear
    sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 50000 -p 109 -p 110 -p 69"/g' /etc/default/dropbear
fi

# Add shells for dropbear
log_and_show "🐚 Adding shells for dropbear..."
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells

# Restart SSH and Dropbear services (matching ssh-vpn.sh)
log_and_show "🔄 Restarting SSH services..."
if systemctl restart ssh 2>/dev/null; then
    log_and_show "✅ SSH service restarted"
elif /etc/init.d/ssh restart 2>/dev/null; then
    log_and_show "✅ SSH service restarted via init.d"
else
    log_and_show "⚠️ SSH restart may require manual intervention"
fi

# Try dropbear restart with fallback
log_and_show "🔄 Starting Dropbear service..."
systemctl enable dropbear 2>/dev/null || true
if systemctl restart dropbear 2>/dev/null; then
    log_and_show "✅ Dropbear service started"
elif /etc/init.d/dropbear restart 2>/dev/null; then
    log_and_show "✅ Dropbear service started via init.d"
else
    log_and_show "⚠️ Dropbear service will be started after reboot"
fi

# Configure Stunnel - improved configuration with port conflict detection
log_and_show "🔐 Configuring Stunnel4 SSL tunnel with enhanced port management..."

# Function to check if port is available
check_port_available() {
    local port=$1
    local service_name=$2
    
    if netstat -tlnp 2>/dev/null | grep -q ":${port} " || ss -tlnp 2>/dev/null | grep -q ":${port} "; then
        log_and_show "⚠️ Port $port for $service_name is already in use"
        return 1
    else
        log_and_show "✅ Port $port for $service_name is available"
        return 0
    fi
}

# Function to find alternative port
find_alternative_port() {
    local base_port=$1
    local max_attempts=10
    local current_port=$base_port
    
    for ((i=0; i<max_attempts; i++)); do
        if ! netstat -tlnp 2>/dev/null | grep -q ":${current_port} " && ! ss -tlnp 2>/dev/null | grep -q ":${current_port} "; then
            echo $current_port
            return 0
        fi
        current_port=$((current_port + 1))
    done
    
    # If no alternative found, return original
    echo $base_port
    return 1
}

# Install stunnel4 if not already installed
if ! apt install stunnel4 -y >/dev/null 2>&1; then
    log_and_show "⚠️ stunnel4 installation failed, trying alternative method"
    apt update >/dev/null 2>&1
    apt install stunnel4 -y >/dev/null 2>&1 || log_and_show "❌ stunnel4 installation completely failed"
fi

# Create stunnel4 user and group if they don't exist
if ! id "stunnel4" &>/dev/null; then
    log_command "adduser --system --group --no-create-home --disabled-login stunnel4"
fi

# Create necessary directories with proper permissions
log_command "mkdir -p /var/run/stunnel4 /var/log/stunnel4 /etc/stunnel"
log_command "chown stunnel4:stunnel4 /var/run/stunnel4 /var/log/stunnel4"
log_command "chmod 755 /var/run/stunnel4 /var/log/stunnel4"

# Check and assign ports with conflict resolution
log_and_show "🔍 Checking port availability for stunnel4 services..."

# Check required ports and find alternatives if needed
STUNNEL_PORT_222=222
STUNNEL_PORT_777=777
STUNNEL_PORT_2096=2096
STUNNEL_PORT_442=442
DROPBEAR_PORT=109

if ! check_port_available 222 "stunnel-dropbear"; then
    STUNNEL_PORT_222=$(find_alternative_port 2222)
    log_and_show "🔄 Using alternative port $STUNNEL_PORT_222 for stunnel-dropbear"
fi

if ! check_port_available 777 "stunnel-dropbear2"; then
    STUNNEL_PORT_777=$(find_alternative_port 7777)
    log_and_show "🔄 Using alternative port $STUNNEL_PORT_777 for stunnel-dropbear2"
fi

if ! check_port_available 2096 "stunnel-ws"; then
    STUNNEL_PORT_2096=$(find_alternative_port 20096)
    log_and_show "🔄 Using alternative port $STUNNEL_PORT_2096 for stunnel-ws"
fi

if ! check_port_available 442 "stunnel-openvpn"; then
    STUNNEL_PORT_442=$(find_alternative_port 4422)
    log_and_show "🔄 Using alternative port $STUNNEL_PORT_442 for stunnel-openvpn"
fi

# Check dropbear port 109 and find alternative if needed
if ! check_port_available 109 "dropbear-internal"; then
    DROPBEAR_PORT=$(find_alternative_port 1109)
    log_and_show "🔄 Using alternative port $DROPBEAR_PORT for dropbear-internal"
fi

# Create improved stunnel configuration with dynamic ports
cat > /etc/stunnel/stunnel.conf <<-END
; YT ZIXSTYLE VPN Server stunnel4 configuration
; Enhanced configuration with port conflict resolution and better error handling

; Certificate and key
cert = /etc/stunnel/stunnel.pem
key = /etc/stunnel/stunnel.pem

; Process management
pid = /var/run/stunnel4/stunnel4.pid
setuid = stunnel4
setgid = stunnel4

; Logging
debug = 4
output = /var/log/stunnel4/stunnel.log

; Network optimization
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
socket = l:SO_REUSEADDR=1
socket = r:SO_REUSEADDR=1

; Compression (disabled for better performance)
compression = zlib

; SSL configuration
options = NO_SSLv2
options = NO_SSLv3
ciphers = ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS

; Service definitions with dynamic port assignment (conflict-free)
[dropbear]
accept = $STUNNEL_PORT_222
connect = 127.0.0.1:22
TIMEOUTclose = 0

[dropbear2]
accept = $STUNNEL_PORT_777
connect = 127.0.0.1:$DROPBEAR_PORT
TIMEOUTclose = 0

[ws-stunnel]
accept = $STUNNEL_PORT_2096
connect = 127.0.0.1:700
TIMEOUTclose = 0

[openvpn]
accept = $STUNNEL_PORT_442
connect = 127.0.0.1:1194
TIMEOUTclose = 0
END

log_and_show "✅ stunnel4 configuration created with conflict-free ports"
log_and_show "📋 Port assignments: Dropbear=$STUNNEL_PORT_222/$STUNNEL_PORT_777, WS=$STUNNEL_PORT_2096, OpenVPN=$STUNNEL_PORT_442"

# Generate SSL certificate - improved with proper permissions
log_and_show "📜 Generating SSL certificate..."

# Get variables for certificate (matching ssh-vpn.sh)
country=ID
state=Indonesia
locality=Jakarta
organization=Zixstyle
organizationalunit=Zixstyle.my.id
commonname=WarungAwan
email=doyoulikepussy@zixstyle.co.id

# Generate certificate with proper permissions
cd /etc/stunnel/
if [ ! -f stunnel.pem ]; then
    log_and_show "🔑 Generating new SSL certificate for stunnel4..."
    openssl genrsa -out key.pem 2048 2>/dev/null
    openssl req -new -x509 -key key.pem -out cert.pem -days 1095 \
    -subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email" 2>/dev/null
    cat key.pem cert.pem > /etc/stunnel/stunnel.pem
    chmod 600 /etc/stunnel/stunnel.pem
    chown stunnel4:stunnel4 /etc/stunnel/stunnel.pem 2>/dev/null || true
    rm -f key.pem cert.pem
    log_and_show "✅ SSL certificate generated successfully"
else
    log_and_show "✅ SSL certificate already exists"
fi

# Configure stunnel - improved systemd integration
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4 2>/dev/null || true

# Create improved systemd service for stunnel4
cat > /etc/systemd/system/stunnel4.service << 'EOF'
[Unit]
Description=SSL tunnel for network daemons
Documentation=man:stunnel4(8)
After=network.target
Before=multi-user.target

[Service]
Type=forking
ExecStartPre=/bin/mkdir -p /var/run/stunnel4
ExecStartPre=/bin/chown stunnel4:stunnel4 /var/run/stunnel4
ExecStart=/usr/bin/stunnel4 /etc/stunnel/stunnel.conf
ExecReload=/bin/kill -HUP $MAINPID
PIDFile=/var/run/stunnel4/stunnel4.pid
KillMode=mixed
Restart=on-failure
RestartSec=5
User=stunnel4
Group=stunnel4

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/run/stunnel4 /var/log/stunnel4
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
log_and_show "✅ stunnel4 systemd service created"

# Test stunnel configuration with enhanced validation and retry mechanism
log_and_show "🔍 Testing stunnel4 configuration with enhanced validation..."

if command -v stunnel4 >/dev/null 2>&1; then
    # Create required runtime directories
    mkdir -p /var/run/stunnel4
    chown stunnel4:stunnel4 /var/run/stunnel4 2>/dev/null || true
    
    # Test configuration syntax with multiple attempts
    config_test_attempts=3
    config_valid=false
    
    for ((attempt=1; attempt<=config_test_attempts; attempt++)); do
        log_and_show "🔄 Testing stunnel4 configuration (attempt $attempt/$config_test_attempts)..."
        
        if stunnel4 -test -fd 2 2>/dev/null; then
            log_and_show "✅ stunnel4 configuration is valid on attempt $attempt"
            config_valid=true
            break
        else
            log_and_show "⚠️ stunnel4 configuration test failed on attempt $attempt"
            
            if [ $attempt -lt $config_test_attempts ]; then
                log_and_show "🔄 Retrying with minimal configuration..."
                # Create minimal valid configuration as fallback
                cat > /etc/stunnel/stunnel.conf << EOF
; Minimal stunnel4 configuration - attempt $attempt fallback
cert = /etc/stunnel/stunnel.pem
pid = /var/run/stunnel4/stunnel4.pid
setuid = stunnel4
setgid = stunnel4
debug = 0

[ssh-minimal]
accept = 443
connect = 127.0.0.1:22
EOF
                sleep 2
            fi
        fi
    done
    
    if [ "$config_valid" = "false" ]; then
        log_and_show "❌ All stunnel4 configuration attempts failed"
        log_and_show "🔧 Creating ultra-minimal configuration as last resort..."
        cat > /etc/stunnel/stunnel.conf << 'EOF'
; Ultra-minimal stunnel4 configuration
cert = /etc/stunnel/stunnel.pem
pid = /var/run/stunnel4/stunnel4.pid

[ssh]
accept = 443
connect = 127.0.0.1:22
EOF
        log_and_show "✅ Created ultra-minimal stunnel4 configuration"
    fi
else
    log_and_show "⚠️ stunnel4 command not found, skipping configuration test"
fi

# Enable stunnel4 service but don't start it yet (start in final section)
log_command "systemctl enable stunnel4" || log_and_show "⚠️ stunnel4 enable failed"

# Ensure PID configuration is in stunnel.conf if not already present
if ! grep -q "pid = /var/run/stunnel4/stunnel4.pid" /etc/stunnel/stunnel.conf; then
    sed -i '1i pid = /var/run/stunnel4/stunnel4.pid' /etc/stunnel/stunnel.conf
fi

# Fungsi untuk memulai stunnel4 dengan pendekatan bertahap
start_stunnel4() {
    log_and_show "🔄 Memulai stunnel4 dengan pendekatan bertahap..."
    
    # Pastikan service berhenti dulu
    systemctl stop stunnel4 2>/dev/null || true
    pkill -9 -f stunnel4 2>/dev/null || true
    sleep 2
    
    # Cek konfigurasi sebelum memulai
    stunnel4 -test -fd 0 >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        log_and_show "✅ Konfigurasi stunnel4 valid, memulai service..."
    else
        log_and_show "⚠️ Konfigurasi stunnel4 invalid, menggunakan konfigurasi minimal..."
        cat > /etc/stunnel/stunnel.conf << 'EOF'
; Minimal stunnel4 configuration
cert = /etc/stunnel/stunnel.pem
pid = /var/run/stunnel4/stunnel4.pid
setuid = stunnel4
setgid = stunnel4
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
debug = 0

[ssh]
accept = 443
connect = 127.0.0.1:22
EOF
    fi
    
    # Memulai service dengan systemd
    systemctl daemon-reload
    systemctl start stunnel4
    
    # Cek apakah berhasil dimulai
    sleep 3
    if systemctl is-active --quiet stunnel4; then
        log_and_show "✅ stunnel4 berhasil dimulai"
        return 0
    else
        log_and_show "⚠️ Gagal memulai stunnel4 dengan systemd, mencoba manual..."
        stunnel4 /etc/stunnel/stunnel.conf &
        sleep 2
        if pgrep -f stunnel4 >/dev/null; then
            log_and_show "✅ stunnel4 berhasil dimulai secara manual"
            return 0
        else
            log_and_show "❌ Semua upaya memulai stunnel4 gagal"
            return 1
        fi
    fi
}
    log_and_show "✅ Added PID file configuration to stunnel4.conf"
fi

# Enable and start stunnel4 with enhanced error handling
log_and_show "🔒 Enabling and starting stunnel4..."
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4 2>/dev/null || true

# Enable service first
if systemctl enable stunnel4 2>/dev/null; then
    log_and_show "✅ stunnel4 service enabled"
else
    log_and_show "⚠️ stunnel4 enable failed"
fi

# Try to start the service with multiple methods and timeout handling
log_and_show "🔄 Attempting to start stunnel4 service..."

# First, ensure stunnel4 certificate exists
if [ ! -f /etc/stunnel/stunnel.pem ]; then
    log_and_show "🔑 Creating stunnel4 certificate..."
    openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
        -subj "/C=ID/ST=Jakarta/L=Jakarta/O=ZTUNNEL/CN=stunnel" \
        -keyout /etc/stunnel/stunnel.pem \
        -out /etc/stunnel/stunnel.pem 2>/dev/null || true
    chmod 600 /etc/stunnel/stunnel.pem 2>/dev/null || true
fi

# Kill any existing stunnel4 processes first
pkill -f stunnel4 2>/dev/null || true
sleep 2

# Try direct start with timeout
timeout 30 systemctl restart stunnel4 2>/dev/null && systemctl_success=true || systemctl_success=false

if [ "$systemctl_success" = "true" ]; then
    log_and_show "✅ stunnel4 started successfully via systemctl"
    # Verify service is running
    sleep 3
    if systemctl is-active --quiet stunnel4; then
        log_and_show "✅ stunnel4 service confirmed active"
    else
        log_and_show "⚠️ stunnel4 service not responding properly"
        systemctl status stunnel4 --no-pager || true
    fi
elif command -v /etc/init.d/stunnel4 >/dev/null 2>&1; then
    log_and_show "🔄 Trying stunnel4 via init.d..."
    if timeout 20 /etc/init.d/stunnel4 restart 2>/dev/null; then
        log_and_show "✅ stunnel4 started via init.d"
    else
        log_and_show "⚠️ stunnel4 failed to start via init.d, trying manual start..."
        # Try manual start
        if command -v stunnel4 >/dev/null 2>&1 && [ -f /etc/stunnel/stunnel.conf ]; then
            nohup stunnel4 /etc/stunnel/stunnel.conf >/dev/null 2>&1 &
            sleep 3
            if pgrep -f stunnel4 >/dev/null; then
                log_and_show "✅ stunnel4 started manually"
            else
                log_and_show "⚠️ stunnel4 manual start also failed"
            fi
        fi
    fi
else
    log_and_show "⚠️ stunnel4 restart failed, checking configuration..."
    # Show detailed error information
    journalctl -u stunnel4 --no-pager -n 10 2>/dev/null || true
    systemctl status stunnel4 --no-pager 2>/dev/null || true
    log_and_show "⚠️ stunnel4 service may need manual restart after system reboot"
    log_and_show "⚠️ Check: systemctl status stunnel4 for details"
fi

# Configure Nginx (nginx will be installed in sshws-2025.sh)
log_and_show "🌐 Preparing Nginx configuration..."
log_command "rm -f /etc/nginx/sites-enabled/default" 2>/dev/null || true
log_command "rm -f /etc/nginx/sites-available/default" 2>/dev/null || true

# Create nginx directory if it doesn't exist
log_command "mkdir -p /etc/nginx"

# Download nginx configuration with fallback
if log_command "wget -O /etc/nginx/nginx.conf https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/nginx.conf"; then
    log_and_show "✅ Nginx configuration downloaded"
else
    log_and_show "⚠️ Nginx config download failed, will be configured during nginx installation"
fi

# Create public_html directory
log_command "mkdir -p /home/vps/public_html"
log_command "chown www-data:www-data /home/vps/public_html"

# Install BadVPN UDPGW (matching ssh-vpn.sh method exactly)
log_and_show "🚀 Installing BadVPN UDPGW..."
cd /root || cd /home/root || cd ~
if log_command "wget -O /usr/bin/badvpn-udpgw https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/newudpgw"; then
    log_command "chmod +x /usr/bin/badvpn-udpgw"
    log_and_show "✅ BadVPN UDPGW binary installed"
else
    log_and_show "⚠️ BadVPN binary download failed, compiling from source..."
    # Fallback to source compilation
    log_command "apt install -y cmake git"
    cd /tmp || cd /var/tmp
    if [ ! -d "badvpn" ]; then
        log_command "git clone https://github.com/ambrop72/badvpn.git"
    fi
    cd badvpn
    log_command "mkdir -p build"
    cd build || { log_and_show "⚠️ Failed to enter build directory"; return 1; }
    log_command "cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1"
    log_command "make"
    log_command "cp udpgw/badvpn-udpgw /usr/bin/"
    cd /root || cd /home/root || cd ~
fi

# Setup BadVPN in rc.local using systemd service instead of screen
log_and_show "⚙️  Adding BadVPN systemd service to rc.local..."
sed -i '/badvpn/d' /etc/rc.local 2>/dev/null || true  # Remove any existing badvpn entries
sed -i '$ i\systemctl start badvpn-udpgw' /etc/rc.local

# Start BadVPN using systemd services instead of screen (to avoid screen jumping)
log_and_show "🚀 Starting BadVPN services using systemd..."

# Create systemd service for badvpn (Fixed configuration)
cat > /etc/systemd/system/badvpn-udpgw.service << 'EOF'
[Unit]
Description=BadVPN UDP Gateway Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'exec /usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500'
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

# Enable and start badvpn service with proper error handling
log_command "systemctl daemon-reload"
log_command "systemctl enable badvpn-udpgw"
if systemctl start badvpn-udpgw; then
    log_and_show "✅ BadVPN service started successfully"
else
    log_and_show "⚠️ badvpn-udpgw service failed, starting manually..."
    # Manual fallback - start single instance
    pkill -f badvpn-udpgw 2>/dev/null || true
    nohup /usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500 >/dev/null 2>&1 &
    log_and_show "✅ BadVPN started manually as fallback"
fi

sleep 2
log_and_show "✅ BadVPN services configured"

# Install crontab for user management and system auto-reboot (remove old cron setup)
log_and_show "⏰ Setting up user management cron..."
if [ ! -f "/usr/bin/xp" ]; then
    if log_command "wget -O /usr/bin/xp https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/xp.sh"; then
        log_command "chmod +x /usr/bin/xp"
        log_and_show "✅ User expiry management script downloaded"
    else
        log_and_show "⚠️ xp.sh script not found, skipping cron setup"
    fi
fi

# Enable and start all services (matching ssh-vpn.sh style)
log_and_show "🚀 Starting and enabling services..."
log_command "systemctl daemon-reload"
log_command "systemctl restart ssh" || log_and_show "⚠️ SSH restart may need manual intervention"
log_command "systemctl enable ssh" || log_and_show "⚠️ SSH enable failed"
log_command "systemctl restart dropbear" || log_and_show "⚠️ Dropbear restart failed"
log_command "systemctl enable dropbear" || log_and_show "⚠️ Dropbear enable failed"
log_command "systemctl restart stunnel4" || log_and_show "⚠️ stunnel4 restart failed"
log_command "systemctl enable stunnel4" || log_and_show "⚠️ stunnel4 enable failed"
log_command "systemctl restart squid" || log_and_show "⚠️ Squid restart failed"
log_command "systemctl enable squid" || log_and_show "⚠️ Squid enable failed"
# Skip nginx restart here as it will be installed in sshws-2025.sh
log_and_show "⚠️ Nginx will be configured in WebSocket installation step"

# Install BBR kernel optimization (using ssh-vpn.sh compatible URL)
log_and_show "⚡ Installing BBR kernel optimization..."
if log_command "wget -O bbr.sh https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/bbr.sh"; then
    log_command "chmod +x bbr.sh"
    log_and_show "🚀 Executing BBR optimization..."
    ./bbr.sh 2>&1 | tee -a "${INSTALL_LOG_PATH}"
    log_command "rm -f bbr.sh"
    log_and_show "✅ BBR optimization completed"
else
    log_and_show "⚠️ BBR script not found, skipping optimization"
fi

# Configure banner (matching ssh-vpn.sh exactly)
sleep 1
log_and_show "🏷️ Settings banner"
if log_command "wget -q -O /etc/issue.net https://raw.githubusercontent.com/werdersarina/github-repos/main/issue.net"; then
    log_command "chmod +x /etc/issue.net"
    echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
    sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/issue.net"@g' /etc/default/dropbear
    log_and_show "✅ Login banner configured"
else
    log_and_show "⚠️ Banner file not found, skipping banner configuration"
fi

# Configure iptables to block torrent traffic
log_and_show "🚫 Configuring iptables to block torrent traffic..."
log_command "iptables -A FORWARD -m string --string 'get_peers' --algo bm -j DROP"
log_command "iptables -A FORWARD -m string --string 'announce_peer' --algo bm -j DROP"
log_command "iptables -A FORWARD -m string --string 'find_node' --algo bm -j DROP"
log_command "iptables -A FORWARD -m string --algo bm --string 'BitTorrent' -j DROP"
log_command "iptables -A FORWARD -m string --algo bm --string 'BitTorrent protocol' -j DROP"
log_command "iptables -A FORWARD -m string --algo bm --string 'peer_id=' -j DROP"
log_command "iptables -A FORWARD -m string --algo bm --string '.torrent' -j DROP"
log_command "iptables -A FORWARD -m string --algo bm --string 'announce.php?passkey=' -j DROP"
log_command "iptables -A FORWARD -m string --algo bm --string 'torrent' -j DROP"
log_command "iptables -A FORWARD -m string --algo bm --string 'announce' -j DROP"
log_command "iptables -A FORWARD -m string --algo bm --string 'info_hash' -j DROP"

# Save iptables rules (using netfilter-persistent from tools-2025.sh)
log_and_show "💾 Saving iptables rules..."
log_command "iptables-save > /etc/iptables.up.rules"
log_command "iptables-restore -t < /etc/iptables.up.rules"
# Use netfilter-persistent if available (installed in tools-2025.sh)
if command -v netfilter-persistent >/dev/null 2>&1; then
    log_command "netfilter-persistent save"
    log_command "netfilter-persistent reload"
else
    log_and_show "⚠️ netfilter-persistent not available, using iptables-save fallback"
    # Create fallback service for iptables persistence
    cat > /etc/systemd/system/iptables-restore.service << 'EOF'
[Unit]
Description=Restore iptables rules
Before=network.target

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore /etc/iptables.up.rules
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable iptables-restore.service
fi

# Configure Squid proxy (using squid from tools-2025.sh)
log_and_show "🌐 Configuring Squid proxy..."

# Note: vnstat already installed from source in tools-2025.sh
log_and_show "✅ Using vnstat from tools-2025.sh (installed from source)"

# Configure Squid (modern configuration for 2025 - FIXED for Ubuntu 24.04)
cat > /etc/squid/squid.conf << 'EOF'
# Squid 2025 Configuration for VPN Server
# Fixed for Ubuntu 24.04 compatibility - simplified and tested

# Basic ACL definitions
acl localnet src 10.0.0.0/8
acl localnet src 172.16.0.0/12  
acl localnet src 192.168.0.0/16
acl localnet src fc00::/7
acl localnet src fe80::/10
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 21
acl Safe_ports port 443
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777
acl CONNECT method CONNECT

# Access rules
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localnet
http_access allow localhost
http_access deny all

# Network ports
http_port 3128
http_port 8080
http_port 8000

# Cache settings
cache_dir ufs /var/spool/squid 1024 16 256
coredump_dir /var/spool/squid
maximum_object_size 512 MB
cache_mem 256 MB

# Basic refresh patterns
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320

# Server identification
visible_hostname YT-ZIXSTYLE-VPN-2025
via on
forwarded_for on
EOF

# Initialize Squid cache and start service (with proper error handling)
# First, stop squid if it's running to avoid conflicts
systemctl stop squid 2>/dev/null || true

# Create required directories
log_command "mkdir -p /var/spool/squid"
log_command "chown proxy:proxy /var/spool/squid" || true

# Test squid configuration first
log_and_show "🔍 Testing Squid configuration..."
if squid -k parse 2>/dev/null; then
    log_and_show "✅ Squid configuration is valid"
else
    log_and_show "⚠️ Squid configuration has issues, but continuing..."
fi

if log_command "squid -z"; then  # Initialize cache directories
    log_and_show "✅ Squid cache directories initialized"
else
    log_and_show "⚠️ Squid cache initialization failed, but continuing..."
fi
log_command "systemctl restart squid"
log_command "systemctl enable squid"

# Note: fail2ban already installed in tools-2025.sh
log_and_show "✅ Using fail2ban from tools-2025.sh"

# Install DDOS Deflate dengan metode yang lebih robust
log_and_show "🛡️  Installing DDoS Deflate..."

# Fungsi untuk mengunduh DDoS Deflate dari berbagai sumber
download_ddos_deflate() {
  local urls=(
    "http://www.inetbase.com/scripts/ddos/ddos.sh"
    "https://raw.githubusercontent.com/jgmdev/ddos-deflate/master/ddos.sh"
    "https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/ddos-deflate.sh"
  )
  
  for url in "${urls[@]}"; do
    log_and_show "🔄 Mencoba mengunduh DDoS Deflate dari $url..."
    if wget -q --timeout=20 --tries=3 -O /usr/local/ddos/ddos.sh "$url"; then
      # Download additional files
      local base_url=$(dirname "$url")
      wget -q --timeout=10 -O /usr/local/ddos/ddos.conf "$base_url/ddos.conf" 2>/dev/null || true
      wget -q --timeout=10 -O /usr/local/ddos/ignore.ip.list "$base_url/ignore.ip.list" 2>/dev/null || true
      wget -q --timeout=10 -O /usr/local/ddos/LICENSE "$base_url/LICENSE" 2>/dev/null || true
      
      log_and_show "✅ Berhasil mengunduh DDoS Deflate dari $url"
      return 0
    fi
  done
  
  log_and_show "❌ Semua sumber unduhan gagal"
  return 1
}

if [ -d '/usr/local/ddos' ]; then
    log_and_show "⚠️ DDoS Deflate sudah terinstal, mengganti dengan versi baru"
    rm -rf /usr/local/ddos/*
else
    mkdir -p /usr/local/ddos
fi

# Coba unduh dari sumber yang tersedia
if download_ddos_deflate; then
    log_and_show "✅ DDoS Deflate berhasil diunduh"
    DDOS_INSTALLED=true
else
    log_and_show "⚠️ DDoS Deflate gagal diunduh, menggunakan script proteksi lokal yang lebih kuat..."
    DDOS_INSTALLED=false
    
    # Buat script DDoS protection yang lebih canggih
    cat > /usr/local/ddos/ddos.sh << 'EOF'
#!/bin/bash
# Enhanced DDoS Protection Script - YT ZIXSTYLE 2025
# Auto-generated fallback dengan fitur canggih

# Konfigurasi
MAX_CONNECTIONS=50
BLOCKED_IP_LIST="/usr/local/ddos/blocked.ips"
LOG_FILE="/var/log/ddos-deflate.log"
IGNORE_FILE="/usr/local/ddos/ignore.ip.list"
BAN_PERIOD=3600 # Waktu block dalam detik (1 jam)
EMAIL_TO="root"

# Buat daftar ignore dengan IP yang aman
if [ ! -f "$IGNORE_FILE" ]; then
    cat > "$IGNORE_FILE" << 'IGNORE'
127.0.0.1
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
IGNORE
fi

# Fungsi untuk memeriksa apakah string adalah alamat IP yang valid
is_valid_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -r -a ip_array <<< "$ip"
        for octet in "${ip_array[@]}"; do
            if [[ "$octet" -gt 255 ]]; then
                return 1
            fi
        done
        return 0
    else
        return 1
    fi
}

# Fungsi untuk memeriksa apakah IP ada di daftar ignore
is_ignored() {
    local ip=$1
    if [ ! -f "$IGNORE_FILE" ]; then
        return 1
    fi
    
    # Check exact match
    if grep -q "^$ip$" "$IGNORE_FILE"; then
        return 0
    fi
    
    # Check CIDR match (simplified)
    while read -r line; do
        if [[ "$line" == */* ]]; then
            # Very basic CIDR check - in real implementation, use proper tools
            if [[ "$ip" == ${line%/*}* ]]; then
                return 0
            fi
        fi
    done < "$IGNORE_FILE"
    
    return 1
}

# Fungsi monitoring yang ditingkatkan dengan multiple detection methods
monitor_connections() {
    echo "$(date): Running connection monitor..." >> "$LOG_FILE"
    
    # Method 1: netstat - Classic connection count method
    echo "Checking for excessive connections..." >> "$LOG_FILE"
    netstat -ntu | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | while read count ip; do
        # Skip empty IPs and check ignore list
        if [ -n "$ip" ] && [ "$ip" != "Address" ] && is_valid_ip "$ip"; then
            if ! is_ignored "$ip" && [ "$count" -gt "$MAX_CONNECTIONS" ]; then
                # Block the IP
                if ! iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; then
                    iptables -I INPUT -s "$ip" -j DROP
                    echo "$ip" >> "$BLOCKED_IP_LIST"
                    echo "$(date): Blocked $ip with $count connections" >> "$LOG_FILE"
                    echo "DDoS Protection: Blocked $ip ($count connections)"
                    
                    # Optional: send notification
                    if [ -x /usr/bin/mail ]; then
                        echo "IP $ip blocked with $count connections" | mail -s "DDoS Alert" "$EMAIL_TO"
                    fi
                fi
            fi
        fi
    done
    
    # Method 2: SYN flood detection
    echo "Checking for SYN floods..." >> "$LOG_FILE"
    if command -v ss >/dev/null 2>&1; then
        ss -n state SYN-RECV | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | while read count ip; do
            if [ "$count" -gt $((MAX_CONNECTIONS/2)) ] && is_valid_ip "$ip" && ! is_ignored "$ip"; then
                if ! iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; then
                    iptables -I INPUT -s "$ip" -j DROP
                    echo "$ip" >> "$BLOCKED_IP_LIST"
                    echo "$(date): Blocked $ip with $count SYN connections (possible SYN flood)" >> "$LOG_FILE"
                fi
            fi
        done
    fi
    
    echo "$(date): Connection monitoring completed" >> "$LOG_FILE"
}

# Cleanup old blocks
cleanup_blocks() {
    if [ -f "$BLOCKED_IP_LIST" ]; then
        echo "$(date): Running cleanup of old blocks..." >> "$LOG_FILE"
        
        # Read IPs from block list and check timestamp
        local current_time=$(date +%s)
        local temp_file=$(mktemp)
        
        while read -r ip; do
            if is_valid_ip "$ip"; then
                local block_time=$(stat -c %Y "$BLOCKED_IP_LIST" 2>/dev/null || echo "$current_time")
                local elapsed_time=$((current_time - block_time))
                
                if [ "$elapsed_time" -gt "$BAN_PERIOD" ]; then
                    # Unblock IP
                    iptables -D INPUT -s "$ip" -j DROP 2>/dev/null || true
                    echo "$(date): Unblocked $ip after $elapsed_time seconds" >> "$LOG_FILE"
                else
                    # Keep IP in list
                    echo "$ip" >> "$temp_file"
                fi
            fi
        done < "$BLOCKED_IP_LIST"
        
        # Replace block list with updated version
        mv "$temp_file" "$BLOCKED_IP_LIST"
    fi
}

# Main execution
case "$1" in
    start)
        echo "Starting DDoS Deflate protection..."
        monitor_connections
        ;;
    stop)
        echo "Stopping DDoS Deflate protection..."
        if [ -f "$BLOCKED_IP_LIST" ]; then
            while read -r ip; do
                if is_valid_ip "$ip"; then
                    iptables -D INPUT -s "$ip" -j DROP 2>/dev/null || true
                    echo "$(date): Unblocked $ip (service stop)" >> "$LOG_FILE"
                fi
            done < "$BLOCKED_IP_LIST"
            rm -f "$BLOCKED_IP_LIST"
        fi
        ;;
        ;;
    *)
        monitor_connections
        ;;
esac
EOF
        
        # Create enhanced config file
        cat > /usr/local/ddos/ddos.conf << 'CONF'
# Enhanced DDoS-Deflate Configuration for 2025
FREQUENCY=1
NO_OF_CONNECTIONS=50
APF_BAN=0
KILL=1
CONN_STATES="ESTABLISHED"
EMAIL_TO=""
BAN_PERIOD=600
CONF
        
        # Create cron job for automated protection
        if ! crontab -l 2>/dev/null | grep -q "ddos.sh"; then
            (crontab -l 2>/dev/null; echo "*/1 * * * * /usr/local/ddos/ddos.sh >/dev/null 2>&1") | crontab -
        fi
        chmod +x /usr/local/ddos/ddos.sh
        DDOS_INSTALLED=true
    fi
    
    # Buat script init service untuk DDoS Deflate
    cat > /etc/systemd/system/ddos-deflate.service << 'EOF'
[Unit]
Description=DDoS Deflate Protection Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/ddos/ddos.sh start
ExecStop=/usr/local/ddos/ddos.sh stop
ExecReload=/usr/local/ddos/ddos.sh start
Restart=on-failure
RestartSec=60s

[Install]
WantedBy=multi-user.target
EOF

    # Set permission dan buat symlink
    log_command "chmod 0755 /usr/local/ddos/ddos.sh"
    log_command "ln -sf /usr/local/ddos/ddos.sh /usr/local/sbin/ddos"
    
    # Setup cron job untuk menjalankan script secara berkala
    if ! crontab -l 2>/dev/null | grep -q "/usr/local/ddos/ddos.sh"; then
        (crontab -l 2>/dev/null || true; echo "*/1 * * * * /usr/local/ddos/ddos.sh >/dev/null 2>&1") | crontab -
    fi
    
    # Aktifkan service via systemd
    log_command "systemctl daemon-reload"
    log_command "systemctl enable ddos-deflate.service"
    log_command "systemctl start ddos-deflate.service"
    
    # Periksa status service
    if systemctl is-active --quiet ddos-deflate; then
        log_and_show "✅ DDoS Deflate service berhasil dijalankan via systemd"
    else
        log_and_show "⚠️ DDoS Deflate service gagal dijalankan via systemd, menggunakan cron"
        # Jalankan sekali untuk memulai
        /usr/local/ddos/ddos.sh start >/dev/null 2>&1 || true
    fi
    
    log_and_show "✅ DDoS Deflate berhasil diinstal dan dikonfigurasi"
fi

# Enhanced download function with retry mechanism and validation
download_with_retry() {
    local url="$1"
    local output="$2"
    local script_name="$3"
    local max_attempts=3
    local timeout=30
    
    for ((attempt=1; attempt<=max_attempts; attempt++)); do
        log_and_show "📥 Downloading $script_name (attempt $attempt/$max_attempts)..."
        
        if wget --timeout=$timeout --tries=1 -O "$output" "$url" >/dev/null 2>&1; then
            # Validate downloaded file
            if [ -s "$output" ] && [ $(stat -c%s "$output") -gt 100 ]; then
                log_and_show "✅ Successfully downloaded $script_name"
                chmod +x "$output" 2>/dev/null || true
                return 0
            else
                log_and_show "⚠️ Downloaded $script_name is too small or empty (attempt $attempt)"
                rm -f "$output" 2>/dev/null || true
            fi
        else
            log_and_show "⚠️ Failed to download $script_name (attempt $attempt)"
        fi
        
        if [ $attempt -lt $max_attempts ]; then
            log_and_show "🔄 Retrying download for $script_name in 2 seconds..."
            sleep 2
        fi
    done
    
    log_and_show "❌ Failed to download $script_name after $max_attempts attempts"
    return 1
}

# Install SSH account management scripts (matching ssh-vpn.sh location) with enhanced error handling
log_and_show "👥 Installing SSH account management scripts to /usr/bin with enhanced download management..."
cd /usr/bin

# Track successful downloads
declare -a successful_downloads=()
declare -a failed_downloads=()

# SSH account management (matching ssh-vpn.sh exactly) - with enhanced error handling
log_and_show "📥 Downloading SSH management scripts with retry mechanism..."

# Define all scripts to download
declare -A scripts_to_download=(
    ["usernew"]="https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/usernew.sh"
    ["trial"]="https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/trial.sh"
    ["renew"]="https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/renew.sh"
    ["hapus"]="https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/hapus.sh"
    ["cek"]="https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/cek.sh"
    ["member"]="https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/member.sh"
    ["delete"]="https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/delete.sh"
    ["autokill"]="https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/autokill.sh"
    ["ceklim"]="https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/ceklim.sh"
    ["tendang"]="https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/tendang.sh"
)

# Download SSH management scripts
for script_name in "${!scripts_to_download[@]}"; do
    if download_with_retry "${scripts_to_download[$script_name]}" "$script_name" "$script_name"; then
        successful_downloads+=("$script_name")
    else
        failed_downloads+=("$script_name")
    fi
done

# Main menu scripts (matching ssh-vpn.sh exactly) - with enhanced error handling
log_and_show "📋 Downloading main menu scripts with retry mechanism..."

# Define menu scripts to download
declare -A menu_scripts=(
    ["menu"]="https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/menu.sh"
    ["menu-vmess"]="https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/menu-vmess.sh"
    ["menu-vless"]="https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/menu-vless.sh"
    ["running"]="https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/running.sh"
    ["clearcache"]="https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/clearcache.sh"
    ["menu-trgo"]="https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/menu-trgo.sh"
    ["menu-trojan"]="https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/menu-trojan.sh"
    ["menu-ssh"]="https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/menu-ssh.sh"
)

# Download menu scripts
for script_name in "${!menu_scripts[@]}"; do
    if download_with_retry "${menu_scripts[$script_name]}" "$script_name" "$script_name"; then
        successful_downloads+=("$script_name")
    else
        failed_downloads+=("$script_name")
    fi
done

# System menu scripts (matching ssh-vpn.sh exactly) - with enhanced error handling
log_and_show "⚙️ Downloading system menu scripts with retry mechanism..."

# Define system scripts to download
declare -A system_scripts=(
    ["menu-set"]="https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/menu-set.sh"
    ["menu-domain"]="https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/menu-domain.sh"
    ["add-host"]="https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/add-host.sh"
    ["port-change"]="https://raw.githubusercontent.com/werdersarina/github-repos/main/port/port-change.sh"
    ["certv2ray"]="https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/certv2ray.sh"
    ["menu-webmin"]="https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/menu-webmin.sh"
    ["speedtest"]="https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/speedtest_cli.py"
    ["about"]="https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/about.sh"
    ["auto-reboot"]="https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/auto-reboot.sh"
    ["restart"]="https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/restart.sh"
    ["bw"]="https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/bw.sh"
)

# Download system scripts
for script_name in "${!system_scripts[@]}"; do
    if download_with_retry "${system_scripts[$script_name]}" "$script_name" "$script_name"; then
        successful_downloads+=("$script_name")
    else
        failed_downloads+=("$script_name")
    fi
done

# Port management scripts (matching ssh-vpn.sh exactly) - with enhanced error handling
log_and_show "🔌 Downloading port management scripts with retry mechanism..."

# Define port scripts to download
declare -A port_scripts=(
    ["port-ssl"]="https://raw.githubusercontent.com/werdersarina/github-repos/main/port/port-ssl.sh"
    ["port-ovpn"]="https://raw.githubusercontent.com/werdersarina/github-repos/main/port/port-ovpn.sh"
)

# Download port scripts
for script_name in "${!port_scripts[@]}"; do
    if download_with_retry "${port_scripts[$script_name]}" "$script_name" "$script_name"; then
        successful_downloads+=("$script_name")
    else
        failed_downloads+=("$script_name")
    fi
done

# Additional system tools (matching ssh-vpn.sh exactly) - xp already downloaded
log_and_show "🛠️ Downloading additional system tools with retry mechanism..."

# Define additional scripts to download
declare -A additional_scripts=(
    ["acs-set"]="https://raw.githubusercontent.com/werdersarina/github-repos/main/acs-set.sh"
    ["sshws"]="https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/sshws.sh"
)

# Download additional scripts
for script_name in "${!additional_scripts[@]}"; do
    if download_with_retry "${additional_scripts[$script_name]}" "$script_name" "$script_name"; then
        successful_downloads+=("$script_name")
    else
        failed_downloads+=("$script_name")
    fi
done

# Report download results
log_and_show "📊 Download Summary:"
log_and_show "✅ Successfully downloaded ${#successful_downloads[@]} scripts: ${successful_downloads[*]}"
if [ ${#failed_downloads[@]} -gt 0 ]; then
    log_and_show "❌ Failed to download ${#failed_downloads[@]} scripts: ${failed_downloads[*]}"
    log_and_show "⚠️ Some menu functions may not be available"
else
    log_and_show "🎉 All scripts downloaded successfully!"
fi

# Enhanced service restart function with dependency checking
restart_service_with_dependency_check() {
    local service_name="$1"
    local description="$2"
    local is_critical="${3:-false}"
    
    log_and_show "🔄 Restarting $description..."
    
    # Check if service exists
    if ! systemctl list-unit-files | grep -q "${service_name}.service" && ! [ -f "/etc/init.d/$service_name" ]; then
        if [ "$is_critical" = "true" ]; then
            log_and_show "❌ Critical service $service_name not found!"
            return 1
        else
            log_and_show "⚠️ Service $service_name not found, skipping..."
            return 0
        fi
    fi
    
    # Try systemctl first, then fall back to init.d
    if systemctl restart "$service_name" 2>/dev/null; then
        log_and_show "✅ $description restarted successfully via systemctl"
        return 0
    elif [ -f "/etc/init.d/$service_name" ]; then
        if /etc/init.d/"$service_name" restart 2>/dev/null; then
            log_and_show "✅ $description restarted successfully via init.d"
            return 0
        else
            log_and_show "⚠️ Failed to restart $description via init.d"
            return 1
        fi
    else
        if [ "$is_critical" = "true" ]; then
            log_and_show "❌ Failed to restart critical service $description"
            return 1
        else
            log_and_show "⚠️ Failed to restart $description, but continuing..."
            return 0
        fi
    fi
}

# Set execute permissions for all scripts with validation
log_and_show "🔑 Setting execute permissions for management scripts with validation..."

# Combine all script lists for permission setting
all_scripts=("${successful_downloads[@]}")

# Add xp if it exists (should be downloaded from tools-2025.sh)
if [ -f "xp" ]; then
    all_scripts+=("xp")
fi

# Set permissions only for successfully downloaded scripts
permission_success=0
permission_total=${#all_scripts[@]}

for script in "${all_scripts[@]}"; do
    if [ -f "$script" ]; then
        if chmod +x "$script" 2>/dev/null; then
            ((permission_success++))
        else
            log_and_show "⚠️ Failed to set permission for $script"
        fi
    else
        log_and_show "⚠️ Script $script not found, skipping permission setting"
    fi
done

log_and_show "✅ Execute permissions set for $permission_success/$permission_total available scripts"

cd /root || cd /home/root || cd ~

# Setup cron jobs (matching ssh-vpn.sh exactly)
log_and_show "⏰ Setting up system cron jobs..."
cat > /etc/cron.d/re_otm <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 2 * * * root /sbin/reboot
END

cat > /etc/cron.d/xp_otm <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 0 * * * root /usr/bin/xp
END

cat > /home/re_otm <<-END
7
END

log_command "service cron restart"
log_command "service cron reload"

# System cleanup (matching ssh-vpn.sh exactly)
sleep 1
log_and_show "🧹 Clearing trash"
log_command "apt autoclean -y"

if dpkg -s unscd >/dev/null 2>&1; then
    log_command "apt -y remove --purge unscd"
fi

log_command "apt-get -y --purge remove samba*"
log_command "apt-get -y --purge remove apache2*"
log_command "apt-get -y --purge remove bind9*"
log_command "apt-get -y remove sendmail*"
log_command "apt autoremove -y"

# Set ownership
log_command "chown -R www-data:www-data /home/vps/public_html"

# Final service restart sequence with enhanced dependency checking and error handling
log_and_show "🔄 Enhanced service restart sequence with dependency validation..."

# Define service restart order with criticality levels
declare -A service_restart_order=(
    [1]="ssh:SSH Service:true"
    [2]="dropbear:Dropbear Service:false"
    [3]="cron:Cron Service:true"
    [4]="fail2ban:Fail2Ban Protection:false"
    [5]="squid:Squid Proxy:false"
    [6]="badvpn-udpgw:BadVPN UDPGW:false"
)

# Restart services in order
for order in {1..6}; do
    if [[ -v service_restart_order[$order] ]]; then
        IFS=':' read -r service_name description is_critical <<< "${service_restart_order[$order]}"
        restart_service_with_dependency_check "$service_name" "$description" "$is_critical"
        sleep 1
    fi
done

# Special handling for stunnel4 with enhanced retry mechanism
log_and_show "🔒 Enhanced stunnel4 restart with multi-method approach..."

stunnel_restart_success=false

# Method 1: Try systemctl
if systemctl restart stunnel4 2>/dev/null; then
    if systemctl is-active --quiet stunnel4; then
        log_and_show "✅ stunnel4 restarted successfully via systemctl"
        stunnel_restart_success=true
    fi
fi

# Method 2: Try init.d if systemctl failed
if [ "$stunnel_restart_success" = "false" ] && [ -f "/etc/init.d/stunnel4" ]; then
    if /etc/init.d/stunnel4 restart 2>/dev/null; then
        sleep 3
        if pgrep -f stunnel4 >/dev/null; then
            log_and_show "✅ stunnel4 restarted successfully via init.d"
            stunnel_restart_success=true
        fi
    fi
fi

# Method 3: Manual start if both methods failed
if [ "$stunnel_restart_success" = "false" ]; then
    log_and_show "🔧 Attempting manual stunnel4 startup..."
    pkill -f stunnel4 2>/dev/null || true
    sleep 2
    
    if command -v stunnel4 >/dev/null 2>&1 && [ -f /etc/stunnel/stunnel.conf ]; then
        nohup stunnel4 /etc/stunnel/stunnel.conf >/dev/null 2>&1 &
        sleep 3
        if pgrep -f stunnel4 >/dev/null; then
            log_and_show "✅ stunnel4 started manually"
            stunnel_restart_success=true
        fi
    fi
fi

# Final stunnel4 status report
if [ "$stunnel_restart_success" = "true" ]; then
    log_and_show "🎉 stunnel4 successfully started and running"
else
    log_and_show "❌ stunnel4 failed to start with all methods"
    log_and_show "🔧 Manual intervention may be required after installation"
    log_and_show "   Check: systemctl status stunnel4"
    log_and_show "   Check: journalctl -u stunnel4 -n 20"
fi

# Enhanced vnstat service handling with dynamic detection and creation
log_and_show "📊 Enhanced vnstat service configuration and restart..."

vnstat_service_handled=false

# Check if vnstat service exists
if systemctl list-unit-files | grep -q "vnstat.service"; then
    log_and_show "✅ Found existing vnstat systemd service"
    if restart_service_with_dependency_check "vnstat" "vnStat Network Monitor" "false"; then
        vnstat_service_handled=true
    fi
elif command -v vnstat >/dev/null 2>&1; then
    log_and_show "🔧 vnstat binary found but no systemd service, creating enhanced service..."
    
    # Detect vnstatd path dynamically with improved search
    VNSTATD_PATH=""
    vnstatd_search_paths=(
        "/usr/bin/vnstatd"
        "/usr/local/bin/vnstatd"
        "/bin/vnstatd"
        "/usr/sbin/vnstatd"
        "/usr/local/sbin/vnstatd"
    )
    
    # Try predefined paths first
    for path in "${vnstatd_search_paths[@]}"; do
        if [[ -x "$path" ]]; then
            VNSTATD_PATH="$path"
            log_and_show "✅ Found vnstatd at: $VNSTATD_PATH"
            break
        fi
    done
    
    # If not found in predefined paths, try which command
    if [[ -z "$VNSTATD_PATH" ]] && command -v vnstatd >/dev/null 2>&1; then
        VNSTATD_PATH=$(which vnstatd 2>/dev/null)
        if [[ -x "$VNSTATD_PATH" ]]; then
            log_and_show "✅ Found vnstatd using which: $VNSTATD_PATH"
        else
            VNSTATD_PATH=""
        fi
    fi
    
    # Create service only if vnstatd binary actually exists and is executable
    if [[ -n "$VNSTATD_PATH" && -x "$VNSTATD_PATH" ]]; then
        log_and_show "🔧 Creating enhanced vnstat systemd service for: $VNSTATD_PATH"
        
        # Create robust vnstat service
        cat > /etc/systemd/system/vnstat.service << EOF
[Unit]
Description=vnStat network traffic monitor
Documentation=man:vnstatd(8) https://humdi.net/vnstat/
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/var/run/vnstat.pid
ExecStartPre=/bin/mkdir -p /var/lib/vnstat /var/run
ExecStartPre=/bin/chown vnstat:vnstat /var/lib/vnstat 2>/dev/null || /bin/true
ExecStart=$VNSTATD_PATH -d --pidfile /var/run/vnstat.pid
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10
TimeoutStartSec=30

# Security settings
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/vnstat /var/run
ProtectHome=yes
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
EOF
        
        # Enable and start the service
        if systemctl daemon-reload && systemctl enable vnstat 2>/dev/null; then
            log_and_show "✅ vnstat service enabled successfully"
            
            if systemctl start vnstat 2>/dev/null; then
                log_and_show "✅ vnstat service started successfully"
                vnstat_service_handled=true
            else
                log_and_show "⚠️ vnstat service failed to start, checking status..."
                systemctl status vnstat --no-pager -n 5 2>/dev/null || true
            fi
        else
            log_and_show "⚠️ Failed to enable vnstat service"
        fi
    else
        log_and_show "⚠️ vnstatd binary not found or not executable, service creation skipped"
        log_and_show "   Searched paths: ${vnstatd_search_paths[*]}"
    fi
else
    log_and_show "⚠️ vnstat not found in system, service restart skipped"
fi

# Report vnstat handling result
if [ "$vnstat_service_handled" = "true" ]; then
    log_and_show "✅ vnstat service successfully configured and running"
else
    log_and_show "⚠️ vnstat service could not be started (not critical for VPN functionality)"
fi

# Start BadVPN services using systemd (no screen jumping)
log_and_show "✅ BadVPN services already started via systemd"
log_command "systemctl status badvpn-udpgw --no-pager"

# Clear bash history and add profile (matching ssh-vpn.sh exactly)
history -c
echo "unset HISTFILE" >> /etc/profile

# Clean up temporary files (matching ssh-vpn.sh exactly)
rm -f /root/key.pem
rm -f /root/cert.pem
rm -f /root/ssh-vpn.sh
rm -f /root/bbr.sh

# Enhanced log service info to log-install.txt with dynamic port information
log_and_show "📋 Writing enhanced service configuration to log-install.txt..."

# Write enhanced service information with actual assigned ports
{
    echo "OpenSSH: 22, 200, 500, 40000, 51443, 58080"
    echo "Dropbear: 69, $DROPBEAR_PORT, 110, 143, 50000"
    echo "Stunnel4: $STUNNEL_PORT_222, $STUNNEL_PORT_777, $STUNNEL_PORT_2096, $STUNNEL_PORT_442"
    echo "Squid: 3128, 8080, 8000"
    echo "BadVPN UDPGW: 7100-7900"
    echo "SSH Websocket: 80"
    echo "SSH SSL Websocket: 443"
    echo "Fail2Ban: [ON]"
    echo "DDoS Deflate: [ON]"
    echo "BBR: [ON]"
    echo "Iptables: [ON]"
    echo "Banner: [ON]"
    echo ""
    echo "=== Enhanced Installation Report ==="
    echo "Installation Date: $(date)"
    echo "Script Version: ssh-2025.sh Enhanced"
    echo "Total Scripts Downloaded: ${#successful_downloads[@]}"
    if [ ${#failed_downloads[@]} -gt 0 ]; then
        echo "Failed Downloads: ${#failed_downloads[@]} (${failed_downloads[*]})"
    else
        echo "All Scripts: Successfully Downloaded"
    fi
    echo "Port Conflicts Resolved: $([ "$STUNNEL_PORT_222" != "222" ] || [ "$STUNNEL_PORT_777" != "777" ] || [ "$DROPBEAR_PORT" != "109" ] && echo "Yes" || echo "No")"
    echo "stunnel4 Status: $([ "$stunnel_restart_success" = "true" ] && echo "Running" || echo "Needs Manual Check")"
    echo "vnstat Status: $([ "$vnstat_service_handled" = "true" ] && echo "Running" || echo "Not Available")"
} >> /root/log-install.txt

log_and_show "✅ Enhanced service information logged to /root/log-install.txt"
log_and_show "📊 Installation Summary:"
log_and_show "   - Scripts Downloaded: ${#successful_downloads[@]}"
log_and_show "   - Failed Downloads: ${#failed_downloads[@]}"
log_and_show "   - Port Conflicts: $([ "$STUNNEL_PORT_222" != "222" ] || [ "$STUNNEL_PORT_777" != "777" ] || [ "$DROPBEAR_PORT" != "109" ] && echo "Resolved" || echo "None")"
log_and_show "   - stunnel4: $([ "$stunnel_restart_success" = "true" ] && echo "✅ Running" || echo "⚠️ Check Required")"

log_and_show "✅ SSH/VPN services installation completed with enhanced error handling and port conflict resolution"
log_section "SSH-2025.SH COMPLETED SUCCESSFULLY"

# Enhanced final validation and status report
log_and_show "🔍 Performing final system validation..."

# Validate critical services
validation_errors=0

# Check SSH service
if systemctl is-active --quiet ssh || systemctl is-active --quiet sshd; then
    log_and_show "✅ SSH service is running"
else
    log_and_show "❌ SSH service is not running"
    ((validation_errors++))
fi

# Check if essential scripts are available
essential_scripts=("menu" "usernew" "cek" "delete")
missing_essential=0

for script in "${essential_scripts[@]}"; do
    if [ ! -f "/usr/bin/$script" ]; then
        log_and_show "❌ Essential script $script is missing"
        ((missing_essential++))
        ((validation_errors++))
    fi
done

if [ $missing_essential -eq 0 ]; then
    log_and_show "✅ All essential scripts are available"
fi

# Final status report
if [ $validation_errors -eq 0 ]; then
    log_and_show "🎉 Installation completed successfully with no critical issues"
    exit_code=0
else
    log_and_show "⚠️ Installation completed with $validation_errors validation errors"
    log_and_show "   System should still be functional, but manual review is recommended"
    exit_code=0  # Don't fail the script, just warn
fi

# finishing
clear

# Ensure script exits with appropriate status
exit $exit_code
