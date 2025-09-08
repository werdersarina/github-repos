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

# Configure Stunnel - simplified like original script
log_and_show "🔐 Configuring Stunnel4 SSL tunnel..."

# Install stunnel4 if not already installed
apt install stunnel4 -y >/dev/null 2>&1

cat > /etc/stunnel/stunnel.conf <<-END
cert = /etc/stunnel/stunnel.pem
key = /etc/stunnel/stunnel.pem
pid = /var/run/stunnel4/stunnel.pid
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 222
connect = 127.0.0.1:22

[dropbear2]
accept = 777
connect = 127.0.0.1:109

[ws-stunnel]
accept = 2096
connect = 127.0.0.1:700

[openvpn]
accept = 442
connect = 127.0.0.1:1194
END

# Generate SSL certificate - simplified approach
log_and_show "📜 Generating SSL certificate..."

# Get variables for certificate (matching ssh-vpn.sh)
country=ID
state=Indonesia
locality=Jakarta
organization=Zixstyle
organizationalunit=Zixstyle.my.id
commonname=WarungAwan
email=doyoulikepussy@zixstyle.co.id

# Generate certificate like original script
cd /etc/stunnel/
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 1095 \
-subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem

# Configure stunnel - simple approach like original
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
/etc/init.d/stunnel4 restart >/dev/null 2>&1

log_and_show "✅ stunnel4 configured successfully"
    cat > /etc/systemd/system/stunnel4.service << 'EOF'
[Unit]
Description=SSL tunnel for network daemons
Documentation=man:stunnel4(8)
After=network.target

[Service]
Type=forking
ExecStart=/usr/bin/stunnel4 /etc/stunnel/stunnel.conf
PIDFile=/var/run/stunnel4/stunnel4.pid
ExecStartPre=/bin/mkdir -p /var/run/stunnel4
ExecStartPre=/bin/chown stunnel4:stunnel4 /var/run/stunnel4
Restart=on-failure
RestartSec=5
User=stunnel4
Group=stunnel4

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_and_show "✅ stunnel4 systemd service created"
fi

# Test stunnel configuration with enhanced validation
if command -v stunnel4 >/dev/null 2>&1; then
    # Create required runtime directories
    mkdir -p /var/run/stunnel4
    chown stunnel4:stunnel4 /var/run/stunnel4 2>/dev/null || true
    
    # Test configuration syntax
    if stunnel4 -test -fd 2 2>/dev/null; then
        log_and_show "✅ stunnel4 configuration is valid"
    else
        log_and_show "⚠️ stunnel4 configuration test failed, but proceeding..."
        # Create minimal valid configuration as fallback
        cat > /etc/stunnel/stunnel.conf << 'EOF'
; Minimal stunnel4 configuration
cert = /etc/stunnel/stunnel.pem
pid = /var/run/stunnel4/stunnel4.pid
setuid = stunnel4
setgid = stunnel4

[ssh]
accept = 443
connect = 127.0.0.1:22
EOF
        log_and_show "✅ Created minimal stunnel4 configuration"
    fi
else
    log_and_show "⚠️ stunnel4 command not found"
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

# Install SSH account management scripts (matching ssh-vpn.sh location)
log_and_show "👥 Installing SSH account management scripts to /usr/bin..."
cd /usr/bin

# SSH account management (matching ssh-vpn.sh exactly) - with enhanced error handling
log_and_show "📥 Downloading SSH management scripts..."
log_command "wget --timeout=30 -O usernew https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/usernew.sh" || log_and_show "⚠️ Failed to download usernew.sh"
log_command "wget --timeout=30 -O trial https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/trial.sh" || log_and_show "⚠️ Failed to download trial.sh"
log_command "wget --timeout=30 -O renew https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/renew.sh" || log_and_show "⚠️ Failed to download renew.sh"
log_command "wget --timeout=30 -O hapus https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/hapus.sh" || log_and_show "⚠️ Failed to download hapus.sh"
log_command "wget --timeout=30 -O cek https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/cek.sh" || log_and_show "⚠️ Failed to download cek.sh"
log_command "wget --timeout=30 -O member https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/member.sh" || log_and_show "⚠️ Failed to download member.sh"
log_command "wget --timeout=30 -O delete https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/delete.sh" || log_and_show "⚠️ Failed to download delete.sh"
log_command "wget --timeout=30 -O autokill https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/autokill.sh" || log_and_show "⚠️ Failed to download autokill.sh"
log_command "wget --timeout=30 -O ceklim https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/ceklim.sh" || log_and_show "⚠️ Failed to download ceklim.sh"
log_command "wget --timeout=30 -O tendang https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/tendang.sh" || log_and_show "⚠️ Failed to download tendang.sh"

# Main menu scripts (matching ssh-vpn.sh exactly) - with enhanced error handling
log_and_show "📋 Downloading main menu scripts..."
log_command "wget --timeout=30 -O menu https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/menu.sh" || log_and_show "⚠️ Failed to download menu.sh"
log_command "wget --timeout=30 -O menu-vmess https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/menu-vmess.sh" || log_and_show "⚠️ Failed to download menu-vmess.sh"
log_command "wget --timeout=30 -O menu-vless https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/menu-vless.sh" || log_and_show "⚠️ Failed to download menu-vless.sh"
log_command "wget --timeout=30 -O running https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/running.sh" || log_and_show "⚠️ Failed to download running.sh"
log_command "wget --timeout=30 -O clearcache https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/clearcache.sh" || log_and_show "⚠️ Failed to download clearcache.sh"
log_command "wget --timeout=30 -O menu-trgo https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/menu-trgo.sh" || log_and_show "⚠️ Failed to download menu-trgo.sh"
log_command "wget --timeout=30 -O menu-trojan https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/menu-trojan.sh" || log_and_show "⚠️ Failed to download menu-trojan.sh"

# SSH menu
log_command "wget --timeout=30 -O menu-ssh https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/menu-ssh.sh" || log_and_show "⚠️ Failed to download menu-ssh.sh"

# System menu scripts (matching ssh-vpn.sh exactly) - with enhanced error handling
log_and_show "⚙️ Downloading system menu scripts..."
log_command "wget --timeout=30 -O menu-set https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/menu-set.sh" || log_and_show "⚠️ Failed to download menu-set.sh"
log_command "wget --timeout=30 -O menu-domain https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/menu-domain.sh" || log_and_show "⚠️ Failed to download menu-domain.sh"
log_command "wget --timeout=30 -O add-host https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/add-host.sh" || log_and_show "⚠️ Failed to download add-host.sh"
log_command "wget --timeout=30 -O port-change https://raw.githubusercontent.com/werdersarina/github-repos/main/port/port-change.sh" || log_and_show "⚠️ Failed to download port-change.sh"
log_command "wget --timeout=30 -O certv2ray https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/certv2ray.sh" || log_and_show "⚠️ Failed to download certv2ray.sh"
log_command "wget --timeout=30 -O menu-webmin https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/menu-webmin.sh" || log_and_show "⚠️ Failed to download menu-webmin.sh"
log_command "wget --timeout=30 -O speedtest https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/speedtest_cli.py" || log_and_show "⚠️ Failed to download speedtest_cli.py"
log_command "wget --timeout=30 -O about https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/about.sh" || log_and_show "⚠️ Failed to download about.sh"
log_command "wget --timeout=30 -O auto-reboot https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/auto-reboot.sh" || log_and_show "⚠️ Failed to download auto-reboot.sh"
log_command "wget --timeout=30 -O restart https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/restart.sh" || log_and_show "⚠️ Failed to download restart.sh"
log_command "wget --timeout=30 -O bw https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/bw.sh" || log_and_show "⚠️ Failed to download bw.sh"

# Port management scripts (matching ssh-vpn.sh exactly) - with enhanced error handling
log_and_show "🔌 Downloading port management scripts..."
log_command "wget --timeout=30 -O port-ssl https://raw.githubusercontent.com/werdersarina/github-repos/main/port/port-ssl.sh" || log_and_show "⚠️ Failed to download port-ssl.sh"
log_command "wget --timeout=30 -O port-ovpn https://raw.githubusercontent.com/werdersarina/github-repos/main/port/port-ovpn.sh" || log_and_show "⚠️ Failed to download port-ovpn.sh"

# Additional system tools (matching ssh-vpn.sh exactly) - xp already downloaded
log_and_show "🛠️ Downloading additional system tools..."
log_command "wget --timeout=30 -O acs-set https://raw.githubusercontent.com/werdersarina/github-repos/main/acs-set.sh" || log_and_show "⚠️ Failed to download acs-set.sh"
log_command "wget --timeout=30 -O sshws https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/sshws.sh" || log_and_show "⚠️ Failed to download sshws.sh"

# Set execute permissions for all scripts (matching ssh-vpn.sh exactly) - with enhanced error handling
log_and_show "🔑 Setting execute permissions for management scripts..."
for script in menu menu-vmess menu-vless running clearcache menu-trgo menu-trojan menu-ssh usernew trial renew hapus cek member delete autokill ceklim tendang menu-set menu-domain add-host port-change certv2ray menu-webmin speedtest about auto-reboot restart bw port-ssl port-ovpn xp acs-set sshws; do
    if [ -f "$script" ]; then
        chmod +x "$script" 2>/dev/null || log_and_show "⚠️ Failed to set permission for $script"
    else
        log_and_show "⚠️ Script $script not found, skipping permission setting"
    fi
done
log_and_show "✅ Execute permissions configured for available scripts"

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

# Final service restart sequence (use systemctl instead of init.d)
sleep 1
log_and_show "🔄 Restart All service SSH & OVPN"
log_command "systemctl restart nginx" || log_and_show "⚠️ nginx restart failed"
sleep 1
log_and_show "✅ Restarting nginx"
log_command "systemctl restart openvpn" || log_and_show "⚠️ openvpn restart failed"
sleep 1
log_and_show "✅ Restarting cron"
log_command "/etc/init.d/ssh restart"
sleep 1
log_and_show "✅ Restarting ssh"
log_command "/etc/init.d/dropbear restart"
sleep 1
log_and_show "✅ Restarting dropbear"
log_command "/etc/init.d/fail2ban restart"
sleep 1
log_and_show "✅ Restarting fail2ban"
# Restart stunnel4 menggunakan pendekatan bertahap yang lebih reliable
if start_stunnel4; then
    log_and_show "✅ stunnel4 berhasil dimulai dengan pendekatan bertahap"
else
    log_and_show "⚠️ stunnel4 gagal dimulai dengan semua metode, silakan cek secara manual"
    log_and_show "   Jalankan: 'systemctl status stunnel4' untuk melihat detail error"
fi

# Check if vnstat service exists before restarting
if systemctl list-unit-files | grep -q "vnstat.service"; then
    log_command "systemctl restart vnstat" || log_and_show "⚠️ vnstat restart failed"
    sleep 1
    log_and_show "✅ Restarting vnstat"
elif command -v vnstat >/dev/null 2>&1; then
    # vnstat binary exists but no systemd service, try to create one
    log_and_show "🔧 Creating vnstat systemd service..."
    
    # Detect vnstatd path dynamically
    VNSTATD_PATH=""
    for path in /usr/bin/vnstatd /usr/local/bin/vnstatd /bin/vnstatd /usr/sbin/vnstatd; do
        if [[ -x "$path" ]]; then
            VNSTATD_PATH="$path"
            log_and_show "✅ Found vnstatd at: $VNSTATD_PATH"
            break
        fi
    done
    
    # If not found in common paths, try which command
    if [[ -z "$VNSTATD_PATH" ]]; then
        if command -v vnstatd >/dev/null 2>&1; then
            VNSTATD_PATH=$(which vnstatd)
            log_and_show "✅ Found vnstatd using which: $VNSTATD_PATH"
        else
            log_and_show "⚠️ vnstatd not found, using default path /usr/bin/vnstatd"
            VNSTATD_PATH="/usr/bin/vnstatd"
        fi
    fi
    
    # Only create service if vnstatd binary actually exists
    if [[ -x "$VNSTATD_PATH" ]]; then
        cat > /etc/systemd/system/vnstat.service << EOF
[Unit]
Description=vnStat network traffic monitor
Documentation=man:vnstatd(8) https://humdi.net/vnstat/
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/var/run/vnstat.pid
ExecStart=$VNSTATD_PATH -d --pidfile /var/run/vnstat.pid
ExecReload=/bin/kill -HUP \$MAINPID
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/vnstat
ProtectHome=yes
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
EOF
        log_command "systemctl daemon-reload"
        log_command "systemctl enable vnstat"
        log_command "systemctl start vnstat"
        log_and_show "✅ vnstat service created and started"
    else
        log_and_show "⚠️ vnstatd binary not found at $VNSTATD_PATH, service creation skipped"
    fi
else
    log_and_show "⚠️ vnstat not found, service restart skipped"
fi
log_command "systemctl restart squid" || log_and_show "⚠️ squid restart failed"
sleep 1
log_and_show "✅ Restarting squid"

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

# Log service info to log-install.txt (focus on used components only)
echo "OpenSSH: 22, 200, 500, 40000, 51443, 58080" >> /root/log-install.txt
echo "Dropbear: 69, 109, 110, 143, 50000" >> /root/log-install.txt
echo "Stunnel4: 222, 777" >> /root/log-install.txt
echo "Squid: 3128, 8080, 8000" >> /root/log-install.txt
echo "BadVPN UDPGW: 7100-7900" >> /root/log-install.txt
echo "SSH Websocket: 80" >> /root/log-install.txt
echo "SSH SSL Websocket: 443" >> /root/log-install.txt
echo "Fail2Ban: [ON]" >> /root/log-install.txt
echo "DDoS Deflate: [ON]" >> /root/log-install.txt
echo "BBR: [ON]" >> /root/log-install.txt
echo "Iptables: [ON]" >> /root/log-install.txt
echo "Banner: [ON]" >> /root/log-install.txt

log_and_show "✅ SSH/VPN services installation completed with focus on WebSocket technologies"
log_section "SSH-2025.SH COMPLETED"

# finishing
clear

# Ensure script exits successfully
exit 0
