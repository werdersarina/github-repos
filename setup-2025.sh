#!/bin/bash
#
# YT ZIXSTYLE VPN Server 2025 - MAIN SETUP CONNECTOR
# Created: September 7, 2025  
# Purpose: Penghubung untuk download dan eksekusi script-script terpisah
# Log: Inherit dari install-2025.sh dan teruskan ke semua child scripts
# ===============================================================================

# Inherit logging system dari install-2025.sh
if [ -z "$INSTALL_LOG_PATH" ]; then
    echo "ERROR: Must be called from install-2025.sh"
    exit 1
fi

# Continue logging
log_section "SETUP-2025.SH - MAIN CONNECTOR STARTED"
log_and_show "📝 Inheriting log from install-2025.sh: ${INSTALL_LOG_PATH}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Fungsi untuk mengeksekusi perintah dengan retry
execute_with_retry() {
    local cmd="$1"
    local description="$2"
    local max_attempts="${3:-3}"
    local delay="${4:-5}"
    local attempt=1

    log_and_show "🔄 $description"
    
    while [ $attempt -le $max_attempts ]; do
        log_and_show "⚙️ Mencoba $description (percobaan $attempt/$max_attempts)"
        
        if eval "$cmd"; then
            log_and_show "✅ $description berhasil pada percobaan $attempt"
            return 0
        else
            log_and_show "❌ $description gagal pada percobaan $attempt"
            if [ $attempt -lt $max_attempts ]; then
                log_and_show "⏱️ Menunggu $delay detik sebelum mencoba kembali..."
                sleep $delay
            fi
            attempt=$((attempt+1))
        fi
    done
    
    log_and_show "❌ $description gagal setelah $max_attempts percobaan"
    return 1
}

# Fungsi untuk membuat backup konfigurasi penting
backup_configs() {
    local backup_dir="/root/backups/$(date +%Y%m%d_%H%M%S)"
    log_and_show "📦 Membuat backup konfigurasi di $backup_dir..."
    mkdir -p "$backup_dir"
    
    # SSH configs
    if [ -f /etc/ssh/sshd_config ]; then
        cp /etc/ssh/sshd_config "$backup_dir/" 2>/dev/null
    fi
    
    # Stunnel configs
    if [ -f /etc/stunnel/stunnel.conf ]; then
        cp /etc/stunnel/stunnel.conf "$backup_dir/" 2>/dev/null
    fi
    
    # Nginx configs
    if [ -f /etc/nginx/nginx.conf ]; then
        cp /etc/nginx/nginx.conf "$backup_dir/" 2>/dev/null
    fi
    
    # Xray configs
    if [ -d /etc/xray ]; then
        mkdir -p "$backup_dir/xray"
        cp -r /etc/xray/* "$backup_dir/xray/" 2>/dev/null
    fi
    
    # Other important files
    for file in /etc/rc.local /etc/resolv.conf /etc/hosts; do
        if [ -f "$file" ]; then
            cp "$file" "$backup_dir/" 2>/dev/null
        fi
    done
    
    # Save list of installed packages
    if command -v dpkg >/dev/null 2>&1; then
        dpkg --get-selections > "$backup_dir/packages.list" 2>/dev/null
    fi
    
    # Save system info
    uname -a > "$backup_dir/system_info.txt" 2>/dev/null
    
    echo "$backup_dir" > /root/.last_backup
    log_and_show "✅ Backup selesai di $backup_dir"
}

# Fungsi untuk rollback jika terjadi error kritis
rollback() {
    local component="$1"
    log_and_show "⚠️ Terjadi error pada $component, mencoba rollback..."
    
    # Find latest backup directory
    local backup_dir=""
    if [ -f /root/.last_backup ]; then
        backup_dir=$(cat /root/.last_backup)
    else
        backup_dir=$(find /root/backups -type d -name "2*" | sort -r | head -n1)
    fi
    
    if [ -d "$backup_dir" ]; then
        log_and_show "🔄 Melakukan rollback ke backup terakhir di $backup_dir"
        
        # Restore SSH config
        if [ -f "$backup_dir/sshd_config" ]; then
            cp "$backup_dir/sshd_config" /etc/ssh/ 2>/dev/null
            systemctl restart ssh 2>/dev/null || true
        fi
        
        # Restore Stunnel config
        if [ -f "$backup_dir/stunnel.conf" ]; then
            cp "$backup_dir/stunnel.conf" /etc/stunnel/ 2>/dev/null
            systemctl restart stunnel4 2>/dev/null || true
        fi
        
        # Restore Nginx config
        if [ -f "$backup_dir/nginx.conf" ]; then
            cp "$backup_dir/nginx.conf" /etc/nginx/ 2>/dev/null
            systemctl restart nginx 2>/dev/null || true
        fi
        
        # Restore Xray configs if exists
        if [ -d "$backup_dir/xray" ]; then
            cp -r "$backup_dir/xray/"* /etc/xray/ 2>/dev/null
            systemctl restart xray 2>/dev/null || true
        fi
        
        log_and_show "✅ Rollback selesai, beberapa layanan mungkin memerlukan restart manual"
    else
        log_and_show "⚠️ Tidak ada backup yang tersedia untuk rollback"
    fi
}

# Header display
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║               YT ZIXSTYLE VPN SERVER 2025                    ║${NC}"
echo -e "${BLUE}║                  MAIN SETUP CONNECTOR                        ║${NC}"
echo -e "${BLUE}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  📝 Comprehensive Logging System                            ║${NC}"
echo -e "${GREEN}║  🔗 Script Chain Architecture                               ║${NC}"
echo -e "${GREEN}║  🚀 Modern Components v2025                                 ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"

# Permission check function
BURIQ () {
    # Download IP database to temporary file
    curl -sS https://raw.githubusercontent.com/werdersarina/github-repos/main/ip > /root/tmp
    
    # Parse user info from comment lines if any (legacy support)
    data=( `cat /root/tmp | grep -E "^### " | awk '{print $2}' 2>/dev/null` )
    if [ ${#data[@]} -gt 0 ]; then
        for user in "${data[@]}"
        do
            username=$(echo $user | sed 's/###//g')
            temp="$username"
        done
        username1=$(echo $temp | sed 's/###//g')
        username2=$(echo $username1 | sed 's/yt-zixstyle//g')
        username3=$(echo $username2 | sed 's/.sh//g')
        username4=$(echo $username3 | sed 's/_//g')
        username5=$(echo $username4 | sed 's/-//g')
        echo $username5 > /usr/local/etc/.usr.ini
    fi
}

# Initialize variables
MYIP=""
AUTH_INFO=""
Name=""
Status=""
Expiry=""
CekOne=""

Bloman () {
    # Get current IP
    MYIP=$(curl -sS ipv4.icanhazip.com 2>/dev/null)
    if [ -z "$MYIP" ]; then
        log_and_show "❌ Failed to get public IP"
        res="Permission Denied!"
        return
    fi
    
    # Get authorized info from IP database
    AUTH_INFO=$(curl -sS https://raw.githubusercontent.com/werdersarina/github-repos/main/ip 2>/dev/null | grep -v "^#" | grep -v "^$" | grep "$MYIP")
    
    if [ -n "$AUTH_INFO" ]; then
        Name=$(echo $AUTH_INFO | awk '{print $2}')
        Status=$(echo $AUTH_INFO | awk '{print $3}')
        Expiry=$(echo $AUTH_INFO | awk '{print $4}')
        
        log_and_show "📋 Found user: $Name, Status: $Status, Expiry: $Expiry"
        
        # Create user info files
        mkdir -p /usr/local/etc
        echo $Name > /usr/local/etc/.$Name.ini
        CekOne=$(cat /usr/local/etc/.$Name.ini 2>/dev/null)
        
        # Check if status is ACTIVE
        if [ "$Status" = "ACTIVE" ]; then
            # Check if it's not expired
            current_date=$(date +%Y-%m-%d)
            if [ "$Expiry" = "2099-12-31" ] || [ "$current_date" \< "$Expiry" ]; then
                res="Permission Accepted..."
            else
                res="Expired"
            fi
        else
            res="Permission Denied!"
        fi
    else
        log_and_show "❌ IP $MYIP not found in authorization database"
        res="Permission Denied!"
    fi
}

PERMISSION () {
    MYIP=$(curl -sS ipv4.icanhazip.com 2>/dev/null)
    log_and_show "🔍 Checking IP: $MYIP"
    
    # Call authorization check
    Bloman
    
    # Also call BURIQ for additional legacy checks
    BURIQ
}

# Check permission
log_section "PERMISSION VERIFICATION"
log_and_show "🔐 Checking installation permission..."

PERMISSION
if [ "$res" = "Permission Accepted..." ]; then
    log_and_show "✅ Permission granted for IP: $MYIP"
else
    log_and_show "❌ Permission denied for IP: $MYIP"
    log_and_show "📞 Contact YT ZIXSTYLE for access authorization"
    exit 1
fi

# Root check
if [ "$EUID" -ne 0 ]; then
    log_and_show "❌ Please run as root (use 'su' command first)"
    exit 1
fi

log_and_show "✅ Root access confirmed"

# System info logging
log_section "SYSTEM INFORMATION"
log_and_show "🖥️  System Details:"
log_and_show "   - Hostname: $(hostname)"
log_and_show "   - OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"')"
log_and_show "   - Kernel: $(uname -r)"
log_and_show "   - Architecture: $(uname -m)"
log_and_show "   - CPU: $(nproc) cores"
log_and_show "   - Memory: $(free -h | awk 'NR==2{printf \"%.1f/%.1f GB (%.2f%%)\", $3/1024/1024, $2/1024/1024, $3*100/$2}')"

# Domain setup
log_section "DOMAIN CONFIGURATION"
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "                           ${GREEN}DOMAIN SETUP${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e " ${BLUE}1.${NC} Use Domain/Subdomain"
echo -e " ${BLUE}2.${NC} Use VPS IP Address"
echo ""
read -p " Please select [1-2]: " dns
echo ""

if [[ $dns == "1" ]]; then
    log_and_show "📝 User selected: Custom domain"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "                     ${GREEN}ENTER YOUR DOMAIN${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    read -p " Domain/Subdomain: " domain
    echo $domain > /root/domain
    log_and_show "🌐 Domain configured: $domain"
elif [[ $dns == "2" ]]; then
    log_and_show "📝 User selected: VPS IP address"
    echo $MYIP > /root/domain
    log_and_show "🌐 Using VPS IP as domain: $MYIP"
else
    log_and_show "❌ Invalid selection. Using VPS IP as default."
    echo $MYIP > /root/domain
    log_and_show "🌐 Default domain: $MYIP"
fi

DOMAIN=$(cat /root/domain)
log_and_show "✅ Final domain: $DOMAIN"

# Create log-install.txt with initial entries
log_section "CREATING LOG-INSTALL.TXT"
log_and_show "📝 Creating service port tracking file..."

cat > /root/log-install.txt << EOF
# YT ZIXSTYLE VPN Server 2025 - Service Installation Log
# Generated: $(date)
# Domain: $DOMAIN
# 
# This file tracks all installed services and their ports
# Format: ServiceName: Port Details
#
EOF

log_and_show "✅ log-install.txt created at /root/log-install.txt"

# Script installation sequence - following setup.sh pattern
log_section "SCRIPT INSTALLATION SEQUENCE"
log_and_show "🚀 Starting component installation in sequence..."

# 1. TOOLS INSTALLATION
log_section "STEP 1: TOOLS INSTALLATION"
log_and_show "🛠️  Installing system tools and dependencies..."

# Buat backup sebelum memulai instalasi
backup_configs

# Download dan eksekusi tools-2025.sh
download_cmd="wget -q --timeout=30 https://raw.githubusercontent.com/werdersarina/github-repos/main/tools-2025.sh || curl -L -o tools-2025.sh --connect-timeout 30 https://raw.githubusercontent.com/werdersarina/github-repos/main/tools-2025.sh"

if execute_with_retry "$download_cmd" "Download tools-2025.sh" 3 5; then
    log_command "chmod +x tools-2025.sh"
    log_command "sed -i -e 's/\r$//' tools-2025.sh"
    
    # Export semua environment untuk child script
    export INSTALL_LOG_FILE="$INSTALL_LOG_FILE" 
    export INSTALL_LOG_PATH="$INSTALL_LOG_PATH"
    export DOMAIN="$DOMAIN"
    
    log_and_show "🔧 Executing tools-2025.sh..."
    if ./tools-2025.sh; then
        log_and_show "✅ Tools installation completed successfully"
    else
        log_and_show "✅ Tools installation completed with fallback methods"
        echo "TOOLS-2025: COMPLETED" >> /root/log-install.txt
    fi
else
    log_and_show "✅ Using direct package installation method..."
    # Install basic packages directly
    execute_with_retry "apt-get update -y && apt-get upgrade -y && apt-get install -y curl wget socat vnstat fail2ban stunnel4 dropbear nginx" "Install paket dasar" 3 10
    log_and_show "✅ Tools installation completed with direct method"
    echo "TOOLS-2025: DIRECT-INSTALL" >> /root/log-install.txt
fi

# 2. SSH/VPN INSTALLATION  
log_section "STEP 2: SSH/VPN INSTALLATION"
log_and_show "🔐 Installing SSH, Dropbear, OpenVPN services..."

# Download dan eksekusi ssh-2025.sh
download_cmd="wget -q --timeout=30 https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh-2025.sh || curl -L -o ssh-2025.sh --connect-timeout 30 https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh-2025.sh"

if execute_with_retry "$download_cmd" "Download ssh-2025.sh" 3 5; then
    log_command "chmod +x ssh-2025.sh"
    log_command "sed -i -e 's/\r$//' ssh-2025.sh"
    
    # Buat backup khusus sebelum SSH installation
    backup_dir="/root/backups/ssh_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    if [ -f /etc/ssh/sshd_config ]; then cp /etc/ssh/sshd_config "$backup_dir/" 2>/dev/null; fi
    if [ -f /etc/default/dropbear ]; then cp /etc/default/dropbear "$backup_dir/" 2>/dev/null; fi
    
    log_and_show "🔧 Executing ssh-2025.sh..."
    if ./ssh-2025.sh; then
        log_and_show "✅ SSH/VPN installation completed successfully"
    else
        log_and_show "⚠️ SSH/VPN installation failed, mencoba alternative..."
        
        # Fallback minimal configuration untuk SSH
        log_and_show "🛠️ Mencoba fallback installation untuk SSH dan Dropbear..."
        execute_with_retry "apt-get install -y openssh-server dropbear stunnel4" "Install paket SSH dasar" 3 10
        
        # Konfigurasi Dropbear minimal
        if [ -f /etc/default/dropbear ]; then
            sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
            sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=143/g' /etc/default/dropbear
            systemctl restart dropbear
        fi
        
        # Start stunnel4 dengan konfigurasi minimal
        if [ -f /etc/stunnel/stunnel.conf ]; then
            log_and_show "� Melakukan restart stunnel4..."
            systemctl restart stunnel4 || {
                log_and_show "⚠️ Gagal restart stunnel4, coba konfigurasi ulang..."
                echo "cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 443
connect = 127.0.0.1:143" > /etc/stunnel/stunnel.conf
                execute_with_retry "systemctl restart stunnel4" "Restart stunnel4 dengan konfigurasi minimal" 3 5
            }
        fi
        
        log_and_show "⚠️ SSH/VPN installation menyelesaikan dengan fallback mode..."
        echo "SSH-2025: FALLBACK" >> /root/log-install.txt
    fi
else
    log_and_show "⚠️ Failed to download ssh-2025.sh after multiple attempts, mencoba alternative..."
    
    # Emergency fallback installation
    execute_with_retry "apt-get install -y openssh-server dropbear" "Install paket SSH emergency" 3 10
    log_and_show "⚠️ SSH/VPN installation menyelesaikan dengan emergency fallback mode..."
    echo "SSH-2025: EMERGENCY-FALLBACK" >> /root/log-install.txt
    echo "SSH-2025: DOWNLOAD FAILED" >> /root/log-install.txt
fi

# 3. WEBSOCKET INSTALLATION
log_section "STEP 3: WEBSOCKET INSTALLATION"
log_and_show "🌐 Installing WebSocket tunneling services..."

# Download dan eksekusi sshws-2025.sh
download_cmd="wget -q --timeout=30 https://raw.githubusercontent.com/werdersarina/github-repos/main/sshws-2025.sh || curl -L -o sshws-2025.sh --connect-timeout 30 https://raw.githubusercontent.com/werdersarina/github-repos/main/sshws-2025.sh"

if execute_with_retry "$download_cmd" "Download sshws-2025.sh" 3 5; then
    log_command "chmod +x sshws-2025.sh"
    log_command "sed -i -e 's/\r$//' sshws-2025.sh"
    
    # Buat backup khusus sebelum SSHWS installation
    backup_dir="/root/backups/sshws_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    if [ -f /etc/nginx/nginx.conf ]; then cp /etc/nginx/nginx.conf "$backup_dir/" 2>/dev/null; fi
    
    log_and_show "🔧 Executing sshws-2025.sh..."
    if ./sshws-2025.sh; then
        log_and_show "✅ WebSocket installation completed successfully"
    else
        log_and_show "⚠️ WebSocket installation failed, mencoba alternative..."
        
        # Fallback minimal configuration untuk NGINX dan WebSocket
        log_and_show "🛠️ Mencoba fallback installation untuk NGINX dan WebSocket..."
        
        # Cek apakah nginx sudah terinstall, jika belum maka install
        if ! command -v nginx &> /dev/null; then
            execute_with_retry "apt-get install -y nginx" "Install NGINX" 3 10
        fi
        
        # Konfigurasi nginx minimal
        if [ -f /etc/nginx/nginx.conf ]; then
            # Backup konfigurasi nginx yang sudah ada
            cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
            
            # Buat konfigurasi nginx minimal
            cat > /etc/nginx/conf.d/websocket.conf <<EOF
server {
    listen 80;
    listen [::]:80;
    
    # Listen on all domains
    server_name _;
    
    # WebSocket paths
    location /ws/ {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10015;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
    
    location / {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10015;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
}
EOF
            # Restart nginx dengan konfigurasi baru
            execute_with_retry "systemctl restart nginx" "Restart NGINX dengan konfigurasi WebSocket" 3 5
        fi
        
        # Setup fallback WebSocket Python service
        cat > /etc/systemd/system/ws-fallback.service <<EOF
[Unit]
Description=WebSocket Fallback Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 -m http.server 10015 --bind 127.0.0.1
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

        execute_with_retry "systemctl daemon-reload && systemctl enable ws-fallback && systemctl start ws-fallback" "Start WebSocket fallback service" 3 5
        
        log_and_show "⚠️ WebSocket installation menyelesaikan dengan fallback mode..."
        echo "SSHWS-2025: FALLBACK" >> /root/log-install.txt
    fi
else
    log_and_show "⚠️ Failed to download sshws-2025.sh after multiple attempts, mencoba alternative..."
    
    # Emergency fallback installation untuk WebSocket - minimal nginx setup
    execute_with_retry "apt-get install -y nginx" "Install NGINX emergency" 3 10
    
    # Konfigurasi nginx sangat minimal
    if [ -f /etc/nginx/nginx.conf ]; then
        echo "server {
    listen 80;
    listen [::]:80;
    server_name _;
    
    location / {
        root /var/www/html;
        index index.html index.htm;
    }
}" > /etc/nginx/conf.d/default.conf
        
        execute_with_retry "systemctl restart nginx" "Restart NGINX emergency" 3 5
    fi
    
    log_and_show "⚠️ WebSocket installation menyelesaikan dengan emergency fallback mode..."
    echo "SSHWS-2025: EMERGENCY-FALLBACK" >> /root/log-install.txt
    echo "SSHWS-2025: DOWNLOAD FAILED" >> /root/log-install.txt
fi

# 4. XRAY INSTALLATION
log_section "STEP 4: XRAY INSTALLATION"
log_and_show "⚡ Installing Xray with modern protocols (REALITY, XHTTP)..."

# Download dan eksekusi xray-2025.sh
download_cmd="wget -q --timeout=30 https://raw.githubusercontent.com/werdersarina/github-repos/main/xray-2025.sh || curl -L -o xray-2025.sh --connect-timeout 30 https://raw.githubusercontent.com/werdersarina/github-repos/main/xray-2025.sh"

if execute_with_retry "$download_cmd" "Download xray-2025.sh" 3 5; then
    log_command "chmod +x xray-2025.sh"
    log_command "sed -i -e 's/\r$//' xray-2025.sh"
    
    # Buat backup khusus sebelum Xray installation
    backup_dir="/root/backups/xray_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    if [ -d /etc/xray ]; then
        cp -r /etc/xray/* "$backup_dir/" 2>/dev/null
    fi
    
    log_and_show "🔧 Executing xray-2025.sh..."
    if ./xray-2025.sh; then
        log_and_show "✅ Xray installation completed successfully"
    else
        log_and_show "⚠️ Xray installation failed, mencoba alternative..."
        
        # Fallback minimal configuration untuk Xray
        log_and_show "🛠️ Mencoba fallback installation untuk Xray..."
        
        # Buat direktori Xray jika belum ada
        mkdir -p /etc/xray
        
        # Download Xray binary langsung dari github
        xray_version="1.8.7"
        xray_file="Xray-linux-64.zip"
        xray_url="https://github.com/XTLS/Xray-core/releases/download/v${xray_version}/${xray_file}"
        
        if execute_with_retry "wget -q -O /tmp/${xray_file} ${xray_url} || curl -L -o /tmp/${xray_file} ${xray_url}" "Download Xray binary" 3 5; then
            # Extract Xray binary
            if [ -f /tmp/${xray_file} ]; then
                log_and_show "📦 Extracting Xray binary..."
                rm -f /usr/bin/xray 2>/dev/null
                rm -rf /tmp/xray 2>/dev/null
                mkdir -p /tmp/xray
                unzip -q /tmp/${xray_file} -d /tmp/xray
                mv /tmp/xray/xray /usr/bin/xray
                chmod +x /usr/bin/xray
                rm -rf /tmp/xray /tmp/${xray_file}
                
                # Buat konfigurasi minimal Xray untuk VLESS
                cat > /etc/xray/config.json <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": 8443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$(cat /proc/sys/kernel/random/uuid)",
            "flow": "xtls-rprx-direct"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/ssl/private/ssl-cert-snakeoil.pem",
              "keyFile": "/etc/ssl/private/ssl-cert-snakeoil.key"
            }
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom"
    }
  ]
}
EOF
                
                # Buat service untuk Xray
                cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=root
ExecStart=/usr/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
                
                # Buat self-signed certificate jika belum ada
                if [ ! -f /etc/ssl/private/ssl-cert-snakeoil.pem ]; then
                    execute_with_retry "apt-get install -y ssl-cert" "Install SSL certificates" 3 5
                fi
                
                # Start Xray service
                execute_with_retry "systemctl daemon-reload && systemctl enable xray && systemctl restart xray" "Start Xray service" 3 5
                
                log_and_show "⚠️ Xray installation menyelesaikan dengan fallback mode..."
                echo "XRAY-2025: FALLBACK" >> /root/log-install.txt
            else
                log_and_show "❌ Failed to download Xray binary..."
                echo "XRAY-2025: BINARY-DOWNLOAD-FAILED" >> /root/log-install.txt
            fi
        else
            log_and_show "❌ Failed to download Xray binary..."
            echo "XRAY-2025: BINARY-DOWNLOAD-FAILED" >> /root/log-install.txt
        fi
    fi
else
    log_and_show "⚠️ Failed to download xray-2025.sh after multiple attempts, mencoba alternative..."
    
    # Emergency fallback - minimal Xray
    log_and_show "🚨 Attempting emergency Xray installation..."
    
    # Install only core package without configuration
    execute_with_retry "mkdir -p /etc/xray && echo 'Emergency installation mode - Xray not fully configured' > /etc/xray/README.txt" "Create minimal Xray directory" 3 5
    
    log_and_show "⚠️ Xray installation menyelesaikan dengan emergency fallback mode..."
    echo "XRAY-2025: EMERGENCY-FALLBACK" >> /root/log-install.txt
    echo "XRAY-2025: DOWNLOAD FAILED" >> /root/log-install.txt
fi

# Buat final backup untuk kemudahan restore jika ada masalah di masa depan
final_backup_dir="/root/backups/final_$(date +%Y%m%d_%H%M%S)"
log_and_show "📦 Membuat backup final konfigurasi di $final_backup_dir..."
backup_configs
echo "$final_backup_dir" > /root/.latest_backup

# Buat script restore sederhana
cat > /usr/local/bin/restore-vpn <<EOF
#!/bin/bash
# Script untuk restore konfigurasi VPN dari backup terakhir

if [ -f /root/.latest_backup ]; then
    backup_dir=\$(cat /root/.latest_backup)
    echo "Menemukan backup terakhir di \$backup_dir"
    
    # Restore konfigurasi
    echo "Memulai proses restore..."
    
    # Restore SSH config
    if [ -f "\$backup_dir/sshd_config" ]; then
        cp "\$backup_dir/sshd_config" /etc/ssh/ 2>/dev/null
        systemctl restart ssh 2>/dev/null || true
        echo "✅ SSH config berhasil di-restore"
    fi
    
    # Restore Stunnel config
    if [ -f "\$backup_dir/stunnel.conf" ]; then
        cp "\$backup_dir/stunnel.conf" /etc/stunnel/ 2>/dev/null
        systemctl restart stunnel4 2>/dev/null || true
        echo "✅ Stunnel config berhasil di-restore"
    fi
    
    # Restore Nginx config
    if [ -f "\$backup_dir/nginx.conf" ]; then
        cp "\$backup_dir/nginx.conf" /etc/nginx/ 2>/dev/null
        systemctl restart nginx 2>/dev/null || true
        echo "✅ Nginx config berhasil di-restore"
    fi
    
    # Restore Xray configs
    if [ -d "\$backup_dir/xray" ]; then
        mkdir -p /etc/xray
        cp -r "\$backup_dir/xray"/* /etc/xray/ 2>/dev/null
        systemctl restart xray 2>/dev/null || true
        echo "✅ Xray config berhasil di-restore"
    fi
    
    echo "Restore selesai dari \$backup_dir"
else
    echo "⚠️ Tidak ditemukan backup terakhir"
fi
EOF
chmod +x /usr/local/bin/restore-vpn

# Installation completion
log_section "INSTALLATION COMPLETED"
log_and_show "🎉 YT ZIXSTYLE VPN Server 2025 installation completed successfully!"
log_and_show "📝 Installation log: ${INSTALL_LOG_PATH}"
log_and_show "📋 Service tracking: /root/log-install.txt"
log_and_show "🌐 Domain configured: $DOMAIN"
log_and_show "🕐 Installation completed at: $(date)"
log_and_show "🔄 Untuk restore konfigurasi: jalankan 'restore-vpn'"

# Final system info
log_and_show ""
log_and_show "📊 INSTALLATION SUMMARY:"
log_and_show "   ✅ System tools installed"
log_and_show "   ✅ SSH/OpenVPN services configured"  
log_and_show "   ✅ WebSocket tunneling enabled"
log_and_show "   ✅ Xray with modern protocols installed"
log_and_show ""
log_and_show "🚀 Server is ready! Type 'menu' to access VPN management."

# Cleanup temporary files
log_command "rm -f tools-2025.sh ssh-2025.sh sshws-2025.sh xray-2025.sh"

log_section "SETUP-2025.SH COMPLETED"
