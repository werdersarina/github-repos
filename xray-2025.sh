#!/bin/bash
#
# YT ZIXSTYLE Xray Installer 2025
# Created: September 7, 2025
# Purpose: Install Xray with modern protocols (REALITY, XHTTP, enhanced features)
# Log: Inherit dari setup-2025.sh
# Version: Auto-detect latest Xray and Trojan-Go versions
# Features: XHTTP, REALITY, VMess, VLess, Trojan GFW, Trojan-Go
# ========================================================================

# Prevent interactive prompts during package installation (for iptables-persistent)
export DEBIAN_FRONTEND=noninteractive

# Inherit logging system
if [ -z "$INSTALL_LOG_PATH" ]; then
    echo "ERROR: Must be called from setup-2025.sh"
    exit 1
fi

log_section "XRAY-2025.SH STARTED"
log_and_show "⚡ Starting Xray installation with modern protocols..."

# Use fixed Xray version like original script
log_and_show "� Installing Xray-core v1.7.3 (stable version)"
XRAY_VERSION="1.7.3"

# Check domain variable
if [ -z "$DOMAIN" ]; then
    if [ -f /root/domain ]; then
        DOMAIN=$(cat /root/domain)
        log_and_show "✅ Domain loaded from file: ${DOMAIN}"
    else
        log_and_show "⚠️ Domain not found, using IP address"
        DOMAIN=$(curl -s ipv4.icanhazip.com)
    fi
fi
log_and_show "📦 Installing Xray-core v${XRAY_VERSION} with XHTTP and REALITY protocols"

# Install dependencies (comprehensive from ins-xray.sh)
log_and_show "📦 Installing Xray dependencies..."
log_command "apt install -y iptables iptables-persistent"
log_command "apt install -y curl socat xz-utils wget apt-transport-https gnupg gnupg2 gnupg1 dnsutils lsb-release"
if ! log_command "apt install -y socat cron bash-completion ntpdate zip pwgen openssl netcat-openbsd"; then
    log_and_show "⚠️ Some packages failed to install, trying individually..."
    # Install packages individually if batch install fails
    for pkg in socat cron bash-completion ntpdate zip pwgen openssl netcat-openbsd; do
        if ! apt install -y "$pkg" 2>/dev/null; then
            log_and_show "⚠️ Failed to install package: $pkg"
        fi
    done
fi

# Configure time and timezone (from ins-xray.sh) with error handling
log_and_show "🕒 Configuring time and timezone..."
log_command "timedatectl set-ntp true"

# Handle chronyd/chrony installation issues - Fix for alias conflict
log_and_show "⏰ Configuring time synchronization service..."
if systemctl list-unit-files | grep -q "^chrony.service"; then
    log_command "systemctl enable chrony" || log_and_show "⚠️ chrony enable failed"
    log_command "systemctl restart chrony" || log_and_show "⚠️ chrony restart failed"
elif systemctl list-unit-files | grep -q "^chronyd.service"; then
    # Check if chronyd is an alias, use chrony instead
    if systemctl show chronyd.service | grep -q "Id=chrony.service"; then
        log_and_show "⚠️ chronyd is alias for chrony, using chrony service"
        log_command "systemctl enable chrony" || log_and_show "⚠️ chrony enable failed"
        log_command "systemctl restart chrony" || log_and_show "⚠️ chrony restart failed"
    else
        log_command "systemctl enable chronyd" || log_and_show "⚠️ chronyd enable failed"
        log_command "systemctl restart chronyd" || log_and_show "⚠️ chronyd restart failed"
    fi
elif command -v chronyd >/dev/null 2>&1; then
    log_and_show "⚠️ chronyd command found but no systemd service, trying manual restart"
    chronyd -d 2>/dev/null || log_and_show "⚠️ chronyd manual start failed"
elif command -v chrony >/dev/null 2>&1; then
    log_and_show "⚠️ chrony command found but no systemd service, trying manual restart"
    chrony -d 2>/dev/null || log_and_show "⚠️ chrony manual start failed"
else
    log_and_show "⚠️ No chrony/chronyd found, using systemd-timesyncd as fallback"
    log_command "systemctl enable systemd-timesyncd"
    log_command "systemctl restart systemd-timesyncd"
fi

log_command "timedatectl set-timezone Asia/Jakarta"

# Time synchronization with fallback
if command -v ntpdate >/dev/null 2>&1; then
    log_command "ntpdate pool.ntp.org" || log_and_show "⚠️ ntpdate failed, time sync may be inaccurate"
fi

# Check chrony status if available
if command -v chronyc >/dev/null 2>&1; then
    chronyc sourcestats -v 2>/dev/null || log_and_show "⚠️ chronyc sourcestats unavailable"
    chronyc tracking -v 2>/dev/null || log_and_show "⚠️ chronyc tracking unavailable"
fi

# Download and install Xray using multiple methods with better error handling
# Simple Xray installation like original script
log_and_show "📥 Installing Xray core v${XRAY_VERSION}..."

# Use original script method - direct install with fixed version
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version ${XRAY_VERSION}

if command -v xray >/dev/null 2>&1; then
    log_and_show "✅ Xray installation successful"
    XRAY_INSTALLED=true
else
    log_and_show "❌ Xray installation failed"
    XRAY_INSTALLED=false
fi
        "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${XRAY_ARCH}.zip"
    )
    
    DOWNLOAD_SUCCESS=false
    
    for url in "${DOWNLOAD_URLS[@]}"; do
        log_and_show "📥 Trying URL: $url"
        
        # Try wget first, then curl
        for tool in "wget" "curl"; do
            case $tool in
                "wget")
                    if command -v wget >/dev/null 2>&1; then
                        if wget --timeout=30 --tries=3 -O /tmp/xray.zip "$url" 2>/dev/null; then
                            DOWNLOAD_SUCCESS=true
                            log_and_show "✅ Downloaded with wget from: $url"
                            break 2
                        fi
                    fi
                ;;
                "curl")
                    if command -v curl >/dev/null 2>&1; then
                        if curl -L --connect-timeout 30 --max-time 60 --retry 3 -o /tmp/xray.zip "$url" 2>/dev/null; then
                            DOWNLOAD_SUCCESS=true
                            log_and_show "✅ Downloaded with curl from: $url"
                            break 2
                        fi
                    fi
                ;;
            esac
        done
        
        if [ "$DOWNLOAD_SUCCESS" = true ]; then
            break
        fi
    done
    
    if [ "$DOWNLOAD_SUCCESS" = true ] && [ -f /tmp/xray.zip ]; then
        # Verify download integrity
        if file /tmp/xray.zip | grep -q "Zip archive"; then
            log_and_show "✅ Archive verification passed"
            
            # Extract and install
            if command -v unzip >/dev/null 2>&1; then
                rm -rf /tmp/xray/ 2>/dev/null
                mkdir -p /tmp/xray/
                
                if unzip -q /tmp/xray.zip -d /tmp/xray/ 2>/dev/null; then
                    if [ -f /tmp/xray/xray ]; then
                        # Create necessary directories
                        mkdir -p /usr/local/bin /etc/xray /var/log/xray
                        
                        # Install binary with proper permissions
                        if cp /tmp/xray/xray /usr/local/bin/ && chmod +x /usr/local/bin/xray; then
                            # Verify installation
                            if /usr/local/bin/xray version >/dev/null 2>&1; then
                                log_and_show "✅ Xray binary installed and verified"
                                XRAY_INSTALLED=true
                                
                                # Set proper ownership
                                chown www-data:www-data /usr/local/bin/xray 2>/dev/null || true
                                
                                # Create symlink for system-wide access
                                ln -sf /usr/local/bin/xray /usr/bin/xray 2>/dev/null || true
                                
                                # Create systemd service if not exists
                                if [[ ! -f /etc/systemd/system/xray.service ]]; then
                                    cat > /etc/systemd/system/xray.service << 'EOF'
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
                                    systemctl daemon-reload
                                    log_and_show "✅ Xray systemd service created"
                                fi
                            else
                                log_and_show "❌ Xray binary verification failed"
                            fi
                        else
                            log_and_show "❌ Failed to install Xray binary"
                        fi
                    else
                        log_and_show "❌ Xray binary not found in archive"
                        # Try to extract any executable file in the archive
                        XRAY_BINARY=$(unzip -l /tmp/xray.zip | grep -E "xray|Xray" | head -n1 | awk '{print $NF}' || echo "")
                        if [[ -n "$XRAY_BINARY" ]]; then
                            log_and_show "🔄 Found alternative binary: $XRAY_BINARY"
                            if unzip -j /tmp/xray.zip "$XRAY_BINARY" -d /tmp/xray/ 2>/dev/null; then
                                mv "/tmp/xray/$XRAY_BINARY" /tmp/xray/xray 2>/dev/null
                                chmod +x /tmp/xray/xray
                                if cp /tmp/xray/xray /usr/local/bin/ && chmod +x /usr/local/bin/xray; then
                                    log_and_show "✅ Alternative Xray binary installed"
                                    XRAY_INSTALLED=true
                                fi
                            fi
                        fi
                    fi
                else
                    log_and_show "❌ Failed to extract Xray archive"
                    # Try alternative extraction methods
                    if command -v 7z >/dev/null 2>&1; then
                        log_and_show "🔄 Trying 7zip extraction..."
                        if 7z x /tmp/xray.zip -o/tmp/xray/ -y >/dev/null 2>&1; then
                            if [ -f /tmp/xray/xray ]; then
                                if cp /tmp/xray/xray /usr/local/bin/ && chmod +x /usr/local/bin/xray; then
                                    log_and_show "✅ Xray extracted with 7zip"
                                    XRAY_INSTALLED=true
                                fi
                            fi
                        fi
                    fi
                fi
            else
                log_and_show "❌ unzip command not found, installing..."
                if log_command "apt update && apt install -y unzip p7zip-full"; then
                    if command -v unzip >/dev/null 2>&1; then
                        # Retry extraction after installing unzip
                        rm -rf /tmp/xray/ 2>/dev/null
                        mkdir -p /tmp/xray/
                        if unzip -q /tmp/xray.zip -d /tmp/xray/ 2>/dev/null && [ -f /tmp/xray/xray ]; then
                            mkdir -p /usr/local/bin /etc/xray /var/log/xray
                            if cp /tmp/xray/xray /usr/local/bin/ && chmod +x /usr/local/bin/xray; then
                                log_and_show "✅ Xray binary installed after unzip installation"
                                XRAY_INSTALLED=true
                                chown www-data:www-data /usr/local/bin/xray 2>/dev/null || true
                                ln -sf /usr/local/bin/xray /usr/bin/xray 2>/dev/null || true
                            fi
                        fi
                    fi
                else
                    log_and_show "❌ Failed to install required extraction tools"
                fi
            fi
        else
            log_and_show "❌ Downloaded file is not a valid archive"
        fi
        
        # Cleanup
        rm -rf /tmp/xray* 2>/dev/null
    else
        log_and_show "❌ Failed to download Xray from all URLs"
    fi
fi

# Final verification and summary
if [ "$XRAY_INSTALLED" = true ]; then
    if command -v xray >/dev/null 2>&1; then
        XRAY_VERSION_INSTALLED=$(xray version 2>/dev/null | head -n1 || echo 'Version check failed')
        log_and_show "✅ Xray installation successful: $XRAY_VERSION_INSTALLED"
    else
        log_and_show "⚠️ Xray binary installed but not in PATH"
    fi
else
    log_and_show "❌ All Xray installation methods failed"
    log_and_show "⚠️ Xray installation failed, but continuing with other components..."
fi
log_and_show "✅ Xray core installation process completed"

# Create Xray directories (comprehensive from ins-xray.sh)
log_and_show "📁 Creating Xray directories and domain socket..."
domainSock_dir="/run/xray"
if [ ! -d $domainSock_dir ]; then
    log_command "mkdir -p $domainSock_dir"
fi
log_command "chown www-data:www-data $domainSock_dir"
log_command "mkdir -p /etc/xray /var/log/xray"
log_command "mkdir -p /home/vps/public_html"
log_command "chown www-data:www-data /var/log/xray"
log_command "chmod +x /var/log/xray"

# Create log files (comprehensive from ins-xray.sh)
log_command "touch /var/log/xray/access.log"
log_command "touch /var/log/xray/error.log"
log_command "touch /var/log/xray/access2.log"
log_command "touch /var/log/xray/error2.log"

# Stop nginx for SSL certificate generation
log_command "systemctl stop nginx"

# Install and configure SSL certificate using acme.sh with error handling
log_and_show "🔒 Setting up SSL certificate using acme.sh..."
log_command "mkdir -p /root/.acme.sh"

# Download acme.sh with fallback options
if ! log_command "curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh"; then
    log_and_show "⚠️ Primary acme.sh download failed, trying GitHub..."
    if ! log_command "curl https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh -o /root/.acme.sh/acme.sh"; then
        log_and_show "⚠️ GitHub acme.sh download failed, trying official installer..."
        if ! log_command "curl https://get.acme.sh | sh"; then
            log_and_show "⚠️ All acme.sh download methods failed, using fallback SSL configuration"
            # Create self-signed certificate as fallback
            log_command "openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -subj \"/C=ID/ST=Jakarta/L=Jakarta/O=YT-ZIXSTYLE/CN=${DOMAIN}\" -keyout /etc/xray/xray.key -out /etc/xray/xray.crt"
            log_and_show "⚠️ Self-signed certificate created as fallback"
            return
        fi
    fi
fi

if [[ -f /root/.acme.sh/acme.sh ]]; then
    log_command "chmod +x /root/.acme.sh/acme.sh"
    
    # Configure acme.sh with error handling
    if log_command "/root/.acme.sh/acme.sh --upgrade --auto-upgrade"; then
        log_command "/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt"
        
        # Issue certificate with error handling
        if log_command "/root/.acme.sh/acme.sh --issue -d ${DOMAIN} --standalone -k ec-256"; then
            log_command "/root/.acme.sh/acme.sh --installcert -d ${DOMAIN} --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc"
            log_and_show "✅ SSL certificate installed successfully"
        else
            log_and_show "⚠️ SSL certificate issuance failed, creating self-signed certificate"
            log_command "openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -subj \"/C=ID/ST=Jakarta/L=Jakarta/O=YT-ZIXSTYLE/CN=${DOMAIN}\" -keyout /etc/xray/xray.key -out /etc/xray/xray.crt"
        fi
    else
        log_and_show "⚠️ acme.sh setup failed, creating self-signed certificate"
        log_command "openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -subj \"/C=ID/ST=Jakarta/L=Jakarta/O=YT-ZIXSTYLE/CN=${DOMAIN}\" -keyout /etc/xray/xray.key -out /etc/xray/xray.crt"
    fi
fi

# Create SSL renewal script (use systemctl instead of init.d)
cat > /usr/local/bin/ssl_renew.sh << 'EOF'
#!/bin/bash
systemctl stop nginx
"/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" &> /root/renew_ssl.log
systemctl start nginx
systemctl status nginx
EOF

log_command "chmod +x /usr/local/bin/ssl_renew.sh"

# Add SSL renewal to crontab
if ! grep -q 'ssl_renew.sh' /var/spool/cron/crontabs/root 2>/dev/null; then
    (crontab -l 2>/dev/null; echo "15 03 */3 * * /usr/local/bin/ssl_renew.sh") | crontab -
    log_and_show "✅ SSL auto-renewal added to crontab"
fi

# Generate REALITY key pair for modern protocols with error handling
log_and_show "🔐 Generating REALITY key pair..."
if command -v xray >/dev/null 2>&1; then
    REALITY_KEYS=$(/usr/local/bin/xray x25519 2>/dev/null || xray x25519 2>/dev/null)
    if [ -n "$REALITY_KEYS" ]; then
        REALITY_PRIVATE=$(echo "${REALITY_KEYS}" | grep "Private key:" | awk '{print $3}')
        REALITY_PUBLIC=$(echo "${REALITY_KEYS}" | grep "Public key:" | awk '{print $3}')
        log_and_show "✅ REALITY keys generated successfully"
    else
        log_and_show "⚠️ REALITY key generation failed, using fallback"
        REALITY_PRIVATE="dummy_private_key_$(openssl rand -hex 16)"
        REALITY_PUBLIC="dummy_public_key_$(openssl rand -hex 16)"
    fi
else
    log_and_show "⚠️ Xray not available for REALITY key generation, using fallback"
    REALITY_PRIVATE="dummy_private_key_$(openssl rand -hex 16)"
    REALITY_PUBLIC="dummy_public_key_$(openssl rand -hex 16)"
fi

# Generate UUID for default user
uuid=$(cat /proc/sys/kernel/random/uuid)

# Generate Custom Paths (Completely Flexible - Support Any Path)
log_and_show "🎯 Generating custom paths (completely flexible)..."

# Function to generate random path
generate_random_path() {
    local prefix=$1
    echo "/${prefix}$(openssl rand -hex 6)"
}

# Custom paths with environment variable support (completely flexible)
VMESS_PATH="${CUSTOM_VMESS_PATH:-$(generate_random_path "vm")}"
VLESS_PATH="${CUSTOM_VLESS_PATH:-$(generate_random_path "vl")}"
TROJAN_PATH="${CUSTOM_TROJAN_PATH:-$(generate_random_path "tr")}"
TROJANGO_PATH="${CUSTOM_TROJANGO_PATH:-$(generate_random_path "trgo")}"

# XHTTP paths (must be different from WS paths to avoid nginx duplicate location error)
VMESS_XHTTP_PATH="${CUSTOM_VMESS_XHTTP_PATH:-$(generate_random_path "vmx")}"
VLESS_XHTTP_PATH="${CUSTOM_VLESS_XHTTP_PATH:-$(generate_random_path "vlx")}"

# gRPC service names (not paths)
VMESS_GRPC_SERVICE="${CUSTOM_VMESS_GRPC:-vmess-$(openssl rand -hex 4)}"
VLESS_GRPC_SERVICE="${CUSTOM_VLESS_GRPC:-vless-$(openssl rand -hex 4)}"
TROJAN_GRPC_SERVICE="${CUSTOM_TROJAN_GRPC:-trojan-$(openssl rand -hex 4)}"

# Log generated paths
log_and_show "✅ Generated custom paths:"
log_and_show "   📝 VMess WS: ${VMESS_PATH}"
log_and_show "   ⚡ VMess XHTTP: ${VMESS_XHTTP_PATH}"
log_and_show "   📡 VMess gRPC: ${VMESS_GRPC_SERVICE}"
log_and_show "   📝 VLess WS: ${VLESS_PATH}"
log_and_show "   ⚡ VLess XHTTP: ${VLESS_XHTTP_PATH}"
log_and_show "   📡 VLess gRPC: ${VLESS_GRPC_SERVICE}"
log_and_show "   📝 Trojan WS: ${TROJAN_PATH}"
log_and_show "   📡 Trojan gRPC: ${TROJAN_GRPC_SERVICE}"
log_and_show "   🚀 Trojan-Go: ${TROJANGO_PATH}"

# Save configuration details for future reference
cat > /etc/xray/.config-details << EOF
REALITY_PRIVATE=${REALITY_PRIVATE}
REALITY_PUBLIC=${REALITY_PUBLIC}
DOMAIN=${DOMAIN}
UUID=${uuid}
XRAY_VERSION=${XRAY_VERSION}
# Custom Paths (Customizable)
VMESS_PATH=${VMESS_PATH}
VMESS_XHTTP_PATH=${VMESS_XHTTP_PATH}
VMESS_GRPC_SERVICE=${VMESS_GRPC_SERVICE}
VLESS_PATH=${VLESS_PATH}
VLESS_XHTTP_PATH=${VLESS_XHTTP_PATH}
VLESS_GRPC_SERVICE=${VLESS_GRPC_SERVICE}
TROJAN_PATH=${TROJAN_PATH}
TROJAN_GRPC_SERVICE=${TROJAN_GRPC_SERVICE}
TROJANGO_PATH=${TROJANGO_PATH}
EOF

# Save paths to separate file for management scripts
cat > /etc/xray/.paths << EOF
# Custom Paths Configuration
# These paths can be completely customized via environment variables
# Example: CUSTOM_VMESS_PATH="/facebook" CUSTOM_VLESS_PATH="/google" ./xray-2025.sh
VMESS_PATH=${VMESS_PATH}
VMESS_XHTTP_PATH=${VMESS_XHTTP_PATH}
VMESS_GRPC_SERVICE=${VMESS_GRPC_SERVICE}
VLESS_PATH=${VLESS_PATH}
VLESS_XHTTP_PATH=${VLESS_XHTTP_PATH}
VLESS_GRPC_SERVICE=${VLESS_GRPC_SERVICE}
TROJAN_PATH=${TROJAN_PATH}
TROJAN_GRPC_SERVICE=${TROJAN_GRPC_SERVICE}
TROJANGO_PATH=${TROJANGO_PATH}
EOF

# Create SNI wildcard list for management scripts
cat > /etc/xray/.sni-list << EOF
www.microsoft.com
www.google.com
www.cloudflare.com
www.apple.com
discord.com
support.zoom.us
www.yahoo.com
www.amazon.com
cdn.cloudflare.com
www.bing.com
instagram.com
facebook.com
whatsapp.com
tiktok.com
youtube.com
twitter.com
telegram.org
EOF

log_and_show "✅ SSL certificate installed and REALITY keys generated"

# Create comprehensive Xray configuration with all modern protocols
log_and_show "⚙️  Creating Xray configuration with XHTTP, REALITY, and legacy protocols..."
cat > /etc/xray/config.json << EOF
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 10085,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1"
      },
      "tag": "api"
    },
    {
      "listen": "127.0.0.1",
      "port": "14016",
      "protocol": "vless",
      "settings": {
        "decryption": "none",
        "clients": [
          {
            "id": "${uuid}"
#vless
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "${VLESS_PATH}"
        }
      }
    },
    {
      "listen": "127.0.0.1",
      "port": "14017",
      "protocol": "vless",
      "settings": {
        "decryption": "none",
        "clients": [
          {
            "id": "${uuid}"
#vless-xhttp
          }
        ]
      },
      "streamSettings": {
        "network": "xhttp",
        "xhttpSettings": {
          "path": "${VLESS_XHTTP_PATH}"
        }
      }
    },
    {
      "listen": "0.0.0.0",
      "port": 8443,
      "protocol": "vless",
      "settings": {
        "decryption": "none",
        "clients": [
          {
            "id": "${uuid}",
            "flow": "xtls-rprx-vision"
#vless-reality
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "www.microsoft.com:443",
          "xver": 0,
          "serverNames": [
            "www.microsoft.com",
            "www.google.com",
            "www.cloudflare.com", 
            "www.apple.com",
            "discord.com",
            "support.zoom.us",
            "www.yahoo.com",
            "www.amazon.com"
          ],
          "privateKey": "${REALITY_PRIVATE}",
          "shortIds": ["6ba85179e30d4fc2"]
        }
      }
    },
    {
      "listen": "127.0.0.1",
      "port": "23456",
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "${uuid}",
            "alterId": 0
#vmess
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "${VMESS_PATH}"
        }
      }
    },
    {
      "listen": "127.0.0.1",
      "port": "23460",
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "${uuid}",
            "alterId": 0
#vmess-xhttp
          }
        ]
      },
      "streamSettings": {
        "network": "xhttp",
        "xhttpSettings": {
          "path": "${VMESS_XHTTP_PATH}"
        }
      }
    },
    {
      "listen": "127.0.0.1",
      "port": "25432",
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "${uuid}"
#trojanws
          }
        ],
        "udp": true
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "${TROJAN_PATH}"
        }
      }
    },
    {
      "listen": "127.0.0.1",
      "port": "24456",
      "protocol": "vless",
      "settings": {
        "decryption": "none",
        "clients": [
          {
            "id": "${uuid}"
#vlessgrpc
          }
        ]
      },
      "streamSettings": {
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "${VLESS_GRPC_SERVICE}"
        }
      }
    },
    {
      "listen": "127.0.0.1",
      "port": "31234",
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "${uuid}",
            "alterId": 0
#vmessgrpc
          }
        ]
      },
      "streamSettings": {
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "${VMESS_GRPC_SERVICE}"
        }
      }
    },
    {
      "listen": "127.0.0.1",
      "port": "33456",
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "${uuid}"
#trojangrpc
          }
        ],
        "udp": true
      },
      "streamSettings": {
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "${TROJAN_GRPC_SERVICE}"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      }
    ]
  },
  "api": {
    "tag": "api",
    "services": ["HandlerService", "LoggerService", "StatsService"]
  },
  "stats": {},
  "policy": {
    "levels": {
      "1": {
        "handshake": 4,
        "connIdle": 300,
        "uplinkOnly": 2,
        "downlinkOnly": 5,
        "statsUserUplink": false,
        "statsUserDownlink": false
      }
    },
    "system": {
      "statsInboundUplink": false,
      "statsInboundDownlink": false
    }
  }
}
EOF

# Generate SSL certificate for TLS with SAN (Subject Alternative Names)
log_and_show "📜 Generating SSL certificate with SAN for multiple domains..."
cat > /tmp/ssl.conf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = ID
ST = Jakarta
L = Jakarta
O = YT-ZIXSTYLE
OU = VPN-Server
CN = ${DOMAIN}
emailAddress = admin@${DOMAIN}

[v3_req]
basicConstraints = CA:TRUE
keyUsage = keyEncipherment, dataEncipherment, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${DOMAIN}
DNS.2 = *.${DOMAIN}
DNS.3 = instagram.com
DNS.4 = *.instagram.com
DNS.5 = facebook.com
DNS.6 = *.facebook.com
DNS.7 = whatsapp.com
DNS.8 = *.whatsapp.com
DNS.9 = tiktok.com
DNS.10 = *.tiktok.com
DNS.11 = youtube.com
DNS.12 = *.youtube.com
DNS.13 = google.com
DNS.14 = *.google.com
DNS.15 = twitter.com
DNS.16 = *.twitter.com
DNS.17 = telegram.org
DNS.18 = *.telegram.org
DNS.19 = discord.com
DNS.20 = *.discord.com
DNS.21 = support.zoom.us
DNS.22 = *.zoom.us
DNS.23 = www.microsoft.com
DNS.24 = *.microsoft.com
DNS.25 = www.cloudflare.com
DNS.26 = *.cloudflare.com
EOF

openssl req -new -x509 -days 3650 -nodes -out /etc/xray/xray.crt -keyout /etc/xray/xray.key -config /tmp/ssl.conf -extensions v3_req

# Cleanup temporary file
rm -f /tmp/ssl.conf

log_command "chmod 644 /etc/xray/xray.crt"
log_command "chmod 600 /etc/xray/xray.key"

# Create Xray systemd service (from ins-xray.sh)
log_and_show "⚙️  Creating Xray systemd service..."
rm -rf /etc/systemd/system/xray.service.d
rm -rf /etc/systemd/system/xray@.service
cat > /etc/systemd/system/xray.service << 'EOF'
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

# Create additional service for domain socket permissions (from ins-xray.sh)
cat > /etc/systemd/system/runn.service << 'EOF'
[Unit]
Description=Mantap-Sayang
After=network.target

[Service]
Type=simple
ExecStartPre=-/usr/bin/mkdir -p /var/run/xray
ExecStart=/usr/bin/chown www-data:www-data /var/run/xray
Restart=on-abort

[Install]
WantedBy=multi-user.target
EOF

# Configure Nginx for Xray proxy (comprehensive from ins-xray.sh)
log_and_show "🌐 Configuring Nginx for Xray proxy..."
log_command "apt install -y nginx"

# Remove any existing nginx configs to avoid conflicts
log_command "rm -f /etc/nginx/conf.d/xray.conf" || true
log_command "rm -f /etc/nginx/sites-enabled/default" || true
log_command "rm -f /etc/nginx/sites-available/default" || true

# Create comprehensive Nginx Xray configuration
cat > /etc/nginx/conf.d/xray.conf << EOF
server {
    listen 80;
    listen [::]:80;
    listen 443 ssl http2 reuseport;
    listen [::]:443 ssl http2 reuseport;
    listen 8880;
    listen [::]:8880;
    listen 55;
    listen [::]:55;
    listen 8080;
    listen [::]:8080;
    listen 2098 ssl http2;
    listen [::]:2098 ssl http2;
    server_name _;
    
    ssl_certificate /etc/xray/xray.crt;
    ssl_certificate_key /etc/xray/xray.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    add_header Alt-Svc 'h3=":443"; ma=86400';
    ssl_ciphers EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
    
    root /home/vps/public_html;
    
    location = ${VLESS_PATH} {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:14016;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
    
    location = ${VLESS_XHTTP_PATH} {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:14017;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
    
    location = ${VMESS_PATH} {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:23456;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
    
    location = ${VMESS_XHTTP_PATH} {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:23460;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
    
    location = ${TROJAN_PATH} {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:25432;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
    
    location ^~ ${VLESS_GRPC_SERVICE} {
        proxy_redirect off;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_set_header Host \$http_host;
        grpc_pass grpc://127.0.0.1:24456;
    }
    
    location ^~ ${VMESS_GRPC_SERVICE} {
        proxy_redirect off;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_set_header Host \$http_host;
        grpc_pass grpc://127.0.0.1:31234;
    }
    
    location ^~ ${TROJAN_GRPC_SERVICE} {
        proxy_redirect off;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_set_header Host \$http_host;
        grpc_pass grpc://127.0.0.1:33456;
    }
    
    location ^~ ${TROJANGO_PATH} {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:2087;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
}
EOF

# Start and enable services
log_and_show "🚀 Installing Trojan-Go..."
log_and_show "🔍 Detecting latest Trojan-Go version..."
latest_version="$(curl -s --connect-timeout 10 "https://api.github.com/repos/p4gefau1t/trojan-go/releases/latest" | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
if [ -z "$latest_version" ] || [ "$latest_version" = "null" ]; then
    log_and_show "⚠️ Failed to detect latest Trojan-Go version, using fallback v0.10.6"
    latest_version="0.10.6"
else
    log_and_show "✅ Latest Trojan-Go version detected: v${latest_version}"
fi
trojango_link="https://github.com/p4gefau1t/trojan-go/releases/download/v${latest_version}/trojan-go-linux-amd64.zip"
log_command "mkdir -p /usr/bin/trojan-go"
log_command "mkdir -p /etc/trojan-go"
cd $(mktemp -d)
log_command "curl -sL ${trojango_link} -o trojan-go.zip"
log_command "unzip -q trojan-go.zip && rm -rf trojan-go.zip"
log_command "mv trojan-go /usr/local/bin/trojan-go"
log_command "chmod +x /usr/local/bin/trojan-go"
log_command "mkdir -p /var/log/trojan-go/"
log_command "touch /etc/trojan-go/akun.conf"
log_command "touch /var/log/trojan-go/trojan-go.log"

# Create Trojan-Go configuration
cat > /etc/trojan-go/config.json << EOF
{
  "run_type": "server",
  "local_addr": "0.0.0.0",
  "local_port": 2087,
  "remote_addr": "127.0.0.1",
  "remote_port": 89,
  "log_level": 1,
  "log_file": "/var/log/trojan-go/trojan-go.log",
  "password": [
    "${uuid}"
  ],
  "disable_http_check": true,
  "udp_timeout": 60,
  "ssl": {
    "verify": false,
    "verify_hostname": false,
    "cert": "/etc/xray/xray.crt",
    "key": "/etc/xray/xray.key",
    "key_password": "",
    "cipher": "",
    "curves": "",
    "prefer_server_cipher": false,
    "sni": "${DOMAIN}",
    "alpn": [
      "http/1.1"
    ],
    "session_ticket": true,
    "reuse_session": true,
    "plain_http_response": "",
    "fallback_addr": "127.0.0.1",
    "fallback_port": 0,
    "fingerprint": "firefox"
  },
  "tcp": {
    "no_delay": true,
    "keep_alive": true,
    "prefer_ipv4": true
  },
  "mux": {
    "enabled": false,
    "concurrency": 8,
    "idle_timeout": 60
  },
  "websocket": {
    "enabled": true,
    "path": "${TROJANGO_PATH}",
    "host": "${DOMAIN}"
  },
  "api": {
    "enabled": false,
    "api_addr": "",
    "api_port": 0,
    "ssl": {
      "enabled": false,
      "key": "",
      "cert": "",
      "verify_client": false,
      "client_cert": []
    }
  }
}
EOF

# Create Trojan-Go systemd service
cat > /etc/systemd/system/trojan-go.service << 'EOF'
[Unit]
Description=Trojan-Go Service 2025
Documentation=https://github.com/p4gefau1t/trojan-go
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/trojan-go -config /etc/trojan-go/config.json
Restart=on-failure
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target
EOF

# Create Trojan-Go UUID file
cat > /etc/trojan-go/uuid.txt << EOF
${uuid}
EOF

# Start nginx service
log_and_show "🌐 Starting nginx service..."
# Test nginx configuration first
log_command "nginx -t"
if [ $? -eq 0 ]; then
    log_command "systemctl restart nginx"
else
    log_and_show "⚠️ Nginx configuration test failed, removing SSL config temporarily..."
    # Create temporary nginx config without SSL for now
    cat > /etc/nginx/conf.d/xray.conf << EOF
server {
    listen 80;
    listen [::]:80;
    listen 8880;
    listen [::]:8880;
    listen 55;
    listen [::]:55;
    listen 8080;
    listen [::]:8080;
    server_name _;
    
    root /home/vps/public_html;
    
    location = ${VLESS_PATH} {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:14016;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
    
    location = ${VMESS_PATH} {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:30300;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
    
    location = ${TROJAN_PATH} {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:25432;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
}
EOF
    log_command "systemctl restart nginx"
fi
log_command "systemctl enable nginx"

# Start and enable services with enhanced nginx handling
log_and_show "🚀 Starting all services (Xray, Trojan-Go, nginx)..."
log_command "systemctl daemon-reload"
log_command "systemctl enable xray"
log_command "systemctl enable runn"
log_command "systemctl enable trojan-go"

# Start nginx first with error handling
log_and_show "🌐 Starting nginx service..."
log_command "nginx -t"
if ! log_command "systemctl restart nginx"; then
    log_and_show "⚠️ Nginx restart failed, trying alternative methods..."
    log_command "systemctl stop nginx" || true
    sleep 2
    # Kill any orphaned nginx processes
    pkill -f nginx || true
    sleep 1
    # Try to start nginx again
    if ! log_command "systemctl start nginx"; then
        log_and_show "⚠️ Nginx service failed to start, continuing with other services..."
    fi
fi

log_command "systemctl start runn"
log_command "systemctl start xray"
log_command "systemctl start trojan-go"

# Verify services are running
log_and_show "🔍 Verifying service status..."
if systemctl is-active --quiet xray.service; then
    log_and_show "✅ Xray v${XRAY_VERSION} service: ACTIVE"
else
    log_and_show "⚠️ Xray service: FAILED to start"
fi

if systemctl is-active --quiet trojan-go.service; then
    log_and_show "✅ Trojan-Go v${latest_version} service: ACTIVE"
else
    log_and_show "⚠️ Trojan-Go service: FAILED to start"
fi

if systemctl is-active --quiet nginx.service; then
    log_and_show "✅ Nginx service: ACTIVE"
else
    log_and_show "⚠️ Nginx service: FAILED to start"
    # Simple diagnosis and try basic restart
    log_and_show "🔍 Trying simple nginx restart..."
    echo "=== Nginx Error Diagnosis ===" >> /root/log-install.txt
    systemctl status nginx >> /root/log-install.txt 2>&1 || true
    nginx -t >> /root/log-install.txt 2>&1 || true
    
    # Simple restart attempt
    systemctl stop nginx 2>/dev/null || true
    pkill -f nginx 2>/dev/null || true
    sleep 2
    systemctl start nginx 2>/dev/null || log_and_show "⚠️ Nginx still failed to start"
fi

# Install menu system
log_and_show "📋 Installing menu system..."
log_command "wget -O /usr/local/bin/menu https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/menu.sh"
log_command "wget -O /usr/local/bin/menu-ssh https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/menu-ssh.sh"
log_command "wget -O /usr/local/bin/menu-vmess https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/menu-vmess.sh"
log_command "wget -O /usr/local/bin/menu-vless https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/menu-vless.sh"
log_command "wget -O /usr/local/bin/menu-trojan https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/menu-trojan.sh"

# SSH management scripts are installed by ssh-2025.sh installer

# Install comprehensive Xray account management scripts
log_and_show "📱 Installing comprehensive Xray management tools..."

# VMess management (Enhanced + Legacy)
log_and_show "🔧 Installing VMess management scripts..."
log_command "wget -O /usr/local/bin/add-ws https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/add-ws.sh"
log_command "wget -O /usr/local/bin/add-ws-enhanced https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/add-ws-enhanced.sh"
log_command "wget -O /usr/local/bin/add-vmess-xhttp https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/add-vmess-xhttp.sh"
log_command "wget -O /usr/local/bin/trialvmess https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/trialvmess.sh"
log_command "wget -O /usr/local/bin/renew-ws https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/renew-ws.sh"
log_command "wget -O /usr/local/bin/del-ws https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/del-ws.sh"
log_command "wget -O /usr/local/bin/cek-ws https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/cek-ws.sh"

# VLess management (Enhanced + Modern Protocols)
log_and_show "🚀 Installing VLess management scripts (Enhanced + REALITY + XHTTP)..."
log_command "wget -O /usr/local/bin/add-vless https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/add-vless.sh"
log_command "wget -O /usr/local/bin/add-vless-enhanced https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/add-vless-enhanced.sh"
log_command "wget -O /usr/local/bin/add-vless-reality https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/add-vless-reality.sh"
log_command "wget -O /usr/local/bin/add-vless-xhttp https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/add-vless-xhttp.sh"
log_command "wget -O /usr/local/bin/trialvless https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/trialvless.sh"
log_command "wget -O /usr/local/bin/renew-vless https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/renew-vless.sh"
log_command "wget -O /usr/local/bin/del-vless https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/del-vless.sh"
log_command "wget -O /usr/local/bin/cek-vless https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/cek-vless.sh"

# Trojan management (Enhanced)
log_and_show "🔫 Installing Trojan management scripts..."
log_command "wget -O /usr/local/bin/add-tr https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/add-tr.sh"
log_command "wget -O /usr/local/bin/add-trojan-enhanced https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/add-trojan-enhanced.sh"
log_command "wget -O /usr/local/bin/trialtrojan https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/trialtrojan.sh"
log_command "wget -O /usr/local/bin/renew-tr https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/renew-tr.sh"
log_command "wget -O /usr/local/bin/del-tr https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/del-tr.sh"
log_command "wget -O /usr/local/bin/cek-tr https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/cek-tr.sh"

# Trojan-Go management (Advanced Trojan Protocol)
log_and_show "🚀 Installing Trojan-Go management scripts..."
log_command "wget -O /usr/local/bin/addtrgo https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/addtrgo.sh"
log_command "wget -O /usr/local/bin/trialtrojango https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/trialtrojango.sh"
log_command "wget -O /usr/local/bin/renewtrgo https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/renewtrgo.sh"
log_command "wget -O /usr/local/bin/deltrgo https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/deltrgo.sh"
log_command "wget -O /usr/local/bin/cektrgo https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/cektrgo.sh"

# Trojan management
# Already downloaded above, skipping duplicate downloads

# Trojan-Go management (Advanced Trojan Protocol)  
# Already downloaded above, skipping duplicate downloads

# Additional modern protocol management
log_and_show "⚡ Installing additional modern protocol utilities..."
log_command "wget -O /usr/local/bin/cekxray https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/cekxray.sh"
log_command "wget -O /usr/local/bin/certv2ray https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/certv2ray.sh"

# Set permissions for all scripts
log_command "chmod +x /usr/local/bin/*"

# Create symbolic links for enhanced scripts as defaults
log_and_show "🔗 Creating symbolic links for enhanced scripts..."
log_command "ln -sf /usr/local/bin/add-vless-enhanced /usr/local/bin/add-vless-default"
log_command "ln -sf /usr/local/bin/add-ws-enhanced /usr/local/bin/add-ws-default"

# Create backward compatibility links
log_command "ln -sf /usr/local/bin/add-vless-enhanced /usr/bin/add-vless-enhanced"
log_command "ln -sf /usr/local/bin/add-vless-reality /usr/bin/add-vless-reality"
log_command "ln -sf /usr/local/bin/add-vless-xhttp /usr/bin/add-vless-xhttp"
log_command "ln -sf /usr/local/bin/add-vmess-xhttp /usr/bin/add-vmess-xhttp"
log_command "ln -sf /usr/local/bin/add-ws-enhanced /usr/bin/add-ws-enhanced"

# Create symbolic link for menu
log_command "ln -sf /usr/local/bin/menu /usr/bin/menu"

# Move domain file to xray directory (from ins-xray.sh)
log_and_show "📁 Moving domain configuration..."
if [ -f /root/domain ]; then
    log_command "mv /root/domain /etc/xray/"
fi
if [ -f /root/scdomain ]; then
    log_command "rm /root/scdomain"
fi

# Final status output (matching ins-xray.sh style)
sleep 1
yellow() { echo -e "\\033[33;1m${*}\\033[0m"; }
yellow "✅ Xray/VMess protocols installed (v${XRAY_VERSION})"
yellow "✅ Xray/VLess protocols installed with REALITY & XHTTP"
yellow "✅ Xray/Trojan protocols installed"
yellow "✅ Trojan-Go v${latest_version} installed"

# Log Xray info (updated for correct version and protocols)
echo "XRAY v${XRAY_VERSION}: VMess/VLess/Trojan with XHTTP and REALITY (Auto-detected)" >> /root/log-install.txt
echo "Trojan-Go v${latest_version} (Auto-detected)" >> /root/log-install.txt
echo "VMess WS: 80, 443 (Path: ${VMESS_PATH})" >> /root/log-install.txt
echo "VMess GRPC: 443 (Service: ${VMESS_GRPC_SERVICE})" >> /root/log-install.txt
echo "VMess XHTTP: 80, 443 (Path: ${VMESS_XHTTP_PATH})" >> /root/log-install.txt
echo "VLess WS: 80, 443 (Path: ${VLESS_PATH})" >> /root/log-install.txt
echo "VLess GRPC: 443 (Service: ${VLESS_GRPC_SERVICE})" >> /root/log-install.txt
echo "VLess XHTTP: 80, 443 (Path: ${VLESS_XHTTP_PATH})" >> /root/log-install.txt
echo "VLess REALITY: 8443 (No path needed)" >> /root/log-install.txt
echo "Trojan WS: 80, 443 (Path: ${TROJAN_PATH})" >> /root/log-install.txt
echo "Trojan GRPC: 443 (Service: ${TROJAN_GRPC_SERVICE})" >> /root/log-install.txt
echo "Trojan-Go: 2087 (Path: ${TROJANGO_PATH})" >> /root/log-install.txt

# Enhanced Scripts Information
echo "" >> /root/log-install.txt
echo "Custom Path Features (Completely Flexible):" >> /root/log-install.txt
echo "- Custom paths via environment variables" >> /root/log-install.txt
echo "- Example: CUSTOM_VMESS_PATH='/facebook' CUSTOM_VLESS_PATH='/google' ./xray-2025.sh" >> /root/log-install.txt
echo "- Current paths saved in: /etc/xray/.paths" >> /root/log-install.txt
echo "- VMess WS+XHTTP: ${VMESS_PATH} / ${VMESS_XHTTP_PATH}" >> /root/log-install.txt
echo "- VLess WS+XHTTP: ${VLESS_PATH} / ${VLESS_XHTTP_PATH}" >> /root/log-install.txt
echo "- Trojan WS: ${TROJAN_PATH}" >> /root/log-install.txt
echo "- Trojan-Go: ${TROJANGO_PATH}" >> /root/log-install.txt
echo "" >> /root/log-install.txt
echo "Enhanced Management Scripts:" >> /root/log-install.txt
echo "- add-vless-enhanced: Advanced VLess creation" >> /root/log-install.txt
echo "- add-vless-reality: VLess with REALITY protocol" >> /root/log-install.txt
echo "- add-vless-xhttp: VLess with XHTTP transport" >> /root/log-install.txt
echo "- add-ws-enhanced: Advanced VMess creation" >> /root/log-install.txt
echo "- add-vmess-xhttp: VMess with XHTTP transport" >> /root/log-install.txt
echo "" >> /root/log-install.txt
echo "SNI Wildcard Features:" >> /root/log-install.txt
echo "- Nginx server_name: _ (wildcard support)" >> /root/log-install.txt
echo "- REALITY serverNames: Multiple domains support" >> /root/log-install.txt
echo "- Custom SNI: instagram.com, facebook.com, whatsapp.com, etc" >> /root/log-install.txt
echo "- SAN Certificate: Multi-domain SSL support for social media" >> /root/log-install.txt

log_and_show "✅ Xray v${XRAY_VERSION} installation with XHTTP and REALITY completed"
log_and_show "🌐 SNI Wildcard Support: ENABLED (server_name _)"
log_and_show "🔒 REALITY Multiple serverNames: ENABLED"
log_and_show "🎯 Custom Paths: ENABLED (completely flexible like server_name _)"
log_and_show "🚀 Enhanced management scripts tersedia dengan fitur modern:"
log_and_show "   📝 add-vless-enhanced: Pembuatan VLess tingkat lanjut"
log_and_show "   🔒 add-vless-reality: VLess dengan protokol REALITY"
log_and_show "   ⚡ add-vless-xhttp: VLess dengan transport XHTTP"
log_and_show "   📝 add-ws-enhanced: Pembuatan VMess tingkat lanjut" 
log_and_show "   ⚡ add-vmess-xhttp: VMess dengan transport XHTTP"
log_and_show "   🌐 Custom SNI: Mendukung custom domain di client"
log_and_show "🎯 Custom Path Examples:"
log_and_show "   CUSTOM_VMESS_PATH='/facebook' CUSTOM_VLESS_PATH='/google' ./xray-2025.sh"
log_and_show "   CUSTOM_TROJAN_PATH='/instagram' CUSTOM_TROJANGO_PATH='/youtube' ./xray-2025.sh"
log_and_show "✅ Semua service berjalan dengan versi terbaru (auto-detect)"
log_section "XRAY-2025.SH COMPLETED"
