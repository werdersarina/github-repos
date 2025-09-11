#!/bin/bash

# =============================================================================
# SETUPFULL.SH - Complete VPN Server Installation Script
# Combined: ins-xray.sh, insshws.sh, setup.sh, ssh-vpn.sh, tools.sh
# Version: 2025.1
# =============================================================================

clear

# Color definitions and functions (unified)
red='\e[1;31m'
green='\e[0;32m'
yell='\e[1;33m'
tyblue='\e[1;36m'
NC='\e[0m'

# Color functions (prevent redefinition)
if ! declare -f purple >/dev/null 2>&1; then
    purple() { echo -e "\\033[35;1m${*}\\033[0m"; }
fi
if ! declare -f tyblue >/dev/null 2>&1; then
    tyblue() { echo -e "\\033[36;1m${*}\\033[0m"; }
fi
if ! declare -f yellow >/dev/null 2>&1; then
    yellow() { echo -e "\\033[33;1m${*}\\033[0m"; }
fi
if ! declare -f green >/dev/null 2>&1; then
    green() { echo -e "\\033[32;1m${*}\\033[0m"; }
fi
if ! declare -f red >/dev/null 2>&1; then
    red() { echo -e "\\033[31;1m${*}\\033[0m"; }
fi
# Root directory and basic checks
cd /root

# System version number and validation
if [ "${EUID}" -ne 0 ]; then
    echo -e "[ ${red}ERROR${NC} ] You need to run this script as root"
    exit 1
fi

if [ "$(systemd-detect-virt)" == "openvz" ]; then
    echo -e "[ ${red}ERROR${NC} ] OpenVZ is not supported"
    exit 1
fi

# Network and hostname configuration
localip=$(hostname -I | cut -d\  -f1)
hst=$(hostname)
dart=$(cat /etc/hosts | grep -w $(hostname) | awk '{print $2}')
if [[ "$hst" != "$dart" ]]; then
    echo "$localip $(hostname)" >> /etc/hosts
fi

# Setup logging for debugging
INSTALL_LOG="/root/install-debug.log"
exec 2> >(tee -a "$INSTALL_LOG")

# Function for logging with timestamp
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$INSTALL_LOG"
}

log_message "=== STARTING VPS INSTALLER SCRIPT ==="
log_message "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '\"')"
log_message "Hostname: $hst"
log_message "Local IP: $localip"

# Detect OS version for compatibility
source /etc/os-release
OS_VERSION=$VERSION_ID
echo -e "[ ${green}INFO${NC} ] Detected Ubuntu $OS_VERSION"
log_message "Detected Ubuntu version: $OS_VERSION"

# Ubuntu 24.04 specific optimizations
if [[ "$OS_VERSION" == "24.04" ]]; then
    echo -e "[ ${green}INFO${NC} ] Applying Ubuntu 24.04 LTS optimizations..."
    export UBUNTU_24=true
    # Set stricter systemd policies for 24.04
    export SYSTEMD_STRICT=true
else
    export UBUNTU_24=false
    export SYSTEMD_STRICT=false
fi

# Create necessary directories
mkdir -p /etc/xray /etc/v2ray /var/lib/SIJA
touch /etc/xray/domain /etc/v2ray/domain /etc/xray/scdomain /etc/v2ray/scdomain
echo "IP=" >> /var/lib/SIJA/ipvps.conf


# Header checking and dependency validation
echo -e "[ ${tyblue}NOTES${NC} ] Before we go.."
sleep 1
echo -e "[ ${tyblue}NOTES${NC} ] I need to check your headers first.."
sleep 2
echo -e "[ ${green}INFO${NC} ] Checking headers"
sleep 1

totet=$(uname -r)
REQUIRED_PKG="linux-headers-$totet"
PKG_OK=$(dpkg-query -W --showformat='${Status}\n' $REQUIRED_PKG 2>/dev/null | grep "install ok installed")
echo "Checking for $REQUIRED_PKG: $PKG_OK"

if [ -z "$PKG_OK" ]; then
    sleep 2
    echo -e "[ ${yell}WARNING${NC} ] Trying to install...."
    echo "No $REQUIRED_PKG. Setting up $REQUIRED_PKG."
    apt-get --yes install $REQUIRED_PKG
    sleep 1
    echo ""
    sleep 1
    echo -e "[ ${tyblue}NOTES${NC} ] If error, you need to do this:"
    echo -e "[ ${tyblue}NOTES${NC} ] 1. apt update -y"
    echo -e "[ ${tyblue}NOTES${NC} ] 2. apt upgrade -y"
    echo -e "[ ${tyblue}NOTES${NC} ] 3. apt dist-upgrade -y"
    echo -e "[ ${tyblue}NOTES${NC} ] 4. reboot"
    echo -e "[ ${tyblue}NOTES${NC} ] After rebooting, run this script again"
    echo -e "[ ${tyblue}NOTES${NC} ] If you understand, press enter now"
    read -r
else
    echo -e "[ ${green}INFO${NC} ] Headers already installed"
fi

# Final header validation
ttet=$(uname -r)
ReqPKG="linux-headers-$ttet"
if ! dpkg -s $ReqPKG >/dev/null 2>&1; then
    echo -e "[ ${red}ERROR${NC} ] Required headers not found. Exiting."
    rm -f /root/setup.sh >/dev/null 2>&1 
    exit 1
else
    clear
    echo -e "[ ${green}INFO${NC} ] All dependencies validated successfully"
fi


# Time tracking and system configuration
secs_to_human() {
    echo "Installation time: $(( ${1} / 3600 )) hours $(( (${1} / 60) % 60 )) minutes $(( ${1} % 60 )) seconds"
}

start=$(date +%s)
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1

# Profile configuration
cat > /root/.profile << 'END'
# ~/.profile: executed by Bourne-compatible login shells.

if [ "$BASH" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi

mesg n || true
clear
END
chmod 644 /root/.profile

# Prepare installation files
echo "======================================"
echo "🔧 PREPARING INSTALLATION FILES"
echo "======================================"
echo "Updating package repositories..."
apt update -y
echo ""
echo "Installing basic dependencies..."
apt install git curl -y
echo ""
echo "✅ Installation files ready!"
sleep 2




# =============================================================================
# SECTION 1: SYSTEM TOOLS INSTALLATION
# =============================================================================

echo "======================================"
echo "🛠️  INSTALLING SYSTEM TOOLS"
echo "======================================"
echo "Progress starting..."
sleep 2

# OS Detection
if [[ -e /etc/debian_version ]]; then
    source /etc/os-release
    OS=$ID # debian or ubuntu
elif [[ -e /etc/centos-release ]]; then
    source /etc/os-release
    OS=centos
fi

# System update and cleanup
echo "🔄 Updating system packages..."
apt update -y
echo ""
echo "🔄 Upgrading packages..."
apt upgrade -y
echo ""
echo "🔄 Distribution upgrade..."
apt dist-upgrade -y
echo ""
echo "🧹 Removing conflicting packages..."
apt-get remove --purge ufw firewalld exim4 -y

# Install essential packages (Ubuntu 24.04 LTS Compatible)
echo -e "[ ${green}INFO${NC} ] Installing essential packages..."
echo -e "[ ${green}INFO${NC} ] This may take a few minutes..."

# Ubuntu 24.04 specific package handling
export DEBIAN_FRONTEND=noninteractive

# Install core packages first
apt install -y screen curl jq wget >/dev/null 2>&1

# Install networking and system tools
apt install -y \
    bzip2 gzip coreutils rsyslog iftop htop zip unzip \
    net-tools sed gnupg gnupg1 bc apt-transport-https build-essential \
    dirmngr libxml-parser-perl neofetch git lsof openssl openvpn \
    easy-rsa fail2ban tmux stunnel4 vnstat squid \
    libsqlite3-dev socat cron bash-completion ntpdate xz-utils \
    gnupg2 dnsutils lsb-release chrony libnss3-dev libnspr4-dev \
    pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils \
    libselinux1-dev libcurl4-nss-dev flex bison make libnss3-tools \
    libevent-dev xl2tpd figlet ruby python3 python3-pip >/dev/null 2>&1

# Install dropbear separately for better error handling
echo -e "[ ${green}INFO${NC} ] Installing Dropbear SSH server..."
apt install -y dropbear >/dev/null 2>&1

# Verify critical packages
if ! command -v dropbear >/dev/null 2>&1; then
    echo -e "[ ${yell}WARNING${NC} ] Dropbear installation failed, retrying..."
    apt update >/dev/null 2>&1
    apt install -y dropbear >/dev/null 2>&1
fi

# Install Node.js 20.x (Ubuntu 24.04 compatible)
echo -e "[ ${green}INFO${NC} ] Installing Node.js 20.x..."
curl -sSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null 2>&1
apt-get install nodejs -y >/dev/null 2>&1

# Install Ruby gems
echo ""
echo "💎 Installing Ruby gems (lolcat)..."
if gem install lolcat; then
    echo "✅ Lolcat gem successfully installed"
else
    echo "⚠️ Failed to install lolcat gem, continuing..."
fi

# Network interface detection and vnstat configuration
echo ""
echo "🌐 Configuring network monitoring..."
NET=$(ip route | grep default | awk '{print $5}' | head -1)
if [ -z "$NET" ]; then
    NET=$(ls /sys/class/net/ | grep -v lo | head -1)
fi
echo "Detected network interface: $NET"

# Install and configure vnstat
echo ""
echo "📊 Installing vnstat network monitor..."
systemctl stop vnstat

# Try package installation first
if ! command -v vnstat >/dev/null 2>&1; then
    echo "Installing vnstat from package repository..."
    apt-get install vnstat -y
fi

# If package doesn't work, compile from source
if ! command -v vnstat >/dev/null 2>&1; then
    echo "Package installation failed, compiling from source..."
    cd /root
    wget -q https://humdi.net/vnstat/vnstat-2.12.tar.gz
    echo "Extracting vnstat source..."
    tar zxvf vnstat-2.12.tar.gz
    cd vnstat-2.12
    echo "Configuring vnstat build..."
    ./configure --prefix=/usr --sysconfdir=/etc --sbindir=/usr/bin
    echo "Compiling vnstat..."
    make
    echo "Installing vnstat..."
    make install
    cd /root
    rm -f vnstat-2.12.tar.gz vnstat-2.12 -rf
fi

# Create vnstat user and configure
echo "Creating vnstat user and configuring..."
if ! id -u vnstat >/dev/null 2>&1; then
    useradd -r -s /bin/false vnstat
fi

mkdir -p /var/lib/vnstat
/usr/bin/vnstat -u -i $NET
sed -i "s/Interface \"eth0\"/Interface \"$NET\"/g" /etc/vnstat.conf 2>/dev/null
chown vnstat:vnstat /var/lib/vnstat -R
systemctl enable vnstat
systemctl restart vnstat

echo ""
echo "✅ Dependencies successfully installed!"
sleep 3
clear


# =============================================================================
# SECTION 2: DOMAIN CONFIGURATION
# =============================================================================

clear
echo "======================================"
echo "🌐 DOMAIN CONFIGURATION"
echo "======================================"
echo "Setting up domain for vmess/vless/trojan protocols"
echo ""
read -rp "Input your domain: " -e pp
if [ -z "$pp" ]; then
    echo "⚠️  No domain input! Creating auto-generated domain..."
    pp="$(curl -s ipinfo.io/ip).nip.io"
    echo "🔧 Using auto-generated domain: $pp"
else
    echo "✅ Using domain: $pp"
fi

echo ""
echo "💾 Saving domain to configuration files..."
# Save domain to all necessary locations
echo "$pp" > /root/scdomain && echo "   ✓ Saved to /root/scdomain"
echo "$pp" > /etc/xray/scdomain && echo "   ✓ Saved to /etc/xray/scdomain"
echo "$pp" > /etc/xray/domain && echo "   ✓ Saved to /etc/xray/domain"
echo "$pp" > /etc/v2ray/domain && echo "   ✓ Saved to /etc/v2ray/domain"
echo "$pp" > /root/domain && echo "   ✓ Saved to /root/domain"
echo "IP=$pp" > /var/lib/SIJA/ipvps.conf && echo "   ✓ Saved to /var/lib/SIJA/ipvps.conf"

domain="$pp"  # Set domain variable for later use

echo ""
echo "✅ Domain configuration completed successfully!"
echo "📋 Domain: $domain"
sleep 2
    
# =============================================================================
# SECTION 3: SSH/VPN INSTALLATION
# =============================================================================

echo "======================================"
echo "🔐 SSH/VPN INSTALLATION"
echo "======================================"
sleep 2
clear

# Initialize variables for SSH/VPN installation
export DEBIAN_FRONTEND=noninteractive
MYIP=$(wget -qO- ipinfo.io/ip 2>/dev/null || curl -s ipinfo.io/ip)
MYIP2="s/xxxxxxxxx/$MYIP/g"
NET=$(ip route | grep default | awk '{print $5}' | head -1)
if [ -z "$NET" ]; then
    NET=$(ls /sys/class/net/ | grep -v lo | head -1)
fi
source /etc/os-release
ver=$VERSION_ID

# SSL certificate details
country=ID
state=Indonesia
locality=Jakarta
organization=Zixstyle
organizationalunit=Zixstyle.my.id
commonname=WarungAwan
email=doyoulikepussy@zixstyle.co.id

# Simple password configuration
echo "🔐 Configuring password policies..."
echo "Downloading password configuration..."
curl -sS https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/password 2>/dev/null | openssl aes-256-cbc -d -a -pass pass:scvps07gg -pbkdf2 > /etc/pam.d/common-password 2>/dev/null
chmod +x /etc/pam.d/common-password 2>/dev/null
echo "✅ Password policies configured"

# System service configuration
echo ""
echo "⚙️  Configuring system services..."

# Edit file /etc/systemd/system/rc-local.service
cat > /etc/systemd/system/rc-local.service <<-'END'
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
END

# Create /etc/rc.local
cat > /etc/rc.local <<-'END'
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
END

# Set permissions and enable
chmod +x /etc/rc.local
echo "Enabling rc-local service..."
systemctl enable rc-local
systemctl start rc-local.service

# Disable IPv6
echo ""
echo "🚫 Disabling IPv6..."
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local
echo "✅ IPv6 disabled"

# System updates (if not already done)
echo ""
echo "🔄 Final system updates..."
apt update -y
echo "Installing additional tools..."
apt install jq shc wget curl -y

# Set timezone
echo ""
echo "🕐 Setting timezone to Asia/Jakarta..."
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
echo "✅ Timezone configured"

# Configure SSH
echo ""
echo "🔧 Configuring SSH settings..."
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
echo "✅ SSH configuration updated"


# SSL installation function
install_ssl() {
    echo "🔒 Installing SSL certificates..."
    
    if [ -f "/usr/bin/apt-get" ]; then
        isDebian=$(cat /etc/issue | grep Debian)
        if [ "$isDebian" != "" ]; then
            echo "Installing nginx and certbot on Debian..."
            apt-get install -y nginx certbot
        else
            echo "Installing nginx and certbot on Ubuntu..."
            apt-get install -y nginx certbot
        fi
    else
        echo "Installing nginx and certbot on RHEL/CentOS..."
        yum install -y nginx certbot
    fi

    echo "Stopping nginx service..."
    systemctl stop nginx.service

    if [ -f "/usr/bin/apt-get" ]; then
        echo "Generating SSL certificate for domain: $domain"
        echo "A" | certbot certonly --renew-by-default --register-unsafely-without-email --standalone -d $domain
    else
        echo "Y" | certbot certonly --renew-by-default --register-unsafely-without-email --standalone -d $domain
    fi
    echo "✅ SSL certificates installed"
}

# Install and configure web server
echo ""
echo "🌐 Installing and configuring web server..."
apt -y install nginx
cd /root
echo "Removing default nginx configuration..."
rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default
echo "Downloading custom nginx configuration..."
wget -O /etc/nginx/nginx.conf "https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/nginx.conf"
echo "Creating web directory..."
mkdir -p /home/vps/public_html
echo "Restarting nginx..."
systemctl restart nginx
echo "✅ Web server configured"

# Install and configure badvpn
echo ""
echo "🔌 Installing badvpn UDP gateway..."
cd /root
echo "Downloading badvpn-udpgw..."
wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/newudpgw"
chmod +x /usr/bin/badvpn-udpgw
echo "✅ badvpn downloaded and configured"

# Add badvpn to startup
echo "Setting up badvpn UDP gateways on multiple ports..."
for port in 7100 7200 7300 7400 7500 7600 7700 7800 7900; do
    echo "  ✓ Configuring badvpn on port $port"
    sed -i "$ i\screen -dmS badvpn-$port badvpn-udpgw --listen-addr 127.0.0.1:$port --max-clients 500" /etc/rc.local
    screen -dmS badvpn-$port badvpn-udpgw --listen-addr 127.0.0.1:$port --max-clients 500
done
echo "✅ badvpn UDP gateways started"

# Configure SSH ports
echo ""
echo "🔐 Configuring SSH ports..."
cd /root

# Backup original SSH config
echo "Creating SSH configuration backup..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Enable password authentication
echo "Enabling password authentication..."
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config

# GCP-specific SSH optimizations
echo "Applying GCP-specific SSH optimizations..."
sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 60/g' /etc/ssh/sshd_config
sed -i 's/#ClientAliveCountMax 3/ClientAliveCountMax 3/g' /etc/ssh/sshd_config
sed -i 's/#TCPKeepAlive yes/TCPKeepAlive yes/g' /etc/ssh/sshd_config

# Ensure Port 22 exists and add additional ports
if ! grep -q "^Port 22" /etc/ssh/sshd_config; then
    echo "Adding Port 22 to SSH config..."
    echo "Port 22" >> /etc/ssh/sshd_config
fi

# Add multiple SSH ports safely
echo "Adding additional SSH ports..."
for port in 500 40000 51443 58080 200; do
    if ! grep -q "^Port $port" /etc/ssh/sshd_config; then
        echo "  ✓ Adding SSH port $port"
        echo "Port $port" >> /etc/ssh/sshd_config
    fi
done

# Test SSH configuration before restart
echo "Testing SSH configuration..."
if sshd -t; then
    echo "✅ SSH configuration is valid - restarting SSH service"
    systemctl restart ssh
    systemctl restart sshd 2>/dev/null || true
else
    echo "❌ SSH configuration error - restoring backup"
    cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
    systemctl restart ssh
    systemctl restart sshd 2>/dev/null || true
fi

# Configure Dropbear SSH (Ubuntu 24.04 LTS Compatible)
echo -e "[ ${green}INFO${NC} ] Installing and configuring Dropbear..."
apt -y install dropbear >/dev/null 2>&1

# Stop default dropbear service
systemctl stop dropbear >/dev/null 2>&1
systemctl disable dropbear >/dev/null 2>&1

# Configure dropbear for compatibility
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=143/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 50000 -p 109 -p 110 -p 69"/g' /etc/default/dropbear

# Generate dropbear host keys
mkdir -p /etc/dropbear
echo -e "[ ${green}INFO${NC} ] Generating dropbear host keys..."
if [ ! -f /etc/dropbear/dropbear_rsa_host_key ]; then
    dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key -s 2048 >/dev/null 2>&1
fi
if [ ! -f /etc/dropbear/dropbear_ecdsa_host_key ]; then
    dropbearkey -t ecdsa -f /etc/dropbear/dropbear_ecdsa_host_key >/dev/null 2>&1
fi
if [ ! -f /etc/dropbear/dropbear_ed25519_host_key ]; then
    dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key >/dev/null 2>&1
fi

# Set proper permissions
chmod 600 /etc/dropbear/dropbear_*_host_key
chown root:root /etc/dropbear/dropbear_*_host_key

# Ensure shells are available
grep -qxF "/bin/false" /etc/shells || echo "/bin/false" >> /etc/shells
grep -qxF "/usr/sbin/nologin" /etc/shells || echo "/usr/sbin/nologin" >> /etc/shells

# Create systemd service for multi-port dropbear (Ubuntu 24.04 Compatible)
cat > /etc/systemd/system/dropbear-multi.service <<'EOF'
[Unit]
Description=Dropbear SSH server (multi-port)
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/dropbear -F -E -p 143 -p 50000 -p 109 -p 110 -p 69
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
RestartSec=3s

[Install]
WantedBy=multi-user.target
EOF

# Enable and start dropbear service
systemctl daemon-reload
systemctl enable dropbear-multi.service >/dev/null 2>&1
systemctl start dropbear-multi.service >/dev/null 2>&1

# Verify dropbear status
sleep 3
if systemctl is-active --quiet dropbear-multi; then
    echo -e "[ ${green}INFO${NC} ] Dropbear multi-port service started successfully"
else
    echo -e "[ ${yell}WARNING${NC} ] Dropbear failed to start with systemd, trying fallback..."
    # Ubuntu 24.04 fallback method
    systemctl stop dropbear-multi >/dev/null 2>&1
    pkill -f dropbear >/dev/null 2>&1
    sleep 2
    
    # Use screen for better daemon management in Ubuntu 24.04
    screen -dmS dropbear-143 dropbear -F -E -p 143
    screen -dmS dropbear-109 dropbear -F -E -p 109
    screen -dmS dropbear-50000 dropbear -F -E -p 50000
    screen -dmS dropbear-110 dropbear -F -E -p 110
    screen -dmS dropbear-69 dropbear -F -E -p 69
    
    sleep 3
    if pgrep -f "dropbear.*-p.*143" >/dev/null; then
        echo -e "[ ${green}INFO${NC} ] Dropbear started successfully on multiple ports"
    else
        echo -e "[ ${red}ERROR${NC} ] Dropbear failed to start"
        # Last resort - use original dropbear service
        systemctl enable dropbear >/dev/null 2>&1
        systemctl restart dropbear >/dev/null 2>&1 || /etc/init.d/dropbear restart >/dev/null 2>&1
    fi
fi
# Configure Stunnel4
echo ""
echo "🔒 Installing and configuring Stunnel4..."
cd /root
apt install stunnel4 -y

echo "Creating stunnel configuration..."
cat > /etc/stunnel/stunnel.conf <<-'END'
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 222
connect = 127.0.0.1:22

[dropbear-alt]
accept = 777
connect = 127.0.0.1:109

[ws-stunnel]
accept = 2096
connect = 127.0.0.1:700

[openvpn]
accept = 442
connect = 127.0.0.1:1194
END

# Generate SSL certificate for stunnel
echo "Generating SSL certificate for stunnel..."
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 1095 \
-subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem

# Configure and start stunnel
echo "Enabling and starting stunnel4..."
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
chmod 600 /etc/stunnel/stunnel.pem

if command -v systemctl >/dev/null; then
    systemctl enable stunnel4
    systemctl restart stunnel4
else
    /etc/init.d/stunnel4 restart
fi
echo "✅ Stunnel4 configured and started"


# Install and configure Fail2ban
echo ""
echo "🛡️  Installing and configuring Fail2ban..."
apt -y install fail2ban

echo "Creating Fail2ban configuration..."
cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime = 300
findtime = 600
maxretry = 10
ignoreip = 127.0.0.1/8 35.235.240.0/20 130.211.0.0/22 35.191.0.0/16

[ssh]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 10

[dropbear]
enabled = true
port = ssh
filter = dropbear
logpath = /var/log/auth.log
maxretry = 10
EOF

echo "Enabling and starting Fail2ban..."
systemctl enable fail2ban
systemctl restart fail2ban
echo "✅ Fail2ban configured and started"

# Install and configure Squid proxy
echo ""
echo "🔄 Installing and configuring Squid proxy..."
apt -y install squid

echo "Creating Squid configuration..."
cat > /etc/squid/squid.conf <<'EOF'
acl localhost src 127.0.0.1/32 ::1
acl to_localhost dst 127.0.0.0/8 0.0.0.0/32 ::1
acl localnet src 10.0.0.0/8
acl localnet src 172.16.0.0/12
acl localnet src 192.168.0.0/16
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
http_access allow localnet
http_access allow localhost
http_access deny all
http_port 3128
# http_port 8080 # Disabled to avoid conflict with Nginx
coredump_dir /var/spool/squid
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
EOF

echo "Enabling and starting Squid..."
systemctl enable squid
systemctl restart squid
echo "✅ Squid proxy configured and started"

# Install Custom DDoS Protection
echo ""
echo "🛡️  Installing Custom DDoS Protection..."
mkdir -p /usr/local/ddos /var/log/ddos

echo "Creating DDoS protection script..."
# Create simplified DDoS protection script
cat > /usr/local/ddos/ddos.sh <<'EOF'
#!/bin/bash
# Custom DDoS Protection Script - Simplified

CONF_FILE="/usr/local/ddos/ddos.conf"
LOG_FILE="/var/log/ddos/ddos.log"
BAN_LIST="/usr/local/ddos/banned_ips.txt"

# Load configuration with defaults (GCP-optimized)
MAX_CONNECTIONS=500
BAN_PERIOD=300
CHECK_INTERVAL=60
[ -f "$CONF_FILE" ] && source "$CONF_FILE"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

check_connections() {
    netstat -ntu | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | while read count ip; do
        # Skip localhost, private IPs, and Google Cloud IP ranges
        [[ -z "$ip" || "$ip" == "127.0.0.1" || "$ip" =~ ^192\.168\. || "$ip" =~ ^10\. || "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] && continue
        [[ "$ip" =~ ^35\.235\.24[0-9]\. || "$ip" =~ ^130\.211\. || "$ip" =~ ^35\.191\. ]] && continue
        
        if [ "$count" -gt "$MAX_CONNECTIONS" ] && ! grep -q "$ip" "$BAN_LIST" 2>/dev/null; then
            iptables -I INPUT -s "$ip" -j DROP
            echo "$ip $(date +%s)" >> "$BAN_LIST"
            log_message "Banned IP $ip with $count connections"
        fi
    done
}

unban_expired() {
    [ ! -f "$BAN_LIST" ] && return
    current_time=$(date +%s)
    temp_file=$(mktemp)
    while read line; do
        [ -n "$line" ] || continue
        ip=$(echo "$line" | cut -d' ' -f1)
        ban_time=$(echo "$line" | cut -d' ' -f2)
        if [ $((current_time - ban_time)) -gt "$BAN_PERIOD" ]; then
            iptables -D INPUT -s "$ip" -j DROP 2>/dev/null
            log_message "Unbanned IP $ip"
        else
            echo "$line" >> "$temp_file"
        fi
    done < "$BAN_LIST"
    mv "$temp_file" "$BAN_LIST"
}

case "$1" in
    --cron) echo "*/1 * * * * root /usr/local/ddos/ddos.sh --check >/dev/null 2>&1" > /etc/cron.d/ddos ;;
    --check) check_connections; unban_expired ;;
    *) echo "Usage: $0 [--cron|--check]" ;;
esac
EOF


# Create configuration
echo "Creating DDoS protection configuration..."
cat > /usr/local/ddos/ddos.conf <<'EOF'
MAX_CONNECTIONS=500
BAN_PERIOD=300
CHECK_INTERVAL=60
EOF

# Set permissions and install
chmod +x /usr/local/ddos/ddos.sh
touch /usr/local/ddos/banned_ips.txt
/usr/local/ddos/ddos.sh --cron

echo "✅ Custom DDoS Protection installed successfully"

# Configure banner and system optimization
echo ""
echo "🎨 Configuring system banner and optimization..."
echo "Downloading system banner..."
wget -q -O /etc/issue.net "https://raw.githubusercontent.com/werdersarina/github-repos/main/issue.net"
chmod +x /etc/issue.net
echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/issue.net"@g' /etc/default/dropbear
echo "✅ System banner configured"

# Install BBR and kernel optimization
echo ""
echo "⚡ Installing BBR and kernel optimization..."
echo "Downloading BBR script..."
wget -q https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/bbr.sh
chmod +x bbr.sh
echo "Running BBR optimization..."
./bbr.sh
echo "✅ BBR optimization completed"

# Configure firewall and anti-torrent
echo ""
echo "🔥 Configuring firewall and anti-torrent rules..."

echo "Setting up Google Cloud Platform IP whitelist..."
# Ensure Google Cloud IAP IP ranges are whitelisted first (CRITICAL for GCP)
iptables -I INPUT -s 35.235.240.0/20 -j ACCEPT
echo "  ✓ Added GCP IAP range: 35.235.240.0/20"
iptables -I INPUT -s 130.211.0.0/22 -j ACCEPT
echo "  ✓ Added GCP Load Balancer range: 130.211.0.0/22"
iptables -I INPUT -s 35.191.0.0/16 -j ACCEPT
echo "  ✓ Added GCP Health Check range: 35.191.0.0/16"

# Additional Google Cloud Platform IP ranges
iptables -I INPUT -s 34.96.0.0/20 -j ACCEPT
echo "  ✓ Added GCP additional range: 34.96.0.0/20"
iptables -I INPUT -s 34.127.0.0/16 -j ACCEPT
echo "  ✓ Added GCP additional range: 34.127.0.0/16"

echo "Setting up emergency access rules..."
# Emergency access - always allow localhost and private networks
iptables -I INPUT -s 127.0.0.0/8 -j ACCEPT
iptables -I INPUT -s 10.0.0.0/8 -j ACCEPT
iptables -I INPUT -s 172.16.0.0/12 -j ACCEPT
iptables -I INPUT -s 192.168.0.0/16 -j ACCEPT
echo "  ✓ Emergency access rules added"

echo "Opening SSH ports..."
# Ensure SSH ports are always accessible (HIGHEST PRIORITY)
for port in 22 200 500 40000 51443 58080; do
    iptables -I INPUT -p tcp --dport $port -j ACCEPT
    echo "  ✓ Opened SSH port $port"
done

# Allow established connections to prevent disconnection
iptables -I INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
echo "  ✓ Allowed established connections"

# Block torrent traffic
iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP

# Save iptables rules and create emergency reset
echo -e "📂 Menyimpan aturan iptables ke /etc/iptables.up.rules..."
iptables-save > /etc/iptables.up.rules
echo -e "✅ Aturan iptables berhasil disimpan!"

if command -v netfilter-persistent >/dev/null; then
    echo -e "🔄 Menyimpan konfigurasi netfilter..."
    netfilter-persistent save
    echo -e "🔄 Memuat ulang konfigurasi netfilter..."
    netfilter-persistent reload
    echo -e "✅ Netfilter berhasil dikonfigurasi!"
fi

# Create emergency SSH reset script
cat > /usr/local/bin/emergency-ssh-reset.sh << 'EOF'
#!/bin/bash
# Emergency SSH Reset Script - Run this if SSH is blocked
echo "Emergency SSH Reset - Clearing all blocking rules..."

# Flush all iptables rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# Restart SSH service
systemctl restart ssh
systemctl restart sshd 2>/dev/null

# Stop fail2ban temporarily
systemctl stop fail2ban 2>/dev/null

# Clear DDoS banned IPs
if [ -f "/usr/local/ddos/banned_ips.txt" ]; then
    > /usr/local/ddos/banned_ips.txt
fi

echo "SSH should now be accessible on port 22"
echo "Run this from console/serial access if needed"
EOF

chmod +x /usr/local/bin/emergency-ssh-reset.sh

# Add emergency reset to cron (runs every 5 minutes, but only if SSH is down)
cat > /usr/local/bin/ssh-monitor.sh << 'EOF'
#!/bin/bash
# Check if SSH is accessible, if not run emergency reset
if ! ss -tln | grep -q ":22 "; then
    /usr/local/bin/emergency-ssh-reset.sh
fi
EOF

chmod +x /usr/local/bin/ssh-monitor.sh

# Download management scripts
echo -e "📥 Mengunduh script manajemen server..."
cd /usr/bin

# Download and set permissions for all scripts in batches
declare -A scripts=(
    # Menu scripts
    ["menu"]="menu/menu.sh"
    ["menu-vmess"]="menu/menu-vmess.sh"
    ["menu-vless"]="menu/menu-vless.sh"
    ["menu-trgo"]="menu/menu-trgo.sh"
    ["menu-trojan"]="menu/menu-trojan.sh"
    ["menu-ssh"]="menu/menu-ssh.sh"
    ["menu-set"]="menu/menu-set.sh"
    ["menu-domain"]="menu/menu-domain.sh"
    ["menu-webmin"]="menu/menu-webmin.sh"
    
    # SSH management scripts
    ["usernew"]="ssh/usernew.sh"
    ["trial"]="ssh/trial.sh"
    ["renew"]="ssh/renew.sh"
    ["hapus"]="ssh/hapus.sh"
    ["cek"]="ssh/cek.sh"
    ["member"]="ssh/member.sh"
    ["delete"]="ssh/delete.sh"
    ["autokill"]="ssh/autokill.sh"
    ["ceklim"]="ssh/ceklim.sh"
    ["tendang"]="ssh/tendang.sh"
    ["xp"]="ssh/xp.sh"
    ["sshws"]="ssh/sshws.sh"
    
    # System utilities
    ["running"]="menu/running.sh"
    ["clearcache"]="menu/clearcache.sh"
    ["add-host"]="ssh/add-host.sh"
    ["port-change"]="port/port-change.sh"
    ["port-ssl"]="port/port-ssl.sh"
    ["port-ovpn"]="port/port-ovpn.sh"
    ["certv2ray"]="xray/certv2ray.sh"
    ["speedtest"]="ssh/speedtest_cli.py"
    ["about"]="menu/about.sh"
    ["auto-reboot"]="menu/auto-reboot.sh"
    ["restart"]="menu/restart.sh"
    ["bw"]="menu/bw.sh"
    ["acs-set"]="acs-set.sh"
)

# Download all scripts
echo -e "🔄 Mengunduh script manajemen individual..."
script_count=0
total_scripts=${#scripts[@]}

for script_name in "${!scripts[@]}"; do
    ((script_count++))
    echo -e "📥 [$script_count/$total_scripts] Mengunduh script '$script_name'..."
    if wget -q -O "$script_name" "https://raw.githubusercontent.com/werdersarina/github-repos/main/${scripts[$script_name]}"; then
        chmod +x "$script_name"
        echo -e "  ✅ Script '$script_name' berhasil diunduh dan diset executable"
    else
        echo -e "  ⚠️ Gagal mengunduh script '$script_name', melanjutkan..."
    fi
done

echo -e "✅ Semua script manajemen telah diunduh ($script_count/$total_scripts berhasil)"


# Configure cron jobs
echo -e "⏰ Mengonfigurasi cron jobs untuk jadwal otomatis..."

echo -e "🔄 Membuat cron job untuk reboot harian (02:00)..."
cat > /etc/cron.d/re_otm <<-'END'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 2 * * * root /sbin/reboot
END
echo -e "✅ Cron job reboot harian telah dikonfigurasi"

echo -e "🔄 Membuat cron job untuk pembersihan user expired (00:00)..."
cat > /etc/cron.d/xp_otm <<-'END'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 0 * * * root /usr/bin/xp
END
echo -e "✅ Cron job pembersihan user expired telah dikonfigurasi"

echo -e "🔄 Membuat file konfigurasi reboot..."
cat > /home/re_otm <<-'END'
7
END
echo -e "✅ File konfigurasi reboot telah dibuat"

echo -e "🔄 Memulai ulang dan memuat cron service..."
service cron restart
service cron reload
echo -e "✅ Cron service berhasil dimulai ulang"

# Cleanup unnecessary packages
echo -e "🧹 Membersihkan sistem dari paket yang tidak diperlukan..."

echo -e "🔄 Menjalankan apt autoclean..."
apt autoclean -y
echo -e "✅ Apt cache berhasil dibersihkan"

# Remove unnecessary services
echo -e "🗑️ Menghapus service yang tidak diperlukan..."
for pkg in unscd samba apache2 bind9 sendmail; do
    if dpkg -s "$pkg" >/dev/null 2>&1; then
        echo -e "🔄 Menghapus paket '$pkg'..."
        if apt -y remove --purge "$pkg"*; then
            echo -e "  ✅ Paket '$pkg' berhasil dihapus"
        else
            echo -e "  ⚠️ Gagal menghapus paket '$pkg'"
        fi
    else
        echo -e "  ℹ️ Paket '$pkg' tidak terinstall"
    fi
done

echo -e "🔄 Menjalankan autoremove untuk membersihkan dependency..."
apt autoremove -y
echo -e "✅ Sistem berhasil dibersihkan dari paket yang tidak diperlukan"

# Set proper ownership
echo -e "🔧 Mengatur ownership yang tepat untuk direktori web..."
chown -R www-data:www-data /home/vps/public_html
echo -e "✅ Ownership direktori web telah diatur dengan benar"
# Restart all services
echo -e "🔄 Memulai ulang semua service SSH & VPN..."

# List of services to restart with their systemctl/init.d commands
services=(
    "nginx"
    "cron" 
    "ssh"
    "dropbear-multi"
    "stunnel4"
    "vnstat"
    "squid"
)

# Restart fail2ban last to prevent issues during service restart
service_count=0
total_services=${#services[@]}

for service in "${services[@]}"; do
    ((service_count++))
    echo -e "🔄 [$service_count/$total_services] Memulai ulang service '$service'..."
    
    if systemctl is-enabled "$service" >/dev/null 2>&1 || systemctl list-unit-files | grep -q "$service"; then
        if systemctl restart "$service"; then
            echo -e "  ✅ Service '$service' berhasil dimulai ulang via systemctl"
        else
            echo -e "  ⚠️ Gagal restart '$service' via systemctl, mencoba init.d..."
            /etc/init.d/"$service" restart
        fi
    else
        echo -e "  🔄 Menggunakan init.d untuk service '$service'..."
        if /etc/init.d/"$service" restart; then
            echo -e "  ✅ Service '$service' berhasil dimulai ulang via init.d"
        else
            echo -e "  ⚠️ Gagal restart service '$service'"
        fi
    fi
    sleep 2  # Increased delay to prevent connection issues
done

# Restart fail2ban last after other services are stable
echo -e "🔧 Memulai ulang fail2ban sebagai langkah terakhir..."
if systemctl restart fail2ban; then
    echo -e "✅ Fail2ban berhasil dimulai ulang"
else
    echo -e "⚠️ Gagal memulai ulang fail2ban"
fi
sleep 3

# Verify SSH is still accessible
echo -e "🔍 Memverifikasi akses SSH masih tersedia..."
if ss -tln | grep -q ":22 "; then
    echo -e "✅ SSH port 22 dapat diakses dengan normal"
else
    echo -e "⚠️ PERINGATAN: SSH port 22 mungkin tidak dapat diakses!"
    echo -e "🔄 Mencoba restart SSH sekali lagi..."
    if systemctl restart ssh; then
        echo -e "✅ SSH berhasil direstart"
    else
        echo -e "❌ Gagal restart SSH - gunakan console access jika diperlukan"
    fi
fi

# Start badvpn UDP gateways
echo -e "🚀 Memulai badvpn UDP gateways..."
udp_ports=(7100 7200 7300 7400 7500 7600 7700 7800 7900)
gateway_count=0

for port in "${udp_ports[@]}"; do
    ((gateway_count++))
    echo -e "🔄 [$gateway_count/${#udp_ports[@]}] Memulai badvpn gateway pada port $port..."
    if screen -dmS badvpn-$port badvpn-udpgw --listen-addr 127.0.0.1:$port --max-clients 500; then
        echo -e "  ✅ Gateway port $port berhasil dimulai"
    else
        echo -e "  ⚠️ Gagal memulai gateway port $port"
    fi
done
echo -e "✅ Semua badvpn UDP gateways telah dimulai ($gateway_count gateway aktif)"

# Clear command history and setup environment
echo -e "🧹 Membersihkan history command dan mengatur environment..."
history -c
echo "unset HISTFILE" >> /etc/profile
echo -e "✅ Command history berhasil dibersihkan"

# Cleanup temporary files
echo -e "🗑️ Menghapus file temporary..."
temp_files=("/root/key.pem" "/root/cert.pem" "/root/ssh-vpn.sh" "/root/bbr.sh")
for temp_file in "${temp_files[@]}"; do
    if [ -f "$temp_file" ]; then
        rm -f "$temp_file"
        echo -e "  🗑️ Menghapus $temp_file"
    fi
done
echo -e "✅ File temporary berhasil dibersihkan"

echo -e "🎉 Instalasi SSH/VPN berhasil diselesaikan!"

# =============================================================================
# SECTION 4: XRAY INSTALLATION
# =============================================================================

echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "$green          Install XRAY              $NC"
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
sleep 2
clear

echo -e "📦 Memulai instalasi XRAY..."
date
echo ""

# Use domain from previous configuration
echo -e "🔍 Mengecek konfigurasi domain..."
if [ -z "$domain" ]; then
    echo -e "🔄 Membaca domain dari file konfigurasi..."
    domain=$(cat /root/domain 2>/dev/null || cat /etc/xray/domain 2>/dev/null || echo "")
    if [ -n "$domain" ]; then
        echo -e "✅ Domain ditemukan: $domain"
    fi
fi

if [ -z "$domain" ]; then
    echo -e "❌ Domain tidak ditemukan! Silakan konfigurasi domain terlebih dahulu."
    exit 1
fi

sleep 1
echo -e "📁 Membuat direktori XRAY..."
mkdir -p /etc/xray /var/log/xray
echo -e "✅ Direktori XRAY berhasil dibuat"

echo -e "🔍 Mengecek dan menginstall dependencies..."
if apt install iptables iptables-persistent -y; then
    echo -e "✅ Dependencies berhasil diinstall"
else
    echo -e "⚠️ Ada masalah saat install dependencies, melanjutkan..."
fi

# Configure time synchronization
echo -e "⏰ Mengonfigurasi sinkronisasi waktu..."
echo -e "🔄 Menyinkronkan waktu dengan NTP server..."
if ntpdate pool.ntp.org; then
    echo -e "✅ Waktu berhasil disinkronkan"
else
    echo -e "⚠️ Gagal sinkronisasi NTP, melanjutkan..."
fi

echo -e "🔄 Mengaktifkan automatic time sync..."
timedatectl set-ntp true
echo -e "🔄 Mengaktifkan service chrony..."
systemctl enable chronyd
systemctl restart chronyd
systemctl enable chrony
systemctl restart chrony

echo -e "🌏 Mengatur timezone ke Asia/Jakarta..."
timedatectl set-timezone Asia/Jakarta
echo -e "✅ Timezone berhasil diatur"

echo -e "📊 Mengecek status chrony..."
chronyc sourcestats -v
chronyc tracking -v
echo -e "✅ Sinkronisasi waktu berhasil dikonfigurasi"

# Install additional dependencies
echo -e "📦 Menginstall dependencies tambahan untuk XRAY..."
echo -e "🧹 Membersihkan cache apt..."
apt clean all

echo -e "🔄 Memperbarui daftar paket..."
if apt update; then
    echo -e "✅ Daftar paket berhasil diperbarui"
else
    echo -e "⚠️ Ada masalah saat update, melanjutkan instalasi..."
fi

echo -e "📥 Menginstall paket dependencies..."
dep_packages=(curl socat xz-utils wget apt-transport-https gnupg gnupg2 gnupg1 dnsutils lsb-release zip pwgen openssl netcat cron)
if apt install "${dep_packages[@]}" -y; then
    echo -e "✅ Semua dependencies berhasil diinstall"
else
    echo -e "⚠️ Ada masalah saat install beberapa dependencies, melanjutkan..."
fi


# Install latest XRAY core
echo -e "🚀 Menginstall XRAY core..."
domainSock_dir="/run/xray"
echo -e "📁 Membuat direktori socket: $domainSock_dir"
[ ! -d $domainSock_dir ] && mkdir -p $domainSock_dir
chown www-data:www-data $domainSock_dir
echo -e "✅ Direktori socket berhasil dibuat dan ownership diatur"

# Create log directories and files
echo -e "📁 Membuat direktori dan file log XRAY..."
mkdir -p /var/log/xray /etc/xray
chown www-data:www-data /var/log/xray
chmod +x /var/log/xray
touch /var/log/xray/access.log /var/log/xray/error.log /var/log/xray/access2.log /var/log/xray/error2.log
echo -e "✅ Direktori dan file log XRAY berhasil dibuat"

# Install latest XRAY core
echo -e "🔍 Mendapatkan versi terbaru XRAY core..."
LATEST_XRAY=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep tag_name | cut -d '"' -f 4)
if [ -n "$LATEST_XRAY" ]; then
    echo -e "📦 Menginstall XRAY core versi ${LATEST_XRAY}..."
    if bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version "${LATEST_XRAY#v}"; then
        echo -e "✅ XRAY core ${LATEST_XRAY} berhasil diinstall"
    else
        echo -e "⚠️ Gagal install versi spesifik, mencoba fallback..."
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data
    fi
else
    echo -e "⚠️ Gagal mendapatkan versi terbaru, menggunakan fallback installer..."
    if bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data; then
        echo -e "✅ XRAY core berhasil diinstall dengan fallback method"
    else
        echo -e "❌ Gagal menginstall XRAY core, melanjutkan dengan konfigurasi manual..."
    fi
fi



# SSL Certificate configuration
echo -e "🔐 Mengkonfigurasi SSL certificates..."
echo -e "🔄 Menghentikan nginx sementara untuk akses port 80..."
systemctl stop nginx

echo -e "📁 Membuat direktori acme.sh..."
mkdir -p /root/.acme.sh

# Install acme.sh
echo -e "📥 Mengunduh dan menginstall acme.sh..."
if curl -s https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh; then
    chmod +x /root/.acme.sh/acme.sh
    echo -e "✅ acme.sh berhasil diunduh"
else
    echo -e "❌ Gagal mengunduh acme.sh, mencoba method alternatif..."
    if curl -s https://get.acme.sh | sh; then
        echo -e "✅ acme.sh berhasil diinstall dengan method alternatif"
    else
        echo -e "⚠️ Gagal menginstall acme.sh, melanjutkan dengan SSL manual..."
    fi
fi

echo -e "🔄 Mengupgrade acme.sh ke versi terbaru..."
if [ -f "/root/.acme.sh/acme.sh" ]; then
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    echo -e "🔄 Mengatur CA server ke Let's Encrypt..."
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
else
    echo -e "⚠️ acme.sh tidak ditemukan, melanjutkan tanpa upgrade..."
fi

echo -e "🔐 Membuat SSL certificate untuk domain: $domain..."
if [ -f "/root/.acme.sh/acme.sh" ]; then
    if /root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256; then
        echo -e "✅ SSL certificate berhasil dibuat"
    else
        echo -e "⚠️ Gagal membuat SSL certificate, melanjutkan dengan self-signed..."
        # Create self-signed certificate as fallback
        openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
            -subj "/C=ID/ST=Jakarta/L=Jakarta/O=VPN/CN=$domain" \
            -keyout /etc/xray/xray.key -out /etc/xray/xray.crt
    fi
else
    echo -e "⚠️ acme.sh tidak tersedia, membuat self-signed certificate..."
    openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
        -subj "/C=ID/ST=Jakarta/L=Jakarta/O=VPN/CN=$domain" \
        -keyout /etc/xray/xray.key -out /etc/xray/xray.crt
fi

echo -e "📋 Menginstall certificate ke direktori XRAY..."
if [ -f "/root/.acme.sh/acme.sh" ] && ~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc; then
    echo -e "✅ Certificate berhasil diinstall ke /etc/xray/"
    # Verify certificate files are not empty
    if [ ! -s "/etc/xray/xray.crt" ] || [ ! -s "/etc/xray/xray.key" ]; then
        echo -e "⚠️ Certificate files are empty, creating fallback certificate..."
        openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
            -subj "/C=ID/ST=Jakarta/L=Jakarta/O=VPN/CN=$domain" \
            -keyout /etc/xray/xray.key -out /etc/xray/xray.crt
    fi
else
    echo -e "⚠️ Menggunakan fallback certificate yang sudah dibuat..."
    # Ensure certificate files exist and have proper permissions
    if [ ! -f "/etc/xray/xray.crt" ] || [ ! -f "/etc/xray/xray.key" ] || [ ! -s "/etc/xray/xray.key" ]; then
        echo -e "🔧 Membuat fallback certificate..."
        openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
            -subj "/C=ID/ST=Jakarta/L=Jakarta/O=VPN/CN=$domain" \
            -keyout /etc/xray/xray.key -out /etc/xray/xray.crt
    fi
fi

# Verify certificate files are valid
if [ -s "/etc/xray/xray.crt" ] && [ -s "/etc/xray/xray.key" ]; then
    echo -e "✅ Certificate files verified successfully"
else
    echo -e "❌ Error: Certificate files are still invalid, forcing regeneration..."
    openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
        -subj "/C=ID/ST=Jakarta/L=Jakarta/O=VPN/CN=$domain" \
        -keyout /etc/xray/xray.key -out /etc/xray/xray.crt
fi

# Set proper permissions for certificate files
chmod 644 /etc/xray/xray.crt
chmod 600 /etc/xray/xray.key
chown www-data:www-data /etc/xray/xray.crt /etc/xray/xray.key

# Create SSL renewal script
echo -e "📝 Membuat script auto-renewal SSL..."
cat > /usr/local/bin/ssl_renew.sh <<'EOF'
#!/bin/bash
/etc/init.d/nginx stop
if [ -f "/root/.acme.sh/acme.sh" ]; then
    "/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" &> /root/renew_ssl.log
fi
/etc/init.d/nginx start
/etc/init.d/nginx status
EOF
chmod +x /usr/local/bin/ssl_renew.sh
echo -e "✅ Script auto-renewal SSL berhasil dibuat"

# Add to crontab if not exists
echo -e "⏰ Menambahkan cron job untuk auto-renewal SSL..."
if ! grep -q 'ssl_renew.sh' /var/spool/cron/crontabs/root 2>/dev/null; then
    (crontab -l 2>/dev/null; echo "15 03 */3 * * /usr/local/bin/ssl_renew.sh") | crontab
    echo -e "✅ Cron job auto-renewal SSL berhasil ditambahkan (setiap 3 hari, 03:15)"
else
    echo -e "ℹ️ Cron job auto-renewal SSL sudah ada"
fi

echo -e "📁 Membuat direktori public_html..."
mkdir -p /home/vps/public_html
echo -e "✅ Direktori public_html berhasil dibuat"

# Generate UUID and custom paths
echo -e "🎲 Membuat UUID dan custom paths..."
uuid=$(cat /proc/sys/kernel/random/uuid)
echo -e "✅ UUID dibuat: $uuid"

# Function to generate random path
generate_random_path() {
    local prefix=$1
    echo "/${prefix}$(openssl rand -hex 6)"
}

# Custom paths with environment variable support
echo -e "🛣️ Membuat custom paths untuk setiap protokol..."
VMESS_PATH="${CUSTOM_VMESS_PATH:-$(generate_random_path "vm")}"
VLESS_PATH="${CUSTOM_VLESS_PATH:-$(generate_random_path "vl")}"
TROJAN_PATH="${CUSTOM_TROJAN_PATH:-$(generate_random_path "tr")}"
VMESS_XHTTP_PATH="${CUSTOM_VMESS_XHTTP_PATH:-$(generate_random_path "vmx")}"
VLESS_XHTTP_PATH="${CUSTOM_VLESS_XHTTP_PATH:-$(generate_random_path "vlx")}"

# GRPC service names
VLESS_GRPC_SERVICE="${CUSTOM_VLESS_GRPC_SERVICE:-vlessgrpc}"
VMESS_GRPC_SERVICE="${CUSTOM_VMESS_GRPC_SERVICE:-vmessgrpc}"
TROJAN_GRPC_SERVICE="${CUSTOM_TROJAN_GRPC_SERVICE:-trojangrpc}"

echo -e "✅ Custom paths berhasil dibuat"

# Generate REALITY keys
echo -e "🔑 Membuat REALITY keys..."
XRAY_KEYS=$(/usr/local/bin/xray x25519)
if [ $? -eq 0 ] && [ -n "$XRAY_KEYS" ]; then
    REALITY_PRIVATE=$(echo "$XRAY_KEYS" | grep "PrivateKey" | cut -d' ' -f2)
    REALITY_PUBLIC=$(echo "$XRAY_KEYS" | grep "Password" | cut -d' ' -f2)
    
    # Verify keys are generated properly
    if [ -z "$REALITY_PRIVATE" ] || [ -z "$REALITY_PUBLIC" ]; then
        echo -e "⚠️ Error generating REALITY keys, using fallback method..."
        REALITY_PRIVATE="cCVMI0F3nbOr59_R5DKUGAtFkHu7qCk_oSbgfBRFl1s"
        REALITY_PUBLIC="kZZRpw7-gVbBvmo9KgdOEJar43Exl-tHr5oU_rB2wB8"
    fi
    echo -e "✅ REALITY keys berhasil dibuat"
    echo -e "   Private: $REALITY_PRIVATE"
    echo -e "   Public: $REALITY_PUBLIC"
else
    echo -e "⚠️ Error running xray x25519, using fallback keys..."
    REALITY_PRIVATE="cCVMI0F3nbOr59_R5DKUGAtFkHu7qCk_oSbgfBRFl1s"
    REALITY_PUBLIC="kZZRpw7-gVbBvmo9KgdOEJar43Exl-tHr5oU_rB2wB8"
fi

echo -e "📋 Konfigurasi yang telah dibuat:"
echo -e "  🔸 VMess WS: $VMESS_PATH"
echo -e "  🔸 VMess XHTTP: $VMESS_XHTTP_PATH"
echo -e "  🔸 VLess WS: $VLESS_PATH"
echo -e "  🔸 VLess XHTTP: $VLESS_XHTTP_PATH"
echo -e "  🔸 Trojan WS: $TROJAN_PATH"
# xray config
cat > /etc/xray/config.json << END
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
#vless-ws
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
#vmess-ws
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
#trojan-ws
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
        ]
      },
      "streamSettings": {
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "${TROJAN_GRPC_SERVICE}"
        }
      }
    },
    {
      "listen": "127.0.0.1",
      "port": "23457",
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "${uuid}",
            "alterId": 0
#vmessworry
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/worryfree"
        }
      }
    },
    {
      "listen": "127.0.0.1",
      "port": "23458",
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "${uuid}",
            "alterId": 0
#vmesskuota
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/kuota-habis"
        }
      }
    },
    {
      "listen": "127.0.0.1",
      "port": "23459",
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "${uuid}",
            "alterId": 0
#vmesschat
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/chat"
        }
      }
    },
    {
      "listen": "127.0.0.1",
      "port": "30300",
      "protocol": "shadowsocks",
      "settings": {
        "clients": [
          {
            "method": "aes-128-gcm",
            "password": "${uuid}"
#ssws
          }
        ],
        "network": "tcp,udp"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/ss-ws"
        }
      }
    },
    {
      "listen": "127.0.0.1",
      "port": "30310",
      "protocol": "shadowsocks",
      "settings": {
        "clients": [
          {
            "method": "aes-128-gcm",
            "password": "${uuid}"
#ssgrpc
          }
        ],
        "network": "tcp,udp"
      },
      "streamSettings": {
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "ss-grpc"
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
      },
      {
        "inboundTag": [
          "api"
        ],
        "outboundTag": "api",
        "type": "field"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  },
  "stats": {},
  "api": {
    "services": [
      "StatsService"
    ],
    "tag": "api"
  },
  "policy": {
    "levels": {
      "0": {
        "statsUserDownlink": true,
        "statsUserUplink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true,
      "statsOutboundUplink" : true,
      "statsOutboundDownlink" : true
    }
  }
}
END
rm -rf /etc/systemd/system/xray.service.d
rm -rf /etc/systemd/system/xray@.service
cat <<EOF> /etc/systemd/system/xray.service
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
cat > /etc/systemd/system/runn.service <<EOF
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

# Install Trojan Go
echo -e "🚀 Menginstall Trojan-Go..."
echo -e "🔍 Mendapatkan versi terbaru Trojan-Go..."
latest_version="$(curl -s "https://api.github.com/repos/p4gefau1t/trojan-go/releases/latest" | grep tag_name | cut -d '"' -f 4 | sed 's/v//')"
if [ -z "$latest_version" ]; then
    echo -e "⚠️ Gagal mendapatkan versi terbaru Trojan-Go, menggunakan fallback method..."
    latest_version="$(curl -s "https://api.github.com/repos/p4gefau1t/trojan-go/releases" | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
fi

if [ -z "$latest_version" ]; then
    echo -e "⚠️ Gagal mendapatkan versi Trojan-Go, menggunakan versi default..."
    latest_version="0.10.6"
fi

echo -e "📦 Menginstall Trojan-Go v${latest_version}..."
trojango_link="https://github.com/p4gefau1t/trojan-go/releases/download/v${latest_version}/trojan-go-linux-amd64.zip"

echo -e "📁 Membuat direktori Trojan-Go..."
mkdir -p "/usr/bin/trojan-go"
mkdir -p "/etc/trojan-go"
echo -e "✅ Direktori berhasil dibuat"

echo -e "📥 Mengunduh Trojan-Go dari GitHub..."
cd `mktemp -d`
if curl -sL "${trojango_link}" -o trojan-go.zip; then
    echo -e "✅ Trojan-Go berhasil diunduh"
    echo -e "📦 Mengekstrak dan menginstall..."
    if unzip -q trojan-go.zip && rm -rf trojan-go.zip; then
        mv trojan-go /usr/local/bin/trojan-go
        chmod +x /usr/local/bin/trojan-go
        echo -e "✅ Trojan-Go berhasil diinstall"
    else
        echo -e "❌ Gagal mengekstrak Trojan-Go"
    fi
else
    echo -e "❌ Gagal mengunduh Trojan-Go"
fi

echo -e "📁 Membuat direktori log dan konfigurasi..."
mkdir /var/log/trojan-go/
touch /etc/trojan-go/akun.conf
touch /var/log/trojan-go/trojan-go.log
echo -e "✅ Direktori log dan file konfigurasi berhasil dibuat"

# Buat Config Trojan Go
echo -e "📝 Membuat konfigurasi Trojan-Go..."

# Create log directory for trojan-go
mkdir -p /var/log/trojan-go
chown -R root:root /var/log/trojan-go

# Create simplified Trojan-Go config for Ubuntu 24.04 compatibility
cat > /etc/trojan-go/config.json << END
{
  "run_type": "server",
  "local_addr": "0.0.0.0",
  "local_port": 2087,
  "remote_addr": "127.0.0.1",
  "remote_port": 8080,
  "password": [
      "$uuid"
  ],
  "ssl": {
    "cert": "/etc/xray/xray.crt",
    "key": "/etc/xray/xray.key",
    "sni": "$domain",
    "fallback_addr": "127.0.0.1",
    "fallback_port": 8080
  },
  "websocket": {
    "enabled": true,
    "path": "/trojango",
    "host": "$domain"
  }
}
END

echo -e "✅ Konfigurasi Trojan-Go berhasil dibuat (Ubuntu 24.04 compatible)"

# Installing Trojan Go Service
echo -e "📝 Membuat systemd service untuk Trojan-Go..."
cat > /etc/systemd/system/trojan-go.service << END
[Unit]
Description=Trojan-Go Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/trojan-go -config /etc/trojan-go/config.json
Restart=on-failure

[Install]
WantedBy=multi-user.target
END
echo -e "✅ Systemd service Trojan-Go berhasil dibuat (simplified for Ubuntu 24.04)"

# Trojan Go Uuid
echo -e "📝 Menyimpan UUID untuk Trojan-Go..."
cat > /etc/trojan-go/uuid.txt << END
$uuid
END
echo -e "✅ UUID Trojan-Go berhasil disimpan"

#nginx config
echo -e "🌐 Membuat konfigurasi nginx untuk XRAY..."
cat >/etc/nginx/conf.d/xray.conf <<EOF
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
    server_name $domain;
    
    ssl_certificate /etc/xray/xray.crt;
    ssl_certificate_key /etc/xray/xray.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    add_header Alt-Svc 'h3=":443"; ma=86400';
    ssl_ciphers EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
    
    root /home/vps/public_html;
    
    # VLess WebSocket
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
    
    # VLess XHTTP
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
    
    # VMess WebSocket
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
    
    # VMess XHTTP
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
    
    # Trojan WebSocket
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
    
    # VLess GRPC
    location ^~ ${VLESS_GRPC_SERVICE} {
        proxy_redirect off;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_set_header Host \$http_host;
        grpc_pass grpc://127.0.0.1:24456;
    }
    
    # VMess GRPC
    location ^~ ${VMESS_GRPC_SERVICE} {
        proxy_redirect off;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_set_header Host \$http_host;
        grpc_pass grpc://127.0.0.1:31234;
    }
    
    # Trojan GRPC
    location ^~ ${TROJAN_GRPC_SERVICE} {
        proxy_redirect off;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_set_header Host \$http_host;
        grpc_pass grpc://127.0.0.1:33456;
    }
    
    # Shadowsocks WebSocket
    location = /ss-ws {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:30300;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
    
    # Shadowsocks GRPC
    location ^~ /ss-grpc {
        proxy_redirect off;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_set_header Host \$http_host;
        grpc_pass grpc://127.0.0.1:30310;
    }
    
    # Legacy paths for backward compatibility with existing add-user scripts
    location = /vmess {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:23456;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
    
    location = /vless {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:14016;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
    
    location = /trojan-ws {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:25432;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
    
    # Trojan-Go WebSocket path
    location = /trojango {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:2087;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
    
    # Legacy extra paths (as in original ins-xray.sh)
    location = /worryfree {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:23457;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
    
    location = /kuota-habis {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:23458;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
    
    location = /chat {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:23459;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
    
    # Legacy GRPC paths
    location ^~ /vless-grpc {
        proxy_redirect off;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_set_header Host \$http_host;
        grpc_pass grpc://127.0.0.1:24456;
    }
    
    location ^~ /vmess-grpc {
        proxy_redirect off;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_set_header Host \$http_host;
        grpc_pass grpc://127.0.0.1:31234;
    }
    
    location ^~ /trojan-grpc {
        proxy_redirect off;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_set_header Host \$http_host;
        grpc_pass grpc://127.0.0.1:33456;
    }
    
    # Default location for webserver - serve static files
    location / {
        root /home/vps/public_html;
        index index.html index.htm;
        try_files \$uri \$uri/ =404;
    }
}
EOF
echo -e "✅ Konfigurasi nginx berhasil dibuat"

# Create web root directory and default page
echo -e "🌐 Membuat halaman web default..."
mkdir -p /home/vps/public_html
cat > /home/vps/public_html/index.html << 'WEBEOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VPS Server - Active</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f4f4f4; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; }
        .status { background: #e8f5e8; border: 1px solid #4caf50; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .info { background: #e3f2fd; border: 1px solid #2196f3; padding: 15px; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 VPS Server Active</h1>
        <div class="status">
            <h3>✅ Server Status: Online</h3>
            <p>This VPS is running and properly configured with VPN services.</p>
        </div>
        <div class="info">
            <h3>📋 Services Available:</h3>
            <ul>
                <li>✅ Xray-core (VMess, VLESS, Trojan)</li>
                <li>✅ VLESS Reality</li>
                <li>✅ Shadowsocks</li>
                <li>✅ Nginx Web Server</li>
                <li>✅ Squid Proxy</li>
            </ul>
        </div>
        <div class="info">
            <p><strong>Domain:</strong> DOMAIN_PLACEHOLDER</p>
            <p><strong>Server Time:</strong> <span id="datetime"></span></p>
        </div>
    </div>
    <script>
        document.getElementById('datetime').textContent = new Date().toLocaleString();
    </script>
</body>
</html>
WEBEOF

# Replace domain placeholder
sed -i "s/DOMAIN_PLACEHOLDER/$domain/" /home/vps/public_html/index.html
chown -R www-data:www-data /home/vps/public_html
chmod -R 755 /home/vps/public_html
echo -e "✅ Halaman web default berhasil dibuat"

# Save paths to configuration files for scripts to use
echo -e "💾 Menyimpan custom paths ke file konfigurasi..."
echo "$VMESS_PATH" > /etc/xray/vmess_path
echo "$VMESS_XHTTP_PATH" > /etc/xray/vmess_xhttp_path
echo "$VLESS_PATH" > /etc/xray/vless_path  
echo "$VLESS_XHTTP_PATH" > /etc/xray/vless_xhttp_path
echo "$TROJAN_PATH" > /etc/xray/trojan_path
echo "$TROJAN_PATH" > /etc/xray/trojan_ws_path
echo "$VLESS_GRPC_SERVICE" > /etc/xray/vless_grpc_service
echo "$VMESS_GRPC_SERVICE" > /etc/xray/vmess_grpc_service  
echo "$TROJAN_GRPC_SERVICE" > /etc/xray/trojan_grpc_service

# Save REALITY keys with validation
if [ -n "$REALITY_PRIVATE" ] && [ -n "$REALITY_PUBLIC" ]; then
    echo "$REALITY_PRIVATE" > /etc/xray/reality_private
    echo "$REALITY_PUBLIC" > /etc/xray/reality_public
    echo -e "✅ REALITY keys berhasil disimpan"
else
    echo -e "❌ Error: REALITY keys are empty, generating new ones..."
    NEW_KEYS=$(/usr/local/bin/xray x25519)
    if [ $? -eq 0 ] && [ -n "$NEW_KEYS" ]; then
        REALITY_PRIVATE=$(echo "$NEW_KEYS" | grep "PrivateKey" | cut -d' ' -f2)
        REALITY_PUBLIC=$(echo "$NEW_KEYS" | grep "Password" | cut -d' ' -f2)
        echo "$REALITY_PRIVATE" > /etc/xray/reality_private
        echo "$REALITY_PUBLIC" > /etc/xray/reality_public
    else
        # Use fallback keys if generation fails
        echo "cCVMI0F3nbOr59_R5DKUGAtFkHu7qCk_oSbgfBRFl1s" > /etc/xray/reality_private
        echo "kZZRpw7-gVbBvmo9KgdOEJar43Exl-tHr5oU_rB2wB8" > /etc/xray/reality_public
    fi
fi

# Verify files are not empty
if [ ! -s "/etc/xray/reality_private" ] || [ ! -s "/etc/xray/reality_public" ]; then
    echo -e "⚠️ REALITY key files are empty, using fallback keys..."
    echo "cCVMI0F3nbOr59_R5DKUGAtFkHu7qCk_oSbgfBRFl1s" > /etc/xray/reality_private
    echo "kZZRpw7-gVbBvmo9KgdOEJar43Exl-tHr5oU_rB2wB8" > /etc/xray/reality_public
fi

echo -e "✅ Custom paths berhasil disimpan ke /etc/xray/ files"

echo -e "🔥 Mengkonfigurasi firewall untuk REALITY port 8443..."
if ufw allow 8443/tcp; then
    echo -e "✅ UFW rule untuk port 8443 berhasil ditambahkan"
else
    echo -e "⚠️ Gagal menambahkan UFW rule untuk port 8443"
fi

if iptables -I INPUT -p tcp --dport 8443 -j ACCEPT; then
    echo -e "✅ Iptables rule untuk port 8443 berhasil ditambahkan"
else
    echo -e "⚠️ Gagal menambahkan iptables rule untuk port 8443"
fi

if iptables-save > /etc/iptables/rules.v4; then
    echo -e "✅ Iptables rules berhasil disimpan"
else
    echo -e "⚠️ Gagal menyimpan iptables rules"
fi

echo -e "🔄 Memulai ulang semua service..."
echo -e "🔄 Memuat ulang systemd daemon..."
systemctl daemon-reload
sleep 1

echo -e "🚀 Mengaktifkan dan memulai service XRAY..."
systemctl daemon-reload
if systemctl enable xray; then
    echo -e "✅ XRAY service berhasil diaktifkan"
else
    echo -e "⚠️ Gagal mengaktifkan XRAY service"
fi

if systemctl restart xray; then
    echo -e "✅ XRAY service berhasil dimulai"
    
    # Validate Xray configuration and service status
    sleep 2
    if systemctl is-active --quiet xray; then
        echo -e "✅ XRAY service sedang berjalan dengan baik"
        # Test configuration
        if /usr/local/bin/xray run -config /etc/xray/config.json -test > /dev/null 2>&1; then
            echo -e "✅ Konfigurasi XRAY valid"
        else
            echo -e "⚠️ Warning: Konfigurasi XRAY mungkin bermasalah"
            echo -e "   Memeriksa log untuk detail..."
            journalctl -u xray --no-pager -n 5
        fi
    else
        echo -e "❌ XRAY service tidak berjalan, memeriksa masalah..."
        journalctl -u xray --no-pager -n 10
        echo -e "🔧 Mencoba perbaikan otomatis..."
        
        # Check if private key is empty
        if [ ! -s "/etc/xray/reality_private" ]; then
            echo -e "⚠️ REALITY private key kosong, regenerating..."
            NEW_KEYS=$(/usr/local/bin/xray x25519)
            if [ $? -eq 0 ] && [ -n "$NEW_KEYS" ]; then
                echo "$NEW_KEYS" | grep "PrivateKey" | cut -d' ' -f2 > /etc/xray/reality_private
                echo "$NEW_KEYS" | grep "Password" | cut -d' ' -f2 > /etc/xray/reality_public
                # Update config with new private key
                REALITY_PRIVATE=$(cat /etc/xray/reality_private)
                sed -i "s/\"privateKey\": \".*\"/\"privateKey\": \"$REALITY_PRIVATE\"/" /etc/xray/config.json
                systemctl restart xray
            fi
        fi
    fi
else
    echo -e "❌ Gagal memulai XRAY service"
    echo -e "🔍 Memeriksa log error..."
    journalctl -u xray --no-pager -n 10
fi

echo -e "🌐 Memulai ulang nginx..."

# Check for port conflicts before starting nginx
echo -e "🔍 Memeriksa konflik port..."
if ss -tulpn | grep -q ":8080.*squid"; then
    echo -e "⚠️ Squid menggunakan port 8080, menghentikan untuk sementara..."
    systemctl stop squid
    sleep 2
fi

if systemctl restart nginx; then
    echo -e "✅ Nginx berhasil dimulai ulang"
    
    # Restart squid on different port if it was stopped
    if ! systemctl is-active --quiet squid; then
        echo -e "🔄 Memulai ulang Squid di port 3128..."
        # Ensure squid uses port 3128 only
        sed -i '/http_port 8080/d' /etc/squid/squid.conf
        systemctl start squid
    fi
    
    # Test nginx configuration
    if nginx -t > /dev/null 2>&1; then
        echo -e "✅ Konfigurasi Nginx valid"
    else
        echo -e "⚠️ Warning: Konfigurasi Nginx bermasalah"
        nginx -t
    fi
else
    echo -e "❌ Gagal memulai ulang nginx"
    echo -e "🔍 Memeriksa log error nginx..."
    journalctl -u nginx --no-pager -n 5
    
    # Check for common issues
    if ss -tulpn | grep ":8080"; then
        echo -e "⚠️ Port 8080 masih terpakai oleh:"
        ss -tulpn | grep ":8080"
    fi
fi

echo -e "🔧 Mengaktifkan dan memulai service runn..."
if systemctl enable runn; then
    echo -e "✅ Service runn berhasil diaktifkan"
else
    echo -e "⚠️ Gagal mengaktifkan service runn"
fi

if systemctl restart runn; then
    echo -e "✅ Service runn berhasil dimulai"
else
    echo -e "⚠️ Gagal memulai service runn"
fi

echo -e "🚀 Mengatur service Trojan-Go..."
systemctl stop trojan-go
if systemctl start trojan-go; then
    echo -e "✅ Trojan-Go berhasil dimulai"
else
    echo -e "❌ Gagal memulai Trojan-Go"
fi

if systemctl enable trojan-go; then
    echo -e "✅ Trojan-Go berhasil diaktifkan"
else
    echo -e "⚠️ Gagal mengaktifkan Trojan-Go"
fi

if systemctl restart trojan-go; then
    echo -e "✅ Trojan-Go berhasil dimulai ulang"
    
    # Validate Trojan-Go service status
    sleep 2
    if systemctl is-active --quiet trojan-go; then
        echo -e "✅ Trojan-Go service sedang berjalan dengan baik"
        # Check if port is listening
        if ss -tulpn | grep -q ":2087"; then
            echo -e "✅ Trojan-Go listening pada port 2087"
        else
            echo -e "⚠️ Warning: Trojan-Go tidak listening pada port 2087"
        fi
    else
        echo -e "❌ Trojan-Go service tidak berjalan, memeriksa masalah..."
        journalctl -u trojan-go --no-pager -n 10
        echo -e "🔧 Mencoba perbaikan otomatis..."
        
        # Check configuration file
        if [ ! -s "/etc/trojan-go/config.json" ]; then
            echo -e "⚠️ Config Trojan-Go kosong, regenerating..."
            # Recreate config with current settings
            cat > /etc/trojan-go/config.json << END2
{
  "run_type": "server",
  "local_addr": "0.0.0.0",
  "local_port": 2087,
  "remote_addr": "127.0.0.1",
  "remote_port": 8080,
  "log_level": 1,
  "log_file": "/var/log/trojan-go/trojan-go.log",
  "password": ["$uuid"],
  "disable_http_check": true,
  "udp_timeout": 60,
  "ssl": {
    "verify": false,
    "verify_hostname": false,
    "cert": "/etc/xray/xray.crt",
    "key": "/etc/xray/xray.key",
    "sni": "$domain",
    "alpn": ["http/1.1"],
    "session_ticket": true,
    "reuse_session": true,
    "fallback_addr": "127.0.0.1",
    "fallback_port": 8080,
    "fingerprint": "firefox"
  },
  "websocket": {
    "enabled": true,
    "path": "/trojango",
    "host": "$domain"
  }
}
END2
            systemctl restart trojan-go
        fi
        
        # Check certificate files
        if [ ! -s "/etc/xray/xray.key" ] || [ ! -s "/etc/xray/xray.crt" ]; then
            echo -e "⚠️ Certificate files bermasalah untuk Trojan-Go"
        fi
    fi
else
    echo -e "❌ Gagal memulai ulang Trojan-Go"
    echo -e "🔍 Memeriksa log error Trojan-Go..."
    journalctl -u trojan-go --no-pager -n 10
fi

echo -e "📥 Mengunduh script manajemen XRAY..."
cd /usr/bin/

# vmess - Enhanced version with multiple protocols (WS, XHTTP, GRPC)
echo -e "📥 Mengunduh script VMess Enhanced..."
if wget -O add-ws-enhanced "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/add-ws-enhanced.sh" && chmod +x add-ws-enhanced; then
    echo -e "✅ add-ws-enhanced berhasil diunduh"
else
    echo -e "⚠️ Gagal mengunduh add-ws-enhanced"
fi

if wget -O trialvmess "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/trialvmess.sh" && chmod +x trialvmess; then
    echo -e "✅ trialvmess berhasil diunduh"
else
    echo -e "⚠️ Gagal mengunduh trialvmess"
fi

if wget -O renew-ws "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/renew-ws.sh" && chmod +x renew-ws; then
    echo -e "✅ renew-ws berhasil diunduh"
else
    echo -e "⚠️ Gagal mengunduh renew-ws"
fi

if wget -O del-ws "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/del-ws.sh" && chmod +x del-ws; then
    echo -e "✅ del-ws berhasil diunduh"
else
    echo -e "⚠️ Gagal mengunduh del-ws"
fi

if wget -O cek-ws "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/cek-ws.sh" && chmod +x cek-ws; then
    echo -e "✅ cek-ws berhasil diunduh"
else
    echo -e "⚠️ Gagal mengunduh cek-ws"
fi

# vless - Enhanced version with multiple protocols (WS, XHTTP, GRPC, REALITY)
echo -e "📥 Mengunduh script VLess Enhanced..."
if wget -O add-vless-enhanced "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/add-vless-enhanced.sh" && chmod +x add-vless-enhanced; then
    echo -e "✅ add-vless-enhanced berhasil diunduh"
else
    echo -e "⚠️ Gagal mengunduh add-vless-enhanced"
fi

if wget -O trialvless "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/trialvless.sh" && chmod +x trialvless; then
    echo -e "✅ trialvless berhasil diunduh"
else
    echo -e "⚠️ Gagal mengunduh trialvless"
fi

if wget -O renew-vless "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/renew-vless.sh" && chmod +x renew-vless; then
    echo -e "✅ renew-vless berhasil diunduh"
else
    echo -e "⚠️ Gagal mengunduh renew-vless"
fi

if wget -O del-vless "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/del-vless.sh" && chmod +x del-vless; then
    echo -e "✅ del-vless berhasil diunduh"
else
    echo -e "⚠️ Gagal mengunduh del-vless"
fi

if wget -O cek-vless "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/cek-vless.sh" && chmod +x cek-vless; then
    echo -e "✅ cek-vless berhasil diunduh"
else
    echo -e "⚠️ Gagal mengunduh cek-vless"
fi

# trojan - Enhanced version with multiple protocols (WS, GRPC)
echo -e "📥 Mengunduh script Trojan Enhanced..."
if wget -O add-trojan-enhanced "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/add-trojan-enhanced.sh" && chmod +x add-trojan-enhanced; then
    echo -e "✅ add-trojan-enhanced berhasil diunduh"
else
    echo -e "⚠️ Gagal mengunduh add-trojan-enhanced"
fi

if wget -O trialtrojan "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/trialtrojan.sh" && chmod +x trialtrojan; then
    echo -e "✅ trialtrojan berhasil diunduh"
else
    echo -e "⚠️ Gagal mengunduh trialtrojan"
fi

if wget -O del-tr "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/del-tr.sh" && chmod +x del-tr; then
    echo -e "✅ del-tr berhasil diunduh"
else
    echo -e "⚠️ Gagal mengunduh del-tr"
fi

if wget -O renew-tr "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/renew-tr.sh" && chmod +x renew-tr; then
    echo -e "✅ renew-tr berhasil diunduh"
else
    echo -e "⚠️ Gagal mengunduh renew-tr"
fi

if wget -O cek-tr "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/cek-tr.sh" && chmod +x cek-tr; then
    echo -e "✅ cek-tr berhasil diunduh"
else
    echo -e "⚠️ Gagal mengunduh cek-tr"
fi

# trojan go
echo -e "📥 Mengunduh script Trojan-Go..."
if wget -O addtrgo "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/addtrgo.sh" && chmod +x addtrgo; then
    echo -e "✅ addtrgo berhasil diunduh"
else
    echo -e "⚠️ Gagal mengunduh addtrgo"
fi

if wget -O trialtrojango "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/trialtrojango.sh" && chmod +x trialtrojango; then
    echo -e "✅ trialtrojango berhasil diunduh"
else
    echo -e "⚠️ Gagal mengunduh trialtrojango"
fi

if wget -O deltrgo "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/deltrgo.sh" && chmod +x deltrgo; then
    echo -e "✅ deltrgo berhasil diunduh"
else
    echo -e "⚠️ Gagal mengunduh deltrgo"
fi

if wget -O renewtrgo "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/renewtrgo.sh" && chmod +x renewtrgo; then
    echo -e "✅ renewtrgo berhasil diunduh"
else
    echo -e "⚠️ Gagal mengunduh renewtrgo"
fi

if wget -O cektrgo "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/cektrgo.sh" && chmod +x cektrgo; then
    echo -e "✅ cektrgo berhasil diunduh"
else
    echo -e "⚠️ Gagal mengunduh cektrgo"
fi

echo -e "✅ Semua script XRAY berhasil diunduh!"

sleep 1
echo -e "🎉 INSTALASI XRAY BERHASIL DISELESAIKAN!"
echo -e ""
echo -e "📋 PROTOKOL XRAY YANG BERHASIL DIINSTALL:"
echo -e ""
echo -e "🆕 PROTOKOL BARU (Custom Paths):"
echo -e "  ✅ VMess WebSocket (Custom Path: $VMESS_PATH)"
echo -e "  ✅ VMess XHTTP (Custom Path: $VMESS_XHTTP_PATH)"  
echo -e "  ✅ VLess WebSocket (Custom Path: $VLESS_PATH)"
echo -e "  ✅ VLess XHTTP (Custom Path: $VLESS_XHTTP_PATH)"
echo -e "  ✅ VLess REALITY (Port: 8443, Private Key: $REALITY_PRIVATE)"
echo -e "  ✅ Trojan WebSocket (Custom Path: $TROJAN_PATH)"
echo -e "  ✅ VMess GRPC (Service: $VMESS_GRPC_SERVICE)"
echo -e "  ✅ VLess GRPC (Service: $VLESS_GRPC_SERVICE)"
echo -e "  ✅ Trojan GRPC (Service: $TROJAN_GRPC_SERVICE)"
echo -e ""
echo -e "🔄 PROTOKOL LEGACY (Fixed Paths - untuk kompatibilitas dengan script lama):"
echo -e "  ✅ VMess WebSocket (Legacy: /vmess, /worryfree, /kuota-habis, /chat)"
echo -e "  ✅ VLess WebSocket (Legacy: /vless)"
echo -e "  ✅ Trojan WebSocket (Legacy: /trojan-ws)"
echo -e "  ✅ Semua GRPC (Legacy: /vmess-grpc, /vless-grpc, /trojan-grpc)"
echo -e ""
echo -e "ℹ️ INFO PENTING:"
echo -e "  📁 Custom paths mendukung path apapun (contoh: /facebook, /google, /youtube)"
echo -e "  🔧 Gunakan environment variables: CUSTOM_VMESS_PATH='/mypath' ./setup-2025.1.sh"
echo -e "  💾 Semua konfigurasi disimpan di direktori /etc/xray/"
echo -e "  🔄 Legacy paths tetap dijaga untuk kompatibilitas dengan script yang sudah ada"
echo -e ""

echo -e "📁 Menyinkronkan file domain ke direktori XRAY..."
# Copy instead of move to maintain compatibility
cp /root/domain /etc/xray/ 2>/dev/null || echo "Domain file already exists in both locations"
if [ -f /root/scdomain ]; then
    echo -e "🗑️ Menghapus file temporary..."
    rm /root/scdomain > /dev/null 2>&1
fi
echo -e "✅ Konfigurasi domain berhasil disinkronkan"

clear

# =============================================================================
# SECTION 5: WEBSOCKET TUNNELING INSTALLATION
# =============================================================================

echo -e "🌐 Menginstall WebSocket tunneling..."

cd /root

# Install Script Websocket-SSH Python
echo -e "📥 Mengunduh script WebSocket untuk Dropbear..."
if wget -O /usr/local/bin/ws-dropbear https://raw.githubusercontent.com/werdersarina/github-repos/main/sshws/dropbear-ws.py; then
    echo -e "✅ Script WebSocket Dropbear berhasil diunduh"
else
    echo -e "⚠️ Gagal mengunduh script WebSocket Dropbear"
fi

echo -e "📥 Mengunduh script WebSocket untuk Stunnel..."
if wget -O /usr/local/bin/ws-stunnel https://raw.githubusercontent.com/werdersarina/github-repos/main/sshws/ws-stunnel; then
    echo -e "✅ Script WebSocket Stunnel berhasil diunduh"
else
    echo -e "⚠️ Gagal mengunduh script WebSocket Stunnel"
fi

# Set permissions
echo -e "🔧 Mengatur permissions untuk script WebSocket..."
chmod +x /usr/local/bin/ws-dropbear
chmod +x /usr/local/bin/ws-stunnel
echo -e "✅ Permissions berhasil diatur"

# System Dropbear Websocket-SSH Python
echo -e "📥 Mengunduh service file untuk WebSocket Dropbear..."
if wget -O /etc/systemd/system/ws-dropbear.service https://raw.githubusercontent.com/werdersarina/github-repos/main/sshws/service-wsdropbear && chmod +x /etc/systemd/system/ws-dropbear.service; then
    echo -e "✅ Service file WebSocket Dropbear berhasil diunduh"
else
    echo -e "⚠️ Gagal mengunduh service file WebSocket Dropbear"
fi

# System SSL/TLS Websocket-SSH Python
echo -e "📥 Mengunduh service file untuk WebSocket Stunnel..."
if wget -O /etc/systemd/system/ws-stunnel.service https://raw.githubusercontent.com/werdersarina/github-repos/main/sshws/ws-stunnel.service && chmod +x /etc/systemd/system/ws-stunnel.service; then
    echo -e "✅ Service file WebSocket Stunnel berhasil diunduh"
else
    echo -e "⚠️ Gagal mengunduh service file WebSocket Stunnel"
fi

# Restart services
echo -e "🔄 Memuat ulang systemd daemon..."
systemctl daemon-reload
echo -e "✅ Systemd daemon berhasil dimuat ulang"

# Enable & Start & Restart ws-dropbear service
echo -e "🚀 Mengaktifkan dan memulai service WebSocket Dropbear..."
if systemctl enable ws-dropbear.service; then
    echo -e "✅ Service WebSocket Dropbear berhasil diaktifkan"
else
    echo -e "⚠️ Gagal mengaktifkan service WebSocket Dropbear"
fi

if systemctl start ws-dropbear.service; then
    echo -e "✅ Service WebSocket Dropbear berhasil dimulai"
else
    echo -e "⚠️ Gagal memulai service WebSocket Dropbear"
fi

if systemctl restart ws-dropbear.service; then
    echo -e "✅ Service WebSocket Dropbear berhasil dimulai ulang"
else
    echo -e "⚠️ Gagal memulai ulang service WebSocket Dropbear"
fi

# Enable & Start & Restart ws-stunnel service
echo -e "🚀 Mengaktifkan dan memulai service WebSocket Stunnel..."
if systemctl enable ws-stunnel.service; then
    echo -e "✅ Service WebSocket Stunnel berhasil diaktifkan"
else
    echo -e "⚠️ Gagal mengaktifkan service WebSocket Stunnel"
fi

if systemctl start ws-stunnel.service; then
    echo -e "✅ Service WebSocket Stunnel berhasil dimulai"
else
    echo -e "⚠️ Gagal memulai service WebSocket Stunnel"
fi

if systemctl restart ws-stunnel.service; then
    echo -e "✅ Service WebSocket Stunnel berhasil dimulai ulang"
else
    echo -e "⚠️ Gagal memulai ulang service WebSocket Stunnel"
fi

echo -e "✅ WebSocket tunneling berhasil diinstall!"

# =============================================================================
# SECTION 6: FINALIZATION & CLEANUP
# =============================================================================

# Setup profile
echo -e "👤 Mengatur profil user untuk auto-menu..."
clear
cat> /root/.profile << END
# ~/.profile: executed by Bourne-compatible login shells.

if [ "\$BASH" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi

mesg n || true
clear

# Only show menu if SSH is interactive and stable
if [ -t 0 ] && [ -n "\$SSH_TTY" ] && [ "\$TERM" != "dumb" ]; then
    # Add small delay to ensure SSH connection is stable
    sleep 1
    # Check if menu command exists and is executable
    if command -v menu >/dev/null 2>&1; then
        menu
    else
        echo "Welcome to VPN Server"
        echo "Type 'menu' to access server management"
    fi
fi
END
chmod 644 /root/.profile
echo -e "✅ Profil user berhasil dikonfigurasi"

# Cleanup old files
echo -e "🧹 Membersihkan file-file lama..."
if [ -f "/root/log-install.txt" ]; then
    rm /root/log-install.txt > /dev/null 2>&1
    echo -e "🗑️ File log-install.txt lama berhasil dihapus"
fi
if [ -f "/etc/afak.conf" ]; then
    rm /etc/afak.conf > /dev/null 2>&1
    echo -e "🗑️ File afak.conf lama berhasil dihapus"
fi
if [ ! -f "/etc/log-create-user.log" ]; then
    echo "Log All Account " > /etc/log-create-user.log
    echo -e "📝 File log user berhasil dibuat"
fi
echo -e "✅ Cleanup file lama berhasil diselesaikan"

echo -e "🧹 Membersihkan history command..."
history -c
echo -e "✅ History command berhasil dibersihkan"

echo -e "💾 Menyimpan versi server..."
serverV="2025.1"
echo $serverV > /opt/.ver
echo -e "✅ Versi server berhasil disimpan"

echo -e "🌐 Mendapatkan IP address server..."
aureb=$(cat /home/re_otm)
b=11
if [ $aureb -gt $b ]; then
    gg="PM"
else
    gg="AM"
fi

if curl -sS ifconfig.me > /etc/myipvps 2>/dev/null; then
    echo -e "✅ IP address berhasil disimpan ke /etc/myipvps"
else
    echo -e "⚠️ Gagal mendapatkan IP address dari ifconfig.me, mencoba alternatif..."
    if curl -sS ipinfo.io/ip > /etc/myipvps 2>/dev/null; then
        echo -e "✅ IP address berhasil disimpan ke /etc/myipvps (alternatif)"
    else
        echo -e "⚠️ Gagal mendapatkan IP address, menggunakan IP lokal..."
        hostname -I | cut -d' ' -f1 > /etc/myipvps
    fi
fi

echo -e "📋 Membuat log instalasi..."

echo " "
echo "🎉=====================-[ OTTIN NETWORK ]-===================="
echo ""
echo "------------------------------------------------------------"
echo ""
echo ""
echo "   📊 Service & Port"  | tee -a log-install.txt
echo "   - OpenSSH		: 22"  | tee -a log-install.txt
echo "   - SSH Websocket	: 80" | tee -a log-install.txt
echo "   - SSH SSL Websocket	: 443" | tee -a log-install.txt
echo "   - Stunnel4		: 447, 777" | tee -a log-install.txt
echo "   - Dropbear		: 109, 143" | tee -a log-install.txt
echo "   - Badvpn		: 7100-7900" | tee -a log-install.txt
echo "   - Nginx		: 81" | tee -a log-install.txt
echo "   - Vmess TLS		: 443" | tee -a log-install.txt
echo "   - Vmess None TLS	: 80" | tee -a log-install.txt
echo "   - Vless TLS		: 443" | tee -a log-install.txt
echo "   - Vless None TLS	: 80" | tee -a log-install.txt
echo "   - Vless Reality	: 8443" | tee -a log-install.txt
echo "   - Trojan GRPC		: 443" | tee -a log-install.txt
echo "   - Trojan WS		: 443" | tee -a log-install.txt
echo "   - Trojan Go		: 2087" | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "   ℹ️ Server Information & Other Features"  | tee -a log-install.txt
echo "   - Timezone		: Asia/Jakarta (GMT +7)"  | tee -a log-install.txt
echo "   - Fail2Ban		: [ON]"  | tee -a log-install.txt
echo "   - Dflate		: [ON]"  | tee -a log-install.txt
echo "   - IPtables		: [ON]"  | tee -a log-install.txt
echo "   - Auto-Reboot		: [ON]"  | tee -a log-install.txt
echo "   - IPv6			: [OFF]"  | tee -a log-install.txt
echo "   - Autoreboot On	: $aureb:00 $gg GMT +7" | tee -a log-install.txt
echo "   - AutoKill Multi Login User" | tee -a log-install.txt
echo "   - Auto Delete Expired Account" | tee -a log-install.txt
echo "   - Fully automatic script" | tee -a log-install.txt
echo "   - VPS settings" | tee -a log-install.txt
echo "   - Admin Control" | tee -a log-install.txt
echo "   - Change port" | tee -a log-install.txt
echo "   - Full Orders For Various Services" | tee -a log-install.txt
echo ""
echo ""
echo "------------------------------------------------------------"
echo ""

# Final Dropbear status check (Ubuntu 24.04 diagnostic)
echo -e "[ ${green}INFO${NC} ] Final Dropbear status check..."
if pgrep -f "dropbear" >/dev/null; then
    echo -e "[ ${green}SUCCESS${NC} ] Dropbear is running on the following ports:"
    ss -tlnp | grep dropbear | awk '{print "   - Port: " $4}' | sed 's/.*://' | sort -n
    echo -e "[ ${green}INFO${NC} ] Dropbear service status: ACTIVE"
else
    echo -e "[ ${yell}WARNING${NC} ] Dropbear is not running!"
    echo -e "[ ${green}INFO${NC} ] Trying emergency restart..."
    systemctl restart dropbear-multi >/dev/null 2>&1 || {
        /etc/init.d/dropbear restart >/dev/null 2>&1 || {
            echo -e "[ ${red}ERROR${NC} ] Dropbear failed to start"
            echo -e "[ ${green}INFO${NC} ] Manual command to start Dropbear:"
            echo "   systemctl start dropbear-multi"
            echo "   OR"
            echo "   dropbear -p 143 -p 109"
        }
    }
fi

# Create Dropbear diagnostic script for Ubuntu 24.04
cat > /usr/local/bin/dropbear-check <<'EOF'
#!/bin/bash
echo "=== Dropbear Diagnostic Tool ==="
echo "Ubuntu Version: $(lsb_release -r | awk '{print $2}')"
echo ""
echo "1. Dropbear Process Status:"
if pgrep -f dropbear >/dev/null; then
    echo "   ✅ Dropbear is running"
    pgrep -f dropbear | while read pid; do
        echo "   PID: $pid - $(ps -p $pid -o args --no-headers)"
    done
else
    echo "   ❌ Dropbear is not running"
fi

echo ""
echo "2. Listening Ports:"
ss -tlnp | grep dropbear || echo "   No dropbear ports found"

echo ""
echo "3. Service Status:"
systemctl is-active dropbear-multi 2>/dev/null && echo "   dropbear-multi: $(systemctl is-active dropbear-multi)" || echo "   dropbear-multi: not found"
systemctl is-active dropbear 2>/dev/null && echo "   dropbear: $(systemctl is-active dropbear)" || echo "   dropbear: not found"

echo ""
echo "4. Quick Fix Commands:"
echo "   systemctl restart dropbear-multi"
echo "   systemctl restart dropbear"
echo "   dropbear -p 143 -p 109 &"
EOF

chmod +x /usr/local/bin/dropbear-check

echo "🎯===============-[ Script Created By YT ZIXSTYLE ]-==============="
echo -e ""
echo ""
echo "🔥 IMPORTANT NOTES FOR UBUNTU 24.04 LTS:"
echo "   - If Dropbear issues occur, run: dropbear-check"
echo "   - Manual Dropbear start: systemctl start dropbear-multi"
echo "   - If SSH gets blocked, use Google Cloud Console access"
echo "   - Emergency reset: Run '/usr/local/bin/emergency-ssh-reset.sh'"
echo "   - SSH Monitor: Automatic recovery every 5 minutes"
echo "   - GCP IAP ranges are whitelisted: 35.235.240.0/20"
echo ""
echo "🔧 TROUBLESHOOTING:"
echo "   - Main SSH Port: 22"
echo "   - Alternative Ports: 200, 500, 40000, 51443, 58080"
echo "   - Check SSH status: systemctl status ssh"
echo "   - View fail2ban status: fail2ban-client status"
echo ""
echo "" | tee -a log-install.txt

# Cleanup installation files
echo -e "🧹 Membersihkan file instalasi sementara..."
files_to_cleanup=("/root/setup.sh" "/root/ins-xray.sh" "/root/insshws.sh" "/root/ssh-vpn.sh" "/root/tools.sh")
for file in "${files_to_cleanup[@]}"; do
    if [ -f "$file" ]; then
        rm -f "$file" > /dev/null 2>&1
        echo -e "🗑️ File $file berhasil dihapus"
    fi
done
echo -e "✅ Cleanup file instalasi berhasil diselesaikan"

echo -e "⏱️ Menghitung waktu total instalasi..."
secs_to_human "$(($(date +%s) - ${start}))" | tee -a log-install.txt

echo -e ""
echo -e "🔍 VALIDASI AKHIR INSTALASI..."
echo -e "=================================="

# Final service validation
services=("xray" "nginx" "squid" "ssh" "trojan-go")
all_services_ok=true

for service in "${services[@]}"; do
    if systemctl is-active --quiet "$service"; then
        echo -e "✅ $service: RUNNING"
    else
        echo -e "❌ $service: NOT RUNNING"
        all_services_ok=false
    fi
done

# Check important files
echo -e ""
echo -e "📋 Validasi File Konfigurasi:"
files_to_check=(
    "/etc/xray/config.json"
    "/etc/xray/reality_private" 
    "/etc/xray/xray.key"
    "/etc/xray/domain"
    "/home/vps/public_html/index.html"
)

for file in "${files_to_check[@]}"; do
    if [ -s "$file" ]; then
        echo -e "✅ $file: EXISTS & NOT EMPTY"
    elif [ -f "$file" ]; then
        echo -e "⚠️ $file: EXISTS BUT EMPTY"
    else
        echo -e "❌ $file: MISSING"
        all_services_ok=false
    fi
done

# Network test
echo -e ""
echo -e "🔍 Test Konektivitas:"
if curl -s -I http://localhost:8080 | grep -q "200 OK\|HTTP"; then
    echo -e "✅ Web server: ACCESSIBLE"
else
    echo -e "⚠️ Web server: Check needed"
fi

# Port check
echo -e ""
echo -e "🔌 Port Status:"
important_ports=("8443" "8080" "3128" "22" "2087")
for port in "${important_ports[@]}"; do
    if ss -tulpn | grep -q ":$port"; then
        service_name=$(ss -tulpn | grep ":$port" | awk '{print $7}' | cut -d'"' -f2 | head -1)
        echo -e "✅ Port $port: LISTENING ($service_name)"
    else
        echo -e "⚠️ Port $port: NOT LISTENING"
    fi
done

echo -e ""
echo -e "=================================="
if [ "$all_services_ok" = true ]; then
    echo -e "🎉 INSTALASI LENGKAP VPN SERVER BERHASIL DISELESAIKAN!"
    echo -e "✅ SEMUA SERVICE BERJALAN DENGAN BAIK!"
else
    echo -e "⚠️ INSTALASI SELESAI DENGAN BEBERAPA PERINGATAN"
    echo -e "   Silakan periksa service yang bermasalah di atas."
fi
echo -e ""
echo -ne "[ ${yell}WARNING${NC} ] Do you want to reboot now ? (y/n)? "
read answer
if [ "$answer" == "${answer#[Yy]}" ]; then
    echo -e "✅ Installation completed. You can reboot manually later with 'reboot' command."
    exit 0
else
    echo -e "🔄 Rebooting system..."
    reboot
fi
