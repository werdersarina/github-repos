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
echo -e "[ ${green}INFO${NC} ] Preparing the installation files"
apt update -y >/dev/null 2>&1
apt install git curl -y >/dev/null 2>&1
echo -e "[ ${green}INFO${NC} ] Installation files ready"
sleep 2




# =============================================================================
# SECTION 1: SYSTEM TOOLS INSTALLATION
# =============================================================================

echo -e "[ ${green}INFO${NC} ] Installing system tools and dependencies..."
echo -e "[ ${green}INFO${NC} ] Progress..."
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
echo -e "[ ${green}INFO${NC} ] Updating system packages..."
apt update -y >/dev/null 2>&1
apt upgrade -y >/dev/null 2>&1
apt dist-upgrade -y >/dev/null 2>&1
apt-get remove --purge ufw firewalld exim4 -y >/dev/null 2>&1

# Install essential packages (consolidated to prevent duplicates)
echo -e "[ ${green}INFO${NC} ] Installing essential packages..."
apt install -y \
    screen curl jq bzip2 gzip coreutils rsyslog iftop htop zip unzip \
    net-tools sed gnupg gnupg1 bc apt-transport-https build-essential \
    dirmngr libxml-parser-perl neofetch git lsof openssl openvpn \
    easy-rsa fail2ban tmux stunnel4 vnstat squid dropbear \
    libsqlite3-dev socat cron bash-completion ntpdate xz-utils \
    gnupg2 dnsutils lsb-release chrony libnss3-dev libnspr4-dev \
    pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils \
    libselinux1-dev libcurl4-nss-dev flex bison make libnss3-tools \
    libevent-dev xl2tpd figlet ruby python3 python3-pip \
    >/dev/null 2>&1

# Install Node.js 20.x
echo -e "[ ${green}INFO${NC} ] Installing Node.js..."
curl -sSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null 2>&1
apt-get install nodejs -y >/dev/null 2>&1

# Install Ruby gems
gem install lolcat >/dev/null 2>&1

# Network interface detection and vnstat configuration
echo -e "[ ${green}INFO${NC} ] Configuring network monitoring..."
NET=$(ip route | grep default | awk '{print $5}' | head -1)
if [ -z "$NET" ]; then
    NET=$(ls /sys/class/net/ | grep -v lo | head -1)
fi

# Install and configure vnstat
echo -e "[ ${green}INFO${NC} ] Installing vnstat..."
systemctl stop vnstat >/dev/null 2>&1

# Try package installation first
if ! command -v vnstat >/dev/null 2>&1; then
    apt-get install vnstat -y >/dev/null 2>&1
fi

# If package doesn't work, compile from source
if ! command -v vnstat >/dev/null 2>&1; then
    echo -e "[ ${green}INFO${NC} ] Compiling vnstat from source..."
    cd /root
    wget -q https://humdi.net/vnstat/vnstat-2.12.tar.gz
    tar zxvf vnstat-2.12.tar.gz >/dev/null 2>&1
    cd vnstat-2.12
    ./configure --prefix=/usr --sysconfdir=/etc --sbindir=/usr/bin >/dev/null 2>&1
    make >/dev/null 2>&1
    make install >/dev/null 2>&1
    cd /root
    rm -f vnstat-2.12.tar.gz vnstat-2.12 -rf >/dev/null 2>&1
fi

# Create vnstat user and configure
if ! id -u vnstat >/dev/null 2>&1; then
    useradd -r -s /bin/false vnstat >/dev/null 2>&1
fi

mkdir -p /var/lib/vnstat
/usr/bin/vnstat -u -i $NET >/dev/null 2>&1
sed -i "s/Interface \"eth0\"/Interface \"$NET\"/g" /etc/vnstat.conf 2>/dev/null
chown vnstat:vnstat /var/lib/vnstat -R
systemctl enable vnstat >/dev/null 2>&1
systemctl restart vnstat >/dev/null 2>&1

echo -e "[ ${green}INFO${NC} ] Dependencies successfully installed"
sleep 3
clear


# =============================================================================
# SECTION 2: DOMAIN CONFIGURATION
# =============================================================================

clear
echo -e "[ ${yellow}INFO${NC} ] Domain configuration for vmess/vless/trojan protocols"
echo ""
read -rp "Input your domain: " -e pp
if [ -z "$pp" ]; then
    echo -e "[ ${yell}WARNING${NC} ] No domain input! A random domain will be created"
    pp="$(curl -s ipinfo.io/ip).nip.io"
    echo -e "[ ${green}INFO${NC} ] Using auto-generated domain: $pp"
else
    echo -e "[ ${green}INFO${NC} ] Using domain: $pp"
fi

# Save domain to all necessary locations
echo "$pp" > /root/scdomain
echo "$pp" > /etc/xray/scdomain
echo "$pp" > /etc/xray/domain
echo "$pp" > /etc/v2ray/domain
echo "$pp" > /root/domain
echo "IP=$pp" > /var/lib/SIJA/ipvps.conf

domain="$pp"  # Set domain variable for later use

echo -e "[ ${green}INFO${NC} ] Domain configuration completed"
sleep 2
    
# =============================================================================
# SECTION 3: SSH/VPN INSTALLATION
# =============================================================================

echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "$green      Install SSH / VPN               $NC"
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
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
echo -e "[ ${green}INFO${NC} ] Configuring password policies..."
curl -sS https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/password 2>/dev/null | openssl aes-256-cbc -d -a -pass pass:scvps07gg -pbkdf2 > /etc/pam.d/common-password 2>/dev/null
chmod +x /etc/pam.d/common-password 2>/dev/null

# System service configuration
echo -e "[ ${green}INFO${NC} ] Configuring system services..."

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
systemctl enable rc-local >/dev/null 2>&1
systemctl start rc-local.service >/dev/null 2>&1

# Disable IPv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

# System updates (if not already done)
echo -e "[ ${green}INFO${NC} ] Final system updates..."
apt update -y >/dev/null 2>&1
apt install jq shc wget curl -y >/dev/null 2>&1

# Set timezone
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# Configure SSH
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config


# SSL installation function
install_ssl() {
    echo -e "[ ${green}INFO${NC} ] Installing SSL certificates..."
    
    if [ -f "/usr/bin/apt-get" ]; then
        isDebian=$(cat /etc/issue | grep Debian)
        if [ "$isDebian" != "" ]; then
            apt-get install -y nginx certbot >/dev/null 2>&1
        else
            apt-get install -y nginx certbot >/dev/null 2>&1
        fi
    else
        yum install -y nginx certbot >/dev/null 2>&1
    fi

    systemctl stop nginx.service >/dev/null 2>&1

    if [ -f "/usr/bin/apt-get" ]; then
        echo "A" | certbot certonly --renew-by-default --register-unsafely-without-email --standalone -d $domain >/dev/null 2>&1
    else
        echo "Y" | certbot certonly --renew-by-default --register-unsafely-without-email --standalone -d $domain >/dev/null 2>&1
    fi
}

# Install and configure web server
echo -e "[ ${green}INFO${NC} ] Installing and configuring web server..."
apt -y install nginx >/dev/null 2>&1
cd /root
rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default
wget -O /etc/nginx/nginx.conf "https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/nginx.conf" >/dev/null 2>&1
mkdir -p /home/vps/public_html
systemctl restart nginx >/dev/null 2>&1

# Install and configure badvpn
echo -e "[ ${green}INFO${NC} ] Installing badvpn UDP gateway..."
cd /root
wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/newudpgw" >/dev/null 2>&1
chmod +x /usr/bin/badvpn-udpgw

# Add badvpn to startup
for port in 7100 7200 7300 7400 7500 7600 7700 7800 7900; do
    sed -i "$ i\screen -dmS badvpn-$port badvpn-udpgw --listen-addr 127.0.0.1:$port --max-clients 500" /etc/rc.local
    screen -dmS badvpn-$port badvpn-udpgw --listen-addr 127.0.0.1:$port --max-clients 500 >/dev/null 2>&1
done

# Configure SSH ports
echo -e "[ ${green}INFO${NC} ] Configuring SSH ports..."
cd /root

# Backup original SSH config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Enable password authentication
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config

# GCP-specific SSH optimizations
sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 60/g' /etc/ssh/sshd_config
sed -i 's/#ClientAliveCountMax 3/ClientAliveCountMax 3/g' /etc/ssh/sshd_config
sed -i 's/#TCPKeepAlive yes/TCPKeepAlive yes/g' /etc/ssh/sshd_config

# Ensure Port 22 exists and add additional ports
if ! grep -q "^Port 22" /etc/ssh/sshd_config; then
    echo "Port 22" >> /etc/ssh/sshd_config
fi

# Add multiple SSH ports safely
for port in 500 40000 51443 58080 200; do
    if ! grep -q "^Port $port" /etc/ssh/sshd_config; then
        echo "Port $port" >> /etc/ssh/sshd_config
    fi
done

# Test SSH configuration before restart
if sshd -t; then
    echo -e "[ ${green}INFO${NC} ] SSH configuration is valid"
    systemctl restart ssh >/dev/null 2>&1
else
    echo -e "[ ${red}ERROR${NC} ] SSH configuration error, restoring backup"
    cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
    systemctl restart ssh >/dev/null 2>&1
fi

# Configure Dropbear SSH
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

# Create systemd service for multi-port dropbear
cat > /etc/systemd/system/dropbear-multi.service <<'EOF'
[Unit]
Description=Dropbear SSH server (multi-port)
After=network.target
Wants=network.target

[Service]
Type=notify
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
    echo -e "[ ${yell}WARNING${NC} ] Dropbear failed to start with systemd, trying manual start..."
    pkill -f dropbear 2>/dev/null
    sleep 2
    nohup /usr/sbin/dropbear -F -E -p 143 -p 50000 -p 109 -p 110 -p 69 >/dev/null 2>&1 &
    sleep 2
    if pgrep -f "dropbear.*-p.*143" >/dev/null; then
        echo -e "[ ${green}INFO${NC} ] Dropbear started manually on multiple ports"
    else
        echo -e "[ ${red}ERROR${NC} ] Dropbear failed to start completely"
    fi
fi
# Configure Stunnel4
echo -e "[ ${green}INFO${NC} ] Installing and configuring Stunnel4..."
cd /root
apt install stunnel4 -y >/dev/null 2>&1

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
echo -e "[ ${green}INFO${NC} ] Generating SSL certificate for stunnel..."
openssl genrsa -out key.pem 2048 >/dev/null 2>&1
openssl req -new -x509 -key key.pem -out cert.pem -days 1095 \
-subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email" >/dev/null 2>&1
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem

# Configure and start stunnel
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
chmod 600 /etc/stunnel/stunnel.pem

if command -v systemctl >/dev/null; then
    systemctl enable stunnel4 >/dev/null 2>&1
    systemctl restart stunnel4 >/dev/null 2>&1
else
    /etc/init.d/stunnel4 restart >/dev/null 2>&1
fi


# Install and configure Fail2ban
echo -e "[ ${green}INFO${NC} ] Installing and configuring Fail2ban..."
apt -y install fail2ban >/dev/null 2>&1

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

systemctl enable fail2ban >/dev/null 2>&1
systemctl restart fail2ban >/dev/null 2>&1

# Install and configure Squid proxy
echo -e "[ ${green}INFO${NC} ] Installing and configuring Squid proxy..."
apt -y install squid >/dev/null 2>&1

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
http_port 8080
coredump_dir /var/spool/squid
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
EOF

systemctl enable squid >/dev/null 2>&1
systemctl restart squid >/dev/null 2>&1

# Install Custom DDoS Protection
echo -e "[ ${green}INFO${NC} ] Installing Custom DDoS Protection..."
mkdir -p /usr/local/ddos /var/log/ddos

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
cat > /usr/local/ddos/ddos.conf <<'EOF'
MAX_CONNECTIONS=150
BAN_PERIOD=600
CHECK_INTERVAL=60
EOF

# Set permissions and install
chmod +x /usr/local/ddos/ddos.sh
touch /usr/local/ddos/banned_ips.txt
/usr/local/ddos/ddos.sh --cron

echo -e "[ ${green}INFO${NC} ] Custom DDoS Protection installed successfully"

# Configure banner and system optimization
echo -e "[ ${green}INFO${NC} ] Configuring system banner and optimization..."
wget -q -O /etc/issue.net "https://raw.githubusercontent.com/werdersarina/github-repos/main/issue.net"
chmod +x /etc/issue.net
echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/issue.net"@g' /etc/default/dropbear

# Install BBR and kernel optimization
echo -e "[ ${green}INFO${NC} ] Installing BBR and kernel optimization..."
wget -q https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/bbr.sh
chmod +x bbr.sh
./bbr.sh >/dev/null 2>&1

# Configure firewall and anti-torrent
echo -e "[ ${green}INFO${NC} ] Configuring firewall and anti-torrent rules..."

# Ensure Google Cloud IAP IP ranges are whitelisted first (CRITICAL for GCP)
iptables -I INPUT -s 35.235.240.0/20 -j ACCEPT
iptables -I INPUT -s 130.211.0.0/22 -j ACCEPT
iptables -I INPUT -s 35.191.0.0/16 -j ACCEPT

# Additional Google Cloud Platform IP ranges
iptables -I INPUT -s 34.96.0.0/20 -j ACCEPT
iptables -I INPUT -s 34.127.0.0/16 -j ACCEPT

# Emergency access - always allow localhost and private networks
iptables -I INPUT -s 127.0.0.0/8 -j ACCEPT
iptables -I INPUT -s 10.0.0.0/8 -j ACCEPT
iptables -I INPUT -s 172.16.0.0/12 -j ACCEPT
iptables -I INPUT -s 192.168.0.0/16 -j ACCEPT

# Ensure SSH ports are always accessible (HIGHEST PRIORITY)
for port in 22 200 500 40000 51443 58080; do
    iptables -I INPUT -p tcp --dport $port -j ACCEPT
done

# Allow established connections to prevent disconnection
iptables -I INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

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
iptables-save > /etc/iptables.up.rules
if command -v netfilter-persistent >/dev/null; then
    netfilter-persistent save >/dev/null 2>&1
    netfilter-persistent reload >/dev/null 2>&1
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
echo -e "[ ${green}INFO${NC} ] Downloading management scripts..."
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
for script_name in "${!scripts[@]}"; do
    wget -q -O "$script_name" "https://raw.githubusercontent.com/werdersarina/github-repos/main/${scripts[$script_name]}"
    chmod +x "$script_name"
done

echo -e "[ ${green}INFO${NC} ] Management scripts downloaded successfully"


# Configure cron jobs
echo -e "[ ${green}INFO${NC} ] Configuring cron jobs..."

cat > /etc/cron.d/re_otm <<-'END'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 2 * * * root /sbin/reboot
END

cat > /etc/cron.d/xp_otm <<-'END'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 0 * * * root /usr/bin/xp
END

cat > /home/re_otm <<-'END'
7
END

service cron restart >/dev/null 2>&1
service cron reload >/dev/null 2>&1

# Cleanup unnecessary packages
echo -e "[ ${green}INFO${NC} ] Cleaning up system..."
apt autoclean -y >/dev/null 2>&1

# Remove unnecessary services
for pkg in unscd samba apache2 bind9 sendmail; do
    if dpkg -s "$pkg" >/dev/null 2>&1; then
        apt -y remove --purge "$pkg"* >/dev/null 2>&1
    fi
done

apt autoremove -y >/dev/null 2>&1

# Set proper ownership
chown -R www-data:www-data /home/vps/public_html
# Restart all services
echo -e "[ ${green}INFO${NC} ] Restarting all SSH & VPN services..."

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
for service in "${services[@]}"; do
    echo -e "[ ${green}INFO${NC} ] Restarting $service..."
    if systemctl is-enabled "$service" >/dev/null 2>&1 || systemctl list-unit-files | grep -q "$service"; then
        systemctl restart "$service" >/dev/null 2>&1
    else
        /etc/init.d/"$service" restart >/dev/null 2>&1
    fi
    sleep 2  # Increased delay to prevent connection issues
done

# Restart fail2ban last after other services are stable
echo -e "[ ${green}INFO${NC} ] Restarting fail2ban..."
systemctl restart fail2ban >/dev/null 2>&1
sleep 3

# Verify SSH is still accessible
if ss -tln | grep -q ":22 "; then
    echo -e "[ ${green}INFO${NC} ] SSH port 22 is accessible"
else
    echo -e "[ ${red}WARNING${NC} ] SSH port 22 may not be accessible"
    # Try to restart SSH again
    systemctl restart ssh >/dev/null 2>&1
fi

# Start badvpn UDP gateways
echo -e "[ ${green}INFO${NC} ] Starting badvpn UDP gateways..."
for port in 7100 7200 7300 7400 7500 7600 7700 7800 7900; do
    screen -dmS badvpn-$port badvpn-udpgw --listen-addr 127.0.0.1:$port --max-clients 500 >/dev/null 2>&1
done

# Clear command history and setup environment
history -c
echo "unset HISTFILE" >> /etc/profile

# Cleanup temporary files
rm -f /root/key.pem /root/cert.pem /root/ssh-vpn.sh /root/bbr.sh

echo -e "[ ${green}INFO${NC} ] SSH/VPN installation completed successfully"

# =============================================================================
# SECTION 4: XRAY INSTALLATION
# =============================================================================

echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "$green          Install XRAY              $NC"
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
sleep 2
clear

echo -e "[ ${green}INFO${NC} ] Starting XRAY installation..."
date
echo ""

# Use domain from previous configuration
if [ -z "$domain" ]; then
    domain=$(cat /root/domain 2>/dev/null || cat /etc/xray/domain 2>/dev/null || echo "")
fi

if [ -z "$domain" ]; then
    echo -e "[ ${red}ERROR${NC} ] Domain not found! Please configure domain first."
    exit 1
fi

sleep 1
mkdir -p /etc/xray /var/log/xray
echo -e "[ ${green}INFO${NC} ] Checking dependencies..."
apt install iptables iptables-persistent -y >/dev/null 2>&1

# Configure time synchronization
echo -e "[ ${green}INFO${NC} ] Configuring time synchronization..."
ntpdate pool.ntp.org >/dev/null 2>&1
timedatectl set-ntp true >/dev/null 2>&1
systemctl enable chronyd >/dev/null 2>&1
systemctl restart chronyd >/dev/null 2>&1
systemctl enable chrony >/dev/null 2>&1
systemctl restart chrony >/dev/null 2>&1
timedatectl set-timezone Asia/Jakarta
chronyc sourcestats -v >/dev/null 2>&1
chronyc tracking -v >/dev/null 2>&1

# Install additional dependencies
echo -e "[ ${green}INFO${NC} ] Installing additional dependencies..."
apt clean all >/dev/null 2>&1
apt update >/dev/null 2>&1
apt install curl socat xz-utils wget apt-transport-https gnupg gnupg2 gnupg1 dnsutils lsb-release zip pwgen openssl netcat cron -y >/dev/null 2>&1


# Install XRAY core
echo -e "[ ${green}INFO${NC} ] Installing XRAY core..."
domainSock_dir="/run/xray"
[ ! -d $domainSock_dir ] && mkdir -p $domainSock_dir
chown www-data:www-data $domainSock_dir

# Create log directories and files
mkdir -p /var/log/xray /etc/xray
chown www-data:www-data /var/log/xray
chmod +x /var/log/xray
touch /var/log/xray/access.log /var/log/xray/error.log /var/log/xray/access2.log /var/log/xray/error2.log

# Install latest XRAY core
echo -e "[ ${green}INFO${NC} ] Getting latest XRAY core version..."
LATEST_XRAY=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep tag_name | cut -d '"' -f 4)
if [ -n "$LATEST_XRAY" ]; then
    echo -e "[ ${green}INFO${NC} ] Installing XRAY core ${LATEST_XRAY}"
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version "${LATEST_XRAY#v}" >/dev/null 2>&1
else
    echo -e "[ ${yell}WARNING${NC} ] Failed to get latest version, using fallback"
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data >/dev/null 2>&1
fi



# SSL Certificate configuration
echo -e "[ ${green}INFO${NC} ] Configuring SSL certificates..."
systemctl stop nginx >/dev/null 2>&1
mkdir -p /root/.acme.sh

# Install acme.sh
curl -s https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
chmod +x /root/.acme.sh/acme.sh
/root/.acme.sh/acme.sh --upgrade --auto-upgrade >/dev/null 2>&1
/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1
/root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256 >/dev/null 2>&1
~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc >/dev/null 2>&1

# Create SSL renewal script
cat > /usr/local/bin/ssl_renew.sh <<'EOF'
#!/bin/bash
/etc/init.d/nginx stop
"/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" &> /root/renew_ssl.log
/etc/init.d/nginx start
/etc/init.d/nginx status
EOF
chmod +x /usr/local/bin/ssl_renew.sh

# Add to crontab if not exists
if ! grep -q 'ssl_renew.sh' /var/spool/cron/crontabs/root 2>/dev/null; then
    (crontab -l 2>/dev/null; echo "15 03 */3 * * /usr/local/bin/ssl_renew.sh") | crontab
fi

mkdir -p /home/vps/public_html

# Generate UUID and custom paths
echo -e "[ ${green}INFO${NC} ] Generating UUID and custom paths..."
uuid=$(cat /proc/sys/kernel/random/uuid)

# Function to generate random path
generate_random_path() {
    local prefix=$1
    echo "/${prefix}$(openssl rand -hex 6)"
}

# Custom paths with environment variable support
VMESS_PATH="${CUSTOM_VMESS_PATH:-$(generate_random_path "vm")}"
VLESS_PATH="${CUSTOM_VLESS_PATH:-$(generate_random_path "vl")}"
TROJAN_PATH="${CUSTOM_TROJAN_PATH:-$(generate_random_path "tr")}"
VMESS_XHTTP_PATH="${CUSTOM_VMESS_XHTTP_PATH:-$(generate_random_path "vmx")}"
VLESS_XHTTP_PATH="${CUSTOM_VLESS_XHTTP_PATH:-$(generate_random_path "vlx")}"

# GRPC service names
VLESS_GRPC_SERVICE="${CUSTOM_VLESS_GRPC_SERVICE:-vlessgrpc}"
VMESS_GRPC_SERVICE="${CUSTOM_VMESS_GRPC_SERVICE:-vmessgrpc}"
TROJAN_GRPC_SERVICE="${CUSTOM_TROJAN_GRPC_SERVICE:-trojangrpc}"

# Generate REALITY keys
echo -e "[ ${green}INFO${NC} ] Generating REALITY keys..."
XRAY_KEYS=$(/usr/local/bin/xray x25519)
REALITY_PRIVATE=$(echo "$XRAY_KEYS" | head -n1 | cut -d' ' -f3)
REALITY_PUBLIC=$(echo "$XRAY_KEYS" | tail -n1 | cut -d' ' -f3)

echo -e "[ ${green}INFO${NC} ] Generated configurations:"
echo -e "[ ${green}INFO${NC} ] VMess WS: $VMESS_PATH"
echo -e "[ ${green}INFO${NC} ] VMess XHTTP: $VMESS_XHTTP_PATH"
echo -e "[ ${green}INFO${NC} ] VLess WS: $VLESS_PATH"
echo -e "[ ${green}INFO${NC} ] VLess XHTTP: $VLESS_XHTTP_PATH"
echo -e "[ ${green}INFO${NC} ] Trojan WS: $TROJAN_PATH"
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
echo -e "[ ${green}INFO$NC ] Getting latest Trojan-Go version..."
latest_version="$(curl -s "https://api.github.com/repos/p4gefau1t/trojan-go/releases/latest" | grep tag_name | cut -d '"' -f 4 | sed 's/v//')"
if [ -z "$latest_version" ]; then
    echo -e "[ ${red}ERROR$NC ] Failed to get latest Trojan-Go version, using fallback method"
    latest_version="$(curl -s "https://api.github.com/repos/p4gefau1t/trojan-go/releases" | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
fi
echo -e "[ ${green}INFO$NC ] Installing Trojan-Go v${latest_version}"
trojango_link="https://github.com/p4gefau1t/trojan-go/releases/download/v${latest_version}/trojan-go-linux-amd64.zip"
mkdir -p "/usr/bin/trojan-go"
mkdir -p "/etc/trojan-go"
cd `mktemp -d`
curl -sL "${trojango_link}" -o trojan-go.zip
unzip -q trojan-go.zip && rm -rf trojan-go.zip
mv trojan-go /usr/local/bin/trojan-go
chmod +x /usr/local/bin/trojan-go
mkdir /var/log/trojan-go/
touch /etc/trojan-go/akun.conf
touch /var/log/trojan-go/trojan-go.log

# Buat Config Trojan Go
cat > /etc/trojan-go/config.json << END
{
  "run_type": "server",
  "local_addr": "0.0.0.0",
  "local_port": 2087,
  "remote_addr": "127.0.0.1",
  "remote_port": 89,
  "log_level": 1,
  "log_file": "/var/log/trojan-go/trojan-go.log",
  "password": [
      "$uuid"
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
    "sni": "$domain",
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
    "path": "/trojango",
    "host": "$domain"
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
END

# Installing Trojan Go Service
cat > /etc/systemd/system/trojan-go.service << END
[Unit]
Description=Trojan-Go Service Mod By ADAM SIJA
Documentation=github.com/adammoi/vipies
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
END

# Trojan Go Uuid
cat > /etc/trojan-go/uuid.txt << END
$uuid
END

#nginx config
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
    
    # Default location for webserver
    location / {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:700;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
}
EOF

# Save paths to configuration files for scripts to use
echo "$VMESS_PATH" > /etc/xray/vmess_path
echo "$VMESS_XHTTP_PATH" > /etc/xray/vmess_xhttp_path
echo "$VLESS_PATH" > /etc/xray/vless_path  
echo "$VLESS_XHTTP_PATH" > /etc/xray/vless_xhttp_path
echo "$TROJAN_PATH" > /etc/xray/trojan_path
echo "$TROJAN_PATH" > /etc/xray/trojan_ws_path
echo "$VLESS_GRPC_SERVICE" > /etc/xray/vless_grpc_service
echo "$VMESS_GRPC_SERVICE" > /etc/xray/vmess_grpc_service  
echo "$TROJAN_GRPC_SERVICE" > /etc/xray/trojan_grpc_service
echo "$REALITY_PRIVATE" > /etc/xray/reality_private
echo "$REALITY_PUBLIC" > /etc/xray/reality_public

echo -e "[ ${green}INFO$NC ] Custom paths saved to /etc/xray/ files"

echo -e "[ ${green}INFO$NC ] Configuring firewall for REALITY port 8443"
ufw allow 8443/tcp >/dev/null 2>&1
iptables -I INPUT -p tcp --dport 8443 -j ACCEPT >/dev/null 2>&1
iptables-save > /etc/iptables/rules.v4 >/dev/null 2>&1

echo -e "$yell[SERVICE]$NC Restart All service"
systemctl daemon-reload
sleep 1
echo -e "[ ${green}ok${NC} ] Enable & restart xray "
systemctl daemon-reload
systemctl enable xray
systemctl restart xray
systemctl restart nginx
systemctl enable runn
systemctl restart runn
systemctl stop trojan-go
systemctl start trojan-go
systemctl enable trojan-go
systemctl restart trojan-go

cd /usr/bin/
# vmess - Enhanced version with multiple protocols (WS, XHTTP, GRPC)
wget -O add-ws "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/add-ws-enhanced.sh" && chmod +x add-ws
wget -O trialvmess "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/trialvmess.sh" && chmod +x trialvmess
wget -O renew-ws "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/renew-ws.sh" && chmod +x renew-ws
wget -O del-ws "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/del-ws.sh" && chmod +x del-ws
wget -O cek-ws "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/cek-ws.sh" && chmod +x cek-ws

# vless - Enhanced version with multiple protocols (WS, XHTTP, GRPC, REALITY)
wget -O add-vless "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/add-vless-enhanced.sh" && chmod +x add-vless
wget -O trialvless "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/trialvless.sh" && chmod +x trialvless
wget -O renew-vless "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/renew-vless.sh" && chmod +x renew-vless
wget -O del-vless "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/del-vless.sh" && chmod +x del-vless
wget -O cek-vless "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/cek-vless.sh" && chmod +x cek-vless

# trojan - Enhanced version with multiple protocols (WS, GRPC)
wget -O add-tr "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/add-trojan-enhanced.sh" && chmod +x add-tr
wget -O trialtrojan "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/trialtrojan.sh" && chmod +x trialtrojan
wget -O del-tr "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/del-tr.sh" && chmod +x del-tr
wget -O renew-tr "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/renew-tr.sh" && chmod +x renew-tr
wget -O cek-tr "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/cek-tr.sh" && chmod +x cek-tr

# trojan go
wget -O addtrgo "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/addtrgo.sh" && chmod +x addtrgo
wget -O trialtrojango "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/trialtrojango.sh" && chmod +x trialtrojango
wget -O deltrgo "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/deltrgo.sh" && chmod +x deltrgo
wget -O renewtrgo "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/renewtrgo.sh" && chmod +x renewtrgo
wget -O cektrgo "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/cektrgo.sh" && chmod +x cektrgo


sleep 1
yellow() { echo -e "\\033[33;1m${*}\\033[0m"; }
yellow "XRAY protocols installed successfully:"
yellow "🆕 NEW PROTOCOLS (Custom Paths):"
yellow "✅ VMess WebSocket (Custom Path: $VMESS_PATH)"
yellow "✅ VMess XHTTP (Custom Path: $VMESS_XHTTP_PATH)"  
yellow "✅ VLess WebSocket (Custom Path: $VLESS_PATH)"
yellow "✅ VLess XHTTP (Custom Path: $VLESS_XHTTP_PATH)"
yellow "✅ VLess REALITY (Port: 8443, Private Key: $REALITY_PRIVATE)"
yellow "✅ Trojan WebSocket (Custom Path: $TROJAN_PATH)"
yellow "✅ VMess GRPC (Service: $VMESS_GRPC_SERVICE)"
yellow "✅ VLess GRPC (Service: $VLESS_GRPC_SERVICE)"
yellow "✅ Trojan GRPC (Service: $TROJAN_GRPC_SERVICE)"
echo ""
yellow "🔄 LEGACY PROTOCOLS (Fixed Paths - for existing add-user scripts):"
yellow "✅ VMess WebSocket (Legacy: /vmess, /worryfree, /kuota-habis, /chat)"
yellow "✅ VLess WebSocket (Legacy: /vless)"
yellow "✅ Trojan WebSocket (Legacy: /trojan-ws)"
yellow "✅ All GRPC (Legacy: /vmess-grpc, /vless-grpc, /trojan-grpc)"
echo ""
echo -e "${green}[INFO]${NC} Custom paths support any path (e.g., /facebook, /google, /youtube)"
echo -e "${green}[INFO]${NC} Use environment variables: CUSTOM_VMESS_PATH='/mypath' ./ins-xray.sh"
echo -e "${green}[INFO]${NC} All configurations saved in /etc/xray/ directory"
echo -e "${green}[INFO]${NC} Legacy paths maintained for backward compatibility with existing scripts"
echo ""

mv /root/domain /etc/xray/ 
if [ -f /root/scdomain ]; then
    rm /root/scdomain > /dev/null 2>&1
fi
clear

# =============================================================================
# SECTION 5: WEBSOCKET TUNNELING INSTALLATION
# =============================================================================

echo -e "[ ${green}INFO${NC} ] Installing WebSocket tunneling..."

cd /root

# Install Script Websocket-SSH Python
wget -O /usr/local/bin/ws-dropbear https://raw.githubusercontent.com/werdersarina/github-repos/main/sshws/dropbear-ws.py >/dev/null 2>&1
wget -O /usr/local/bin/ws-stunnel https://raw.githubusercontent.com/werdersarina/github-repos/main/sshws/ws-stunnel >/dev/null 2>&1

# Set permissions
chmod +x /usr/local/bin/ws-dropbear
chmod +x /usr/local/bin/ws-stunnel

# System Dropbear Websocket-SSH Python
wget -O /etc/systemd/system/ws-dropbear.service https://raw.githubusercontent.com/werdersarina/github-repos/main/sshws/service-wsdropbear >/dev/null 2>&1 && chmod +x /etc/systemd/system/ws-dropbear.service

# System SSL/TLS Websocket-SSH Python
wget -O /etc/systemd/system/ws-stunnel.service https://raw.githubusercontent.com/werdersarina/github-repos/main/sshws/ws-stunnel.service >/dev/null 2>&1 && chmod +x /etc/systemd/system/ws-stunnel.service

# Restart services
systemctl daemon-reload

# Enable & Start & Restart ws-dropbear service
systemctl enable ws-dropbear.service >/dev/null 2>&1
systemctl start ws-dropbear.service >/dev/null 2>&1
systemctl restart ws-dropbear.service >/dev/null 2>&1

# Enable & Start & Restart ws-stunnel service
systemctl enable ws-stunnel.service >/dev/null 2>&1
systemctl start ws-stunnel.service >/dev/null 2>&1
systemctl restart ws-stunnel.service >/dev/null 2>&1

echo -e "[ ${green}INFO${NC} ] WebSocket tunneling installed successfully"

# =============================================================================
# SECTION 6: FINALIZATION & CLEANUP
# =============================================================================

# Setup profile
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

# Cleanup old files
if [ -f "/root/log-install.txt" ]; then
    rm /root/log-install.txt > /dev/null 2>&1
fi
if [ -f "/etc/afak.conf" ]; then
    rm /etc/afak.conf > /dev/null 2>&1
fi
if [ ! -f "/etc/log-create-user.log" ]; then
    echo "Log All Account " > /etc/log-create-user.log
fi

history -c
echo $serverV > /opt/.ver
aureb=$(cat /home/re_otm)
b=11
if [ $aureb -gt $b ]; then
    gg="PM"
else
    gg="AM"
fi

curl -sS ifconfig.me > /etc/myipvps

echo " "
echo "=====================-[ OTTIN NETWORK ]-===================="
echo ""
echo "------------------------------------------------------------"
echo ""
echo ""
echo "   >>> Service & Port"  | tee -a log-install.txt
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
echo "   >>> Server Information & Other Features"  | tee -a log-install.txt
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
echo "===============-[ Script Created By YT ZIXSTYLE ]-==============="
echo -e ""
echo ""
echo "🔥 IMPORTANT NOTES FOR GOOGLE CLOUD PLATFORM:"
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
rm -f /root/setup.sh >/dev/null 2>&1
rm -f /root/ins-xray.sh >/dev/null 2>&1
rm -f /root/insshws.sh >/dev/null 2>&1
rm -f /root/ssh-vpn.sh >/dev/null 2>&1
rm -f /root/tools.sh >/dev/null 2>&1

secs_to_human "$(($(date +%s) - ${start}))" | tee -a log-install.txt
echo -e ""
echo -ne "[ ${yell}WARNING${NC} ] Do you want to reboot now ? (y/n)? "
read answer
if [ "$answer" == "${answer#[Yy]}" ]; then
    exit 0
else
    reboot
fi
