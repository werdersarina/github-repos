#!/bin/bash
#
# ==================================================

# initializing var
export DEBIAN_FRONTEND=noninteractive
MYIP=$(wget -qO- ipinfo.io/ip);
MYIP2="s/xxxxxxxxx/$MYIP/g";
NET=$(ip route | grep default | awk '{print $5}' | head -1);
if [ -z "$NET" ]; then
    NET=$(ls /sys/class/net/ | grep -v lo | head -1)
fi
source /etc/os-release
ver=$VERSION_ID

#detail nama perusahaan
country=ID
state=Indonesia
locality=Jakarta
organization=Zixstyle
organizationalunit=Zixstyle.my.id
commonname=WarungAwan
email=doyoulikepussy@zixstyle.co.id

# simple password minimal
curl -sS https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/password | openssl aes-256-cbc -d -a -pass pass:scvps07gg -pbkdf2 > /etc/pam.d/common-password
chmod +x /etc/pam.d/common-password

# go to root
cd

# Edit file /etc/systemd/system/rc-local.service
cat > /etc/systemd/system/rc-local.service <<-END
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

# nano /etc/rc.local
cat > /etc/rc.local <<-END
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
END

# Ubah izin akses
chmod +x /etc/rc.local

# enable rc local
systemctl enable rc-local
systemctl start rc-local.service

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

#update
apt update -y
apt upgrade -y
apt dist-upgrade -y
apt-get remove --purge ufw firewalld -y
apt-get remove --purge exim4 -y

#install jq
apt -y install jq

#install shc
apt -y install shc

# install wget and curl
apt -y install wget curl

#figlet
apt-get install figlet -y
apt-get install ruby -y
gem install lolcat

# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config


install_ssl(){
    if [ -f "/usr/bin/apt-get" ];then
            isDebian=`cat /etc/issue|grep Debian`
            if [ "$isDebian" != "" ];then
                    apt-get install -y nginx certbot
                    apt install -y nginx certbot
                    sleep 3s
            else
                    apt-get install -y nginx certbot
                    apt install -y nginx certbot
                    sleep 3s
            fi
    else
        yum install -y nginx certbot
        sleep 3s
    fi

    systemctl stop nginx.service

    if [ -f "/usr/bin/apt-get" ];then
            isDebian=`cat /etc/issue|grep Debian`
            if [ "$isDebian" != "" ];then
                    echo "A" | certbot certonly --renew-by-default --register-unsafely-without-email --standalone -d $domain
                    sleep 3s
            else
                    echo "A" | certbot certonly --renew-by-default --register-unsafely-without-email --standalone -d $domain
                    sleep 3s
            fi
    else
        echo "Y" | certbot certonly --renew-by-default --register-unsafely-without-email --standalone -d $domain
        sleep 3s
    fi
}

# install webserver
apt -y install nginx
cd
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/nginx/nginx.conf "https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/nginx.conf"
mkdir -p /home/vps/public_html
/etc/init.d/nginx restart

# install badvpn
cd
wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/newudpgw"
chmod +x /usr/bin/badvpn-udpgw
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500' /etc/rc.local
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 500' /etc/rc.local
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000' /etc/rc.local
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7400 --max-clients 500' /etc/rc.local
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7500 --max-clients 500' /etc/rc.local
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7600 --max-clients 500' /etc/rc.local
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7400 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7500 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7600 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7700 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7800 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7900 --max-clients 500

# setting port ssh
cd
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 500' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 40000' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 51443' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 58080' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 200' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 22' /etc/ssh/sshd_config
/etc/init.d/ssh restart

echo "=== Install Dropbear ==="
# install dropbear
apt -y install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=143/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 50000 -p 109 -p 110 -p 69"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
/etc/init.d/ssh restart
/etc/init.d/dropbear restart

cd
# install stunnel
apt install stunnel4 -y
cat > /etc/stunnel/stunnel.conf <<-END
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 222
connect = 127.0.0.1:22

[dropbear]
accept = 777
connect = 127.0.0.1:109

[ws-stunnel]
accept = 2096
connect = 700

[openvpn]
accept = 442
connect = 127.0.0.1:1194

END

# make a certificate
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 1095 \
-subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem

# konfigurasi stunnel
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
chmod 600 /etc/stunnel/stunnel.pem
# Add to systemd if not using sysvinit
if command -v systemctl > /dev/null; then
    systemctl enable stunnel4
    systemctl restart stunnel4
else
    /etc/init.d/stunnel4 restart
fi


# install fail2ban
apt -y install fail2ban
# Basic fail2ban configuration
cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[ssh]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[dropbear]
enabled = true
port = ssh
filter = dropbear
logpath = /var/log/auth.log
maxretry = 3
EOF
systemctl enable fail2ban
systemctl restart fail2ban

# install squid
apt -y install squid
# Basic squid configuration
cat > /etc/squid/squid.conf <<EOF
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
systemctl enable squid
systemctl restart squid

# Install Custom DDoS Protection
echo; echo 'Installing Custom DDoS Protection'; echo
mkdir -p /usr/local/ddos
mkdir -p /var/log/ddos

# Create DDoS protection script
cat > /usr/local/ddos/ddos.sh <<'EOF'
#!/bin/bash
# Custom DDoS Protection Script
# Version 1.0 - Simple and Reliable

CONF_FILE="/usr/local/ddos/ddos.conf"
LOG_FILE="/var/log/ddos/ddos.log"
BAN_LIST="/usr/local/ddos/banned_ips.txt"

# Load configuration
if [ -f "$CONF_FILE" ]; then
    source "$CONF_FILE"
else
    # Default settings
    MAX_CONNECTIONS=150
    BAN_PERIOD=600
    CHECK_INTERVAL=60
fi

# Function to log messages
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# Function to check connections and ban IPs
check_connections() {
    # Get connection counts per IP
    netstat -ntu | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | while read count ip; do
        # Skip empty lines and local addresses
        if [[ -z "$ip" || "$ip" == "127.0.0.1" || "$ip" =~ ^192\.168\. || "$ip" =~ ^10\. || "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then
            continue
        fi
        
        # Check if connections exceed limit
        if [ "$count" -gt "$MAX_CONNECTIONS" ]; then
            # Check if IP is already banned
            if ! grep -q "$ip" "$BAN_LIST" 2>/dev/null; then
                # Ban the IP
                iptables -I INPUT -s "$ip" -j DROP
                echo "$ip $(date +%s)" >> "$BAN_LIST"
                log_message "Banned IP $ip with $count connections"
                echo "Banned IP: $ip ($count connections)"
            fi
        fi
    done
}

# Function to unban expired IPs
unban_expired() {
    if [ -f "$BAN_LIST" ]; then
        current_time=$(date +%s)
        while read line; do
            if [ -n "$line" ]; then
                ip=$(echo "$line" | cut -d' ' -f1)
                ban_time=$(echo "$line" | cut -d' ' -f2)
                if [ $((current_time - ban_time)) -gt "$BAN_PERIOD" ]; then
                    iptables -D INPUT -s "$ip" -j DROP 2>/dev/null
                    log_message "Unbanned IP $ip"
                    echo "Unbanned IP: $ip"
                fi
            fi
        done < "$BAN_LIST"
        
        # Clean up expired entries
        temp_file=$(mktemp)
        while read line; do
            if [ -n "$line" ]; then
                ban_time=$(echo "$line" | cut -d' ' -f2)
                if [ $((current_time - ban_time)) -le "$BAN_PERIOD" ]; then
                    echo "$line" >> "$temp_file"
                fi
            fi
        done < "$BAN_LIST"
        mv "$temp_file" "$BAN_LIST"
    fi
}

# Main execution
case "$1" in
    --cron)
        echo "*/1 * * * * root /usr/local/ddos/ddos.sh --check >/dev/null 2>&1" > /etc/cron.d/ddos
        echo "DDoS protection cron job installed"
        ;;
    --check)
        check_connections
        unban_expired
        ;;
    *)
        echo "Usage: $0 [--cron|--check]"
        echo "  --cron  : Install cron job"
        echo "  --check : Check connections and manage bans"
        ;;
esac
EOF

# Create configuration file
cat > /usr/local/ddos/ddos.conf <<'EOF'
# DDoS Protection Configuration
MAX_CONNECTIONS=150
BAN_PERIOD=600
CHECK_INTERVAL=60
EOF

# Create ignore list for whitelisted IPs
cat > /usr/local/ddos/ignore.ip.list <<'EOF'
127.0.0.1
::1
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
EOF

# Set permissions
chmod +x /usr/local/ddos/ddos.sh
chmod 644 /usr/local/ddos/ddos.conf
chmod 644 /usr/local/ddos/ignore.ip.list
touch /usr/local/ddos/banned_ips.txt

# Install cron job
/usr/local/ddos/ddos.sh --cron

echo "Custom DDoS Protection installed successfully"
echo "Configuration: /usr/local/ddos/ddos.conf"
echo "Log file: /var/log/ddos/ddos.log"

# banner /etc/issue.net
sleep 1
echo -e "[ ${green}INFO$NC ] Settings banner"
wget -q -O /etc/issue.net "https://raw.githubusercontent.com/werdersarina/github-repos/main/issue.net"
chmod +x /etc/issue.net
echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/issue.net"@g' /etc/default/dropbear

#install bbr dan optimasi kernel
wget https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/bbr.sh && chmod +x bbr.sh && ./bbr.sh

# blockir torrent
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
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload

# download script
cd /usr/bin
# menu
wget -O menu "https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/menu.sh"
wget -O menu-vmess "https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/menu-vmess.sh"
wget -O menu-vless "https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/menu-vless.sh"
wget -O running "https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/running.sh"
wget -O clearcache "https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/clearcache.sh"
wget -O menu-trgo "https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/menu-trgo.sh"
wget -O menu-trojan "https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/menu-trojan.sh"

# menu ssh ovpn
wget -O menu-ssh "https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/menu-ssh.sh"
wget -O usernew "https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/usernew.sh"
wget -O trial "https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/trial.sh"
wget -O renew "https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/renew.sh"
wget -O hapus "https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/hapus.sh"
wget -O cek "https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/cek.sh"
wget -O member "https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/member.sh"
wget -O delete "https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/delete.sh"
wget -O autokill "https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/autokill.sh"
wget -O ceklim "https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/ceklim.sh"
wget -O tendang "https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/tendang.sh"

# menu system
wget -O menu-set "https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/menu-set.sh"
wget -O menu-domain "https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/menu-domain.sh"
wget -O add-host "https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/add-host.sh"
wget -O port-change "https://raw.githubusercontent.com/werdersarina/github-repos/main/port/port-change.sh"
wget -O certv2ray "https://raw.githubusercontent.com/werdersarina/github-repos/main/xray/certv2ray.sh"
wget -O menu-webmin "https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/menu-webmin.sh"
wget -O speedtest "https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/speedtest_cli.py"
wget -O about "https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/about.sh"
wget -O auto-reboot "https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/auto-reboot.sh"
wget -O restart "https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/restart.sh"
wget -O bw "https://raw.githubusercontent.com/werdersarina/github-repos/main/menu/bw.sh"

# change port
wget -O port-ssl "https://raw.githubusercontent.com/werdersarina/github-repos/main/port/port-ssl.sh"
wget -O port-ovpn "https://raw.githubusercontent.com/werdersarina/github-repos/main/port/port-ovpn.sh"


wget -O xp "https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/xp.sh"
wget -O acs-set "https://raw.githubusercontent.com/werdersarina/github-repos/main/acs-set.sh"

wget -O sshws "https://raw.githubusercontent.com/werdersarina/github-repos/main/ssh/sshws.sh"

chmod +x menu
chmod +x menu-vmess
chmod +x menu-vless
chmod +x running
chmod +x clearcache
chmod +x menu-trgo
chmod +x menu-trojan

chmod +x menu-ssh
chmod +x usernew
chmod +x trial
chmod +x renew
chmod +x hapus
chmod +x cek
chmod +x member
chmod +x delete
chmod +x autokill
chmod +x ceklim
chmod +x tendang

chmod +x menu-set
chmod +x menu-domain
chmod +x add-host
chmod +x port-change
chmod +x certv2ray
chmod +x menu-webmin
chmod +x speedtest
chmod +x about
chmod +x auto-reboot
chmod +x restart
chmod +x bw

chmod +x port-ssl
chmod +x port-ovpn

chmod +x xp
chmod +x acs-set
chmod +x sshws
cd


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

service cron restart >/dev/null 2>&1
service cron reload >/dev/null 2>&1

# remove unnecessary files
sleep 1
echo -e "[ ${green}INFO$NC ] Clearing trash"
apt autoclean -y >/dev/null 2>&1

if dpkg -s unscd >/dev/null 2>&1; then
apt -y remove --purge unscd >/dev/null 2>&1
fi

apt-get -y --purge remove samba* >/dev/null 2>&1
apt-get -y --purge remove apache2* >/dev/null 2>&1
apt-get -y --purge remove bind9* >/dev/null 2>&1
apt-get -y remove sendmail* >/dev/null 2>&1
apt autoremove -y >/dev/null 2>&1
# finishing
cd
chown -R www-data:www-data /home/vps/public_html
sleep 1
echo -e "$yell[SERVICE]$NC Restart All service SSH & OVPN"
/etc/init.d/nginx restart >/dev/null 2>&1
sleep 1
echo -e "[ ${green}ok${NC} ] Restarting nginx"
/etc/init.d/openvpn restart >/dev/null 2>&1
sleep 1
echo -e "[ ${green}ok${NC} ] Restarting cron "
/etc/init.d/ssh restart >/dev/null 2>&1
sleep 1
echo -e "[ ${green}ok${NC} ] Restarting ssh "
/etc/init.d/dropbear restart >/dev/null 2>&1
sleep 1
echo -e "[ ${green}ok${NC} ] Restarting dropbear "
/etc/init.d/fail2ban restart >/dev/null 2>&1
sleep 1
echo -e "[ ${green}ok${NC} ] Restarting fail2ban "
/etc/init.d/stunnel4 restart >/dev/null 2>&1
sleep 1
echo -e "[ ${green}ok${NC} ] Restarting stunnel4 "
/etc/init.d/vnstat restart >/dev/null 2>&1
sleep 1
echo -e "[ ${green}ok${NC} ] Restarting vnstat "
/etc/init.d/squid restart >/dev/null 2>&1

screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7400 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7500 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7600 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7700 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7800 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7900 --max-clients 500
history -c
echo "unset HISTFILE" >> /etc/profile


rm -f /root/key.pem
rm -f /root/cert.pem
rm -f /root/ssh-vpn.sh
rm -f /root/bbr.sh

# finihsing
clear
