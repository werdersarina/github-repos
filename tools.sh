#!/bin/bash
clear
red='\e[1;31m'
green='\e[1;32m'
yell='\e[1;33m'
NC='\e[0m'
green() { echo -e "\\033[32;1m${*}\\033[0m"; }
red() { echo -e "\\033[31;1m${*}\\033[0m"; }

if [[ -e /etc/debian_version ]]; then
	source /etc/os-release
	OS=$ID # debian or ubuntu
elif [[ -e /etc/centos-release ]]; then
	source /etc/os-release
	OS=centos
fi




echo "Tools install...!"
echo "Progress..."
sleep 2

sudo apt update -y
sudo apt update -y
sudo apt dist-upgrade -y
sudo apt-get remove --purge ufw firewalld -y 
sudo apt-get remove --purge exim4 -y 


sudo apt install -y screen curl jq bzip2 gzip coreutils rsyslog iftop \
 htop zip unzip net-tools sed gnupg gnupg1 \
 bc sudo apt-transport-https build-essential dirmngr libxml-parser-perl neofetch screenfetch git lsof \
 openssl openvpn easy-rsa fail2ban tmux \
 stunnel4 vnstat squid3 \
 dropbear  libsqlite3-dev \
 socat cron bash-completion ntpdate xz-utils sudo apt-transport-https \
 gnupg2 dnsutils lsb-release chrony

curl -sSL https://deb.nodesource.com/setup_20.x | bash - 
sudo apt-get install nodejs -y

# Get network interface name correctly
NET=$(ip route | grep default | awk '{print $5}' | head -1)
if [ -z "$NET" ]; then
    NET=$(ls /sys/class/net/ | grep -v lo | head -1)
fi

# Install vnstat
echo "Installing vnstat..."
systemctl stop vnstat >/dev/null 2>&1

# First try package installation
apt-get install vnstat -y >/dev/null 2>&1

# If package doesn't work, compile from source
if ! command -v vnstat >/dev/null 2>&1; then
    cd /root
    wget -q https://humdi.net/vnstat/vnstat-2.12.tar.gz
    tar zxvf vnstat-2.12.tar.gz >/dev/null 2>&1
    cd vnstat-2.12
    ./configure --prefix=/usr --sysconfdir=/etc --sbindir=/usr/bin >/dev/null 2>&1
    make >/dev/null 2>&1
    make install >/dev/null 2>&1
    cd /root
    rm -f vnstat-2.12.tar.gz >/dev/null 2>&1
    rm -rf vnstat-2.12 >/dev/null 2>&1
fi

# Create vnstat user if doesn't exist
if ! id -u vnstat >/dev/null 2>&1; then
    useradd -r -s /bin/false vnstat >/dev/null 2>&1
fi

# Initialize vnstat
mkdir -p /var/lib/vnstat
/usr/bin/vnstat -u -i $NET >/dev/null 2>&1
sed -i "s/Interface \"eth0\"/Interface \"$NET\"/g" /etc/vnstat.conf
chown vnstat:vnstat /var/lib/vnstat -R
systemctl enable vnstat >/dev/null 2>&1
systemctl restart vnstat >/dev/null 2>&1

sudo apt install -y libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison make libnss3-tools libevent-dev xl2tpd pptpd

yellow() { echo -e "\\033[33;1m${*}\\033[0m"; }
yellow "Dependencies successfully installed..."
sleep 3
clear

