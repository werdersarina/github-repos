#!/bin/bash
# VMess XHTTP Account Creator - YT ZIXSTYLE 2025
# Mobile optimized protocol with Post-Quantum encryption

domain=$(cat /root/domain)

until [[ $user =~ ^[a-zA-Z0-9_]+$ && ${#user} -ge 1 && ${#user} -le 15 ]]; do
    read -rp "Username : " -e user
done

until [[ $masaaktif =~ ^[0-9]+$ ]]; do
    read -p "Expired (days): " masaaktif
done

exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
uuid=$(cat /proc/sys/kernel/random/uuid)

# Add user to config
sed -i '/#vmess-xhttp$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'","alterId": 0,"security": "chacha20-poly1305"' /etc/xray/config.json

# Create client config
vmesslink="vmess://$(echo -n '{"v":"2","ps":"'$user'-XHTTP","add":"'$domain'","port":"443","id":"'$uuid'","aid":"0","net":"xhttp","path":"/vmess-xhttp","host":"www.youtube.com","tls":"tls","type":"none"}' | base64 -w 0)"

cat > /home/vps/public_html/vmess-xhttp-${user}.txt << EOF
==============================
  VMess XHTTP CONFIG - YT ZIXSTYLE 2025
==============================
Remarks      : ${user}
Domain       : ${domain}
Port         : 443
User ID      : ${uuid}
AlterID      : 0
Encryption   : chacha20-poly1305 (Post-Quantum)
Network      : XHTTP
Path         : /vmess-xhttp
Host         : www.youtube.com
Security     : TLS
SNI          : ${domain}
Expired      : $exp
==============================
Link         : $vmesslink
==============================
EOF

clear
echo -e ""
echo -e "=============================="
echo -e "  VMess XHTTP ACCOUNT"
echo -e "=============================="
echo -e "Remarks      : ${user}"
echo -e "Domain       : ${domain}"
echo -e "Port         : 443"
echo -e "User ID      : ${uuid}"
echo -e "Network      : XHTTP"
echo -e "Encryption   : chacha20-poly1305"
echo -e "Path         : /vmess-xhttp"
echo -e "Expired      : $exp"
echo -e "=============================="
echo -e "Link: $vmesslink"
echo -e "=============================="
echo -e "Config saved: /home/vps/public_html/vmess-xhttp-${user}.txt"
echo -e ""

# Restart services
systemctl restart xray
sleep 1
echo -e "Account created successfully!"
echo -e ""
read -n 1 -s -r -p "Press any key to back on menu"
menu-vmess
