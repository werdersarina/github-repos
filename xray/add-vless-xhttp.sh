#!/bin/bash
# VLESS XHTTP Account Creator - YT ZIXSTYLE 2025
# Superior mobile performance protocol

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
sed -i '/#vless-xhttp$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'"' /etc/xray/config.json

# Create client config
vlesslink="vless://${uuid}@${domain}:443?type=xhttp&path=/vless-xhttp&host=www.google.com&security=tls&encryption=none&sni=${domain}#${user}-XHTTP"

cat > /home/vps/public_html/vless-xhttp-${user}.txt << EOF
==============================
  VLESS XHTTP CONFIG - YT ZIXSTYLE 2025
==============================
Remarks      : ${user}
Domain       : ${domain}
Port         : 443
User ID      : ${uuid}
Encryption   : none
Network      : XHTTP
Path         : /vless-xhttp
Host         : www.google.com
Security     : TLS
SNI          : ${domain}
Expired      : $exp
==============================
Link         : $vlesslink
==============================
EOF

clear
echo -e ""
echo -e "=============================="
echo -e "  VLESS XHTTP ACCOUNT"
echo -e "=============================="
echo -e "Remarks      : ${user}"
echo -e "Domain       : ${domain}"
echo -e "Port         : 443"
echo -e "User ID      : ${uuid}"
echo -e "Network      : XHTTP"
echo -e "Path         : /vless-xhttp"
echo -e "Expired      : $exp"
echo -e "=============================="
echo -e "Link: $vlesslink"
echo -e "=============================="
echo -e "Config saved: /home/vps/public_html/vless-xhttp-${user}.txt"
echo -e ""

# Restart services
systemctl restart xray
sleep 1
echo -e "Account created successfully!"
echo -e ""
read -n 1 -s -r -p "Press any key to back on menu"
menu-vless
