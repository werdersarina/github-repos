#!/bin/bash
# VLESS REALITY Account Creator - YT ZIXSTYLE 2025
# Modern protocol without certificate requirement

domain=$(cat /root/domain)
REALITY_PRIVATE=$(grep "REALITY_PRIVATE=" /etc/xray/.config-details | cut -d'=' -f2)
REALITY_PUBLIC=$(grep "REALITY_PUBLIC=" /etc/xray/.config-details | cut -d'=' -f2)

until [[ $user =~ ^[a-zA-Z0-9_]+$ && ${#user} -ge 1 && ${#user} -le 15 ]]; do
    read -rp "Username : " -e user
done

until [[ $masaaktif =~ ^[0-9]+$ ]]; do
    read -p "Expired (days): " masaaktif
done

exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
uuid=$(cat /proc/sys/kernel/random/uuid)

# Add user to config
sed -i '/#vless-reality$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'","flow": "xtls-rprx-vision"' /etc/xray/config.json

# Create client config
vlesslink="vless://${uuid}@${domain}:8443?type=tcp&security=reality&fp=chrome&pbk=${REALITY_PUBLIC}&sni=www.google.com&flow=xtls-rprx-vision&sid=0123456789abcdef#${user}-REALITY"

cat > /home/vps/public_html/vless-reality-${user}.txt << EOF
==============================
  VLESS REALITY CONFIG - YT ZIXSTYLE 2025
==============================
Remarks      : ${user}
Domain       : ${domain}
Port         : 8443
User ID      : ${uuid}
Encryption   : none
Network      : TCP
Security     : REALITY (No Certificate Needed)
Public Key   : ${REALITY_PUBLIC}
SNI          : www.google.com
Flow         : xtls-rprx-vision
Expired      : $exp
==============================
Link         : $vlesslink
==============================
EOF

clear
echo -e ""
echo -e "=============================="
echo -e "  VLESS REALITY ACCOUNT"
echo -e "=============================="
echo -e "Remarks      : ${user}"
echo -e "Domain       : ${domain}"
echo -e "Port         : 8443"
echo -e "User ID      : ${uuid}"
echo -e "Security     : REALITY"
echo -e "Public Key   : ${REALITY_PUBLIC}"
echo -e "Expired      : $exp"
echo -e "=============================="
echo -e "Link: $vlesslink"
echo -e "=============================="
echo -e "Config saved: /home/vps/public_html/vless-reality-${user}.txt"
echo -e ""

# Restart services
systemctl restart xray
sleep 1
echo -e "Account created successfully!"
echo -e ""
read -n 1 -s -r -p "Press any key to back on menu"
menu-vless
