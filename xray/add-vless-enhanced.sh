#!/bin/bash
# VLess Enhanced Creator - YT ZIXSTYLE 2025  
# Auto-generates ALL VLess protocols (WebSocket + GRPC + XHTTP + REALITY) with same UUID

domain=$(cat /root/domain)
REALITY_PRIVATE=$(grep "REALITY_PRIVATE=" /etc/xray/.config-details | cut -d'=' -f2)
REALITY_PUBLIC=$(grep "REALITY_PUBLIC=" /etc/xray/.config-details | cut -d'=' -f2)

# Load Custom Paths (with fallback to legacy)
VLESS_WS_PATH=$(cat /etc/xray/vless_path 2>/dev/null || echo "/vless")
VLESS_XHTTP_PATH=$(cat /etc/xray/vless_xhttp_path 2>/dev/null || echo "/vless-xhttp")
VLESS_GRPC_SERVICE=$(cat /etc/xray/vless_grpc_service 2>/dev/null || echo "vless-grpc")

until [[ $user =~ ^[a-zA-Z0-9_]+$ && ${#user} -ge 1 && ${#user} -le 15 ]]; do
    read -rp "Username : " -e user
done

until [[ $masaaktif =~ ^[0-9]+$ ]]; do
    read -p "Expired (days): " masaaktif
done

exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
uuid=$(cat /proc/sys/kernel/random/uuid)

# Enhanced VLess Registration: Add same UUID to ALL protocol sections
echo "🔧 Adding VLess account to ALL protocols..."

# 1. WebSocket (port 80/443)
sed -i '/#vless-ws$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'"' /etc/xray/config.json

# 2. GRPC (port 443)
sed -i '/#vlessgrpc$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'"' /etc/xray/config.json

# 3. XHTTP (port 80/443 via Nginx)
sed -i '/#vless-xhttp$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'"' /etc/xray/config.json

# 4. REALITY (port 443 direct) - BONUS!
sed -i '/#vless-reality$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'","flow": "xtls-rprx-vision"' /etc/xray/config.json

# Generate Enhanced Client Configs - Using CUSTOM paths
vless_ws_tls="vless://${uuid}@${domain}:443?type=ws&path=${VLESS_WS_PATH}&host=${domain}&security=tls&encryption=none&sni=${domain}#${user}-WS-TLS"
vless_ws_ntls="vless://${uuid}@${domain}:80?type=ws&path=${VLESS_WS_PATH}&host=${domain}&security=none&encryption=none#${user}-WS-NTLS"
vless_grpc="vless://${uuid}@${domain}:443?type=grpc&serviceName=${VLESS_GRPC_SERVICE}&host=${domain}&security=tls&encryption=none&sni=${domain}#${user}-GRPC"
vless_xhttp="vless://${uuid}@${domain}:443?type=xhttp&path=${VLESS_XHTTP_PATH}&host=${domain}&security=tls&encryption=none&sni=${domain}#${user}-XHTTP"
vless_reality="vless://${uuid}@${domain}:8443?type=tcp&security=reality&fp=chrome&pbk=${REALITY_PUBLIC}&sni=www.microsoft.com&flow=xtls-rprx-vision&sid=6ba85179e30d4fc2#${user}-REALITY"

# Create Enhanced Config File
cat > /home/vps/public_html/vless-enhanced-${user}.txt << EOF
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        Enhanced VLess Account        
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Remarks        : ${user}
Domain         : ${domain}  
UUID           : ${uuid}
Networks       : ws/grpc/xhttp/reality
Ports          : 80 (HTTP non-TLS via Nginx) / 443 (HTTPS TLS via Nginx) / 8443 (REALITY direct)
Protocol Route : Nginx → WS/GRPC/XHTTP | Direct → REALITY
Expired        : $exp
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Link TLS       : $vless_ws_tls
Link none TLS  : $vless_ws_ntls
Link GRPC      : $vless_grpc
Link XHTTP     : $vless_xhttp
🚀 BONUS REALITY  : $vless_reality
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ MULTI-TRANSPORT: All VLess protocols + REALITY!
🔥 SAME UUID: Choose protocol by need!
📱 FLEXIBLE: WS(compatibility) + GRPC(performance) + XHTTP(mobile) + REALITY(stealth)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF

clear
echo -e ""
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "        Enhanced VLess Account        "
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "Remarks        : ${user}"
echo -e "Domain         : ${domain}"
echo -e "UUID           : ${uuid}"
echo -e "Networks       : ws/grpc/xhttp/reality"
echo -e "Ports          : 80 (HTTP non-TLS via Nginx) / 443 (HTTPS TLS via Nginx) / 8443 (REALITY direct)"
echo -e "Protocol Route : Nginx → WS/GRPC/XHTTP | Direct → REALITY"
echo -e "Expired        : $exp"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "Link TLS       : $vless_ws_tls"
echo -e "Link none TLS  : $vless_ws_ntls"
echo -e "Link GRPC      : $vless_grpc"
echo -e "Link XHTTP     : $vless_xhttp"
echo -e "🚀 BONUS REALITY  : $vless_reality"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "✅ MULTI-TRANSPORT: All VLess protocols + REALITY!"
echo -e "🔥 SAME UUID: Choose protocol by need!"
echo -e "📱 FLEXIBLE: WS(compatibility) + GRPC(performance) + XHTTP(mobile) + REALITY(stealth)"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "Config saved: /home/vps/public_html/vless-enhanced-${user}.txt"
echo -e ""

# Restart services
systemctl restart xray
sleep 1
echo -e "Enhanced VLess account created successfully!"
echo -e ""
read -n 1 -s -r -p "Press any key to back on menu"
menu-vless
