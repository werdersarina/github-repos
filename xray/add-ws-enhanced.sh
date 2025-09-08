#!/bin/bash
# VMess Enhanced Creator - YT ZIXSTYLE 2025
# Auto-generates ALL VMess protocols (WebSocket + GRPC + XHTTP) with same UUID

domain=$(cat /root/domain)

until [[ $user =~ ^[a-zA-Z0-9_]+$ && ${#user} -ge 1 && ${#user} -le 15 ]]; do
    read -rp "Username : " -e user
done

until [[ $masaaktif =~ ^[0-9]+$ ]]; do
    read -p "Expired (days): " masaaktif
done

exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
uuid=$(cat /proc/sys/kernel/random/uuid)

# Enhanced VMess Registration: Add same UUID to ALL protocol sections
echo "🔧 Adding VMess account to ALL protocols..."

# 1. WebSocket (port 80/443)
sed -i '/#vmess-ws$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'"' /etc/xray/config.json

# 2. GRPC (port 443)
sed -i '/#vmessgrpc$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'"' /etc/xray/config.json

# 3. XHTTP (port 80/443 via Nginx)
sed -i '/#vmess-xhttp$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'"' /etc/xray/config.json

# Generate Enhanced Client Configs - ALL using standard ports 80/443
vmess_ws_tls="vmess://$(echo '{"v":"2","ps":"'"$user"'-WS-TLS","add":"'"$domain"'","port":"443","id":"'"$uuid"'","aid":"0","net":"ws","path":"/vmess","type":"none","host":"'"$domain"'","tls":"tls"}' | base64 -w 0)"
vmess_ws_ntls="vmess://$(echo '{"v":"2","ps":"'"$user"'-WS-NTLS","add":"'"$domain"'","port":"80","id":"'"$uuid"'","aid":"0","net":"ws","path":"/vmess","type":"none","host":"'"$domain"'","tls":"none"}' | base64 -w 0)"
vmess_grpc="vmess://$(echo '{"v":"2","ps":"'"$user"'-GRPC","add":"'"$domain"'","port":"443","id":"'"$uuid"'","aid":"0","net":"grpc","path":"vmess-grpc","type":"none","host":"'"$domain"'","tls":"tls"}' | base64 -w 0)"
vmess_xhttp="vmess://$(echo '{"v":"2","ps":"'"$user"'-XHTTP","add":"'"$domain"'","port":"443","id":"'"$uuid"'","aid":"0","net":"xhttp","path":"/vmess-xhttp","type":"none","host":"'"$domain"'","tls":"tls"}' | base64 -w 0)"

# Create Enhanced Config File
cat > /home/vps/public_html/vmess-enhanced-${user}.txt << EOF
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        Enhanced VMess Account        
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Remarks        : ${user}
Domain         : ${domain}
UUID           : ${uuid}
Networks       : ws/grpc/xhttp
Ports          : 80 (HTTP non-TLS via Nginx) / 443 (HTTPS TLS via Nginx)
Protocol Route : Nginx → WS/GRPC/XHTTP internal routing
Expired        : $exp
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Link TLS       : $vmess_ws_tls
Link none TLS  : $vmess_ws_ntls
Link GRPC      : $vmess_grpc
Link XHTTP     : $vmess_xhttp
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ MULTI-TRANSPORT: All VMess protocols!
🔥 SAME UUID: Choose protocol by need!
📱 FLEXIBLE: WS(compatibility) + GRPC(performance) + XHTTP(mobile)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF

clear
echo -e ""
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "        Enhanced VMess Account        "
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "Remarks        : ${user}"
echo -e "Domain         : ${domain}"
echo -e "UUID           : ${uuid}"
echo -e "Networks       : ws/grpc/xhttp"
echo -e "Ports          : 80 (HTTP non-TLS via Nginx) / 443 (HTTPS TLS via Nginx)"
echo -e "Protocol Route : Nginx → WS/GRPC/XHTTP internal routing"
echo -e "Expired        : $exp"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "Link TLS       : $vmess_ws_tls"
echo -e "Link none TLS  : $vmess_ws_ntls"
echo -e "Link GRPC      : $vmess_grpc"
echo -e "Link XHTTP     : $vmess_xhttp"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "✅ MULTI-TRANSPORT: All VMess protocols!"
echo -e "🔥 SAME UUID: Choose protocol by need!"
echo -e "📱 FLEXIBLE: WS(compatibility) + GRPC(performance) + XHTTP(mobile)"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "Config saved: /home/vps/public_html/vmess-enhanced-${user}.txt"
echo -e ""

# Restart services
systemctl restart xray
sleep 1
echo -e "Enhanced VMess account created successfully!"
echo -e ""
read -n 1 -s -r -p "Press any key to back on menu"
menu-vmess
