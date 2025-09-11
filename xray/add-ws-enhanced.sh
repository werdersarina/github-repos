#!/bin/bash
# VMess Enhanced Creator - YT ZIXSTYLE 2025
# Auto-generates ALL VMess protocols (WebSocket + GRPC + XHTTP) with same UUID

domain=$(cat /root/domain)

# Load custom paths from configuration (fallback to legacy if not found)
VMESS_WS_PATH=$(cat /etc/xray/vmess_path 2>/dev/null || echo "/vmess")
VMESS_XHTTP_PATH=$(cat /etc/xray/vmess_xhttp_path 2>/dev/null || echo "/vmess-xhttp") 
VMESS_GRPC_SERVICE=$(cat /etc/xray/vmess_grpc_service 2>/dev/null || echo "vmess-grpc")

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

# 1. WebSocket (port 80/443 - main path)
sed -i '/#vmess-ws$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'"' /etc/xray/config.json

# 2. GRPC (port 443)
sed -i '/#vmessgrpc$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'"' /etc/xray/config.json

# 3. XHTTP (port 80/443 via Nginx)
sed -i '/#vmess-xhttp$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'"' /etc/xray/config.json

# 4. Alternative WebSocket paths (for redundancy and load balancing)
echo "🔧 Adding UUID to alternative VMess paths..."
sed -i '/#vmessworry$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'"' /etc/xray/config.json

sed -i '/#vmesskuota$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'"' /etc/xray/config.json

sed -i '/#vmesschat$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'"' /etc/xray/config.json

# Load alternative paths
VMESS_ALT_PATH_1=$(cat /etc/xray/vmess_alt_path_1 2>/dev/null || echo "/worryfree")
VMESS_ALT_PATH_2=$(cat /etc/xray/vmess_alt_path_2 2>/dev/null || echo "/kuota-habis")
VMESS_ALT_PATH_3=$(cat /etc/xray/vmess_alt_path_3 2>/dev/null || echo "/chat")

# Generate Enhanced Client Configs - Using CUSTOM paths
vmess_ws_tls="vmess://$(echo '{"v":"2","ps":"'"$user"'-WS-TLS","add":"'"$domain"'","port":"443","id":"'"$uuid"'","aid":"0","net":"ws","path":"'"$VMESS_WS_PATH"'","type":"none","host":"'"$domain"'","tls":"tls"}' | base64 -w 0)"
vmess_ws_ntls="vmess://$(echo '{"v":"2","ps":"'"$user"'-WS-NTLS","add":"'"$domain"'","port":"80","id":"'"$uuid"'","aid":"0","net":"ws","path":"'"$VMESS_WS_PATH"'","type":"none","host":"'"$domain"'","tls":"none"}' | base64 -w 0)"
vmess_grpc="vmess://$(echo '{"v":"2","ps":"'"$user"'-GRPC","add":"'"$domain"'","port":"443","id":"'"$uuid"'","aid":"0","net":"grpc","path":"'"$VMESS_GRPC_SERVICE"'","type":"none","host":"'"$domain"'","tls":"tls"}' | base64 -w 0)"
vmess_xhttp="vmess://$(echo '{"v":"2","ps":"'"$user"'-XHTTP","add":"'"$domain"'","port":"443","id":"'"$uuid"'","aid":"0","net":"xhttp","path":"'"$VMESS_XHTTP_PATH"'","type":"none","host":"'"$domain"'","tls":"tls"}' | base64 -w 0)"

# Generate Alternative VMess WebSocket configs for redundancy
vmess_alt1_tls="vmess://$(echo '{"v":"2","ps":"'"$user"'-ALT1-TLS","add":"'"$domain"'","port":"443","id":"'"$uuid"'","aid":"0","net":"ws","path":"'"$VMESS_ALT_PATH_1"'","type":"none","host":"'"$domain"'","tls":"tls"}' | base64 -w 0)"
vmess_alt2_tls="vmess://$(echo '{"v":"2","ps":"'"$user"'-ALT2-TLS","add":"'"$domain"'","port":"443","id":"'"$uuid"'","aid":"0","net":"ws","path":"'"$VMESS_ALT_PATH_2"'","type":"none","host":"'"$domain"'","tls":"tls"}' | base64 -w 0)"
vmess_alt3_tls="vmess://$(echo '{"v":"2","ps":"'"$user"'-ALT3-TLS","add":"'"$domain"'","port":"443","id":"'"$uuid"'","aid":"0","net":"ws","path":"'"$VMESS_ALT_PATH_3"'","type":"none","host":"'"$domain"'","tls":"tls"}' | base64 -w 0)"

# Create Enhanced Config File
cat > /home/vps/public_html/vmess-enhanced-${user}.txt << EOF
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        Enhanced VMess Account        
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Remarks        : ${user}
Domain         : ${domain}
UUID           : ${uuid}
Networks       : ws/grpc/xhttp + alternative paths
Ports          : 80 (HTTP non-TLS via Nginx) / 443 (HTTPS TLS via Nginx)
Protocol Route : Nginx → WS/GRPC/XHTTP internal routing
Expired        : $exp
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PRIMARY CONFIGS:
Link TLS       : $vmess_ws_tls
Link none TLS  : $vmess_ws_ntls
Link GRPC      : $vmess_grpc
Link XHTTP     : $vmess_xhttp
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ALTERNATIVE PATHS (for redundancy):
Alt Path 1     : $vmess_alt1_tls
Alt Path 2     : $vmess_alt2_tls
Alt Path 3     : $vmess_alt3_tls
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ MULTI-TRANSPORT: All VMess protocols!
🔥 SAME UUID: Choose protocol by need!
📱 FLEXIBLE: WS(compatibility) + GRPC(performance) + XHTTP(mobile)
🔄 REDUNDANCY: 7 total configs (4 primary + 3 alternative paths)
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
echo -e "Networks       : ws/grpc/xhttp + alternative paths"
echo -e "Ports          : 80 (HTTP non-TLS via Nginx) / 443 (HTTPS TLS via Nginx)"
echo -e "Protocol Route : Nginx → WS/GRPC/XHTTP internal routing"
echo -e "Expired        : $exp"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "PRIMARY CONFIGS:"
echo -e "Link TLS       : $vmess_ws_tls"
echo -e "Link none TLS  : $vmess_ws_ntls"
echo -e "Link GRPC      : $vmess_grpc"
echo -e "Link XHTTP     : $vmess_xhttp"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "ALTERNATIVE PATHS (for redundancy):"
echo -e "Alt Path 1     : $vmess_alt1_tls"
echo -e "Alt Path 2     : $vmess_alt2_tls"
echo -e "Alt Path 3     : $vmess_alt3_tls"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "✅ MULTI-TRANSPORT: All VMess protocols!"
echo -e "🔥 SAME UUID: Choose protocol by need!"
echo -e "📱 FLEXIBLE: WS(compatibility) + GRPC(performance) + XHTTP(mobile)"
echo -e "🔄 REDUNDANCY: 7 total configs (4 primary + 3 alternative paths)"
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
