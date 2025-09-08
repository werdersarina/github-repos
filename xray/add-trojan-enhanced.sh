#!/bin/bash
# Trojan Enhanced Creator - YT ZIXSTYLE 2025
# Auto-generates ALL Trojan protocols (WebSocket + GRPC) with same password

domain=$(cat /root/domain)

until [[ $user =~ ^[a-zA-Z0-9_]+$ && ${#user} -ge 1 && ${#user} -le 15 ]]; do
    read -rp "Username : " -e user
done

until [[ $masaaktif =~ ^[0-9]+$ ]]; do
    read -p "Expired (days): " masaaktif
done

exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
uuid=$(cat /proc/sys/kernel/random/uuid)

# Enhanced Trojan Registration: Add same password to ALL protocol sections
echo "🔧 Adding Trojan account to ALL protocols..."

# 1. Trojan WebSocket (port 80/443 via Nginx)
sed -i '/#trojanws$/a\### '"$user $exp"'\
},{"password": "'""$uuid""'"' /etc/xray/config.json

# 2. Trojan GRPC (port 443 via Nginx)
sed -i '/#trojangrpc$/a\### '"$user $exp"'\
},{"password": "'""$uuid""'"' /etc/xray/config.json

# Generate Enhanced Client Configs - ALL using standard ports 80/443
trojan_ws_tls="trojan://${uuid}@${domain}:443?type=ws&path=%2Ftrojan-ws&host=${domain}&security=tls&sni=${domain}#${user}-WS-TLS"
trojan_ws_ntls="trojan://${uuid}@${domain}:80?type=ws&path=%2Ftrojan-ws&host=${domain}&security=none#${user}-WS-NTLS"
trojan_grpc="trojan://${uuid}@${domain}:443?type=grpc&serviceName=trojan-grpc&host=${domain}&security=tls&sni=${domain}#${user}-GRPC"

# Create Enhanced Config File
cat > /home/vps/public_html/trojan-enhanced-${user}.txt << EOF
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        Enhanced Trojan Account        
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Remarks        : ${user}
Domain         : ${domain}
Password       : ${uuid}
Networks       : ws/grpc
Ports          : 80/443 (via Nginx)
Expired        : $exp
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Link TLS       : $trojan_ws_tls
Link none TLS  : $trojan_ws_ntls
Link GRPC      : $trojan_grpc
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ MULTI-TRANSPORT: WS + GRPC protocols!
🔥 SAME PASSWORD: Choose protocol by need!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF

clear
echo -e ""
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "        Enhanced Trojan Account        "
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "Remarks        : ${user}"
echo -e "Domain         : ${domain}"
echo -e "Password       : ${uuid}"
echo -e "Networks       : ws/grpc"
echo -e "Ports          : 80/443 (via Nginx)"
echo -e "Expired        : $exp"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "Link TLS       : $trojan_ws_tls"
echo -e "Link none TLS  : $trojan_ws_ntls"
echo -e "Link GRPC      : $trojan_grpc"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "✅ MULTI-TRANSPORT: WS + GRPC protocols!"
echo -e "🔥 SAME PASSWORD: Choose protocol by need!"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "Config saved: /home/vps/public_html/trojan-enhanced-${user}.txt"
echo -e ""

# Restart services
systemctl restart xray
sleep 1
echo -e "Enhanced Trojan account created successfully!"
echo -e ""
read -n 1 -s -r -p "Press any key to back on menu"
menu-trojan
