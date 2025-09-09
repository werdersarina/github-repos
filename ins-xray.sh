#!/bin/bash
echo -e "
"
date
echo ""
domain=$(cat /root/domain)
sleep 1
mkdir -p /etc/xray 
echo -e "[ ${green}INFO${NC} ] Checking... "
apt install iptables iptables-persistent -y
sleep 1
echo -e "[ ${green}INFO$NC ] Setting ntpdate"
ntpdate pool.ntp.org 
timedatectl set-ntp true
sleep 1
echo -e "[ ${green}INFO$NC ] Enable chronyd"
systemctl enable chronyd
systemctl restart chronyd
sleep 1
echo -e "[ ${green}INFO$NC ] Enable chrony"
systemctl enable chrony
systemctl restart chrony
timedatectl set-timezone Asia/Jakarta
sleep 1
echo -e "[ ${green}INFO$NC ] Setting chrony tracking"
chronyc sourcestats -v
chronyc tracking -v
echo -e "[ ${green}INFO$NC ] Setting dll"
apt clean all && apt update
apt install curl socat xz-utils wget apt-transport-https gnupg gnupg2 gnupg1 dnsutils lsb-release -y 
apt install socat cron bash-completion ntpdate -y
ntpdate pool.ntp.org
apt -y install chrony
apt install zip -y
apt install curl pwgen openssl netcat cron -y


# install xray
sleep 1
echo -e "[ ${green}INFO$NC ] Downloading & Installing xray core"
domainSock_dir="/run/xray";! [ -d $domainSock_dir ] && mkdir  $domainSock_dir
chown www-data.www-data $domainSock_dir
# Make Folder XRay
mkdir -p /var/log/xray
mkdir -p /etc/xray
chown www-data.www-data /var/log/xray
chmod +x /var/log/xray
touch /var/log/xray/access.log
touch /var/log/xray/error.log
touch /var/log/xray/access2.log
touch /var/log/xray/error2.log
# / / Ambil Xray Core Version Terbaru
echo -e "[ ${green}INFO$NC ] Getting latest Xray-core version..."
LATEST_XRAY=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep tag_name | cut -d '"' -f 4)
echo -e "[ ${green}INFO$NC ] Installing Xray-core ${LATEST_XRAY}"
if [ -n "$LATEST_XRAY" ]; then
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version "${LATEST_XRAY#v}"
else
    echo -e "[ ${red}ERROR$NC ] Failed to get latest version, using fallback"
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data
fi



## crt xray
systemctl stop nginx
mkdir /root/.acme.sh
curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
chmod +x /root/.acme.sh/acme.sh
/root/.acme.sh/acme.sh --upgrade --auto-upgrade
/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
/root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc

# nginx renew ssl
echo -n '#!/bin/bash
/etc/init.d/nginx stop
"/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" &> /root/renew_ssl.log
/etc/init.d/nginx start
/etc/init.d/nginx status
' > /usr/local/bin/ssl_renew.sh
chmod +x /usr/local/bin/ssl_renew.sh
if ! grep -q 'ssl_renew.sh' /var/spool/cron/crontabs/root;then (crontab -l;echo "15 03 */3 * * /usr/local/bin/ssl_renew.sh") | crontab;fi

mkdir -p /home/vps/public_html

# set uuid
uuid=$(cat /proc/sys/kernel/random/uuid)

# Generate Custom Paths (Support Any Path)
echo -e "[ ${green}INFO$NC ] Generating custom paths..."

# Function to generate random path
generate_random_path() {
    local prefix=$1
    echo "/${prefix}$(openssl rand -hex 6)"
}

# Custom paths with environment variable support (completely flexible)
VMESS_PATH="${CUSTOM_VMESS_PATH:-$(generate_random_path "vm")}"
VLESS_PATH="${CUSTOM_VLESS_PATH:-$(generate_random_path "vl")}"
TROJAN_PATH="${CUSTOM_TROJAN_PATH:-$(generate_random_path "tr")}"

# XHTTP paths (must be different from WS paths to avoid nginx duplicate location error)
VMESS_XHTTP_PATH="${CUSTOM_VMESS_XHTTP_PATH:-$(generate_random_path "vmx")}"
VLESS_XHTTP_PATH="${CUSTOM_VLESS_XHTTP_PATH:-$(generate_random_path "vlx")}"

# GRPC service names
VLESS_GRPC_SERVICE="${CUSTOM_VLESS_GRPC_SERVICE:-vlessgrpc}"
VMESS_GRPC_SERVICE="${CUSTOM_VMESS_GRPC_SERVICE:-vmessgrpc}"
TROJAN_GRPC_SERVICE="${CUSTOM_TROJAN_GRPC_SERVICE:-trojangrpc}"

# Generate REALITY keys
echo -e "[ ${green}INFO$NC ] Generating REALITY keys..."
XRAY_KEYS=$(/usr/local/bin/xray x25519)
REALITY_PRIVATE=$(echo "$XRAY_KEYS" | head -n1 | cut -d' ' -f3)
REALITY_PUBLIC=$(echo "$XRAY_KEYS" | tail -n1 | cut -d' ' -f3)

echo -e "[ ${green}INFO$NC ] Generated paths:"
echo -e "[ ${green}INFO$NC ] VMess WS: $VMESS_PATH"
echo -e "[ ${green}INFO$NC ] VMess XHTTP: $VMESS_XHTTP_PATH"
echo -e "[ ${green}INFO$NC ] VLess WS: $VLESS_PATH"
echo -e "[ ${green}INFO$NC ] VLess XHTTP: $VLESS_XHTTP_PATH"
echo -e "[ ${green}INFO$NC ] Trojan WS: $TROJAN_PATH"
echo -e "[ ${green}INFO$NC ] REALITY Private Key: $REALITY_PRIVATE"
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
if [ -f /root/scdomain ];then
rm /root/scdomain > /dev/null 2>&1
fi
clear
rm -f ins-xray.sh  
