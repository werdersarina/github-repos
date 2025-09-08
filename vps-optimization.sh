#!/bin/bash
#
# VPS Resource Optimization Script untuk 1GB RAM
# Created: September 8, 2025
# Purpose: Optimasi server VPN untuk spec 1 shared core + 1GB memory
# ===============================================================================

echo "🔧 VPS OPTIMIZATION untuk 1GB RAM + 1 Shared Core"
echo "================================================="

# 1. Optimasi Nginx untuk low memory
echo "📝 Optimizing Nginx configuration..."
cat > /etc/nginx/nginx.conf.optimized << 'EOF'
user www-data;
worker_processes 1;  # Sesuai dengan 1 core
worker_rlimit_nofile 8192;
pid /run/nginx.pid;

events {
    worker_connections 1024;  # Dikurangi untuk save memory
    use epoll;
    multi_accept on;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 15;  # Lebih pendek untuk save memory
    types_hash_max_size 2048;
    server_tokens off;
    
    # Memory optimization
    client_max_body_size 8m;
    client_body_buffer_size 128k;
    client_header_buffer_size 1k;
    large_client_header_buffers 4 4k;
    
    # Gzip compression untuk save bandwidth
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_comp_level 6;
    gzip_types text/plain text/css application/json application/javascript;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log warn;
    
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

# 2. Optimasi Xray config untuk low resource
echo "📝 Creating optimized Xray config..."
cat > /etc/xray/config_optimized.json << 'EOF'
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "wsSettings": {
          "path": "/vless-ws"
        },
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/xray/xray.crt",
              "keyFile": "/etc/xray/xray.key"
            }
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ],
  "stats": {},
  "api": {
    "tag": "api",
    "services": ["HandlerService", "LoggerService", "StatsService"]
  },
  "policy": {
    "levels": {
      "0": {
        "handshake": 2,
        "connIdle": 120,
        "uplinkOnly": 0,
        "downlinkOnly": 0,
        "bufferSize": 4096,
        "statsUserUplink": false,
        "statsUserDownlink": false
      }
    },
    "system": {
      "statsInboundUplink": false,
      "statsInboundDownlink": false,
      "statsOutboundUplink": false,
      "statsOutboundDownlink": false
    }
  }
}
EOF

# 3. Memory optimization untuk system
echo "📝 Applying memory optimizations..."

# Swappiness (lebih agresif menggunakan swap)
echo 'vm.swappiness=60' >> /etc/sysctl.conf

# Dirty ratio (flush data lebih cepat)
echo 'vm.dirty_ratio=10' >> /etc/sysctl.conf
echo 'vm.dirty_background_ratio=5' >> /etc/sysctl.conf

# Network optimizations
echo 'net.core.rmem_max=16777216' >> /etc/sysctl.conf
echo 'net.core.wmem_max=16777216' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_rmem=4096 16384 16777216' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_wmem=4096 16384 16777216' >> /etc/sysctl.conf

# Apply changes
sysctl -p

# 4. Service monitoring script
cat > /usr/local/bin/vps_monitor.sh << 'EOF'
#!/bin/bash
# VPS Resource Monitor untuk 1GB setup

LOG_FILE="/var/log/vps_monitor.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Check memory usage
MEM_USAGE=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
MEM_AVAILABLE=$(free -h | grep Mem | awk '{print $7}')

# Check CPU usage
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//')

# Check active connections
CONNECTIONS=$(netstat -an | grep ESTABLISHED | wc -l)

echo "$DATE | Memory: ${MEM_USAGE}% used, Available: $MEM_AVAILABLE | CPU: $CPU_USAGE | Connections: $CONNECTIONS" >> $LOG_FILE

# Alert if memory > 90%
if (( $(echo "$MEM_USAGE > 90" | bc -l) )); then
    echo "$DATE | WARNING: High memory usage: ${MEM_USAGE}%" >> $LOG_FILE
    # Optional: restart heavy services
    # systemctl restart xray nginx
fi

# Keep only last 1000 lines
tail -n 1000 $LOG_FILE > $LOG_FILE.tmp && mv $LOG_FILE.tmp $LOG_FILE
EOF

chmod +x /usr/local/bin/vps_monitor.sh

# 5. Cron job untuk monitoring
echo "*/5 * * * * /usr/local/bin/vps_monitor.sh" | crontab -

# 6. Logrotate optimization
cat > /etc/logrotate.d/vps_optimization << 'EOF'
/var/log/xray/*.log {
    daily
    missingok
    rotate 3
    compress
    delaycompress
    notifempty
    postrotate
        systemctl reload xray
    endscript
}

/var/log/nginx/*.log {
    daily
    missingok
    rotate 3
    compress
    delaycompress
    notifempty
    postrotate
        systemctl reload nginx
    endscript
}
EOF

echo "✅ VPS Optimization Complete!"
echo "📊 Monitoring: tail -f /var/log/vps_monitor.log"
echo "🔧 Manual check: free -h && top -bn1 | head -5"
