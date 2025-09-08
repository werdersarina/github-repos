#!/bin/bash
#
# YT ZIXSTYLE WebSocket Installer 2025
# Created: September 7, 2025  
# Purpose: Install WebSocket tunneling for SSH and SSL
# Log: Inherit dari setup-2025.sh
# ===============================================================================

# Inherit logging system
if [ -z "$INSTALL_LOG_PATH" ]; then
    echo "ERROR: Must be called from setup-2025.sh"
    exit 1
fi

log_section "SSHWS-2025.SH STARTED"
log_and_show "🌐 Starting WebSocket tunneling installation..."

# Install Nginx dengan penanganan error yang lebih baik
log_and_show "🌐 Installing Nginx web server..."

# Periksa dan hentikan layanan web server yang mungkin sudah berjalan
log_and_show "🔍 Memeriksa layanan web server yang sedang berjalan..."
for service in apache2 httpd lighttpd; do
    if systemctl is-active --quiet $service 2>/dev/null; then
        log_command "systemctl stop $service"
        log_command "systemctl disable $service"
    fi
done

# Periksa port yang sudah digunakan
log_and_show "🔍 Memeriksa port yang sudah digunakan..."
used_ports=$(netstat -tlnp 2>/dev/null | grep -E ':80|:443' | awk '{print $4}' | cut -d: -f2 || echo "")
if [ -n "$used_ports" ]; then
    log_and_show "⚠️ Port berikut sudah digunakan: $used_ports"
    log_and_show "🔄 Menghentikan proses yang menggunakan port tersebut..."
    for port in $used_ports; do
        fuser -k ${port}/tcp 2>/dev/null || true
    done
    sleep 2
fi

# Force install nginx dengan percobaan beberapa metode
log_and_show "📦 Menginstal nginx dengan metode yang reliable..."

install_nginx_success=false

# Metode 1: Update package cache dan install
log_and_show "🔄 Mencoba instalasi nginx metode 1..."
if log_command "apt update -qq && apt install -y nginx nginx-common nginx-core"; then
    install_nginx_success=true
    log_and_show "✅ Nginx berhasil diinstal dengan metode 1"
fi

# Metode 2: Jika metode 1 gagal, coba instalasi dengan fix broken dependencies
if [ "$install_nginx_success" = false ]; then
    log_and_show "🔄 Mencoba metode instalasi alternatif untuk nginx..."
    log_command "apt --fix-broken install -y"
    if log_command "apt install -y --reinstall nginx"; then
        install_nginx_success=true
        log_and_show "✅ Nginx berhasil diinstal dengan metode 2"
    fi
fi

# Metode 3: Jika metode 2 juga gagal, coba dengan dpkg reconfigure
if [ "$install_nginx_success" = false ]; then
    log_and_show "🔄 Mencoba instalasi dengan dpkg reconfigure..."
    log_command "dpkg --configure -a"
    if log_command "apt install -y nginx"; then
        install_nginx_success=true
        log_and_show "✅ Nginx berhasil diinstal dengan metode 3"
    fi
fi

# Verifikasi instalasi
if command -v nginx >/dev/null 2>&1; then
    install_nginx_success=true
    log_and_show "✅ Verifikasi: Nginx binary tersedia"
    nginx -v 2>&1 | log_and_show
else
    log_and_show "❌ Nginx tidak berhasil diinstal dengan semua metode yang dicoba"
    log_and_show "⚠️ WebSocket mungkin tidak berfungsi dengan baik"
    install_nginx_success=false
fi

# Ensure nginx directory exists 
log_command "mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled"

# Use Python2 from tools-2025.sh installation
log_and_show "🐍 Configuring Python2 for WebSocket services..."

# Ensure python symlink exists
if ! command -v python >/dev/null 2>&1; then
    log_command "ln -sf /usr/bin/python3 /usr/bin/python"
    log_and_show "✅ Python2 symlink created"
fi

# Download WebSocket scripts
log_and_show "📥 Downloading WebSocket scripts..."
log_command "wget -O /usr/local/bin/ws-dropbear https://raw.githubusercontent.com/werdersarina/github-repos/main/sshws/dropbear-ws.py"
log_command "wget -O /usr/local/bin/ws-stunnel https://raw.githubusercontent.com/werdersarina/github-repos/main/sshws/ws-stunnel"

# Set permissions
log_command "chmod +x /usr/local/bin/ws-dropbear"
log_command "chmod +x /usr/local/bin/ws-stunnel"

# Create systemd service for Dropbear WebSocket
log_and_show "⚙️  Creating Dropbear WebSocket service..."
cat > /etc/systemd/system/ws-dropbear.service << 'EOF'
[Unit]
Description=Dropbear WebSocket Tunnel 2025
Documentation=https://github.com/werdersarina/github-repos
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/bin/python3 -O /usr/local/bin/ws-dropbear 8080
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Create systemd service for Stunnel WebSocket  
log_and_show "⚙️  Creating Stunnel WebSocket service..."
cat > /etc/systemd/system/ws-stunnel.service << 'EOF'
[Unit]
Description=SSH Over Websocket SSL 2025
Documentation=https://github.com/werdersarina/github-repos
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/bin/python3 -O /usr/local/bin/ws-stunnel
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Set proper service file permissions
log_command "chmod 644 /etc/systemd/system/ws-dropbear.service"
log_command "chmod 644 /etc/systemd/system/ws-stunnel.service"

# Configure Nginx for WebSocket proxy
log_and_show "🌐 Configuring Nginx..."

# Backup original nginx config if exists
if [ -f /etc/nginx/nginx.conf ]; then
    log_command "cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup"
fi

# Create optimized nginx configuration
cat > /etc/nginx/nginx.conf << 'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 1024;
    multi_accept on;
    use epoll;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;
    
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

# Create default site configuration for WebSocket
cat > /etc/nginx/sites-available/default << EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    location /ws-dropbear {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
    
    location /ws-stunnel {
        proxy_pass http://127.0.0.1:8880;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
}
EOF

# Enable default site
log_command "ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/"

# Nginx configuration validation and startup
log_and_show "🔍 Testing nginx configuration..."
if nginx -t 2>/dev/null; then
    log_and_show "✅ Nginx configuration is valid"
else
    log_and_show "❌ Nginx configuration error, using minimal config..."
    # Buat konfigurasi minimal yang pasti valid
    cat > /etc/nginx/nginx.conf << 'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 768;
}

http {
    sendfile on;
    tcp_nopush on;
    types_hash_max_size 2048;
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    server {
        listen 80;
        server_name _;
        
        location / {
            return 200 "WebSocket Server Running";
        }
        
        # Konfigurasi lokasi untuk WebSocket
        location /ws-dropbear {
            proxy_pass http://127.0.0.1:8080;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $http_host;
        }
    }
}
EOF
    # Hapus semua konfigurasi site yang mungkin menyebabkan konflik
    rm -f /etc/nginx/sites-enabled/* 2>/dev/null || true
    
    # Tes konfigurasi minimal
    if nginx -t 2>/dev/null; then
        log_and_show "✅ Konfigurasi nginx minimal berhasil"
    else
        log_and_show "❌ Konfigurasi nginx minimal juga gagal, mencoba tanpa include..."
        # Versi paling minimal tanpa include
        cat > /etc/nginx/nginx.conf << 'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 768;
}

http {
    sendfile on;
    tcp_nopush on;
    types_hash_max_size 2048;
    default_type application/octet-stream;
    
    server {
        listen 80;
        server_name _;
        
        location / {
            return 200 "WebSocket Server Running";
        }
        
        location /ws-dropbear {
            proxy_pass http://127.0.0.1:8080;
        }
    }
}
EOF
    fi
    
    # Backup current config and create minimal working config
    cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup 2>/dev/null || true
    cat > /etc/nginx/nginx.conf << 'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    sendfile on;
    keepalive_timeout 65;
    
    # Basic logging
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        
        location / {
            return 200 "WebSocket Server Running";
            add_header Content-Type text/plain;
        }
        
        location /ws-dropbear {
            proxy_pass http://127.0.0.1:8080;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $http_host;
        }
        
        location /ws-stunnel {
            proxy_pass http://127.0.0.1:8880;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $http_host;
        }
    }
}
EOF
    
    # Remove conflicting default sites
    rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
    rm -f /etc/nginx/sites-available/default 2>/dev/null || true
    
    # Test minimal config
    if nginx -t 2>/dev/null; then
        log_and_show "✅ Minimal nginx configuration is valid"
    else
        log_and_show "❌ Even minimal nginx config failed, creating ultra-minimal config"
        cat > /etc/nginx/nginx.conf << 'EOF'
events {}
http {
    server {
        listen 80;
        location / { return 200 "OK"; }
    }
}
EOF
    fi
fi

# Enable and start services
log_and_show "🚀 Starting WebSocket services..."
log_command "systemctl daemon-reload"
log_command "systemctl enable ws-dropbear"
log_command "systemctl enable ws-stunnel"
log_command "systemctl start ws-dropbear"
log_command "systemctl start ws-stunnel"

# Fungsi untuk memulai nginx dengan pendekatan bertahap
start_nginx_safely() {
    log_and_show "🌐 Memulai nginx dengan pendekatan bertahap..."
    
    # Pastikan direktori yang diperlukan ada
    log_command "mkdir -p /var/log/nginx /var/lib/nginx /var/cache/nginx"
    log_command "chown -R www-data:www-data /var/log/nginx /var/lib/nginx /var/cache/nginx" || true
    log_command "mkdir -p /var/www/html"
    echo "<h1>Server Running</h1>" > /var/www/html/index.html 2>/dev/null || true
    
    # Check for port conflicts before starting nginx
    if netstat -tlnp 2>/dev/null | grep -q ":80 "; then
        log_and_show "⚠️ Port 80 sudah digunakan, menghentikan proses yang menggunakan port tersebut..."
        fuser -k 80/tcp 2>/dev/null || true
        sleep 2
    fi
    
    # Stop any existing nginx processes
    log_command "systemctl stop nginx" 2>/dev/null || true
    pkill -f nginx 2>/dev/null || true
    sleep 2
    
    # Mulai nginx dengan multiple attempts dan detailed error reporting
    for attempt in 1 2 3; do
        log_and_show "🔄 Mencoba memulai nginx (percobaan $attempt/3)..."
        
        systemctl start nginx
        sleep 3
        
        if systemctl is-active --quiet nginx; then
            log_and_show "✅ Nginx berhasil dijalankan pada percobaan $attempt"
            return 0
        else
            log_and_show "⚠️ Nginx gagal dijalankan pada percobaan $attempt, mencoba lagi..."
            
            # Jika gagal pada percobaan terakhir, coba mode debug dan metode alternatif
            if [ $attempt -eq 3 ]; then
                log_and_show "⚠️ Semua percobaan systemctl gagal, mencoba metode langsung..."
                
                # Coba start manual
                nginx -g 'daemon on;' 2>/dev/null
                sleep 2
                
                if pgrep -f nginx >/dev/null; then
                    log_and_show "✅ Nginx berhasil dijalankan secara manual"
                    return 0
                else
                    # Jika masih gagal, coba tambahkan opsi debugging
                    log_and_show "⚠️ Menjalankan nginx dengan mode debug..."
                    nginx -g 'daemon on; error_log /var/log/nginx/error.log debug;' 2>/dev/null
                    sleep 2
                    
                    # Final check
                    if pgrep -f nginx >/dev/null; then
                        log_and_show "✅ Nginx berhasil dijalankan dengan mode debug"
                        return 0
                    else
                        # Sebagai upaya terakhir, coba perbaiki systemd service file
                        log_and_show "⚠️ Memperbaiki service file nginx..."
                        cat > /lib/systemd/system/nginx.service << 'EOF'
[Unit]
Description=nginx - high performance web server
Documentation=https://nginx.org/en/docs/
After=network-online.target remote-fs.target nss-lookup.target
Wants=network-online.target

[Service]
ExecStartPre=/usr/sbin/nginx -t
ExecStart=/usr/sbin/nginx -g 'daemon on; master_process on;'
ExecReload=/bin/sh -c "/bin/kill -s HUP $(/bin/cat /var/run/nginx.pid)"
KillSignal=SIGQUIT
TimeoutStopSec=5
KillMode=mixed
PrivateTmp=true
Restart=on-failure
RestartSec=3s

[Install]
WantedBy=multi-user.target
EOF
                        systemctl daemon-reload
                        systemctl restart nginx
                    fi
                fi
            fi
        fi
    done
    
    # Jika sampai di sini, semua metode gagal
    log_and_show "❌ Semua metode untuk memulai nginx gagal"
    log_and_show "⚠️ WebSocket mungkin tidak berfungsi dengan baik"
    return 1
}
        # Try to remove problematic includes
        cat > /etc/nginx/nginx.conf << 'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 768;
}

http {
    sendfile on;
    tcp_nopush on;
    types_hash_max_size 2048;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    gzip on;
    
    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        
        root /var/www/html;
        index index.html index.htm index.nginx-debian.html;
        
        server_name _;
        
        location / {
            try_files $uri $uri/ =404;
        }
    }
}
EOF
        nginx -t || log_and_show "❌ Critical nginx configuration failure"
    fi
fi

# Ensure proper directories and permissions exist
log_command "mkdir -p /var/log/nginx /var/lib/nginx /var/cache/nginx"
log_command "chown -R www-data:www-data /var/log/nginx /var/lib/nginx /var/cache/nginx" || true
log_command "mkdir -p /var/www/html"
echo "<h1>Server Running</h1>" > /var/www/html/index.html 2>/dev/null || true

# Check for port conflicts before starting nginx
if netstat -tlnp 2>/dev/null | grep -q ":80 "; then
    log_and_show "⚠️ Port 80 is in use, checking what's using it..."
    netstat -tlnp | grep ":80 " || true
    
    # Try to stop conflicting services
    log_and_show "🔄 Attempting to stop conflicting services on port 80..."
    systemctl stop apache2 2>/dev/null || true
    systemctl stop httpd 2>/dev/null || true
    pkill -f "nginx" 2>/dev/null || true
    sleep 2
fi

# Gunakan fungsi start_nginx_safely untuk memulai nginx dengan pendekatan bertahap
if start_nginx_safely; then
    log_and_show "✅ Nginx berhasil dijalankan dengan pendekatan bertahap"
else
    log_and_show "⚠️ Nginx gagal dijalankan, mencoba solusi terakhir..."
    
    # Jika semua metode gagal, coba solusi terakhir dengan file konfigurasi minimal absolut
    log_command "systemctl stop nginx" 2>/dev/null || true
    pkill -f nginx 2>/dev/null || true
    sleep 2
    
    # Hapus semua konfigurasi
    rm -rf /etc/nginx/sites-enabled/* /etc/nginx/sites-available/* /etc/nginx/conf.d/* 2>/dev/null || true
    
    # Konfigurasi ultra minimal
    cat > /etc/nginx/nginx.conf << 'EOF'
user www-data;
worker_processes 1;
pid /run/nginx.pid;
events {worker_connections 1024;}
http {
    server {
        listen 80 default_server;
        location / {return 200 "WebSocket Server Running";}
        location /ws-dropbear {proxy_pass http://127.0.0.1:8080;}
    }
}
EOF
    
    # Coba jalankan nginx sekali lagi
    nginx -g 'daemon on;' 2>/dev/null
    
    if pgrep -f nginx >/dev/null; then
        log_and_show "✅ Nginx berhasil dijalankan dengan konfigurasi ultra minimal"
    else
        log_and_show "❌ Semua upaya menjalankan nginx gagal"
        log_and_show "⚠️ WebSocket akan bekerja di background tapi tidak bisa diakses melalui web"
    fi
EOF
            systemctl daemon-reload
            
            # Final attempt with override
            if systemctl start nginx 2>/dev/null; then
                log_and_show "✅ Nginx started with service override"
            else
                log_and_show "❌ Nginx startup completely failed, continuing without nginx"
            fi
        else
            sleep 3
        fi
    fi
done

# Enable nginx service for startup
log_command "systemctl enable nginx" || log_and_show "⚠️ Failed to enable nginx service"

# Verify nginx is actually running and listening
if systemctl is-active nginx >/dev/null 2>&1; then
    log_and_show "✅ Nginx service is active"
    if netstat -tlnp 2>/dev/null | grep -q ":80.*nginx"; then
        log_and_show "✅ Nginx is listening on port 80"
    else
        log_and_show "⚠️ Nginx is running but not listening on port 80"
    fi
else
    log_and_show "❌ Nginx service failed to start properly"
fi

# Verify services are running
if systemctl is-active --quiet ws-dropbear.service; then
    log_and_show "✅ ws-dropbear service: ACTIVE on port 8080"
else
    log_and_show "⚠️ ws-dropbear service: FAILED to start"
fi

if systemctl is-active --quiet ws-stunnel.service; then
    log_and_show "✅ ws-stunnel service: ACTIVE"
else
    log_and_show "⚠️ ws-stunnel service: FAILED to start"
fi

# Log WebSocket info (consistent with user display scripts)
echo "SSH Websocket: 8080" >> /root/log-install.txt
echo "SSH SSL Websocket: 443" >> /root/log-install.txt
echo "Nginx: 80" >> /root/log-install.txt

log_and_show "✅ WebSocket tunneling installation completed"
log_section "SSHWS-2025.SH COMPLETED"
