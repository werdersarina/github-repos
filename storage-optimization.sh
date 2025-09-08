#!/bin/bash
#
# Storage Optimization Script untuk 5GB Disk
# Purpose: Optimasi untuk minimal storage requirement
# ===============================================================================

echo "💾 STORAGE OPTIMIZATION untuk 5GB Disk"
echo "======================================="

# 1. Disable swap file creation (save 2GB)
echo "🔧 Configuring minimal swap (512MB instead of 2GB)..."
cat > /etc/systemd/system/create-minimal-swap.service << 'EOF'
[Unit]
Description=Create minimal swap file
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'if [ ! -f /swapfile ]; then fallocate -l 512M /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile; fi'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# 2. Aggressive log rotation
echo "📝 Setting up aggressive log rotation..."
cat > /etc/logrotate.d/vpn-minimal << 'EOF'
/var/log/xray/*.log {
    daily
    missingok
    rotate 2
    compress
    delaycompress
    notifempty
    maxsize 10M
    postrotate
        systemctl reload xray
    endscript
}

/var/log/nginx/*.log {
    daily
    missingok
    rotate 2
    compress
    delaycompress
    notifempty
    maxsize 5M
    postrotate
        systemctl reload nginx
    endscript
}

/var/log/*.log {
    weekly
    rotate 1
    compress
    maxsize 50M
}
EOF

# 3. Clean package cache regularly
echo "🧹 Setting up automatic cleanup..."
cat > /etc/cron.daily/storage-cleanup << 'EOF'
#!/bin/bash
# Daily storage cleanup for 5GB systems

# Clean package cache
apt autoremove -y
apt autoclean
apt clean

# Clean old logs
journalctl --vacuum-time=3d
journalctl --vacuum-size=50M

# Clean temp files
find /tmp -type f -atime +1 -delete 2>/dev/null
find /var/tmp -type f -atime +3 -delete 2>/dev/null

# Clean build artifacts if any
rm -rf /tmp/vnstat-* /tmp/*.tar.gz

# Report storage usage
df -h / | tail -1 | awk '{print "Storage usage: " $3 "/" $2 " (" $5 " used)"}'
EOF

chmod +x /etc/cron.daily/storage-cleanup

# 4. Minimal package installation script
echo "📦 Creating minimal installation guide..."
cat > /root/minimal-install-guide.txt << 'EOF'
MINIMAL INSTALLATION GUIDE untuk 5GB Storage:

1. SKIP packages yang tidak essential:
   - Skip build-essential jika tidak compile dari source
   - Skip vnstat compilation, gunakan apt version
   - Skip Node.js jika tidak butuh web panel

2. ALTERNATIVE installations:
   - Gunakan apt install vnstat (bukan compile dari source)
   - Install nginx-light instead of nginx-full
   - Skip development libraries jika tidak perlu

3. MONITORING commands:
   - df -h (check disk usage)
   - du -sh /var/log (check log size)
   - apt list --installed | wc -l (count packages)

4. EMERGENCY cleanup:
   - sudo apt autoremove --purge
   - sudo journalctl --vacuum-size=10M
   - sudo rm -rf /var/cache/apt/*
EOF

echo "✅ Storage optimization configured!"
echo "📊 Run: df -h untuk check current usage"
echo "🔧 Run: /etc/cron.daily/storage-cleanup untuk manual cleanup"
