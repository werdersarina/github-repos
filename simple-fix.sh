#!/bin/bash
#
# Simple IP Fix Script - YT ZIXSTYLE 2025
# Purpose: Memperbaiki fungsi permission secara sederhana
# ===============================================================================

echo "🔧 SIMPLE IP PERMISSION FIX"
echo "==========================="

# Fix setup.sh
if [ -f "setup.sh" ]; then
    echo "🔧 Fixing setup.sh..."
    # Replace the PERMISSION function with simplified version
    sed -i '/PERMISSION () {/,/}/c\
PERMISSION () {\
    MYIP=$(curl -sS ipv4.icanhazip.com)\
    IZIN=$(curl -sS https://raw.githubusercontent.com/werdersarina/github-repos/main/ip | grep $MYIP)\
    if [ -n "$IZIN" ]; then\
    Bloman\
    else\
    res="Permission Denied!"\
    fi\
    BURIQ\
}' setup.sh
    echo "✅ Fixed setup.sh"
fi

# Test the fix
echo ""
echo "🧪 Testing IP permission..."
MYIP=$(curl -sS ipv4.icanhazip.com 2>/dev/null)
IZIN=$(curl -sS https://raw.githubusercontent.com/werdersarina/github-repos/main/ip 2>/dev/null | grep $MYIP)

echo "🌐 Your IP: $MYIP"
if [ -n "$IZIN" ]; then
    echo "✅ IP Permission Test: PASSED"
    echo "📋 Authorization line: $IZIN"
else
    echo "❌ IP Permission Test: FAILED"
fi

echo ""
echo "✅ Simple fix completed!"
