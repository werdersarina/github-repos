#!/bin/bash
dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
biji=`date +"%Y-%m-%d" -d "$dateFromServer"`
#########################





clear
echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "\E[0;41;36m         CEK USER MULTI SSH        \E[0m"
echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo "USERNAME          LOGIN COUNT          STATUS"
echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"

# Get list of all SSH users
cat /etc/passwd | grep "/home/" | cut -d: -f1 > /tmp/user.txt

# Check each user's login count
while read username; do
    # Count Dropbear connections
    dropbear_count=$(ps aux | grep "dropbear.*$username" | grep -v grep | wc -l)
    # Count OpenSSH connections  
    openssh_count=$(ps aux | grep "sshd.*$username" | grep -v grep | wc -l)
    # Total connections
    total_count=$((dropbear_count + openssh_count))
    
    if [ $total_count -gt 0 ]; then
        if [ $total_count -gt 1 ]; then
            status="\033[0;31mMULTI-LOGIN ($total_count)\033[0m"
        else
            status="\033[0;32mSINGLE LOGIN\033[0m"
        fi
        printf "%-17s %-20s %s\n" "$username" "$total_count connections" "$status"
    fi
done < /tmp/user.txt

# Check if any violations found in log
if [ -e "/root/log-limit.txt" ]; then
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[0;43;30m      PREVIOUS VIOLATIONS LOG      \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    cat /root/log-limit.txt
fi

# Clean up
rm -f /tmp/user.txt

echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo " ";
read -n 1 -s -r -p "Press any key to back on menu"

menu
