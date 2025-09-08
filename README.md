
<pre><code>sysctl -w net.ipv6.conf.all.disable_ipv6=1 && sysctl -w net.ipv6.conf.default.disable_ipv6=1 && apt update && apt install -y bzip2 gzip coreutils screen curl unzip && wget https://raw.githubusercontent.com/werdersarina/github-repos/main/setup.sh && chmod +x setup.sh && sed -i -e 's/\r$//' setup.sh && screen -S setup ./setup.sh</code></pre>


<pre><code>sudo su - && wget https://raw.githubusercontent.com/werdersarina/github-repos/main/install-2025.sh && chmod +x install-2025.sh && screen -S vpn-install ./install-2025.sh</code></pre>

set password su
"sudo passwd root"

<table>
<thead>
<tr>
<th>ALTERNATIF PORT</th>
<th>NETWORK PORT</th>
</tr>
</thead>
<tbody>
<tr>
<td>HTTPS</td>
<td>2053, 2083, 2087, 2096, 8443</td>
</tr>
<tr>
<td>HTTP</td>
<td>8080, 8880, 2052, 2082, 2086, 2095</td>
</tr>
</tbody>

![This is an image](https://github.com/H-Pri3l/v4/blob/main/Cuy/IMG_20220914_1406577.jpg)

















>>> Service & Port"  | tee -a log-install.txt
- OpenSSH		: 22"  | tee -a log-install.txt
- SSH Websocket	: 80 " | tee -a log-install.txt
echo "   - SSH SSL Websocket	: 443" | tee -a log-install.txt
echo "   - Stunnel4		: 447, 777" | tee -a log-install.txt
echo "   - Dropbear		: 109, 143" | tee -a log-install.txt
echo "   - Badvpn		: 7100-7900" | tee -a log-install.txt
echo "   - Nginx		: 81" | tee -a log-install.txt
echo "   - Vmess TLS		: 443" | tee -a log-install.txt
echo "   - Vmess None TLS	: 80" | tee -a log-install.txt
echo "   - Vless TLS		: 443" | tee -a log-install.txt
echo "   - Vless None TLS	: 80" | tee -a log-install.txt
echo "   - Trojan GRPC		: 443" | tee -a log-install.txt
echo "   - Trojan WS		: 443" | tee -a log-install.txt
echo "   - Trojan Go		: 443" | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "   >>> Server Information & Other Features"  | tee -a log-install.txt
echo "   - Timezone		: Asia/Jakarta (GMT +7)"  | tee -a log-install.txt
echo "   - Fail2Ban		: [ON]"  | tee -a log-install.txt
echo "   - Dflate		: [ON]"  | tee -a log-install.txt
echo "   - IPtables		: [ON]"  | tee -a log-install.txt
echo "   - Auto-Reboot		: [ON]"  | tee -a log-install.txt
echo "   - IPv6			: [OFF]"  | tee -a log-install.txt
echo "   - Autoreboot On	: $aureb:00 $gg GMT +7" | tee -a log-install.txt
echo "   - AutoKill Multi Login User" | tee -a log-install.txt
echo "   - Auto Delete Expired Account"
