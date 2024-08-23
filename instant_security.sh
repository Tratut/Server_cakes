#!/bin/bash

# Update package list
apt-get update

# Install required packages
apt-get install -y iptables-persistent fail2ban auditd

# Create admin group if it doesn't exist
if ! getent group admins > /dev/null; then
    groupadd admins
fi

# Create user 'admin' with specified groups and sudo privileges
useradd -m -s /bin/bash -G sudo,admins -p $(openssl passwd -1 <password>) admin
echo 'admin ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# Add SSH authorized keys for 'admin' user
mkdir -p /home/admin/.ssh
echo '<ssh_public_key>' > /home/admin/.ssh/authorized_keys
chown -R admin:admin /home/admin/.ssh
chmod 700 /home/admin/.ssh
chmod 600 /home/admin/.ssh/authorized_keys

# Write iptables rules
cat <<EOF > /etc/iptables/rules.v4
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p icmp --icmp-type 0 -j ACCEPT
-A INPUT -p icmp --icmp-type 3 -j ACCEPT
-A INPUT -p icmp --icmp-type 11 -j ACCEPT
COMMIT
EOF

# Set permissions for iptables rules file
chown root:root /etc/iptables/rules.v4
chmod 0640 /etc/iptables/rules.v4

# Write Fail2Ban configuration
cat <<EOF > /etc/fail2ban/jail.local
[sshd]
enabled = true
findtime = 1m
nmaxretry = 5
bantime = 15m
EOF

# Set permissions for Fail2Ban configuration
chown root:root /etc/fail2ban/jail.local
chmod 0640 /etc/fail2ban/jail.local

# Write Auditd rules
cat <<EOF > /etc/audit/rules.d/audit.rules
-D
-e 1
-f 1
-a always,exclude -F msgtype=CWD
-a always,exclude -F msgtype=PATH
-a always,exclude -F msgtype=PROCTITLE
-a always,exit -F dir=/var/log/audit/ -F perm=wa -F auid!=unset -F key=audit-trail-modification
-a always,exit -F path=/var/log/syslog -F perm=wa -F auid!=unset -F key=audit-trail-modification
-a always,exit -F path=/var/log/auth.log -F perm=wa -F auid!=unset -F key=audit-trail-modification
-a always,exit -F arch=x86_64 -S setuid -F auid!=unset -F a0=0 -F exe=/usr/bin/su -F key=elevated-privileges-session
-a always,exit -F arch=x86_64 -S setresuid -F auid!=unset -F a0=0 -F exe=/usr/bin/sudo -F key=elevated-privileges-session
-a always,exit -F arch=x86_64 -S execve -F auid!=unset -C uid!=euid -F euid=0 -F key=elevated-privileges-session
-a always,exit -F arch=x86_64 -S chmod -S fchmod -S chown -S fchown -S lchown -F auid!=unset -F key=access-rights-modification
EOF

# Set permissions for Auditd rules file
chown root:root /etc/audit/rules.d/audit.rules
chmod 0640 /etc/audit/rules.d/audit.rules

# Set system-wide inactivity timeout
echo "readonly TMOUT=900" >> /etc/profile
echo "export TMOUT" >> /etc/profile

# Disable IPv6
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
sysctl -p

# Update SSH configuration
sed -i -e '/^PermitRootLogin/s/^.*$/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i -e '/^PasswordAuthentication/s/^.*$/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i -e '/^#ClientAliveInterval/s/^.*$/ClientAliveInterval 5m/' /etc/ssh/sshd_config
sed -i -e '/^#ClientAliveCountMax/s/^.*$/ClientAliveCountMax 3/' /etc/ssh/sshd_config
sed -i -e '$aAllowGroups admins' /etc/ssh/sshd_config

# Enable and start Fail2Ban
systemctl enable fail2ban

# Reboot the system
reboot
