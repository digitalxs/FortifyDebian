#!/bin/bash
#
# Debian 12 (Bookworm) Server Hardening Script
# Version: 1.0
# Description: Professional-level security hardening for Debian 12 servers
#
# Author: Based on work by DigitalXS.ca
# Date: April 12, 2025
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#

set -e          # Exit immediately if a command exits with a non-zero status
set -u          # Treat unset variables as an error when substituting
set -o pipefail # Exit with non-zero status if any command in a pipeline fails

# Color definitions for pretty output
readonly RESET="\033[0m"
readonly RED="\033[0;31m"
readonly GREEN="\033[0;32m"
readonly YELLOW="\033[0;33m"
readonly BLUE="\033[0;34m"
readonly MAGENTA="\033[0;35m"
readonly CYAN="\033[0;36m"
readonly BOLD="\033[1m"

# Global variables
HOSTNAME=""
LOG_FILE="/var/log/debian12-hardening.log"
BACKUP_DIR="/root/security-hardening-backups"
ADMIN_USER=""
AUDIT_ENABLED="yes"
AIDE_ENABLED="yes"
APPARMOR_ENABLED="yes"
CIS_LEVEL="server" # Options: workstation, server
SSH_PORT="22"
UMASK_VALUE="027"
IPV6_DISABLED="no"

# Security packages to install
SECURITY_PACKAGES="aide apparmor apparmor-profiles apparmor-utils auditd audispd-plugins acct openssh-server libpam-pwquality 
                  libpam-cracklib libpam-tmpdir libpam-apparmor libpam-modules rkhunter arch-audit apt-listchanges needrestart 
                  debsums debsecan unattended-upgrades apt-listbugs libpam-passwdqc yelp-tools apport sysstat auditd chkrootkit 
                  needrestart apt-show-versions password-checker lynis unattended-upgrades lsb-release sysstat systemd-journal-remote 
                  apt-listbugs fail2ban ufw rsyslog ca-certificates acl tcpdump nmap chrony arch-audit haveged apt-transport-https gnupg2 
                  sudo coreutils bcrypt binutils bolt bsdmainutils bsdutils busybox-static curl wget"

# Log file
touch "$LOG_FILE"
chmod 640 "$LOG_FILE"

# Function to ensure we're on Debian 12
check_debian_version() {
    if ! grep -q 'VERSION_ID="12"' /etc/os-release; then
        error "This script is designed for Debian 12 (Bookworm) only. Aborting."
    fi
}

# Helper functions
log() {
    local message="$1"
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "${timestamp} - ${message}" | tee -a "$LOG_FILE"
}

info() {
    log "${BLUE}[INFO]${RESET} $1"
}

success() {
    log "${GREEN}[SUCCESS]${RESET} $1"
}

warning() {
    log "${YELLOW}[WARNING]${RESET} $1"
}

error() {
    log "${RED}[ERROR]${RESET} $1"
    exit 1
}

banner() {
    local message="$1"
    local length=${#message}
    local line=""
    
    for ((i=0; i<length+4; i++)); do
        line="${line}="
    done
    
    echo -e "\n${CYAN}${line}${RESET}"
    echo -e "${CYAN}= ${BOLD}${message}${RESET} ${CYAN}=${RESET}"
    echo -e "${CYAN}${line}${RESET}\n"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
    fi
}

confirm() {
    local prompt="$1"
    local default="${2:-y}"
    
    if [[ "$default" == "y" ]]; then
        local options="[Y/n]"
    else
        local options="[y/N]"
    fi
    
    while true; do
        read -rp "$prompt $options " answer
        answer=${answer:-$default}
        case ${answer:0:1} in
            y|Y) return 0 ;;
            n|N) return 1 ;;
            *) echo "Please answer yes or no." ;;
        esac
    done
}

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        local backup_file="${BACKUP_DIR}$(dirname "$file")"
        mkdir -p "$backup_file"
        cp -p "$file" "${BACKUP_DIR}${file}.bak.$(date +%Y%m%d%H%M%S)" || warning "Failed to backup $file"
        info "Backed up $file"
    else
        warning "File $file does not exist, no backup created"
    fi
}

# Configuration functions
configure_basic_settings() {
    banner "Basic Configuration"
    
    # Hostname configuration
    local default_hostname
    default_hostname=$(hostname -s)
    
    read -rp "Enter hostname [$default_hostname]: " HOSTNAME
    HOSTNAME=${HOSTNAME:-$default_hostname}
    
    # Admin user configuration
    while true; do
        read -rp "Enter username for the administrator: " ADMIN_USER
        if [[ -z "$ADMIN_USER" ]]; then
            echo "Username cannot be empty. Please try again."
        elif id "$ADMIN_USER" &>/dev/null; then
            if confirm "User $ADMIN_USER already exists. Continue with this user?"; then
                break
            fi
        else
            if confirm "User $ADMIN_USER does not exist. Do you want to create it?"; then
                adduser --gecos "" "$ADMIN_USER" || error "Failed to create user $ADMIN_USER"
                usermod -aG sudo "$ADMIN_USER" || error "Failed to add $ADMIN_USER to sudo group"
                break
            fi
        fi
    done
    
    # SSH port configuration
    read -rp "Enter SSH port number [22]: " ssh_port
    SSH_PORT=${ssh_port:-22}
    
    # Disable IPv6?
    if confirm "Do you want to disable IPv6? (Not recommended unless explicitly needed)" "n"; then
        IPV6_DISABLED="yes"
    else
        IPV6_DISABLED="no"
    fi
    
    # Security tooling
    if confirm "Enable AIDE (Advanced Intrusion Detection Environment)?"; then
        AIDE_ENABLED="yes"
    else
        AIDE_ENABLED="no"
    fi
    
    if confirm "Enable Auditd (System audit daemon)?"; then
        AUDIT_ENABLED="yes"
    else
        AUDIT_ENABLED="no"
    fi
    
    if confirm "Enable AppArmor (Mandatory Access Control)?"; then
        APPARMOR_ENABLED="yes"
    else
        APPARMOR_ENABLED="no"
    fi
    
    # CIS compliance level
    echo "Select CIS compliance level:"
    echo "1. Workstation (less strict)"
    echo "2. Server (more strict)"
    
    local choice
    read -rp "Enter your choice [1-2]: " choice
    case $choice in
        1) CIS_LEVEL="workstation";;
        2) CIS_LEVEL="server";;
        *) warning "Invalid selection. Using server level (more strict) by default."
           CIS_LEVEL="server";;
    esac
    
    success "Basic configuration completed"
}

# Implementation functions
update_system() {
    banner "Updating System"
    
    info "Updating package lists"
    apt-get update -qq || error "Failed to update package lists"
    
    info "Upgrading packages"
    apt-get upgrade -y -qq || error "Failed to upgrade packages"
    
    info "Performing distribution upgrade"
    apt-get dist-upgrade -y || warning "Distribution upgrade completed with warnings"
    
    success "System updated successfully"
}

install_security_packages() {
    banner "Installing Security Packages"
    
    info "Installing security-focused packages"
    for package in $SECURITY_PACKAGES; do
        apt-get install -y "$package" || warning "Failed to install package: $package"
    done
    
    success "Security packages installed"
}

# AUTHENTICATION AND AUTHORIZATION HARDENING
harden_authentication() {
    banner "Hardening Authentication"
    
    # Configure password quality
    info "Configuring password quality"
    backup_file "/etc/pam.d/common-password"
    
    # Enforce strong password policy
    # - minlen=12: Minimum length of 12 characters
    # - minclass=4: Require all character classes (uppercase, lowercase, digits, other)
    # - maxrepeat=3: No more than 3 consecutive identical characters
    # - maxclassrepeat=3: No more than 3 consecutive characters from same class
    # - retry=3: Number of retries when password check fails
    # - reject_username: Can't contain username
    # - enforce_for_root: Apply these rules to root as well
    cat > /etc/security/pwquality.conf << EOF
# Password quality configuration
minlen = 12
minclass = 4
maxrepeat = 3
maxclassrepeat = 3
retry = 3
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
reject_username
enforce_for_root
EOF

    # Update PAM configuration
    sed -i 's/password\s*requisite\s*pam_pwquality.so.*/password requisite pam_pwquality.so retry=3 minlen=12 difok=3 reject_username enforce_for_root/g' /etc/pam.d/common-password
    
    # Configure login.defs for password policies
    backup_file "/etc/login.defs"
    
    # Password aging controls
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
    
    # Restrict su command to sudo group
    backup_file "/etc/pam.d/su"
    sed -i 's/# auth\s*required\s*pam_wheel.so$/auth required pam_wheel.so group=sudo/' /etc/pam.d/su
    
    # Configure account locking after failed attempts
    backup_file "/etc/pam.d/common-auth"
    if ! grep -q "pam_tally2.so" /etc/pam.d/common-auth; then
        sed -i '1s/^/auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=1800\n/' /etc/pam.d/common-auth
    fi
    
    # Set system-wide umask
    backup_file "/etc/login.defs"
    sed -i "s/^UMASK.*/UMASK           $UMASK_VALUE/" /etc/login.defs
    
    # Ensure no users have empty passwords
    info "Checking for empty passwords"
    for user in $(cut -d: -f1 /etc/passwd); do
        if passwd -S "$user" 2>/dev/null | grep -q "NP"; then
            warning "User $user has no password! Locking account."
            passwd -l "$user"
        fi
    done
    
    # Set default umask for users
    for profile_file in /etc/profile /etc/bash.bashrc; do
        backup_file "$profile_file"
        if ! grep -q "umask $UMASK_VALUE" "$profile_file"; then
            echo "# Set a secure default umask" >> "$profile_file"
            echo "umask $UMASK_VALUE" >> "$profile_file"
        fi
    done
    
    # Create PAM limits configuration
    backup_file "/etc/security/limits.conf"
    cat > /etc/security/limits.conf << EOF
# /etc/security/limits.conf
#
# Each line describes a limit for a user in the form:
#
# <domain>   <type>   <item>   <value>
#
# Enforce system resource limits

*          soft    core            0
*          hard    core            0
*          soft    nproc           10000
*          hard    nproc           10000
*          soft    nofile          1024
*          hard    nofile          65536
root       soft    nproc           10000
root       hard    nproc           10000
root       soft    nofile          1024
root       hard    nofile          65536

# End of file
EOF

    # Secure /etc/profile
    backup_file "/etc/profile"
    cat >> /etc/profile << 'EOF'

# Set timeout to automatically log out idle users after 15 minutes (TMOUT is in seconds)
readonly TMOUT=900
export TMOUT
EOF
    
    # Enforce password history
    backup_file "/etc/pam.d/common-password"
    if ! grep -q "remember=" /etc/pam.d/common-password; then
        sed -i '/pam_unix.so/s/$/ remember=24/' /etc/pam.d/common-password
    else
        sed -i 's/\(remember=\)[0-9]*/\124/' /etc/pam.d/common-password
    fi
    
    success "Authentication hardening completed"
}

harden_ssh() {
    banner "Hardening SSH"
    
    backup_file "/etc/ssh/sshd_config"
    
    # Create completely new sshd_config with secure settings
    cat > /etc/ssh/sshd_config << EOF
# SSH daemon configuration file - Hardened
# See sshd_config(5) for more information

# Basic SSH server settings
Port $SSH_PORT
AddressFamily any
ListenAddress 0.0.0.0
#ListenAddress ::  # Uncomment if IPv6 is needed

# Protocol and key exchange settings
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256

# Authentication settings
LoginGraceTime 30s
PermitRootLogin no
StrictModes yes
MaxAuthTries 3
MaxSessions 5

# Only use SSH protocol version 2
Protocol 2

# Authentication methods
PubkeyAuthentication yes
PasswordAuthentication yes  # Set to "no" for key-based auth only
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
AuthenticationMethods publickey,password

# SSH features
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
GatewayPorts no
PermitTunnel no

# Terminal settings
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
ClientAliveInterval 300
ClientAliveCountMax 2

# User environment
AcceptEnv LANG LC_*
PermitUserEnvironment no

# Allow only specific users/groups to use SSH
AllowUsers $ADMIN_USER

# Logging settings
SyslogFacility AUTH
LogLevel VERBOSE

# Misc settings
Banner /etc/issue.net
DebianBanner no
Compression no
UseDNS no

Subsystem sftp internal-sftp -l INFO -f LOCAL6
EOF
    
    # Create a warning banner for SSH
    backup_file "/etc/issue.net"
    cat > /etc/issue.net << 'EOF'
***************************************************************************
                            NOTICE TO USERS

This computer system is the private property of its owner, whether
individual, corporate or government. It is for authorized use only.
Users (authorized or unauthorized) have no explicit or implicit
expectation of privacy.

Any or all uses of this system and all files on this system may be
intercepted, monitored, recorded, copied, audited, inspected, and
disclosed to your employer, to authorized site, government, and law
enforcement personnel, as well as authorized officials of government
agencies, both domestic and foreign.

By using this system, the user consents to such interception, monitoring,
recording, copying, auditing, inspection, and disclosure at the
discretion of such personnel or officials. Unauthorized or improper use
of this system may result in civil and criminal penalties and
administrative or disciplinary action, as appropriate. By continuing to
use this system you indicate your awareness of and consent to these terms
and conditions of use. LOG OFF IMMEDIATELY if you do not agree to the
conditions stated in this warning.
***************************************************************************
EOF
    
    # Create or append to the existing MOTD
    backup_file "/etc/motd"
    cat > /etc/motd << 'EOF'
***************************************************************************
                     AUTHORIZED ACCESS ONLY
      This system is restricted to authorized users only.
      All activities are monitored and recorded.
      Disconnect IMMEDIATELY if you are not an authorized user.
***************************************************************************
EOF
    
    # Configure PAM for SSH
    backup_file "/etc/pam.d/sshd"
    
    # Setup SSH keys for admin user if needed
    if [[ -n "$ADMIN_USER" ]]; then
        local ssh_dir="/home/$ADMIN_USER/.ssh"
        if [[ ! -d "$ssh_dir" ]]; then
            info "Setting up SSH directory for $ADMIN_USER"
            mkdir -p "$ssh_dir"
            chown "$ADMIN_USER:$ADMIN_USER" "$ssh_dir"
            chmod 700 "$ssh_dir"
            
            # Check if user wants to add a public key
            if confirm "Do you want to add an SSH public key for $ADMIN_USER?"; then
                local auth_keys="$ssh_dir/authorized_keys"
                
                read -rp "Enter or paste the SSH public key: " ssh_key
                if [[ -n "$ssh_key" ]]; then
                    echo "$ssh_key" > "$auth_keys"
                    chown "$ADMIN_USER:$ADMIN_USER" "$auth_keys"
                    chmod 600 "$auth_keys"
                    info "SSH public key added for $ADMIN_USER"
                    
                    # Offer to disable password authentication
                    if confirm "Do you want to disable SSH password authentication (key-based auth only)?" "n"; then
                        sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
                        sed -i 's/AuthenticationMethods publickey,password/AuthenticationMethods publickey/' /etc/ssh/sshd_config
                        info "SSH password authentication disabled"
                    fi
                fi
            fi
        fi
    fi
    
    # Test SSH configuration
    info "Testing SSH configuration"
    if ! sshd -t; then
        warning "SSH configuration has errors. Restoring backup."
        cp "${BACKUP_DIR}/etc/ssh/sshd_config.bak."* /etc/ssh/sshd_config
        error "SSH hardening failed, check the log for details"
    fi
    
    # Reload SSH service
    systemctl restart ssh || warning "Failed to restart SSH service"
    
    success "SSH hardening completed"
}

harden_network() {
    banner "Hardening Network"
    
    # Backup sysctl configuration
    backup_file "/etc/sysctl.conf"
    
    # Create a new sysctl configuration with enhanced security
    cat > /etc/sysctl.conf << 'EOF'
# /etc/sysctl.conf - Configuration file for setting system variables
# See /etc/sysctl.d/ for additional system variables.
# See sysctl.conf (5) for information.

# Network hardening for Debian 12

# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Block SYN attacks
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Ignore ICMP broadcasts
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Do not send ICMP redirects (we are not a router)
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Do not accept IP source route packets
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Increase system file descriptor limit
fs.file-max = 65535

# Protect against TCP time-wait assassination hazards
net.ipv4.tcp_rfc1337 = 1

# TCP optimization settings
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_sack = 1
net.ipv4.tcp_window_scaling = 1

# Increase system IP port limits
net.ipv4.ip_local_port_range = 1024 65535

# Protect against kernel memory exposure attempts via dmesg
kernel.dmesg_restrict = 1

# Enable ExecShield protection
kernel.exec-shield = 1
kernel.randomize_va_space = 2

# Restrict access to kernel logs
kernel.kptr_restrict = 2

# Restrict ptrace scope for improved process security
kernel.yama.ptrace_scope = 2

# Disable core dumps for setuid programs
fs.suid_dumpable = 0

# Restrict kernel pointer leaks
kernel.kptr_restrict = 2

# Disable Magic SysRq key
kernel.sysrq = 0

# Memory management
vm.swappiness = 10
vm.mmap_min_addr = 65536
EOF

    # Disable IPv6 if requested
    if [[ "$IPV6_DISABLED" == "yes" ]]; then
        cat > /etc/sysctl.d/40-ipv6-disable.conf << 'EOF'
# Disable IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
        info "IPv6 disabled via sysctl"
    fi
    
    # Apply sysctl settings
    info "Applying sysctl settings"
    sysctl -p || warning "Failed to apply sysctl settings"
    
    # Configure firewall with UFW
    info "Configuring UFW firewall"
    
    # Reset UFW to default state
    ufw --force reset
    
    # Set default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH
    ufw allow "$SSH_PORT/tcp" comment "SSH"
    
    # Enable UFW
    echo "y" | ufw enable
    
    # Setup fail2ban
    info "Configuring fail2ban"
    backup_file "/etc/fail2ban/jail.local"
    
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
# Ban hosts for 1 hour
bantime = 3600

# Increase ban time for repeat offenders
bantime.increment = true
bantime.factor = 3
bantime.formula = ban.Time * (1<<(ban.Count if ban.Count<20 else 20)) * banFactor

# A host is banned if it has generated maxretry during the last findtime seconds
findtime = 600
maxretry = 3

# "ignoreip" can be a list of IP addresses, CIDR masks or DNS hosts
ignoreip = 127.0.0.1/8 ::1

# Enable all jails
[sshd]
enabled = true
maxretry = 3
findtime = 600
bantime = 3600
mode = aggressive

[sshd-ddos]
enabled = true
EOF
    
    # Restart fail2ban
    systemctl restart fail2ban
    
    success "Network hardening completed"
}

harden_file_permissions() {
    banner "Hardening File Permissions"
    
    # Set secure permissions on sensitive files
    chmod 644 /etc/passwd
    chmod 640 /etc/shadow
    chmod 640 /etc/gshadow
    chmod 644 /etc/group
    chmod 600 /etc/ssh/*_key
    chmod 644 /etc/ssh/*.pub
    
    # Set ownership
    chown root:root /etc/passwd
    chown root:shadow /etc/shadow
    chown root:shadow /etc/gshadow
    chown root:root /etc/group
    
    # Secure /boot
    chmod 700 /boot
    
    # Secure sudo configuration
    chmod 440 /etc/sudoers
    chmod -R 750 /etc/sudoers.d/
    
    # Restrict access to cron
    chmod 600 /etc/crontab
    chmod 700 /etc/cron.d
    chmod 700 /etc/cron.daily
    chmod 700 /etc/cron.hourly
    chmod 700 /etc/cron.monthly
    chmod 700 /etc/cron.weekly
    
    # Ensure all world-writable directories have sticky bit set
    info "Setting sticky bit on world-writable directories"
    find / -type d -perm -0002 -a \! -perm -1000 -exec chmod +t {} \; 2>/dev/null || true
    
    # Find and secure files with SUID/SGID permissions
    info "Checking for unusual SUID/SGID binaries"
    
    # Define standard SUID/SGID binaries
    standard_suid_sgid=( 
        /usr/bin/chage
        /usr/bin/chfn
        /usr/bin/chsh
        /usr/bin/expiry
        /usr/bin/gpasswd
        /usr/bin/mount
        /usr/bin/newgrp
        /usr/bin/passwd
        /usr/bin/su
        /usr/bin/sudo
        /usr/bin/umount
        /usr/lib/openssh/ssh-keysign
        /usr/lib/dbus-1.0/dbus-daemon-launch-helper
        /usr/lib/eject/dmcrypt-get-device
        /bin/mount
        /bin/su
        /bin/umount
    )
    
    for file in $(find / -type f -perm -4000 -o -perm -2000 2>/dev/null); do
        # Check if this file is in our standard list
        is_standard=0
        for std_file in "${standard_suid_sgid[@]}"; do
            if [[ "$file" == "$std_file" ]]; then
                is_standard=1
                break
            fi
        done
        
        if [[ $is_standard -eq 0 ]]; then
            warning "Non-standard SUID/SGID binary found: $file"
            
            if confirm "Do you want to remove SUID/SGID bit from $file?" "n"; then
                chmod -s "$file"
                info "Removed SUID/SGID bit from $file"
            fi
        fi
    done
    
    success "File permissions hardening completed"
}

harden_system_services() {
    banner "Hardening System Services"
    
    # Disable unnecessary system services
    local services_to_disable=(
        avahi-daemon
        cups
        rpcbind
        isc-dhcp-server
        isc-dhcp-server6
        nfs-server
        rsh-server
        telnet-server
        tftp-server
        xinetd
        nis
        bluetooth
    )
    
    for service in "${services_to_disable[@]}"; do
        if systemctl is-enabled "$service" &>/dev/null; then
            info "Disabling $service"
            systemctl disable "$service" || warning "Failed to disable $service"
            systemctl stop "$service" || warning "Failed to stop $service"
        fi
    done
    
    # Configure auditd if enabled
    if [[ "$AUDIT_ENABLED" == "yes" ]]; then
        info "Configuring auditd"
        backup_file "/etc/audit/auditd.conf"
        
        # Configure auditd.conf
        sed -i 's/^log_file.*/log_file = \/var\/log\/audit\/audit.log/' /etc/audit/auditd.conf
        sed -i 's/^max_log_file.*/max_log_file = 50/' /etc/audit/auditd.conf
        sed -i 's/^max_log_file_action.*/max_log_file_action = keep_logs/' /etc/audit/auditd.conf
        sed -i 's/^space_left_action.*/space_left_action = email/' /etc/audit/auditd.conf
        sed -i 's/^action_mail_acct.*/action_mail_acct = root/' /etc/audit/auditd.conf
        sed -i 's/^admin_space_left_action.*/admin_space_left_action = halt/' /etc/audit/auditd.conf
        sed -i 's/^disk_full_action.*/disk_full_action = halt/' /etc/audit/auditd.conf
        
        # Create custom audit rules
        backup_file "/etc/audit/rules.d/audit.rules"
        
        cat > /etc/audit/rules.d/audit.rules << 'EOF'
# Audit rules for Debian 12 hardening
# This file contains rules for the Linux audit daemon

# Delete all existing rules
-D

# Set buffer size to avoid audit logs loss (increase if needed)
-b 8192

# Set failure mode to panic (2) to halt system on critical errors
-f 2

# Record date/time modifications
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S stime -S clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# Record user/group modifications
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Record network environment modifications
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale
-w /etc/networks -p wa -k system-locale

# Record permission modifications
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

# Record unauthorized access attempts
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# Record privileged commands
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Record mount operations
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

# Record deletion operations
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

# Watch for changes to key system files
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Monitor SELinux/AppArmor modifications
-w /etc/selinux/ -p wa -k MAC-policy
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy

# Monitor audit logs themselves
-w /var/log/audit/ -k audit-logs
-w /var/log/audit/audit.log -p wa -k audit-logs
-w /etc/audit/ -p wa -k audit-config
-w /etc/audit/auditd.conf -p wa -k audit-config
-w /etc/audit/audit.rules -p wa -k audit-config
-w /etc/libaudit.conf -p wa -k audit-config

# Monitor kernel module operations
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-a always,exit -F arch=b32 -S init_module -S delete_module -k modules

# Monitor system calls
-a always,exit -F arch=b32 -S ptrace -k tracing
-a always,exit -F arch=b64 -S ptrace -k tracing
-a always,exit -F arch=b32 -S personality -k bypass
-a always,exit -F arch=b64 -S personality -k bypass

# Make the configuration immutable - remove this line to allow changes
-e 2
EOF
        
        # Restart auditd service
        systemctl restart auditd || warning "Failed to restart auditd"
        
        info "Auditd configured with security rules"
    fi
    
    # Configure AppArmor if enabled
    if [[ "$APPARMOR_ENABLED" == "yes" ]]; then
        info "Configuring AppArmor"
        
        # Install AppArmor profiles and utilities if not already installed
        apt-get install -y apparmor-profiles apparmor-utils || warning "Failed to install AppArmor packages"
        
        # Enable AppArmor
        systemctl enable apparmor
        systemctl start apparmor
        
        # Set AppArmor to enforcing mode
        aa-enforce /etc/apparmor.d/* || warning "Failed to set AppArmor to enforcing mode"
        
        info "AppArmor configured and enabled"
    fi
    
    # Configure AIDE if enabled
    if [[ "$AIDE_ENABLED" == "yes" ]]; then
        info "Configuring AIDE (Advanced Intrusion Detection Environment)"
        
        # Initialize AIDE database
        info "Initializing AIDE database (this may take a while)..."
        aide --init || warning "Failed to initialize AIDE database"
        
        # Rename the initialized database
        if [[ -f /var/lib/aide/aide.db.new ]]; then
            mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
            info "AIDE database initialized"
        else
            warning "AIDE database initialization did not complete successfully"
        fi
        
        # Setup daily cron job for AIDE
        cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/bash
# Daily AIDE check script

# Run the AIDE check and send an email if changes are detected
/usr/bin/aide --check | mail -s "AIDE integrity check report - $(hostname)" root
EOF
        
        chmod 755 /etc/cron.daily/aide-check
        
        info "AIDE configured with daily integrity checks"
    fi
    
    # Configure systemd services
    info "Configuring systemd services"
    
    # Set default target to multi-user (no GUI)
    systemctl set-default multi-user.target
    
    # Mask unnecessary services
    systemctl mask avahi-daemon.service
    systemctl mask bluetooth.service
    
    # Setup NTP for time synchronization
    systemctl enable chrony
    systemctl start chrony
    
    success "System services hardened"
}

harden_kernel_parameters() {
    banner "Hardening Kernel Parameters"
    
    # Create kernel hardening parameters
    backup_file "/etc/sysctl.d/99-kernel-hardening.conf"
    
    cat > /etc/sysctl.d/99-kernel-hardening.conf << 'EOF'
# 99-kernel-hardening.conf
# Kernel hardening settings

# Restrict dmesg access
kernel.dmesg_restrict = 1

# Restrict access to kernel pointers
kernel.kptr_restrict = 2

# Prevent kernel memory exposure via /proc/kallsyms
kernel.kexec_load_disabled = 1

# Disable the SysRq key
kernel.sysrq = 0

# Restrict ptrace scope
kernel.yama.ptrace_scope = 2

# Randomize memory space
kernel.randomize_va_space = 2

# Prevent core dumps
fs.suid_dumpable = 0

# Restrict kernel performance events
kernel.perf_event_paranoid = 3

# Hard and soft link protection
fs.protected_hardlinks = 1
fs.protected_symlinks = 1

# Restrict userfaultfd system call
kernel.unprivileged_userfaultfd = 0

# Memory protection
vm.mmap_min_addr = 65536
vm.unprivileged_userfaultfd = 0

# Limit resources for the user
kernel.pid_max = 65536
kernel.threads-max = 1000000
EOF
    
    # Apply new settings
    sysctl --system || warning "Failed to apply kernel parameters"
    
    # Configure bootloader to add kernel parameters
    backup_file "/etc/default/grub"
    
    # Add security-related kernel parameters
    sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT="quiet apparmor=1 security=apparmor ipv6.disable=0 audit=1 audit_backlog_limit=8192 init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 pti=on spectre_v2=on spec_store_bypass_disable=on mds=full,nosmt mce=0 vsyscall=none module.sig_enforce=1 lockdown=confidentiality quiet splash"/' /etc/default/grub
    
    # Update GRUB
    update-grub || warning "Failed to update GRUB"
    
    success "Kernel hardening completed"
}

configure_automatic_updates() {
    banner "Configuring Automatic Updates"
    
    # Install unattended-upgrades if not already installed
    apt-get install -y unattended-upgrades apt-listchanges || warning "Failed to install unattended-upgrades"
    
    # Enable unattended-upgrades
    dpkg-reconfigure -plow unattended-upgrades
    
    # Configure unattended-upgrades
    backup_file "/etc/apt/apt.conf.d/50unattended-upgrades"
    
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
// Unattended-Upgrade::Origins-Pattern controls which packages are
// upgraded.
Unattended-Upgrade::Origins-Pattern {
    // Archive or Suite based matching:
    "origin=Debian,codename=${distro_codename},label=Debian";
    "origin=Debian,codename=${distro_codename},label=Debian-Security";
    "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
    "origin=Debian,codename=${distro_codename}-updates";
};

// List of packages to not update (regexp are supported)
Unattended-Upgrade::Package-Blacklist {
//  "vim";
//  "libc6";
//  "libc6-dev";
//  "libc6-i686";
};

// This option allows you to control if on a unclean dpkg exit
// unattended-upgrades will automatically run 
//   dpkg --force-confold --configure -a
// The default is true, to ensure updates keep getting installed
Unattended-Upgrade::AutoFixInterruptedDpkg "true";

// Split the upgrade into the smallest possible chunks so that
// they can be interrupted with SIGTERM. This makes the upgrade
// a bit slower but it has the benefit that shutdown while a upgrade
// is running is possible (with a small delay)
Unattended-Upgrade::MinimalSteps "true";

// Install all updates when the machine is shutting down
// instead of doing it in the background while the machine is running
// This will (obviously) make shutdown slower
Unattended-Upgrade::InstallOnShutdown "false";

// Send email to this address for problems or packages upgrades
// If empty or unset then no email is sent, make sure that you
// have a working mail setup on your system. A package that provides
// 'mailx' must be installed. E.g. "user@example.com"
Unattended-Upgrade::Mail "root";

// Set this value to "true" to get emails only on errors. Default
// is to always send a mail if Unattended-Upgrade::Mail is set
Unattended-Upgrade::MailOnlyOnError "false";

// Remove unused automatically installed kernel-related packages
// (kernel images, kernel headers and kernel version locked tools).
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";

// Do automatic removal of newly unused dependencies after the upgrade
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";

// Do automatic removal of unused packages after the upgrade
// (equivalent to apt-get autoremove)
Unattended-Upgrade::Remove-Unused-Dependencies "true";

// Automatically reboot *WITHOUT CONFIRMATION* if
//  the file /var/run/reboot-required is found after the upgrade 
Unattended-Upgrade::Automatic-Reboot "false";

// Automatically reboot even if there are users currently logged in
// when Unattended-Upgrade::Automatic-Reboot is set to true
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";

// If automatic reboot is enabled and needed, reboot at the specific
// time instead of immediately
//  Default: "now"
Unattended-Upgrade::Automatic-Reboot-Time "03:00";

// Use apt bandwidth limit feature, this example limits the download
// speed to 70kb/sec
//Acquire::http::Dl-Limit "70";

// Enable logging to syslog. Default is False
Unattended-Upgrade::SyslogEnable "true";

// Specify syslog facility. Default is daemon
Unattended-Upgrade::SyslogFacility "daemon";

// Download and install upgrades only on AC power
// (on battery power would make more sense for laptops)
Unattended-Upgrade::OnlyOnACPower "false";

// Download and install upgrades only on non-metered connection
// (usually not an issue for servers).
Unattended-Upgrade::Skip-Updates-On-Metered-Connections "false";
EOF
    
    # Configure auto-updates
    cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Verbose "1";
EOF
    
    success "Automatic updates configured"
}

harden_logging() {
    banner "Hardening System Logging"
    
    # Configure rsyslog
    backup_file "/etc/rsyslog.conf"
    
    # Add more detailed logging settings
    cat > /etc/rsyslog.d/90-enhanced-logging.conf << 'EOF'
# Enhanced logging configuration for security monitoring

# Log authentication messages to auth.log
auth,authpriv.*                 /var/log/auth.log

# Log all kernel messages to kern.log
kern.*                          /var/log/kern.log

# Log all mail messages to mail.log
mail.*                          /var/log/mail.log

# Log cron messages to cron.log
cron.*                          /var/log/cron.log

# Log all debug messages to debug.log
*.=debug                        /var/log/debug.log

# Log all informational, notice, warning, error, critical, alert, and emergency messages
*.info;mail.none;authpriv.none;cron.none    /var/log/messages

# Log emergency messages to all logged in users
*.emerg                         :omusrmsg:*

# Set secure file permissions on log files
$FileCreateMode 0640
EOF
    
    # Restart rsyslog
    systemctl restart rsyslog || warning "Failed to restart rsyslog"
    
    # Configure logrotate
    backup_file "/etc/logrotate.conf"
    
    # Set more secure logrotate settings
    cat > /etc/logrotate.d/secure-logs << 'EOF'
# Enhanced secure log rotation configuration
/var/log/auth.log
/var/log/kern.log
/var/log/mail.log
/var/log/cron.log
/var/log/messages
/var/log/secure
/var/log/spooler
/var/log/boot.log
/var/log/syslog
{
    rotate 12
    weekly
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    create 0640 root adm
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
EOF
    
    # Enable and start systemd-journald
    info "Configuring systemd-journald"
    backup_file "/etc/systemd/journald.conf"
    
    cat > /etc/systemd/journald.conf << 'EOF'
[Journal]
# Store journal on disk permanently
Storage=persistent
# Compress journal files
Compress=yes
# Split journals by category
SplitMode=uid
# Allow more space for journal
SystemMaxUse=1G
# Sync journal to disk on each log message
SyncIntervalSec=1m
# Set permissions
ForwardToSyslog=yes
ForwardToWall=yes
# Audit format
MaxLevelStore=warning
MaxLevelSyslog=warning
MaxLevelKMsg=warning
MaxLevelConsole=info
MaxLevelWall=emerg
EOF
    
    # Restart journald
    systemctl restart systemd-journald || warning "Failed to restart systemd-journald"
    
    success "System logging hardening completed"
}

setup_malware_scanning() {
    banner "Setting Up Malware Scanning"
    
    # Install malware scanning tools
    apt-get install -y rkhunter chkrootkit clamav clamav-daemon || warning "Failed to install malware scanning tools"
    
    # Configure rkhunter
    info "Configuring rkhunter"
    backup_file "/etc/rkhunter.conf"
    
    # Update rkhunter database
    rkhunter --update || warning "Failed to update rkhunter database"
    rkhunter --propupd || warning "Failed to update rkhunter properties"
    
    # Set up daily rkhunter scan
    cat > /etc/cron.daily/rkhunter-scan << 'EOF'
#!/bin/bash
# Daily rkhunter scan script

# Run the rkhunter check and send an email if suspicious activity is detected
/usr/bin/rkhunter --checkall --skip-keypress --report-warnings-only | mail -s "RKHunter Scan Report - $(hostname)" root
EOF
    
    chmod 755 /etc/cron.daily/rkhunter-scan
    
    # Configure ClamAV
    info "Configuring ClamAV"
    
    # Ensure freshclam service is enabled
    systemctl enable clamav-freshclam || warning "Failed to enable clamav-freshclam"
    systemctl start clamav-freshclam || warning "Failed to start clamav-freshclam"
    
    # Set up daily ClamAV scan
    cat > /etc/cron.daily/clamscan << 'EOF'
#!/bin/bash
# Daily ClamAV scan script

# Set locations to scan
SCAN_LOCATIONS="/home /etc /opt /usr/local /var/www"

# Run clamscan and email results
/usr/bin/clamscan -r $SCAN_LOCATIONS --infected --log=/var/log/clamav/scan.log --move=/var/quarantine
if [ $? -eq 1 ]; then
    cat /var/log/clamav/scan.log | mail -s "ClamAV Virus Detected - $(hostname)" root
fi
EOF
    
    # Create quarantine directory
    mkdir -p /var/quarantine
    chmod 750 /var/quarantine
    
    chmod 755 /etc/cron.daily/clamscan
    
    # Configure chkrootkit
    info "Configuring chkrootkit"
    
    # Set up daily chkrootkit scan
    cat > /etc/cron.daily/chkrootkit-scan << 'EOF'
#!/bin/bash
# Daily chkrootkit scan script

# Run chkrootkit and send an email if suspicious activity is detected
/usr/sbin/chkrootkit | grep -v "not infected" | grep -v "not found" > /var/log/chkrootkit.log
if [ -s /var/log/chkrootkit.log ]; then
    cat /var/log/chkrootkit.log | mail -s "chkrootkit Suspicious Activity Detected - $(hostname)" root
fi
EOF
    
    chmod 755 /etc/cron.daily/chkrootkit-scan
    
    success "Malware scanning set up"
}

cis_compliance() {
    banner "Implementing CIS Compliance Recommendations"
    
    # Apply CIS recommendations based on the level chosen
    info "Applying CIS level: $CIS_LEVEL"
    
    # Common CIS settings for all levels
    
    # Ensure sticky bit is set on all world-writable directories
    df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t
    
    # Set password expiration according to CIS
    backup_file "/etc/login.defs"
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs
    
    # Restrict access to su command
    backup_file "/etc/pam.d/su"
    if ! grep -q "pam_wheel.so use_uid" /etc/pam.d/su; then
        sed -i '/^#auth\s*required\s*pam_wheel.so$/s/^#//' /etc/pam.d/su
    fi
    
    # CIS: Set more restrictive default umask (027)
    sed -i "s/umask\s*[0-9]*/umask $UMASK_VALUE/g" /etc/profile
    sed -i "s/umask\s*[0-9]*/umask $UMASK_VALUE/g" /etc/bash.bashrc
    
    # Server-specific CIS settings
    if [[ "$CIS_LEVEL" == "server" ]]; then
        # Set more restrictive crypto policies
        cat > /etc/ssh/sshd_config.d/cis.conf << 'EOF'
# CIS hardening settings for OpenSSH

# Use only strong ciphers
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

# Use only strong MACs
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256

# Use only strong key exchange algorithms
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256
EOF
        
        # Turn off source-routed packet acceptance
        echo "net.ipv4.conf.all.accept_source_route=0" > /etc/sysctl.d/01-cis.conf
        echo "net.ipv4.conf.default.accept_source_route=0" >> /etc/sysctl.d/01-cis.conf
        
        # Turn off acceptance of ICMP redirects
        echo "net.ipv4.conf.all.accept_redirects=0" >> /etc/sysctl.d/01-cis.conf
        echo "net.ipv4.conf.default.accept_redirects=0" >> /etc/sysctl.d/01-cis.conf
        
        # Turn off secure ICMP redirects
        echo "net.ipv4.conf.all.secure_redirects=0" >> /etc/sysctl.d/01-cis.conf
        echo "net.ipv4.conf.default.secure_redirects=0" >> /etc/sysctl.d/01-cis.conf
        
        # Enable strict reverse path filtering
        echo "net.ipv4.conf.all.rp_filter=1" >> /etc/sysctl.d/01-cis.conf
        echo "net.ipv4.conf.default.rp_filter=1" >> /etc/sysctl.d/01-cis.conf
        
        # Disable IPv6 router advertisements
        echo "net.ipv6.conf.all.accept_ra=0" >> /etc/sysctl.d/01-cis.conf
        echo "net.ipv6.conf.default.accept_ra=0" >> /etc/sysctl.d/01-cis.conf
        
        # Disable IPv6 redirects
        echo "net.ipv6.conf.all.accept_redirects=0" >> /etc/sysctl.d/01-cis.conf
        echo "net.ipv6.conf.default.accept_redirects=0" >> /etc/sysctl.d/01-cis.conf
        
        # Apply sysctl settings
        sysctl -p /etc/sysctl.d/01-cis.conf || warning "Failed to apply CIS sysctl settings"
    fi
    
    # Disable unused filesystems
    cat > /etc/modprobe.d/cis-blacklist.conf << 'EOF'
# CIS 1.1.1 Disable unused filesystems
blacklist cramfs
blacklist freevxfs
blacklist jffs2
blacklist hfs
blacklist hfsplus
blacklist squashfs
blacklist udf
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
EOF
    
    # Disable uncommon network protocols
    cat > /etc/modprobe.d/cis-network.conf << 'EOF'
# CIS 3.5 Disable uncommon network protocols
blacklist sctp
blacklist rds
blacklist tipc
blacklist dccp
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
install dccp /bin/true
EOF
    
    # Set wireless interface disable
    cat > /etc/modprobe.d/cis-wireless.conf << 'EOF'
# CIS 3.7 Disable wireless networking
install bluetooth /bin/true
install atm /bin/true
EOF
    
    # Update modprobe settings
    update-initramfs -u || warning "Failed to update initramfs"
    
    success "CIS compliance settings applied"
}

additional_hardening() {
    banner "Additional Hardening Measures"
    
    # Configure sysstat for system activity monitoring
    info "Configuring sysstat"
    systemctl enable sysstat
    systemctl start sysstat
    
    # Configure sudo with insults and limited tries
    info "Configuring sudo with enhanced security"
    backup_file "/etc/sudoers"
    
    # Add secure sudo defaults
    cat > /etc/sudoers.d/099-hardening << 'EOF'
# Secure sudo configuration
Defaults    use_pty
Defaults    logfile="/var/log/sudo.log"
Defaults    log_input,log_output
Defaults    lecture=always
Defaults    secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults    insults
Defaults    passwd_timeout=1
Defaults    passwd_tries=3
Defaults    timestamp_timeout=5
Defaults    umask=0077
Defaults    env_reset,env_delete="XAUTHORITY"
EOF
    chmod 440 /etc/sudoers.d/099-hardening
    
    # Limit su to wheel group
    info "Restricting su command to sudo users"
    if ! grep -q "auth required pam_wheel.so use_uid" /etc/pam.d/su; then
        echo "auth required pam_wheel.so use_uid group=sudo" >> /etc/pam.d/su
    fi
    
    # Configure systemd hardening
    info "Configuring systemd hardening"
    mkdir -p /etc/systemd/system.conf.d/
    
    cat > /etc/systemd/system.conf.d/hardening.conf << 'EOF'
# Systemd hardening
[Manager]
DumpCore=no
CrashShell=no
DefaultLimitCORE=0
DefaultLimitNOFILE=1024:65536
DefaultLimitNPROC=1024:65536
EOF
    
    # Disable ctrl-alt-delete
    systemctl mask ctrl-alt-del.target
    
    # Configure mandatory access time for critical filesystems
    info "Configuring filesystem access time"
    if ! grep -q "noatime" /etc/fstab; then
        sed -i 's/defaults/defaults,noatime,nodev,nosuid/' /etc/fstab
    fi
    
    # Configure Debsums for verifying package integrity
    info "Configuring Debsums"
    apt-get install -y debsums || warning "Failed to install debsums"
    debsums_init || warning "Failed to initialize debsums"
    
    # Setup a cron job to run debsums regularly
    cat > /etc/cron.daily/debsums-check << 'EOF'
#!/bin/bash
# Daily debsums integrity check

# Run debsums and email on errors
/usr/bin/debsums -c | grep -v "OK$" > /var/log/debsums-errors.log
if [ -s /var/log/debsums-errors.log ]; then
    echo "Package integrity issues were found on $(hostname) at $(date)" | cat - /var/log/debsums-errors.log | mail -s "Debsums Integrity Alert - $(hostname)" root
fi
EOF
    chmod 755 /etc/cron.daily/debsums-check
    
    # Address physical security concerns
    info "Configuring physical security measures"
    
    # Set GRUB bootloader password
    if confirm "Do you want to set a GRUB bootloader password? (Recommended)" "y"; then
        info "Generating GRUB password hash (you will need to enter a password)"
        grub_password=$(grub-mkpasswd-pbkdf2 | grep -o 'grub.pbkdf2.sha512.*')
        
        cat > /etc/grub.d/01_password << EOF
#!/bin/sh
# Set password protection for GRUB
set -e

cat << EOF_HEADER
set superusers="root"
password_pbkdf2 root ${grub_password}
EOF_HEADER
EOF
        chmod 755 /etc/grub.d/01_password
        update-grub || warning "Failed to update GRUB"
    fi
    
    # Secure shared memory
    info "Securing shared memory"
    if ! grep -q "/dev/shm" /etc/fstab; then
        echo "tmpfs     /dev/shm     tmpfs     defaults,noexec,nosuid,nodev     0     0" >> /etc/fstab
    fi
    
    # Secure /tmp
    info "Securing /tmp directory"
    if ! grep -q "^tmpfs\\s*/tmp" /etc/fstab; then
        echo "tmpfs     /tmp         tmpfs     defaults,noexec,nosuid,nodev     0     0" >> /etc/fstab
    fi
    
    # Secure /var/tmp
    info "Securing /var/tmp directory"
    if ! grep -q "/var/tmp" /etc/fstab; then
        echo "tmpfs     /var/tmp     tmpfs     defaults,noexec,nosuid,nodev     0     0" >> /etc/fstab
    fi
    
    # Secure /dev/shm
    info "Securing /dev/shm"
    if ! grep -q "/dev/shm" /etc/fstab; then
        echo "tmpfs     /dev/shm     tmpfs     defaults,noexec,nosuid,nodev     0     0" >> /etc/fstab
    fi
    
    # Install Lynis for security auditing
    info "Installing Lynis security auditing tool"
    apt-get install -y lynis || warning "Failed to install Lynis"
    
    # Set up a weekly Lynis scan
    cat > /etc/cron.weekly/lynis-audit << 'EOF'
#!/bin/bash
# Weekly security audit using Lynis

# Run a Lynis audit and store the report
/usr/sbin/lynis audit system --quiet --report-file /var/log/lynis-report.dat

# Email a summary report
cat /var/log/lynis.log | mail -s "Lynis Audit Report - $(hostname)" root
EOF
    chmod 755 /etc/cron.weekly/lynis-audit
    
    # Create warning banner for all login services
    info "Creating warning banners for login services"
    cat > /etc/issue << 'EOF'
********************************************************************
*                                                                  *
*                       AUTHORIZED ACCESS ONLY                     *
*                                                                  *
* This system is restricted to authorized users for authorized use *
* only. All activities are logged and monitored. Unauthorized      *
* access attempts may be subject to civil and/or criminal          *
* prosecution.                                                     *
*                                                                  *
********************************************************************
EOF
    
    # Copy the same content to issue.net
    cp /etc/issue /etc/issue.net
    
    success "Additional hardening measures applied"
}

create_security_reporting() {
    banner "Setting Up Security Reporting"
    
    # Create a daily security report script
    info "Creating daily security report script"
    
    cat > /usr/local/bin/security-report << 'EOF'
#!/bin/bash
# Daily security status report for Debian Linux
# This script compiles various security information into a report

REPORT_FILE="/var/log/security-report-$(date +%Y%m%d).txt"

# Function to add a section header to the report
add_section() {
    echo -e "\n========== $1 ==========" >> $REPORT_FILE
}

# Start fresh report
echo "Security Report for $(hostname) - Generated on $(date)" > $REPORT_FILE
echo "===========================================" >> $REPORT_FILE

# System information
add_section "SYSTEM INFORMATION"
echo "Hostname: $(hostname)" >> $REPORT_FILE
echo "Kernel: $(uname -r)" >> $REPORT_FILE
echo "Uptime: $(uptime)" >> $REPORT_FILE
echo "Last reboot: $(who -b | awk '{print $3,$4}')" >> $REPORT_FILE

# Disk space
add_section "DISK USAGE"
df -h >> $REPORT_FILE

# User accounts analysis
add_section "USER ACCOUNTS"
echo "Total user accounts: $(cat /etc/passwd | wc -l)" >> $REPORT_FILE
echo "Users with login shell: $(grep -c "/bin/bash\|/bin/sh" /etc/passwd)" >> $REPORT_FILE
echo "Users with UID 0: $(awk -F: '$3 == 0 {print $1}' /etc/passwd | tr '\n' ' ')" >> $REPORT_FILE

# Recently modified user accounts
add_section "RECENTLY MODIFIED USER ACCOUNTS (Last 7 days)"
find /etc -name "passwd" -o -name "shadow" -o -name "group" -mtime -7 -ls >> $REPORT_FILE

# Failed login attempts
add_section "RECENT FAILED LOGIN ATTEMPTS"
grep "Failed password" /var/log/auth.log | tail -n 10 >> $REPORT_FILE

# Process list with unusual entries
add_section "UNUSUAL PROCESSES"
ps aux | grep -v "^root\|^www-data\|^systemd\|^nobody\|^messagebus\|^syslog\|^_apt\|^daemon\|^USER\|^avahi" >> $REPORT_FILE

# Open ports and listening services
add_section "LISTENING SERVICES"
ss -tuln >> $REPORT_FILE

# Recent package updates
add_section "RECENT PACKAGE UPDATES (Last 7 days)"
grep "upgraded" /var/log/dpkg.log | tail -n 20 >> $REPORT_FILE

# Check for pending updates
add_section "PENDING UPDATES"
apt list --upgradable 2>/dev/null | grep -v "Listing..." >> $REPORT_FILE

# Recent login activity
add_section "RECENT LOGIN ACTIVITY"
last -n 10 >> $REPORT_FILE

# AIDE status (if installed)
if [ -x "$(command -v aide)" ]; then
    add_section "AIDE STATUS"
    aide --status >> $REPORT_FILE 2>&1
fi

# Check for unusual SUID/SGID files
add_section "UNUSUAL SUID/SGID FILES (not in standard locations)"
find / -type f \( -perm -4000 -o -perm -2000 \) -not -path "/usr/bin/*" -not -path "/bin/*" -not -path "/sbin/*" -not -path "/usr/sbin/*" -not -path "/usr/lib/*" -not -path "/usr/libexec/*" 2>/dev/null >> $REPORT_FILE

# Check for world-writable files
add_section "WORLD-WRITABLE FILES (excluding /proc and /sys)"
find / -type f -perm -0002 -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" -not -path "/run/*" 2>/dev/null >> $REPORT_FILE

# Check for unowned files
add_section "UNOWNED FILES"
find / -nouser -o -nogroup -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | head -n 20 >> $REPORT_FILE

# Firewall status
add_section "FIREWALL STATUS"
ufw status verbose >> $REPORT_FILE

# Lynis report summary (if available)
if [ -f "/var/log/lynis-report.dat" ]; then
    add_section "LYNIS SECURITY SCAN SUMMARY"
    grep "hardening_index" /var/log/lynis-report.dat >> $REPORT_FILE
    grep "warning" /var/log/lynis-report.dat | head -n 10 >> $REPORT_FILE
fi

# Mail the report to root
cat $REPORT_FILE | mail -s "Security Report for $(hostname) - $(date +%Y-%m-%d)" root

# Keep only the last 7 days of reports
find /var/log -name "security-report-*.txt" -mtime +7 -delete
EOF
    
    chmod 700 /usr/local/bin/security-report
    
    # Create a daily cron job for the security report
    cat > /etc/cron.daily/security-report << 'EOF'
#!/bin/bash
/usr/local/bin/security-report
EOF
    
    chmod 755 /etc/cron.daily/security-report
    
    success "Security reporting setup completed"
}

system_backup_setup() {
    banner "Setting Up System Backup"
    
    # Ask if user wants to configure backups
    if confirm "Do you want to set up critical system files backup?" "y"; then
        # Install rsync if not already installed
        apt-get install -y rsync || warning "Failed to install rsync"
        
        # Create backup directory structure
        mkdir -p /var/backups/system
        chmod 700 /var/backups/system
        
        # Create backup script
        cat > /usr/local/bin/system-backup << 'EOF'
#!/bin/bash
# System critical files backup script

BACKUP_DIR="/var/backups/system/$(date +%Y%m%d)"
LOG_FILE="/var/log/system-backup.log"

# Create backup directories
mkdir -p $BACKUP_DIR/etc
mkdir -p $BACKUP_DIR/home
mkdir -p $BACKUP_DIR/root
mkdir -p $BACKUP_DIR/var/spool/cron
mkdir -p $BACKUP_DIR/var/log
mkdir -p $BACKUP_DIR/usr/local/bin
mkdir -p $BACKUP_DIR/usr/local/sbin
mkdir -p $BACKUP_DIR/boot

echo "Starting system backup at $(date)" > $LOG_FILE

# Backup system configuration files
echo "Backing up /etc..." >> $LOG_FILE
rsync -az --delete /etc/ $BACKUP_DIR/etc/ >> $LOG_FILE 2>&1

# Backup home directories (only dotfiles and configs, not data)
echo "Backing up dotfiles in /home..." >> $LOG_FILE
rsync -az --include="*/.*" --exclude="*" /home/ $BACKUP_DIR/home/ >> $LOG_FILE 2>&1

# Backup root user configuration
echo "Backing up /root..." >> $LOG_FILE
rsync -az --exclude=".cache" /root/ $BACKUP_DIR/root/ >> $LOG_FILE 2>&1

# Backup cron jobs
echo "Backing up cron jobs..." >> $LOG_FILE
rsync -az /var/spool/cron/ $BACKUP_DIR/var/spool/cron/ >> $LOG_FILE 2>&1

# Backup important logs
echo "Backing up important logs..." >> $LOG_FILE
rsync -az /var/log/auth.log* /var/log/syslog* /var/log/messages* /var/log/secure* $BACKUP_DIR/var/log/ >> $LOG_FILE 2>&1

# Backup custom scripts
echo "Backing up custom scripts..." >> $LOG_FILE
rsync -az /usr/local/bin/ $BACKUP_DIR/usr/local/bin/ >> $LOG_FILE 2>&1
rsync -az /usr/local/sbin/ $BACKUP_DIR/usr/local/sbin/ >> $LOG_FILE 2>&1

# Backup boot configuration
echo "Backing up boot configuration..." >> $LOG_FILE
rsync -az /boot/ $BACKUP_DIR/boot/ >> $LOG_FILE 2>&1

# Create a list of installed packages
echo "Creating list of installed packages..." >> $LOG_FILE
dpkg --get-selections > $BACKUP_DIR/installed-packages.txt

# Create a checksums file
echo "Generating checksums..." >> $LOG_FILE
cd $BACKUP_DIR
find . -type f -exec md5sum {} \; > ../backup-checksums-$(date +%Y%m%d).md5

# Set secure permissions
echo "Setting secure permissions..." >> $LOG_FILE
chmod -R 700 $BACKUP_DIR
chmod 600 ../backup-checksums-$(date +%Y%m%d).md5

# Keep only the last 7 backups
echo "Removing old backups..." >> $LOG_FILE
find /var/backups/system -type d -name "20*" -mtime +7 -exec rm -rf {} \; 2>/dev/null

echo "Backup completed at $(date)" >> $LOG_FILE

# Send a notification
cat $LOG_FILE | mail -s "System Backup Report - $(hostname) - $(date +%Y-%m-%d)" root
EOF
        
        chmod 700 /usr/local/bin/system-backup
        
        # Create weekly cron job for backup
        cat > /etc/cron.weekly/system-backup << 'EOF'
#!/bin/bash
/usr/local/bin/system-backup
EOF
        
        chmod 755 /etc/cron.weekly/system-backup
        
        info "System backup configuration completed"
    else
        info "Skipping system backup configuration"
    fi
    
    success "System backup setup completed"
}

run_security_audit() {
    banner "Running Initial Security Audit"
    
    # Run Lynis audit if installed
    if command -v lynis >/dev/null 2>&1; then
        info "Running Lynis security audit (this may take a while)..."
        lynis audit system --quick
        success "Lynis audit completed. Check /var/log/lynis.log for details."
    else
        warning "Lynis not installed. Skipping security audit."
    fi
    
    success "Initial security audit completed"
}

show_hardening_summary() {
    banner "Hardening Summary"
    
    echo -e "${GREEN}Debian 12 Server Hardening Completed!${RESET}"
    echo
    echo -e "${BOLD}The following security hardening measures have been applied:${RESET}"
    echo
    echo "1. ${BOLD}Authentication Hardening:${RESET}"
    echo "   - Configured strong password policies"
    echo "   - Enforced password aging and complexity"
    echo "   - Limited su command access to sudo group"
    echo "   - Configured account lockout after failed attempts"
    
    echo
    echo "2. ${BOLD}SSH Hardening:${RESET}"
    echo "   - Secured SSH configuration with strong ciphers and MACs"
    echo "   - Disabled root login"
    echo "   - Set strict authentication methods"
    echo "   - Added warning banners"
    if [[ "$SSH_PORT" != "22" ]]; then
        echo "   - Changed SSH port to $SSH_PORT"
    fi
    
    echo
    echo "3. ${BOLD}Network Hardening:${RESET}"
    echo "   - Applied system-wide secure sysctl settings"
    echo "   - Configured UFW firewall"
    echo "   - Set up fail2ban for brute force protection"
    if [[ "$IPV6_DISABLED" == "yes" ]]; then
        echo "   - Disabled IPv6"
    fi
    
    echo
    echo "4. ${BOLD}System Hardening:${RESET}"
    echo "   - Set secure file permissions on critical files"
    echo "   - Removed/secured SUID/SGID binaries"
    echo "   - Disabled unnecessary system services"
    echo "   - Secured shared memory and temporary directories"
    echo "   - Set up automatic security updates"
    
    echo
    echo "5. ${BOLD}Monitoring and Logging:${RESET}"
    echo "   - Enhanced system logging configuration"
    echo "   - Configured log rotation with secure settings"
    echo "   - Set up daily security reports"
    if [[ "$AIDE_ENABLED" == "yes" ]]; then
        echo "   - Configured AIDE for file integrity monitoring"
    fi
    if [[ "$AUDIT_ENABLED" == "yes" ]]; then
        echo "   - Set up auditd with comprehensive audit rules"
    fi
    
    echo
    echo "6. ${BOLD}Malware Detection:${RESET}"
    echo "   - Configured rkhunter, chkrootkit, and ClamAV"
    echo "   - Set up scheduled malware scans"
    
    echo
    echo "7. ${BOLD}Additional Security Measures:${RESET}"
    echo "   - Applied CIS compliance settings (level: $CIS_LEVEL)"
    if [[ "$APPARMOR_ENABLED" == "yes" ]]; then
        echo "   - Enabled and configured AppArmor"
    fi
    echo "   - Set up Lynis for security auditing"
    echo "   - Implemented kernel hardening measures"
    
    echo
    echo -e "${YELLOW}Important Notes:${RESET}"
    echo "1. A log of all hardening operations has been saved to: ${BOLD}$LOG_FILE${RESET}"
    echo "2. Configuration backups are stored in: ${BOLD}$BACKUP_DIR${RESET}"
    echo "3. Daily security reports will be emailed to root"
    echo "4. If SSH port was changed, ensure your firewall allows connections on port ${BOLD}$SSH_PORT${RESET}"
    
    echo
    echo -e "${RED}Post-Hardening Recommendations:${RESET}"
    echo "1. Manually review all service configurations"
    echo "2. Create a complete system backup before making further changes"
    echo "3. Test all critical applications to ensure they still work properly"
    echo "4. Consider setting up centralized logging to a secure log server"
    echo "5. Review the Lynis audit report and address any remaining issues"
    
    echo
    echo -e "${BOLD}Would you like to reboot the system to apply all changes?${RESET}"
    if confirm "Reboot now?" "n"; then
        echo "System will reboot in 10 seconds. Press Ctrl+C to cancel."
        sleep 10
        reboot
    else
        echo -e "${YELLOW}Please reboot the system at your convenience to ensure all changes take effect.${RESET}"
    fi
}

#
# Main function
#

main() {
    # Clear the screen
    clear
    
    banner "Debian 12 (Bookworm) Server Hardening"
    
    # Check if running as root
    check_root
    
    # Check Debian version
    check_debian_version
    
    # Create backup directory
    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"
    
    # Basic configuration
    configure_basic_settings
    
    # Implementation phase
    update_system
    install_security_packages
    harden_authentication
    harden_ssh
    harden_network
    harden_file_permissions
    harden_system_services
    harden_kernel_parameters
    configure_automatic_updates
    harden_logging
    setup_malware_scanning
    cis_compliance
    additional_hardening
    create_security_reporting
    system_backup_setup
    
    # Run security audit
    run_security_audit
    
    # Show summary
    show_hardening_summary
}

# Run the main function
main "$@"
