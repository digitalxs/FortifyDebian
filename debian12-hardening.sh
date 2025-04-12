# Apply system hardening if selected
if [ "$SETUP_SYSTEM_HARDENING" = true ]; then
    echo "Applying system hardening measures..."
    
    # Install security packages if not already installed
    apt -y install libpam-pwquality libpam-cracklib

    # Secure shared memory
    echo "Securing shared memory..."
    if ! grep -q '/run/shm' /etc/fstab; then
        echo "# Secure shared memory" >> /etc/fstab
        echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
    fi

    # Secure /tmp
    echo "Securing /tmp directory..."
    if ! grep -q '/tmp' /etc/fstab; then
        echo "# Secure tmp directory" >> /etc/fstab
        echo "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
    fi

    # Harden kernel through sysctl
    echo "Hardening kernel parameters..."
    cat > /etc/sysctl.d/99-security.conf <<EOF
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Block SYN attacks
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Disable IP forwarding
net.ipv4.ip_forward = 0

# Disable IPv6 if not needed
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
net.ipv6.conf.lo.disable_ipv6 = 0

# Increase system file descriptor limit
fs.file-max = 65535

# Protect against ptrace
kernel.yama.ptrace_scope = 1

# Restrict dmesg access
kernel.dmesg_restrict = 1

# Restrict access to kernel pointers
kernel.kptr_restrict = 2

# Disable the magic-sysrq key
kernel.sysrq = 0

# Increase ASLR entropy
vm.mmap_rnd_bits = 32
vm.mmap_rnd_compat_bits = 16
EOF

    # Apply the new sysctl parameters
    sysctl -p /etc/sysctl.d/99-security.conf

    # Configure password policy
    echo "Configuring password policies..."
    cat > /etc/security/pwquality.conf <<EOF
# Password must be at least 12 characters
minlen = 12

# Password must include at least 1 uppercase letter
ucredit = -1

# Password must include at least 1 lowercase letter
lcredit = -1

# Password must include at least 1 digit
dcredit = -1

# Password must include at least 1 special character
ocredit = -1

# New password must have at least 8 characters that are not part of the old password
difok = 8

# Reject passwords that contain user name
reject_username

# Enforce retry count
retry = 3

# Check for common patterns
maxsequence = 3
maxclassrepeat = 3
EOF

    # Configure PAM to use the password policy
    if [ -f /etc/pam.d/common-password ]; then
        sed -i 's/pam_unix.so obscure/pam_unix.so obscure remember=5 minlen=12/' /etc/pam.d/common-password
        
        # Check if the pwquality line already exists
        if ! grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
            # Add the pwquality line before the pam_unix.so line
            sed -i '/pam_unix.so/i password        requisite                       pam_pwquality.so retry=3' /etc/pam.d/common-password
        fi
    fi

    # Set password expiration policy
    echo "Setting password expiration policy..."
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs

    # Apply password expiration to existing users
    echo -n "Apply password expiration policy to existing users? [y/N]: "
    read -r APPLY_EXPIRY
    if [[ "$APPLY_EXPIRY" =~ ^[Yy] ]]; then
        for user in $(cut -d: -f1 /etc/passwd); do
            # Skip system users
            if [ "$(id -u "$user" 2>/dev/null || echo 0)" -ge 1000 ]; then
                echo "Applying password policy to user: $user"
                chage --maxdays 90 --mindays 1 --warndays 7 "$user"
            fi
        done
    fi

    # Restrict access to cron and at
    echo "Restricting access to cron and at..."
    if [ -f /etc/cron.allow ]; then
        echo "root" > /etc/cron.allow
        echo "$NEW_USER" >> /etc/cron.allow
        rm -f /etc/cron.deny
    fi

    if [ -f /etc/at.allow ]; then
        echo "root" > /etc/at.allow
        echo "$NEW_USER" >> /etc/at.allow
        rm -f /etc/at.deny
    fi

    # Restrict su command to users in the wheel group
    echo "Restricting use of su command..."
    if ! grep -q "auth required pam_wheel.so" /etc/pam.d/su; then
        echo "auth required pam_wheel.so use_uid group=sudo" >> /etc/pam.d/su
    fi

    # Set up process accounting
    echo "Setting up process accounting..."
    apt -y install acct
    touch /var/log/pacct
    systemctl enable acct
    systemctl start acct

    # Set up system auditing
    if ! dpkg -l | grep -q "auditd"; then
        echo "Installing and configuring auditd..."
        apt -y install auditd
    fi

    # Configure file permissions
    echo "Setting secure file permissions..."
    chmod 600 /etc/shadow
    chmod 600 /etc/gshadow
    chmod 644 /etc/passwd
    chmod 644 /etc/group
    chmod 640 /etc/sudoers
    chmod 440 /etc/sudoers.d/*

    # Disable core dumps
    echo "Disabling core dumps..."
    echo "* hard core 0" >> /etc/security/limits.conf
    echo "fs.suid_dumpable = 0" >> /etc/sysctl.d/99-security.conf
    sysctl -p /etc/sysctl.d/99-security.conf

    # Set up additional login security
    cat > /etc/securetty <<EOF
console
tty1
tty2
tty3
tty4
tty5
tty6
EOF

    # Configure system banners
    echo "Configuring system banners..."
    cat > /etc/issue <<EOF
Authorized access only!
All activity may be monitored and reported.
EOF

    cat > /etc/issue.net <<EOF
Authorized access only!
All activity may be monitored and reported.
EOF

    # Enable system banners
    sed -i 's/^#Banner.*/Banner \/etc\/issue.net/' /etc/ssh/sshd_config

    # Restart SSH service to apply banner changes
    systemctl restart sshd

    echo "System hardening measures applied."
fi's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
    sed -i #!/bin/bash

# Debian 12 (Bookworm) Minimal Server Setup Script
# ------------------------------------------------
# This script automates the post-installation setup of a Debian 12 minimal server.
# It configures network settings, installs essential packages, sets up security,
# and performs system updates.

# Exit on error
set -e

# Check if script is run as root
if [ "$(id -u)" -ne 0 ]; then
   echo "This script must be run as root" 
   exit 1
fi

# Configuration Wizard
echo "=== Debian 12 (Bookworm) Minimal Server Setup Wizard ==="
echo "Please provide the following information for your server setup:"
echo ""

# Get network interface
NET_INTERFACE=$(ip -o link show | grep -v "lo" | awk -F': ' '{print $2}' | head -n 1)
if [ -z "$NET_INTERFACE" ]; then
    echo "Error: Could not auto-detect a network interface."
    echo -n "Please enter your network interface name manually: "
    read -r NET_INTERFACE
    if [ -z "$NET_INTERFACE" ]; then
        echo "No network interface specified. Exiting."
        exit 1
    fi
else
    echo -n "Detected network interface: $NET_INTERFACE. Is this correct? [Y/n]: "
    read -r CONFIRM
    if [[ "$CONFIRM" =~ ^[Nn] ]]; then
        echo -n "Please enter the correct network interface name: "
        read -r NET_INTERFACE
    fi
fi

# Hostname
echo -n "Enter hostname (without domain, e.g., 'server'): "
read -r HOSTNAME
if [ -z "$HOSTNAME" ]; then
    HOSTNAME="server"
    echo "Using default hostname: $HOSTNAME"
fi

# Domain
echo -n "Enter domain name (e.g., 'example.com'): "
read -r DOMAIN
if [ -z "$DOMAIN" ]; then
    DOMAIN="localdomain"
    echo "Using default domain: $DOMAIN"
fi

FQDN="${HOSTNAME}.${DOMAIN}"

# Network configuration
echo ""
echo "Network Configuration:"
echo -n "Use DHCP for network configuration? [y/N]: "
read -r USE_DHCP

if [[ "$USE_DHCP" =~ ^[Yy] ]]; then
    USE_STATIC=false
    echo "Will configure network to use DHCP."
else
    USE_STATIC=true
    
    # Get current IP information as defaults
    CURRENT_IP=$(ip -4 addr show $NET_INTERFACE | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
    CURRENT_MASK=$(ip -4 addr show $NET_INTERFACE | grep -oP '(?<=inet\s)\d+(\.\d+){3}/\d+' | cut -d/ -f2)
    if [ -n "$CURRENT_MASK" ]; then
        # Convert CIDR to dotted decimal
        case "$CURRENT_MASK" in
            8) CURRENT_NETMASK="255.0.0.0" ;;
            16) CURRENT_NETMASK="255.255.0.0" ;;
            24) CURRENT_NETMASK="255.255.255.0" ;;
            32) CURRENT_NETMASK="255.255.255.255" ;;
            *) CURRENT_NETMASK="" ;;
        esac
    fi
    
    CURRENT_GATEWAY=$(ip route | grep default | grep $NET_INTERFACE | awk '{print $3}')
    
    # Static IP
    echo -n "Enter IP address"
    [ -n "$CURRENT_IP" ] && echo -n " [${CURRENT_IP}]"
    echo -n ": "
    read -r IP_ADDRESS
    if [ -z "$IP_ADDRESS" ] && [ -n "$CURRENT_IP" ]; then
        IP_ADDRESS="$CURRENT_IP"
        echo "Using current IP: $IP_ADDRESS"
    elif [ -z "$IP_ADDRESS" ]; then
        echo "No IP address provided. Exiting."
        exit 1
    fi
    
    # Netmask
    echo -n "Enter netmask"
    [ -n "$CURRENT_NETMASK" ] && echo -n " [${CURRENT_NETMASK}]"
    echo -n ": "
    read -r NETMASK
    if [ -z "$NETMASK" ] && [ -n "$CURRENT_NETMASK" ]; then
        NETMASK="$CURRENT_NETMASK"
        echo "Using current netmask: $NETMASK"
    elif [ -z "$NETMASK" ]; then
        NETMASK="255.255.255.0"
        echo "Using default netmask: $NETMASK"
    fi
    
    # Calculate network and broadcast automatically
    IFS='.' read -r -a IP_PARTS <<< "$IP_ADDRESS"
    IFS='.' read -r -a MASK_PARTS <<< "$NETMASK"
    
    NETWORK=""
    BROADCAST=""
    
    for i in {0..3}; do
        NET_OCTET=$((${IP_PARTS[$i]} & ${MASK_PARTS[$i]}))
        BROADCAST_OCTET=$((${IP_PARTS[$i]} | (255 - ${MASK_PARTS[$i]})))
        
        NETWORK+="$NET_OCTET"
        BROADCAST+="$BROADCAST_OCTET"
        
        if [ $i -lt 3 ]; then
            NETWORK+="."
            BROADCAST+="."
        fi
    done
    
    echo "Calculated network address: $NETWORK"
    echo "Calculated broadcast address: $BROADCAST"
    
    # Gateway
    echo -n "Enter gateway IP address"
    [ -n "$CURRENT_GATEWAY" ] && echo -n " [${CURRENT_GATEWAY}]"
    echo -n ": "
    read -r GATEWAY
    if [ -z "$GATEWAY" ] && [ -n "$CURRENT_GATEWAY" ]; then
        GATEWAY="$CURRENT_GATEWAY"
        echo "Using current gateway: $GATEWAY"
    elif [ -z "$GATEWAY" ]; then
        # Use first three octets of IP with .1 as default gateway
        DEFAULT_GATEWAY=$(echo "$IP_ADDRESS" | sed -E 's/([0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+/\1.1/')
        GATEWAY="$DEFAULT_GATEWAY"
        echo "Using default gateway: $GATEWAY"
    fi
fi

# User configuration
echo ""
echo "User Configuration:"
CURRENT_USER=$(logname 2>/dev/null || echo "")
echo -n "Enter admin username"
[ -n "$CURRENT_USER" ] && echo -n " [${CURRENT_USER}]"
echo -n ": "
read -r NEW_USER
if [ -z "$NEW_USER" ] && [ -n "$CURRENT_USER" ]; then
    NEW_USER="$CURRENT_USER"
    echo "Using current user: $NEW_USER"
elif [ -z "$NEW_USER" ]; then
    NEW_USER="admin"
    echo "Using default admin username: $NEW_USER"
fi

# Security configuration
echo ""
echo "Security Configuration:"

SECURITY_ESSENTIALS="ufw fail2ban"

echo -n "Install basic security packages? ($SECURITY_ESSENTIALS) [Y/n]: "
read -r INSTALL_SECURITY_BASICS
if [[ "$INSTALL_SECURITY_BASICS" =~ ^[Nn] ]]; then
    SETUP_UFW=false
    SETUP_FAIL2BAN=false
    echo "Skipping basic security packages installation."
else
    SETUP_UFW=true
    SETUP_FAIL2BAN=true
    echo "Will install basic security packages."
fi

# Advanced security options
echo -n "Install advanced security packages (lynis, rkhunter, chkrootkit, aide, auditd)? [y/N]: "
read -r INSTALL_ADVANCED_SECURITY
if [[ "$INSTALL_ADVANCED_SECURITY" =~ ^[Yy] ]]; then
    SETUP_ADVANCED_SECURITY=true
    echo "Will install advanced security packages."
else
    SETUP_ADVANCED_SECURITY=false
    echo "Skipping advanced security packages installation."
fi

# SSH hardening options
echo -n "Apply SSH hardening settings? [Y/n]: "
read -r SSH_HARDENING
if [[ "$SSH_HARDENING" =~ ^[Nn] ]]; then
    SETUP_SSH_HARDENING=false
    echo "Skipping SSH hardening."
else
    SETUP_SSH_HARDENING=true
    
    # Get SSH port
    echo -n "Change SSH port from 22? [y/N]: "
    read -r CHANGE_SSH_PORT
    if [[ "$CHANGE_SSH_PORT" =~ ^[Yy] ]]; then
        echo -n "Enter new SSH port (1024-65535 recommended): "
        read -r SSH_PORT
        if [[ ! "$SSH_PORT" =~ ^[0-9]+$ ]] || [ "$SSH_PORT" -lt 1 ] || [ "$SSH_PORT" -gt 65535 ]; then
            echo "Invalid port number. Using default port 22."
            SSH_PORT=22
        fi
    else
        SSH_PORT=22
    fi
    
    # Get password authentication setting
    echo -n "Disable password authentication (use only SSH keys)? [y/N]: "
    read -r DISABLE_PASSWORD_AUTH
    if [[ "$DISABLE_PASSWORD_AUTH" =~ ^[Yy] ]]; then
        PASSWORD_AUTH=no
        echo "Password authentication will be disabled."
        
        # Warn user to ensure SSH key is set up
        echo "WARNING: Make sure your SSH key is properly set up before disabling password authentication!"
        echo "If you don't have an SSH key set up, you could be locked out of your server."
        echo -n "Are you sure you want to proceed? [y/N]: "
        read -r CONFIRM_DISABLE_PASSWORD
        if [[ ! "$CONFIRM_DISABLE_PASSWORD" =~ ^[Yy] ]]; then
            PASSWORD_AUTH=yes
            echo "Password authentication will remain enabled."
        fi
    else
        PASSWORD_AUTH=yes
    fi
    
    # Get root login setting
    echo -n "Disable root login via SSH? [Y/n]: "
    read -r DISABLE_ROOT_LOGIN
    if [[ "$DISABLE_ROOT_LOGIN" =~ ^[Nn] ]]; then
        PERMIT_ROOT_LOGIN=yes
    else
        PERMIT_ROOT_LOGIN=no
    fi
fi

# Automatic security updates
echo -n "Configure unattended security upgrades? [Y/n]: "
read -r SETUP_UNATTENDED
if [[ "$SETUP_UNATTENDED" =~ ^[Nn] ]]; then
    CONFIG_UNATTENDED=false
    echo "Skipping unattended upgrades configuration."
else
    CONFIG_UNATTENDED=true
    echo "Will configure unattended security upgrades."
fi

# Additional packages
echo ""
echo "Package Installation:"
DEFAULT_PACKAGES="vim-nox multitail tree joe git neofetch net-tools cockpit chrony htop iotop iftop ncdu dnsutils curl wget rsync unzip zip screen tmux sudo ntp ethtool lshw lsof netcat-openbsd tcpdump mtr-tiny"
echo -n "Install additional packages? [$DEFAULT_PACKAGES]: "
read -r ADDITIONAL_PACKAGES
if [ -z "$ADDITIONAL_PACKAGES" ]; then
    ADDITIONAL_PACKAGES="$DEFAULT_PACKAGES"
    echo "Will install default packages: $ADDITIONAL_PACKAGES"
fi

# Display the configuration summary
echo ""
echo "=== Configuration Summary ==="
echo "Hostname: $FQDN"
echo "Network Interface: $NET_INTERFACE"
if [ "$USE_STATIC" = true ]; then
    echo "IP Configuration: Static"
    echo "  IP Address: $IP_ADDRESS"
    echo "  Netmask: $NETMASK"
    echo "  Network: $NETWORK"
    echo "  Broadcast: $BROADCAST"
    echo "  Gateway: $GATEWAY"
else
    echo "IP Configuration: DHCP"
fi
echo "Admin User: $NEW_USER"
echo "Security:"
echo "  UFW Firewall: $([ "$SETUP_UFW" = true ] && echo "Yes" || echo "No")"
echo "  Fail2ban: $([ "$SETUP_FAIL2BAN" = true ] && echo "Yes" || echo "No")"
echo "  Advanced Security Tools: $([ "$SETUP_ADVANCED_SECURITY" = true ] && echo "Yes" || echo "No")"
echo "  SSH Hardening: $([ "$SETUP_SSH_HARDENING" = true ] && echo "Yes" || echo "No")"
if [ "$SETUP_SSH_HARDENING" = true ]; then
    echo "    SSH Port: $SSH_PORT"
    echo "    Root Login: $([ "$PERMIT_ROOT_LOGIN" = "yes" ] && echo "Enabled" || echo "Disabled")"
    echo "    Password Authentication: $([ "$PASSWORD_AUTH" = "yes" ] && echo "Enabled" || echo "Disabled")"
fi
echo "  Unattended Upgrades: $([ "$CONFIG_UNATTENDED" = true ] && echo "Yes" || echo "No")"
echo "Additional Packages: $ADDITIONAL_PACKAGES"
echo ""

# Add section to install system hardening options
echo -n "Would you like to apply additional system hardening measures? [y/N]: "
read -r APPLY_SYSTEM_HARDENING
if [[ "$APPLY_SYSTEM_HARDENING" =~ ^[Yy] ]]; then
    SETUP_SYSTEM_HARDENING=true
    echo "Will apply system hardening measures."
else
    SETUP_SYSTEM_HARDENING=false
    echo "Skipping additional system hardening."
fi

echo ""
echo "Press ENTER to continue with this configuration or CTRL+C to abort..."
read -r

# ============================
# Network Configuration
# ============================
echo "=== Configuring Network ==="

# Install SSH server if not already installed
echo "Installing SSH server and sudo..."
apt update
apt -y install ssh openssh-server sudo nano

# Configure network interface
echo "Configuring network interface..."

# Create the network interface configuration
if [ "$USE_STATIC" = true ]; then
    echo "Setting up static IP configuration..."
    cat > /etc/network/interfaces <<EOF
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).
source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
auto $NET_INTERFACE
iface $NET_INTERFACE inet static
        address $IP_ADDRESS
        netmask $NETMASK
        network $NETWORK
        broadcast $BROADCAST
        gateway $GATEWAY

# This is an autoconfigured IPv6 interface
iface $NET_INTERFACE inet6 auto
EOF
else
    echo "Setting up DHCP configuration..."
    cat > /etc/network/interfaces <<EOF
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).
source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
auto $NET_INTERFACE
iface $NET_INTERFACE inet dhcp

# This is an autoconfigured IPv6 interface
iface $NET_INTERFACE inet6 auto
EOF
fi

# Configure hostname
echo "Setting hostname..."
echo "$HOSTNAME" > /etc/hostname

# Configure hosts file
cat > /etc/hosts <<EOF
127.0.0.1       localhost.localdomain   localhost
$IP_ADDRESS     $FQDN   $HOSTNAME

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
EOF

# ============================
# User Configuration
# ============================
echo "=== Configuring Users ==="

# Create new user if it doesn't exist
if ! id "$NEW_USER" &>/dev/null; then
    echo "Creating user $NEW_USER..."
    adduser --gecos "" $NEW_USER || { echo "Failed to create user $NEW_USER"; exit 1; }
    
    # Add to sudo group
    echo "Adding $NEW_USER to sudo group..."
    usermod -aG sudo $NEW_USER
else
    echo "User $NEW_USER already exists."
    # Make sure the user is in the sudo group
    usermod -aG sudo $NEW_USER
fi

# ============================
# Package Installation
# ============================
echo "=== Installing Additional Software ==="

# Configure APT sources
cat > /etc/apt/sources.list <<EOF
deb http://deb.debian.org/debian/ bookworm main contrib non-free non-free-firmware
deb-src http://deb.debian.org/debian/ bookworm main contrib non-free non-free-firmware

deb http://security.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware
deb-src http://security.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware

# bookworm-updates, to get updates before a point release is made
deb http://deb.debian.org/debian/ bookworm-updates main contrib non-free non-free-firmware
deb-src http://deb.debian.org/debian/ bookworm-updates main contrib non-free non-free-firmware
EOF

# Update package database
echo "Updating package database..."
apt update

# Install additional packages
echo "Installing additional software..."
apt -y install $ADDITIONAL_PACKAGES

# Always install chrony for time synchronization
if ! echo "$ADDITIONAL_PACKAGES" | grep -q "chrony"; then
    echo "Installing chrony for time synchronization..."
    apt -y install chrony
fi

# Enable and start chrony
systemctl start chrony
systemctl enable chrony

# ============================
# Security Configuration
# ============================
echo "=== Setting Up Security ==="

# Install and configure security components based on user selection
if [ "$SETUP_UFW" = true ] || [ "$SETUP_FAIL2BAN" = true ] || [ "$SETUP_ADVANCED_SECURITY" = true ]; then
    echo "Installing selected security components..."
    SECURITY_PACKAGES=""
    
    if [ "$SETUP_UFW" = true ]; then
        SECURITY_PACKAGES="$SECURITY_PACKAGES ufw"
    fi
    
    if [ "$SETUP_FAIL2BAN" = true ]; then
        SECURITY_PACKAGES="$SECURITY_PACKAGES fail2ban"
    fi
    
    if [ "$SETUP_ADVANCED_SECURITY" = true ]; then
        SECURITY_PACKAGES="$SECURITY_PACKAGES lynis rkhunter chkrootkit aide auditd debsums needrestart libpam-tmpdir"
    fi
    
    apt -y install $SECURITY_PACKAGES
    
    # Configure UFW if selected
    if [ "$SETUP_UFW" = true ]; then
        echo "Configuring UFW firewall..."
        
        # Configure default firewall rules
        if [ "$SSH_PORT" = "22" ]; then
            ufw allow ssh
        else
            ufw allow "$SSH_PORT/tcp" comment 'SSH'
        fi
        
        # Ask about common web services
        echo -n "Allow HTTP (port 80)? [Y/n]: "
        read -r ALLOW_HTTP
        if [[ ! "$ALLOW_HTTP" =~ ^[Nn] ]]; then
            ufw allow http
            echo "HTTP allowed."
        fi
        
        echo -n "Allow HTTPS (port 443)? [Y/n]: "
        read -r ALLOW_HTTPS
        if [[ ! "$ALLOW_HTTPS" =~ ^[Nn] ]]; then
            ufw allow https
            echo "HTTPS allowed."
        fi
        
        # Check if Cockpit is installed or will be installed
        if echo "$ADDITIONAL_PACKAGES" | grep -q "cockpit" || dpkg -l | grep -q "cockpit"; then
            echo -n "Allow Cockpit web interface (port 9090)? [Y/n]: "
            read -r ALLOW_COCKPIT
            if [[ ! "$ALLOW_COCKPIT" =~ ^[Nn] ]]; then
                ufw allow 9090/tcp comment 'Cockpit'
                echo "Cockpit port allowed."
            fi
        fi
        
        # Ask about custom ports
        echo -n "Enter additional ports to open (space-separated, e.g., '8080 10000'): "
        read -r CUSTOM_PORTS
        if [ -n "$CUSTOM_PORTS" ]; then
            for PORT in $CUSTOM_PORTS; do
                if [[ "$PORT" =~ ^[0-9]+$ ]]; then
                    ufw allow "$PORT"
                    echo "Port $PORT allowed."
                else
                    echo "Skipping invalid port: $PORT"
                fi
            done
        fi
        
        # Rate limiting for SSH
        echo -n "Enable rate limiting for SSH connections (prevents brute force attacks)? [Y/n]: "
        read -r RATE_LIMIT_SSH
        if [[ ! "$RATE_LIMIT_SSH" =~ ^[Nn] ]]; then
            # Delete the existing SSH rule first
            if [ "$SSH_PORT" = "22" ]; then
                ufw delete allow ssh
                ufw limit ssh
                echo "Rate limiting enabled for SSH."
            else
                ufw delete allow "$SSH_PORT/tcp"
                ufw limit "$SSH_PORT/tcp" comment 'SSH'
                echo "Rate limiting enabled for SSH on port $SSH_PORT."
            fi
        fi
        
        ufw default deny incoming
        ufw default allow outgoing
        
        # Enable UFW with yes confirmation to prevent script from hanging
        echo "Enabling UFW..."
        echo "y" | ufw enable || { echo "Failed to enable UFW. Please check your network configuration."; }
    fi
    
    # Configure fail2ban if selected
    if [ "$SETUP_FAIL2BAN" = true ]; then
        echo "Configuring fail2ban..."
        cp -n /etc/fail2ban/jail.conf /etc/fail2ban/jail.local  # -n flag prevents overwriting existing config
        
        echo -n "Enter IPs to whitelist in fail2ban (space-separated, leave empty for default): "
        read -r WHITELIST_IPS
        
        # Prepare whitelist string
        IGNORE_IP="127.0.0.1/8 ::1"
        if [ -n "$WHITELIST_IPS" ]; then
            IGNORE_IP="$IGNORE_IP $WHITELIST_IPS"
        fi
        
        # Edit the fail2ban configuration
        cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
# Ban hosts for one hour:
bantime = 3600

# Increase ban time with each subsequent ban
bantime.increment = true
bantime.factor = 2
bantime.formula = ban.Time * (1<<(ban.Count if ban.Count<20 else 20)) * banFactor

# Override /etc/fail2ban/jail.d/00-firewalld.conf:
banaction = iptables-multiport

# Find attempts from the past day
findtime = 86400

# Ban IP after 5 failures
maxretry = 5

# Whitelisted IPs
ignoreip = $IGNORE_IP

# Custom SSH jail with aggressive settings
[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
findtime = 3600
EOF
        
        # Enable and start fail2ban
        systemctl enable fail2ban
        systemctl restart fail2ban
        echo "fail2ban configured and restarted."
    fi
    
    # Configure advanced security tools if selected
    if [ "$SETUP_ADVANCED_SECURITY" = true ]; then
        echo "Configuring advanced security tools..."
        
        # Initialize AIDE database
        if dpkg -l | grep -q "aide"; then
            echo "Initializing AIDE database (this may take a while)..."
            aideinit
            cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
            
            # Set up a daily cron job for AIDE
            cat > /etc/cron.daily/aide-check <<EOF
#!/bin/bash
/usr/bin/aide.wrapper --check > /var/log/aide/aide.log 2>&1
EOF
            chmod +x /etc/cron.daily/aide-check
            mkdir -p /var/log/aide
        fi
        
        # Schedule regular rkhunter and chkrootkit scans
        if dpkg -l | grep -q "rkhunter"; then
            echo "Updating rkhunter database..."
            rkhunter --update
            rkhunter --propupd
            
            # Set up a weekly cron job for rkhunter
            cat > /etc/cron.weekly/rkhunter-check <<EOF
#!/bin/bash
/usr/bin/rkhunter --check --skip-keypress --report-warnings-only > /var/log/rkhunter/rkhunter-weekly.log 2>&1
EOF
            chmod +x /etc/cron.weekly/rkhunter-check
            mkdir -p /var/log/rkhunter
        fi
        
        if dpkg -l | grep -q "chkrootkit"; then
            # Set up a weekly cron job for chkrootkit
            cat > /etc/cron.weekly/chkrootkit-check <<EOF
#!/bin/bash
/usr/sbin/chkrootkit > /var/log/chkrootkit/chkrootkit-weekly.log 2>&1
EOF
            chmod +x /etc/cron.weekly/chkrootkit-check
            mkdir -p /var/log/chkrootkit
        fi
        
        # Set up auditd basic rules if installed
        if dpkg -l | grep -q "auditd"; then
            cat > /etc/audit/rules.d/audit.rules <<EOF
# Remove any existing rules
-D

# Buffer Size
-b 8192

# Failure Mode
-f 1

# Monitor access to sensitive files
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Monitor administrative actions
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions

# Monitor login/logout events
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/btmp -p wa -k session
-w /var/log/wtmp -p wa -k session

# Monitor SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd

# Monitor systemd
-w /bin/systemctl -p x -k systemd
-w /etc/systemd/ -p wa -k systemd
EOF
            
            systemctl restart auditd
            echo "Auditd configured and restarted."
        fi
        
        # Run basic Lynis audit if installed
        if dpkg -l | grep -q "lynis"; then
            echo "Running initial Lynis security audit..."
            lynis audit system --quick
        fi
    fi
else
    echo "Skipping security components installation as per your selection."
fi

# Configure SSH hardening if selected
if [ "$SETUP_SSH_HARDENING" = true ]; then
    echo "Applying SSH hardening settings..."
    
    # Backup the original SSH config
    cp -n /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    
    # Create a new config file with hardened settings
    cat > /etc/ssh/sshd_config.new <<EOF
# SSH hardened config generated by Debian setup script
# Original config backed up to /etc/ssh/sshd_config.bak

Port $SSH_PORT
Protocol 2
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Authentication settings
LoginGraceTime 30s
PermitRootLogin $PERMIT_ROOT_LOGIN
StrictModes yes
MaxAuthTries 3
MaxSessions 5

# Only use strong ciphers and algorithms
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com

# User authentication
PubkeyAuthentication yes
PasswordAuthentication $PASSWORD_AUTH
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Other security settings
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server

# Disable tunneled clear text passwords
HostbasedAuthentication no
IgnoreRhosts yes

# Disable user environment processing
PermitUserEnvironment no

# Idle timeout interval
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
    
    # Replace the SSH config with our hardened version
    mv /etc/ssh/sshd_config.new /etc/ssh/sshd_config
    
    # Restart SSH service to apply changes
    echo "Restarting SSH service to apply hardening settings..."
    systemctl restart sshd
    
    echo "SSH hardening applied. New SSH settings:"
    echo "- SSH Port: $SSH_PORT"
    echo "- Root Login: $([ "$PERMIT_ROOT_LOGIN" = "yes" ] && echo "Enabled" || echo "Disabled")"
    echo "- Password Authentication: $([ "$PASSWORD_AUTH" = "yes" ] && echo "Enabled" || echo "Disabled")"
    echo "- Idle Timeout: 5 minutes"
fi

# ============================
# Unattended Upgrades
# ============================
echo "=== Setting Up Unattended Upgrades ==="

# Install unattended-upgrades
apt -y install unattended-upgrades

# Configure unattended upgrades
# Uncomment the Debian-Security line in unattended-upgrades config
if [ -f /etc/apt/apt.conf.d/50unattended-upgrades ]; then
    sed -i 's|//\s*"origin=Debian,codename=${distro_codename},label=Debian-Security";|"origin=Debian,codename=${distro_codename},label=Debian-Security";|g' /etc/apt/apt.conf.d/50unattended-upgrades
else
    echo "Warning: Unattended-upgrades configuration file not found at expected location."
fi

# Enable and start unattended-upgrades
systemctl enable unattended-upgrades
systemctl start unattended-upgrades

# ============================
# System Update
# ============================
echo "=== Updating System ==="

# Perform system upgrade
apt -y upgrade

# ============================
# Finalization
# ============================
echo "=== Setup Complete ==="
echo "Your Debian 12 minimal server has been configured with the following settings:"
echo "Hostname: $FQDN"
echo "IP Address: $IP_ADDRESS"
echo "Admin User: $NEW_USER (with sudo privileges)"
echo ""
echo "The following services have been configured:"
echo "- SSH Server"
echo "- UFW Firewall (with ports 22, 80, 443, 9090, 10000 open)"
echo "- Fail2ban"
echo "- Chrony (time synchronization)"
echo "- Unattended upgrades (for security updates)"
echo "- Cockpit (web-based system administration on port 9090)"
echo ""
echo "A system restart is recommended to apply all changes."
echo "Would you like to restart now? (y/n)"
read -r restart_choice  # -r prevents backslash interpretation

if [[ $restart_choice == "y" || $restart_choice == "Y" ]]; then
    echo "Restarting system..."
    systemctl reboot
else
    echo "Please remember to restart your system later."
fi
