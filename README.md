# <img src="https://www.debian.org/logos/openlogo-nd.svg" alt="Debian Logo" width="40"/> FortifyDebian

A robust, interactive deployment tool for building production-ready Debian 12 servers with enterprise-grade security. FortifyDebian transforms a minimal Debian installation into a fully hardened server environment through an intuitive wizard-driven approach.

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://buymeacoffee.com/digitalxs)

**Project sponsored by [DigitalXS.ca](https://digitalxs.ca) and Luis Miguel P. Freitas**

## Features and Security Components

| Category | Features | Software/Tools Used |
|----------|----------|---------------------|
| **Authentication Hardening** | • Strong password policies<br>• Password aging and complexity enforcement<br>• Account lockout after failed attempts<br>• Secure umask settings<br>• Restricted su command access | • libpam-pwquality<br>• libpam-cracklib<br>• libpam-passwdqc<br>• pam_tally2 |
| **SSH Hardening** | • Strong ciphers, MACs, and key exchange<br>• Disabled root login<br>• Strict authentication methods<br>• Custom warning banners<br>• Optional key-based authentication | • openssh-server<br>• fail2ban |
| **Network Security** | • Secure sysctl network settings<br>• Stateful firewall configuration<br>• Protection against common attacks<br>• Brute force prevention<br>• Optional IPv6 disabling | • ufw<br>• fail2ban<br>• iptables |
| **System Hardening** | • Secure file permissions<br>• SUID/SGID binary controls<br>• Disabled unnecessary services<br>• Secure shared memory and tmp directories<br>• Kernel hardening parameters | • coreutils<br>• systemd<br>• sysctl |
| **Monitoring & Logging** | • Enhanced system logging<br>• Secure log rotation<br>• Automated security reporting<br>• File integrity monitoring<br>• Comprehensive audit rules | • rsyslog<br>• logrotate<br>• auditd<br>• AIDE<br>• systemd-journald |
| **Malware Protection** | • Rootkit detection<br>• Virus scanning<br>• Scheduled malware scans<br>• Email alerts on detection | • rkhunter<br>• chkrootkit<br>• ClamAV |
| **Policy Compliance** | • CIS Benchmark compliance<br>• Customizable compliance levels<br>• AppArmor mandatory access control<br>• Security auditing | • lynis<br>• apparmor<br>• apparmor-profiles<br>• debsums |
| **Automatic Updates** | • Unattended security updates<br>• Package integrity verification<br>• Customizable update settings | • unattended-upgrades<br>• apt-listchanges<br>• apt-listbugs<br>• debsecan |
| **System Backup** | • Critical system files backup<br>• Configuration files preservation<br>• Automated scheduled backups | • rsync<br>• cron |

## Installation & Usage

### Quick Install (Single Command)

If you're starting with a fresh Debian 12 installation, you can download and run the script with this single command:

```bash
# As root user
curl -sSL https://raw.githubusercontent.com/DigitalXS/FortifyDebian/main/debian12-hardening.sh -o /tmp/debian12-hardening.sh && chmod +x /tmp/debian12-hardening.sh && /tmp/debian12-hardening.sh
```

### Manual Installation

1. Login as root or become root:
   ```bash
   # If not already root
   su -
   ```

2. Install git (if not already installed):
   ```bash
   apt update && apt install -y git
   ```

3. Clone the repository:
   ```bash
   git clone https://github.com/DigitalXS/FortifyDebian.git
   ```

4. Change to the directory:
   ```bash
   cd FortifyDebian
   ```

5. Make the script executable:
   ```bash
   chmod +x debian12-hardening.sh
   ```

6. Run the script:
   ```bash
   ./debian12-hardening.sh
   ```

7. Follow the interactive prompts to customize your security configuration

## Requirements

- Debian 12 (Bookworm) minimal installation
- Root access (not sudo - the script will install sudo if needed)
- Internet connection for package installation

## Detailed Changes

The hardening script makes the following specific changes to your system:

### Authentication & Access Control
- Sets password minimum length to 12 characters with complexity requirements
- Configures password aging (90-day expiration, 7-day warning)
- Restricts su command to sudo group members
- Implements account lockout after 5 failed attempts
- Sets secure umask (027) for all users
- Configures PAM modules for enhanced authentication security
- Sets resource limits through /etc/security/limits.conf
- Sets automatic logout for idle sessions (TMOUT=900)
- Enforces password history (24 passwords remembered)

### SSH Hardening
- Disables SSH root login
- Changes default SSH port (if specified)
- Enforces strong cryptographic settings (ciphers, MACs, key exchange)
- Limits SSH login attempts and sessions
- Configures warning banners for SSH connections
- Optional key-based authentication only (no passwords)
- Disables X11 forwarding and TCP forwarding

### Network Security
- Enables kernel IP spoofing protection
- Configures TCP SYN flood protection
- Disables ICMP redirects and broadcasts
- Disables IP source routing
- Configures UFW firewall with default deny policy
- Sets up fail2ban with aggressive mode for SSH
- Optional IPv6 disabling

### File System Security
- Sets secure permissions on sensitive files (/etc/passwd, /etc/shadow, etc.)
- Secures /boot directory (chmod 700)
- Restricts cron access
- Sets sticky bit on world-writable directories
- Identifies and secures unusual SUID/SGID binaries
- Mounts /tmp, /var/tmp, and /dev/shm with noexec, nosuid, nodev

### System Hardening
- Disables unnecessary system services
- Configures AIDE file integrity monitoring with daily checks
- Sets up comprehensive auditd rules
- Enables and configures AppArmor
- Disables uncommon network protocols
- Disables wireless interfaces
- Configures kernel hardening parameters
- Sets up GRUB bootloader password

### Monitoring & Logging
- Enhances rsyslog configuration for detailed logging
- Configures secure log rotation
- Sets up systemd-journald with persistent logging
- Creates daily security report system
- Configures email alerts for security events

### Malware Protection
- Sets up daily rkhunter scans
- Configures ClamAV with daily system scans
- Sets up daily chkrootkit scans
- Creates quarantine directory for infected files

### Automatic Updates
- Configures unattended-upgrades for security patches
- Sets up automatic system packages updates
- Enables notification for important package changes

### System Backup
- Creates weekly backup of critical system files
- Backs up user configuration files
- Maintains list of installed packages
- Creates file checksums for integrity verification

## Post-Hardening Recommendations

1. Manually review all service configurations
2. Create a complete system backup before making further changes
3. Test all critical applications to ensure they still work properly
4. Consider setting up centralized logging to a secure log server
5. Review the Lynis audit report and address any remaining issues

## License

This project is licensed under the GNU General Public License v3.0 - see the LICENSE file for details.

## Support This Project

If you find FortifyDebian useful, consider supporting its development:

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://buymeacoffee.com/digitalxs)

## Disclaimer

This hardening script makes significant changes to your system configuration. Always test thoroughly in a non-production environment before deploying to production systems.
