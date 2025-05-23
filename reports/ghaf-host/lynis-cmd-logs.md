[ Lynis 3.1.4 ]

################################################################################
  Lynis comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
  welcome to redistribute it under the terms of the GNU General Public License.
  See the LICENSE file for details about using this software.

  2007-2024, CISOfy - https://cisofy.com/lynis/
  Enterprise support available (compliance, plugins, interface and tools)
################################################################################


[+] Initializing program
------------------------------------
  - Detecting OS...                                           [ DONE ]
  - Checking profiles...                                      [ DONE ]

  ---------------------------------------------------
  Program version:           3.1.4
  Operating system:          Linux
  Operating system name:     NixOS
  Operating system version:  25.05
  Kernel version:            6.12.28
  Hardware platform:         x86_64
  Hostname:                  ghaf-host
  ---------------------------------------------------
  Profiles:                  /nix/store/gkjx6mvzfaqch5a72l1jzn2vbzvyx2hk-lynis-3.1.4/share/lynis/default.prf
  Log file:                  /var/log/lynis.log
  Report file:               /var/log/lynis-report.dat
  Report version:            1.0
  Plugin directory:          /nix/store/gkjx6mvzfaqch5a72l1jzn2vbzvyx2hk-lynis-3.1.4/share/lynis/plugins
  ---------------------------------------------------
  Auditor:                   [Not Specified]
  Language:                  en
  Test category:             all
  Test group:                all
  ---------------------------------------------------
  - Program update status...                                  [ NO UPDATE ]

[+] System tools
------------------------------------
  - Scanning available tools...
  - Checking system binaries...

[+] Plugins (phase 1)
------------------------------------
 Note: plugins have more extensive tests and may take several minutes to complete
  
  - Plugins enabled                                           [ NONE ]

[+] Boot and services
------------------------------------
  - Service Manager                                           [ systemd ]
  - Checking UEFI boot                                        [ ENABLED ]
  - Checking Secure Boot                                      [ DISABLED ]
  - Checking systemd-boot presence                            [ FOUND ]
  - Check running services (systemctl)                        [ DONE ]
        Result: found 48 running services
  - Check enabled services at boot (systemctl)                [ DONE ]
        Result: found 69 enabled services
  - Check startup files (permissions)                         [ OK ]
  - Running 'systemd-analyze security'
      Unit name (exposure value) and predicate
      --------------------------------
    - alloy.service (value=2.6)                               [ PROTECTED ]
    - auditd.service (value=9.5)                              [ UNSAFE ]
    - balloon-manager.service (value=9.6)                     [ UNSAFE ]
    - business-vm-swtpm.service (value=9.2)                   [ UNSAFE ]
    - chrome-vm-swtpm.service (value=9.2)                     [ UNSAFE ]
    - dbus.service (value=3.4)                                [ PROTECTED ]
    - emergency.service (value=9.5)                           [ UNSAFE ]
    - enable-ksm.service (value=0.7)                          [ PROTECTED ]
    - getty@tty1.service (value=9.6)                          [ UNSAFE ]
    - ghaf-mem-manager-business-vm.service (value=9.6)        [ UNSAFE ]
    - ghaf-mem-manager-chrome-vm.service (value=9.6)          [ UNSAFE ]
    - ghaf-mem-manager-comms-vm.service (value=9.6)           [ UNSAFE ]
    - ghaf-mem-manager-gala-vm.service (value=9.6)            [ UNSAFE ]
    - ghaf-mem-manager-zathura-vm.service (value=9.6)         [ UNSAFE ]
    - givc-ghaf-host.service (value=9.6)                      [ UNSAFE ]
    - givc-key-setup.service (value=9.8)                      [ UNSAFE ]
    - microvm-virtiofsd@admin-vm.service (value=4.3)          [ PROTECTED ]
    - microvm-virtiofsd@audio-vm.service (value=4.3)          [ PROTECTED ]
    - microvm-virtiofsd@business-vm.service (value=4.3)       [ PROTECTED ]
    - microvm-virtiofsd@chrome-vm.service (value=4.3)         [ PROTECTED ]
    - microvm-virtiofsd@comms-vm.service (value=4.3)          [ PROTECTED ]
    - microvm-virtiofsd@gala-vm.service (value=4.3)           [ PROTECTED ]
    - microvm-virtiofsd@gui-vm.service (value=4.3)            [ PROTECTED ]
    - microvm-virtiofsd@net-vm.service (value=4.3)            [ PROTECTED ]
    - microvm-virtiofsd@zathura-vm.service (value=4.3)        [ PROTECTED ]
    - microvm@admin-vm.service (value=4.2)                    [ PROTECTED ]
    - microvm@audio-vm.service (value=4.2)                    [ PROTECTED ]
    - microvm@business-vm.service (value=4.2)                 [ PROTECTED ]
    - microvm@chrome-vm.service (value=4.2)                   [ PROTECTED ]
    - microvm@comms-vm.service (value=4.2)                    [ PROTECTED ]
    - microvm@gala-vm.service (value=4.2)                     [ PROTECTED ]
    - microvm@gui-vm.service (value=4.2)                      [ PROTECTED ]
    - microvm@net-vm.service (value=4.2)                      [ PROTECTED ]
    - microvm@zathura-vm.service (value=4.2)                  [ PROTECTED ]
    - nix-daemon.service (value=9.6)                          [ UNSAFE ]
    - nscd.service (value=0.7)                                [ PROTECTED ]
    - reload-systemd-vconsole-setup.service (value=9.6)       [ UNSAFE ]
    - rescue.service (value=9.5)                              [ UNSAFE ]
    - sshd.service (value=9.6)                                [ UNSAFE ]
    - systemd-ask-password-console.service (value=9.4)        [ UNSAFE ]
    - systemd-ask-password-wall.service (value=9.4)           [ UNSAFE ]
    - systemd-journald.service (value=4.9)                    [ PROTECTED ]
    - systemd-logind.service (value=2.8)                      [ PROTECTED ]
    - systemd-networkd.service (value=2.9)                    [ PROTECTED ]
    - systemd-oomd.service (value=1.8)                        [ PROTECTED ]
    - systemd-resolved.service (value=2.2)                    [ PROTECTED ]
    - systemd-rfkill.service (value=0.2)                      [ PROTECTED ]
    - systemd-timesyncd.service (value=2.1)                   [ PROTECTED ]
    - systemd-udevd.service (value=4.8)                       [ PROTECTED ]
    - tpm2-abrmd.service (value=4.6)                          [ PROTECTED ]
    - user@1001.service (value=9.4)                           [ UNSAFE ]
    - vhotplug.service (value=9.6)                            [ UNSAFE ]
    - vinotify.service (value=9.6)                            [ UNSAFE ]
    - vsockproxy-business-vm.service (value=9.6)              [ UNSAFE ]
    - vsockproxy-chrome-vm.service (value=9.6)                [ UNSAFE ]
    - vsockproxy-comms-vm.service (value=9.6)                 [ UNSAFE ]
    - vsockproxy-gala-vm.service (value=9.6)                  [ UNSAFE ]
    - vsockproxy-zathura-vm.service (value=9.6)               [ UNSAFE ]

[+] Kernel
------------------------------------
  - Checking default runlevel                                 [ runlevel 3 ]
  - Checking CPU support (NX/PAE)
    CPU support: PAE and/or NoeXecute supported               [ FOUND ]
  - Checking kernel version and release                       [ DONE ]
  - Checking kernel type                                      [ DONE ]
  - Checking loaded kernel modules                            [ DONE ]
      Found 228 active modules
  - Checking Linux kernel configuration file                  [ FOUND ]
  - Checking default I/O kernel scheduler                     [ NOT FOUND ]
  - Checking core dumps configuration
    - configuration in systemd conf files                     [ DEFAULT ]
    - configuration in /etc/profile                           [ DEFAULT ]
    - Checking setuid core dumps configuration                [ PROTECTED ]

=================================================================

  Exception found!

  Function/test:  [KRNL-5830:2]
  Message:        Can not find any vmlinuz or kernel files in /boot, which is unexpected

  Help improving the Lynis community with your feedback!

  Steps:
  - Ensure you are running the latest version (/nix/store/gkjx6mvzfaqch5a72l1jzn2vbzvyx2hk-lynis-3.1.4/bin/.lynis-wrapped update check)
  - If so, create a GitHub issue at https://github.com/CISOfy/lynis
  - Include relevant parts of the log file or configuration file

  Thanks!

=================================================================

  - Check if reboot is needed                                 [ UNKNOWN ]

[+] Memory and Processes
------------------------------------
  - Checking /proc/meminfo                                    [ FOUND ]
ps: bad x
  - Searching for dead/zombie processes                       [ NOT FOUND ]
ps: bad x
  - Searching for IO waiting processes                        [ NOT FOUND ]

[+] Users, Groups and Authentication
------------------------------------
  - Administrator accounts                                    [ OK ]
  - Unique UIDs                                               [ OK ]
  - Consistency of group files (grpck)                        [ OK ]
  - Unique group IDs                                          [ OK ]
  - Unique group names                                        [ OK ]
  - Password hashing methods                                  [ OK ]
  - Checking password hashing rounds                          [ DISABLED ]
  - Query system users (non daemons)                          [ DONE ]
  - NIS+ authentication support                               [ NOT ENABLED ]
  - NIS authentication support                                [ NOT ENABLED ]
  - Sudoers file(s)                                           [ FOUND ]
    - Permissions for: /etc/sudoers                           [ OK ]
  - PAM password strength tools                               [ SUGGESTION ]
  - PAM configuration file (pam.conf)                         [ NOT FOUND ]
  - PAM configuration files (pam.d)                           [ FOUND ]
  - PAM modules                                               [ NOT FOUND ]
  - LDAP module in PAM                                        [ NOT FOUND ]
  - Accounts without expire date                              [ OK ]
  - Accounts without password                                 [ OK ]
  - Locked accounts                                           [ FOUND ]
  - Checking user password aging (minimum)                    [ DISABLED ]
  - User password aging (maximum)                             [ DISABLED ]
  - Checking expired passwords                                [ OK ]
  - Determining default umask
    - umask (/etc/profile)                                    [ NOT FOUND ]
    - umask (/etc/login.defs)                                 [ OK ]
  - LDAP authentication support                               [ NOT ENABLED ]
  - Logging failed login attempts                             [ DISABLED ]

[+] Kerberos
------------------------------------
  - Check for Kerberos KDC and principals                     [ NOT FOUND ]

[+] Shells
------------------------------------
  - Checking shells from /etc/shells
    Result: found 5 shells (valid shells: 5).
    - Session timeout settings/tools                          [ NONE ]
  - Checking default umask values
    - Checking default umask in /etc/bashrc                   [ NONE ]
    - Checking default umask in /etc/profile                  [ NONE ]

[+] File systems
------------------------------------
  - Checking mount points
    - Checking /home mount point                              [ SUGGESTION ]
    - Checking /tmp mount point                               [ SUGGESTION ]
    - Checking /var mount point                               [ SUGGESTION ]
  - Query swap partitions (fstab)                             [ OK ]
  - Testing swap partitions                                   [ OK ]
  - Testing /proc mount (hidepid)                             [ SUGGESTION ]
  - Checking for old files in /tmp                            [ OK ]
  - Checking /tmp sticky bit                                  [ OK ]
  - Checking /var/tmp sticky bit                              [ OK ]
  - ACL support root file system                              [ ENABLED ]
  - Mount options of /                                        [ NON DEFAULT ]
  - Mount options of /boot                                    [ NON DEFAULT ]
  - Mount options of /dev                                     [ PARTIALLY HARDENED ]
  - Mount options of /dev/shm                                 [ PARTIALLY HARDENED ]
  - Mount options of /run                                     [ HARDENED ]
  - Total without nodev:9 noexec:14 nosuid:8 ro or noexec (W^X): 10 of total 31
  - Disable kernel support of some filesystems

[+] USB Devices
------------------------------------
  - Checking usb-storage driver (modprobe config)             [ NOT DISABLED ]
  - Checking USB devices authorization                        [ ENABLED ]
  - Checking USBGuard                                         [ NOT FOUND ]

[+] Storage
------------------------------------
  - Checking firewire ohci driver (modprobe config)           [ DISABLED ]

[+] NFS
------------------------------------
ps: bad ax
  - Check running NFS daemon                                  [ NOT FOUND ]

[+] Name services
------------------------------------
  - Checking search domains                                   [ FOUND ]
  - Checking /etc/resolv.conf options                         [ FOUND ]
  - Searching DNS domain name                                 [ UNKNOWN ]
  - Checking /etc/hosts
    - Duplicate entries in hosts file                         [ NONE ]
    - Presence of configured hostname in /etc/hosts           [ FOUND ]
    - Hostname mapped to localhost                            [ NOT FOUND ]
    - Localhost mapping to IP address                         [ OK ]

[+] Ports and packages
------------------------------------
  - Searching package managers
  - Checking package audit tool                               [ NONE ]

[+] Networking
------------------------------------
  - Checking IPv6 configuration                               [ ENABLED ]
      Configuration method                                    [ AUTO ]
      IPv6 only                                               [ NO ]
  - Checking configured nameservers
    - Testing nameservers
        Nameserver: 127.0.0.53                                [ OK ]
    - DNSSEC supported (systemd-resolved)                     [ UNKNOWN ]
  - Checking default gateway                                  [ DONE ]
  - Getting listening ports (TCP/UDP)                         [ DONE ]
  - Checking promiscuous interfaces                           [ WARNING ]
  - Checking waiting connections                              [ OK ]
  - Checking status DHCP client                               [ NOT ACTIVE ]
  - Checking for ARP monitoring software                      [ NOT FOUND ]
  - Uncommon network protocols                                [ 0 ]

[+] Printers and Spools
------------------------------------
  - Checking cups daemon                                      [ NOT FOUND ]
  - Checking lp daemon                                        [ NOT RUNNING ]

[+] Software: e-mail and messaging
------------------------------------
ps: bad ax

[+] Software: firewalls
------------------------------------
  - Checking iptables kernel module                           [ NOT FOUND ]
  - Checking host based firewall                              [ NOT ACTIVE ]

[+] Software: webserver
------------------------------------

  - Checking Apache (binary /run/current-system/sw/bin/httpd)  [ NO MATCH ]

  [WARNING]: Test HTTP-6622 had a long execution: 27.034852 seconds

  - Checking nginx                                            [ NOT FOUND ]

[+] SSH Support
------------------------------------
  - Checking running SSH daemon                               [ FOUND ]
    - Searching SSH configuration                             [ FOUND ]
    - OpenSSH option: AllowTcpForwarding                      [ SUGGESTION ]
    - OpenSSH option: ClientAliveCountMax                     [ SUGGESTION ]
    - OpenSSH option: ClientAliveInterval                     [ OK ]
    - OpenSSH option: FingerprintHash                         [ OK ]
    - OpenSSH option: GatewayPorts                            [ OK ]
    - OpenSSH option: IgnoreRhosts                            [ OK ]
    - OpenSSH option: LoginGraceTime                          [ OK ]
    - OpenSSH option: LogLevel                                [ SUGGESTION ]
    - OpenSSH option: MaxAuthTries                            [ SUGGESTION ]
    - OpenSSH option: MaxSessions                             [ SUGGESTION ]
    - OpenSSH option: PermitRootLogin                         [ OK ]
    - OpenSSH option: PermitUserEnvironment                   [ OK ]
    - OpenSSH option: PermitTunnel                            [ OK ]
    - OpenSSH option: Port                                    [ SUGGESTION ]
    - OpenSSH option: PrintLastLog                            [ OK ]
    - OpenSSH option: StrictModes                             [ OK ]
    - OpenSSH option: TCPKeepAlive                            [ SUGGESTION ]
    - OpenSSH option: UseDNS                                  [ OK ]
    - OpenSSH option: X11Forwarding                           [ OK ]
    - OpenSSH option: AllowAgentForwarding                    [ SUGGESTION ]
    - OpenSSH option: AllowUsers                              [ NOT FOUND ]
    - OpenSSH option: AllowGroups                             [ NOT FOUND ]

[+] SNMP Support
------------------------------------
  - Checking running SNMP daemon                              [ NOT FOUND ]

[+] Databases
------------------------------------
ps: bad ax
ps: bad ax
    No database engines found

[+] LDAP Services
------------------------------------
  - Checking OpenLDAP instance                                [ NOT FOUND ]

[+] PHP
------------------------------------
  - Checking PHP                                              [ NOT FOUND ]

[+] Squid Support
------------------------------------
ps: bad ax
  - Checking running Squid daemon                             [ NOT FOUND ]

[+] Logging and files
------------------------------------
ps: bad ax
  - Checking for a running log daemon                         [ WARNING ]
    - Checking Syslog-NG status                               [ NOT FOUND ]
    - Checking systemd journal status                         [ FOUND ]
    - Checking Metalog status                                 [ NOT FOUND ]
    - Checking RSyslog status                                 [ NOT FOUND ]
    - Checking RFC 3195 daemon status                         [ NOT FOUND ]
    - Checking minilogd instances                             [ NOT FOUND ]
    - Checking wazuh-agent daemon status                      [ NOT FOUND ]
  - Checking logrotate presence                               [ WARNING ]
  - Checking log directories (static list)                    [ DONE ]
  - Checking open log files                                   [ SKIPPED ]

[+] Insecure services
------------------------------------
    - xinetd status                                           [ NOT ACTIVE ]

[+] Banners and identification
------------------------------------
  - /etc/issue                                                [ SYMLINK ]
    - /etc/issue contents                                     [ WEAK ]
  - /etc/issue.net                                            [ NOT FOUND ]

[+] Scheduled tasks
------------------------------------
ps: bad aux
  - Checking crontab and cronjob files                        [ DONE ]
ps: bad ax

[+] Accounting
------------------------------------
  - Checking accounting information                           [ NOT FOUND ]
  - Checking sysstat accounting data                          [ NOT FOUND ]
  - Checking auditd                                           [ ENABLED ]
    - Checking audit rules                                    [ OK ]
    - Checking audit configuration file                       [ FOUND ]

[+] Time and Synchronization
------------------------------------
ps: bad ax
ps: bad ax
  - Checking for a running NTP daemon or client               [ WARNING ]

[+] Cryptography
------------------------------------
  - Kernel entropy is sufficient                              [ YES ]
  - HW RNG & rngd                                             [ NO ]
  - SW prng                                                   [ NO ]
od: Unknown option 'skip-bytes=4' (see "od --help")
  MOR-bit set                                                 [ UNKNOWN ]

[+] Virtualization
------------------------------------

[+] Containers
------------------------------------

[+] Security frameworks
------------------------------------
  - Checking presence AppArmor                                [ NOT FOUND ]
  - Checking presence SELinux                                 [ NOT FOUND ]
  - Checking presence TOMOYO Linux                            [ NOT FOUND ]
  - Checking presence grsecurity                              [ NOT FOUND ]
  - Checking for implemented MAC framework                    [ NONE ]

[+] Software: file integrity
------------------------------------
  - Checking file integrity tools
  - Checking presence integrity tool                          [ NOT FOUND ]

[+] Software: System tooling
------------------------------------
  - Checking automation tooling
  - Automation tooling                                        [ NOT FOUND ]
  - Checking for IDS/IPS tooling                              [ NONE ]

[+] Software: Malware
------------------------------------
  - Malware software components                               [ NOT FOUND ]

[+] File Permissions
------------------------------------
  - Starting file permissions check
    File: /etc/group                                          [ OK ]
    File: /etc/issue                                          [ OK ]
    File: /etc/passwd                                         [ OK ]
    File: /etc/ssh/sshd_config                                [ OK ]
    Directory: /root/.ssh                                     [ OK ]

[+] Home directories
------------------------------------
  - Permissions of home directories                           [ WARNING ]
  - Ownership of home directories                             [ WARNING ]
  - Checking shell history files                              [ OK ]

[+] Kernel Hardening
------------------------------------
  - Comparing sysctl key pairs with scan profile
    - dev.tty.ldisc_autoload (exp: 0)                         [ DIFFERENT ]
    - fs.protected_fifos (exp: 2)                             [ DIFFERENT ]
    - fs.protected_hardlinks (exp: 1)                         [ OK ]
    - fs.protected_regular (exp: 2)                           [ DIFFERENT ]
    - fs.protected_symlinks (exp: 1)                          [ OK ]
    - fs.suid_dumpable (exp: 0)                               [ DIFFERENT ]
    - kernel.core_uses_pid (exp: 1)                           [ OK ]
    - kernel.ctrl-alt-del (exp: 0)                            [ OK ]
    - kernel.dmesg_restrict (exp: 1)                          [ OK ]
    - kernel.kptr_restrict (exp: 2)                           [ DIFFERENT ]
    - kernel.modules_disabled (exp: 1)                        [ DIFFERENT ]
    - kernel.perf_event_paranoid (exp: 2 3 4)                 [ OK ]
    - kernel.randomize_va_space (exp: 2)                      [ OK ]
    - kernel.sysrq (exp: 0)                                   [ DIFFERENT ]
    - kernel.unprivileged_bpf_disabled (exp: 1)               [ DIFFERENT ]
    - kernel.yama.ptrace_scope (exp: 1 2 3)                   [ OK ]
    - net.core.bpf_jit_harden (exp: 2)                        [ DIFFERENT ]
    - net.ipv4.conf.all.accept_redirects (exp: 0)             [ DIFFERENT ]
    - net.ipv4.conf.all.accept_source_route (exp: 0)          [ OK ]
    - net.ipv4.conf.all.bootp_relay (exp: 0)                  [ OK ]
    - net.ipv4.conf.all.forwarding (exp: 0)                   [ OK ]
    - net.ipv4.conf.all.log_martians (exp: 1)                 [ DIFFERENT ]
    - net.ipv4.conf.all.mc_forwarding (exp: 0)                [ OK ]
    - net.ipv4.conf.all.proxy_arp (exp: 0)                    [ OK ]
    - net.ipv4.conf.all.rp_filter (exp: 1)                    [ DIFFERENT ]
    - net.ipv4.conf.all.send_redirects (exp: 0)               [ DIFFERENT ]
    - net.ipv4.conf.default.accept_redirects (exp: 0)         [ DIFFERENT ]
    - net.ipv4.conf.default.accept_source_route (exp: 0)      [ OK ]
    - net.ipv4.conf.default.log_martians (exp: 1)             [ DIFFERENT ]
    - net.ipv4.icmp_echo_ignore_broadcasts (exp: 1)           [ OK ]
    - net.ipv4.icmp_ignore_bogus_error_responses (exp: 1)     [ OK ]
    - net.ipv4.tcp_syncookies (exp: 1)                        [ OK ]
    - net.ipv4.tcp_timestamps (exp: 0 1)                      [ OK ]
    - net.ipv6.conf.all.accept_redirects (exp: 0)             [ DIFFERENT ]
    - net.ipv6.conf.all.accept_source_route (exp: 0)          [ OK ]
    - net.ipv6.conf.default.accept_redirects (exp: 0)         [ DIFFERENT ]
    - net.ipv6.conf.default.accept_source_route (exp: 0)      [ OK ]

[+] Hardening
------------------------------------
    - Installed compiler(s)                                   [ NOT FOUND ]
    - Installed malware scanner                               [ NOT FOUND ]
    - Non-native binary formats                               [ NOT FOUND ]

[+] Custom tests
------------------------------------
  - Running custom tests...                                   [ NONE ]

[+] Plugins (phase 2)
------------------------------------

================================================================================

  -[ Lynis 3.1.4 Results ]-

  Warnings (9):
  ----------------------------
  ! Found promiscuous interface [NETW-3015] 
    - Details  : tap-audio-vm
    - Solution : Determine if this mode is required or whitelist interface in profile
      https://cisofy.com/lynis/controls/NETW-3015/

  ! Found promiscuous interface [NETW-3015] 
    - Details  : tap-admin-vm
    - Solution : Determine if this mode is required or whitelist interface in profile
      https://cisofy.com/lynis/controls/NETW-3015/

  ! Found promiscuous interface [NETW-3015] 
    - Details  : tap-gui-vm
    - Solution : Determine if this mode is required or whitelist interface in profile
      https://cisofy.com/lynis/controls/NETW-3015/

  ! Found promiscuous interface [NETW-3015] 
    - Details  : tap-comms-vm
    - Solution : Determine if this mode is required or whitelist interface in profile
      https://cisofy.com/lynis/controls/NETW-3015/

  ! Found promiscuous interface [NETW-3015] 
    - Details  : tap-business-vm
    - Solution : Determine if this mode is required or whitelist interface in profile
      https://cisofy.com/lynis/controls/NETW-3015/

  ! Found promiscuous interface [NETW-3015] 
    - Details  : tap-gala-vm
    - Solution : Determine if this mode is required or whitelist interface in profile
      https://cisofy.com/lynis/controls/NETW-3015/

  ! Found promiscuous interface [NETW-3015] 
    - Details  : tap-chrome-vm
    - Solution : Determine if this mode is required or whitelist interface in profile
      https://cisofy.com/lynis/controls/NETW-3015/

  ! Found promiscuous interface [NETW-3015] 
    - Details  : tap-net-vm
    - Solution : Determine if this mode is required or whitelist interface in profile
      https://cisofy.com/lynis/controls/NETW-3015/

  ! Found promiscuous interface [NETW-3015] 
    - Details  : tap-zathura-vm
    - Solution : Determine if this mode is required or whitelist interface in profile
      https://cisofy.com/lynis/controls/NETW-3015/

  Suggestions (38):
  ----------------------------
  * Consider hardening system services [BOOT-5264] 
    - Details  : Run '/run/current-system/sw/bin/systemd-analyze security SERVICE' for each service
    - Related resources
      * Article: Systemd features to secure service files: https://linux-audit.com/systemd/systemd-features-to-secure-units-and-services/
      * Website: https://cisofy.com/lynis/controls/BOOT-5264/

  * Configure password hashing rounds in /etc/login.defs [AUTH-9230] 
    - Related resources
      * Article: Linux password security: hashing rounds: https://linux-audit.com/authentication/configure-the-minimum-password-length-on-linux-systems/
      * Website: https://cisofy.com/lynis/controls/AUTH-9230/

  * Install a PAM module for password strength testing like pam_cracklib or pam_passwdqc or libpam-passwdqc [AUTH-9262] 
    - Related resources
      * Article: Configure minimum password length for Linux systems: https://linux-audit.com/configure-the-minimum-password-length-on-linux-systems/
      * Website: https://cisofy.com/lynis/controls/AUTH-9262/

  * Look at the locked accounts and consider removing them [AUTH-9284] 
    - Related resources
      * Website: https://cisofy.com/lynis/controls/AUTH-9284/

  * Configure minimum password age in /etc/login.defs [AUTH-9286] 
    - Related resources
      * Article: Configure minimum password length for Linux systems: https://linux-audit.com/configure-the-minimum-password-length-on-linux-systems/
      * Website: https://cisofy.com/lynis/controls/AUTH-9286/

  * Configure maximum password age in /etc/login.defs [AUTH-9286] 
    - Related resources
      * Article: Configure minimum password length for Linux systems: https://linux-audit.com/configure-the-minimum-password-length-on-linux-systems/
      * Website: https://cisofy.com/lynis/controls/AUTH-9286/

  * To decrease the impact of a full /home file system, place /home on a separate partition [FILE-6310] 
    - Related resources
      * Website: https://cisofy.com/lynis/controls/FILE-6310/

  * To decrease the impact of a full /tmp file system, place /tmp on a separate partition [FILE-6310] 
    - Related resources
      * Website: https://cisofy.com/lynis/controls/FILE-6310/

  * To decrease the impact of a full /var file system, place /var on a separate partition [FILE-6310] 
    - Related resources
      * Website: https://cisofy.com/lynis/controls/FILE-6310/

  * Disable drivers like USB storage when not used, to prevent unauthorized storage or data theft [USB-1000] 
    - Related resources
      * Website: https://cisofy.com/lynis/controls/USB-1000/

  * Check DNS configuration for the dns domain name [NAME-4028] 
    - Related resources
      * Website: https://cisofy.com/lynis/controls/NAME-4028/

  * Install a package audit tool to determine vulnerable packages [PKGS-7398] 
    - Related resources
      * Website: https://cisofy.com/lynis/controls/PKGS-7398/

  * Determine if protocol 'dccp' is really needed on this system [NETW-3200] 
    - Related resources
      * Website: https://cisofy.com/lynis/controls/NETW-3200/

  * Determine if protocol 'sctp' is really needed on this system [NETW-3200] 
    - Related resources
      * Website: https://cisofy.com/lynis/controls/NETW-3200/

  * Determine if protocol 'rds' is really needed on this system [NETW-3200] 
    - Related resources
      * Website: https://cisofy.com/lynis/controls/NETW-3200/

  * Determine if protocol 'tipc' is really needed on this system [NETW-3200] 
    - Related resources
      * Website: https://cisofy.com/lynis/controls/NETW-3200/

  * Configure a firewall/packet filter to filter incoming and outgoing traffic [FIRE-4590] 
    - Related resources
      * Website: https://cisofy.com/lynis/controls/FIRE-4590/

  * Consider hardening SSH configuration [SSH-7408] 
    - Details  : AllowTcpForwarding (set YES to NO)
    - Related resources
      * Article: OpenSSH security and hardening: https://linux-audit.com/ssh/audit-and-harden-your-ssh-configuration/
      * Website: https://cisofy.com/lynis/controls/SSH-7408/

  * Consider hardening SSH configuration [SSH-7408] 
    - Details  : ClientAliveCountMax (set 3 to 2)
    - Related resources
      * Article: OpenSSH security and hardening: https://linux-audit.com/ssh/audit-and-harden-your-ssh-configuration/
      * Website: https://cisofy.com/lynis/controls/SSH-7408/

  * Consider hardening SSH configuration [SSH-7408] 
    - Details  : LogLevel (set INFO to VERBOSE)
    - Related resources
      * Article: OpenSSH security and hardening: https://linux-audit.com/ssh/audit-and-harden-your-ssh-configuration/
      * Website: https://cisofy.com/lynis/controls/SSH-7408/

  * Consider hardening SSH configuration [SSH-7408] 
    - Details  : MaxAuthTries (set 6 to 3)
    - Related resources
      * Article: OpenSSH security and hardening: https://linux-audit.com/ssh/audit-and-harden-your-ssh-configuration/
      * Website: https://cisofy.com/lynis/controls/SSH-7408/

  * Consider hardening SSH configuration [SSH-7408] 
    - Details  : MaxSessions (set 10 to 2)
    - Related resources
      * Article: OpenSSH security and hardening: https://linux-audit.com/ssh/audit-and-harden-your-ssh-configuration/
      * Website: https://cisofy.com/lynis/controls/SSH-7408/

  * Consider hardening SSH configuration [SSH-7408] 
    - Details  : Port (set 22 to )
    - Related resources
      * Article: OpenSSH security and hardening: https://linux-audit.com/ssh/audit-and-harden-your-ssh-configuration/
      * Website: https://cisofy.com/lynis/controls/SSH-7408/

  * Consider hardening SSH configuration [SSH-7408] 
    - Details  : TCPKeepAlive (set YES to NO)
    - Related resources
      * Article: OpenSSH security and hardening: https://linux-audit.com/ssh/audit-and-harden-your-ssh-configuration/
      * Website: https://cisofy.com/lynis/controls/SSH-7408/

  * Consider hardening SSH configuration [SSH-7408] 
    - Details  : AllowAgentForwarding (set YES to NO)
    - Related resources
      * Article: OpenSSH security and hardening: https://linux-audit.com/ssh/audit-and-harden-your-ssh-configuration/
      * Website: https://cisofy.com/lynis/controls/SSH-7408/

  * Check if any syslog daemon is running and correctly configured. [LOGG-2130] 
    - Related resources
      * Website: https://cisofy.com/lynis/controls/LOGG-2130/

  * Check if log files are properly rotated [LOGG-2146] 
    - Related resources
      * Website: https://cisofy.com/lynis/controls/LOGG-2146/

  * Add a legal banner to /etc/issue, to warn unauthorized users [BANN-7126] 
    - Related resources
      * Article: The real purpose of login banners: https://linux-audit.com/the-real-purpose-of-login-banners-on-linux/
      * Website: https://cisofy.com/lynis/controls/BANN-7126/

  * Enable process accounting [ACCT-9622] 
    - Related resources
      * Website: https://cisofy.com/lynis/controls/ACCT-9622/

  * Enable sysstat to collect accounting (no results) [ACCT-9626] 
    - Related resources
      * Website: https://cisofy.com/lynis/controls/ACCT-9626/

  * Determine the location of auditd configuration file [ACCT-9632] 
    - Related resources
      * Website: https://cisofy.com/lynis/controls/ACCT-9632/

  * Use NTP daemon or NTP client to prevent time issues. [TIME-3104] 
    - Related resources
      * Website: https://cisofy.com/lynis/controls/TIME-3104/

  * Install a file integrity tool to monitor changes to critical and sensitive files [FINT-4350] 
    - Related resources
      * Article: Monitoring Linux file access, changes and data modifications: https://linux-audit.com/monitoring-linux-file-access-changes-and-modifications/
      * Article: Monitor for file changes on Linux: https://linux-audit.com/monitor-for-file-system-changes-on-linux/
      * Website: https://cisofy.com/lynis/controls/FINT-4350/

  * Determine if automation tools are present for system management [TOOL-5002] 
    - Related resources
      * Website: https://cisofy.com/lynis/controls/TOOL-5002/

  * Double check the permissions of home directories as some might be not strict enough. [HOME-9304] 
    - Related resources
      * Website: https://cisofy.com/lynis/controls/HOME-9304/

  * Double check the ownership of home directories as some might be incorrect. [HOME-9306] 
    - Related resources
      * Website: https://cisofy.com/lynis/controls/HOME-9306/

  * One or more sysctl values differ from the scan profile and could be tweaked [KRNL-6000] 
    - Solution : Change sysctl value or disable test (skip-test=KRNL-6000:<sysctl-key>)
    - Related resources
      * Article: Linux hardening with sysctl settings: https://linux-audit.com/linux-hardening-with-sysctl/
      * Article: Overview of sysctl options and values: https://linux-audit.com/kernel/sysctl/
      * Website: https://cisofy.com/lynis/controls/KRNL-6000/

  * Harden the system by installing at least one malware scanner, to perform periodic file system scans [HRDN-7230] 
    - Solution : Install a tool like rkhunter, chkrootkit, OSSEC, Wazuh
    - Related resources
      * Article: Antivirus for Linux: is it really needed?: https://linux-audit.com/malware/antivirus-for-linux-really-needed/
      * Article: Monitoring Linux Systems for Rootkits: https://linux-audit.com/monitoring-linux-systems-for-rootkits/
      * Website: https://cisofy.com/lynis/controls/HRDN-7230/

  Follow-up:
  ----------------------------
  - Show details of a test (lynis show details TEST-ID)
  - Check the logfile for all details (less /var/log/lynis.log)
  - Read security controls texts (https://cisofy.com)
  - Use --upload to upload data to central system (Lynis Enterprise users)

================================================================================

  Lynis security scan details:

  Hardening index : 61 [############        ]
  Tests performed : 217
  Plugins enabled : 0

  Components:
  - Firewall               [X]
  - Malware scanner        [X]

  Scan mode:
  Normal [V]  Forensics [ ]  Integration [ ]  Pentest [ ]

  Lynis modules:
  - Compliance status      [?]
  - Security audit         [V]
  - Vulnerability scan     [V]

  Files:
  - Test and debug information      : /var/log/lynis.log
  - Report data                     : /var/log/lynis-report.dat

================================================================================

  Exceptions found
  Some exceptional events or information was found!

  What to do:
  You can help by providing your log file (/var/log/lynis.log).
  Go to https://cisofy.com/contact/ and send your file to the e-mail address listed

================================================================================

  Lynis 3.1.4

  Auditing, system hardening, and compliance for UNIX-based systems
  (Linux, macOS, BSD, and others)

  2007-2024, CISOfy - https://cisofy.com/lynis/
  Enterprise support available (compliance, plugins, interface and tools)

================================================================================

  [TIP]: Enhance Lynis audits by adding your settings to custom.prf (see /nix/store/gkjx6mvzfaqch5a72l1jzn2vbzvyx2hk-lynis-3.1.4/share/lynis/default.prf for all settings)

