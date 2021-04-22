# "Secure" Ubuntu Server
## <strong>Please read [README.md](https://github.com/connergdavis/secure-ubuntu-server/blob/master/index.md) before proceeding.</strong>
## References
### Security Benchmarks
- [CIS Ubuntu 20.04 (cisecurity.org)](https://learn.cisecurity.org/l/799323/2021-04-01/41hcb)

### Security Guides
- [Guide to the Secure Configuration of Red Hat Enterprise Linux 5 (nsa.gov)](https://apps.nsa.gov/iaarchive/customcf/openAttachment.cfm?FilePath=/iad/library/ia-guidance/security-configuration/operating-systems/assets/public/upload/Guide-to-the-Secure-Configuration-of-Red-Hat-Enterprise-Linux-5.pdf&WpKes=aF6woL7fQp3dJiJBWAw3WMetdZYXycAJW5SRcb)
- [imthenachoman/How-To-Secure-A-Linux-Server (github.com)](https://github.com/imthenachoman/How-To-Secure-A-Linux-Server)
- [Linux workstation security checklist (github.com)](https://github.com/lfit/itpol/blob/master/linux-workstation-security.md)
- [Securing Debian Manual (debian.org)](https://www.debian.org/doc/manuals/securing-debian-manual/index.en.html)
- [Security - Arch Linux Wiki (archlinux.org)](https://wiki.archlinux.org/index.php/Security)
- [Security hardening Red Hat Enterprise Linux (redhat.com)](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/index)

### In Chapter 2: SSH
- [Security Guidelines: OpenSSH (mozilla.org)](https://infosec.mozilla.org/guidelines/openssh.html)
- [OpenSSH Security (openssh.com)](https://www.openssh.com/security.html)

### In Chapter 3: Firewall
- [How To Set Up a Firewall with UFW on Ubuntu 18.04 (digitalocean.com)](https://www.digitalocean.com/community/tutorials/how-to-set-up-a-firewall-with-ufw-on-ubuntu-18-04) (note: no differences on Ubuntu 20)
- [Security - Firewall (ubuntu.com)](https://ubuntu.com/server/docs/security-firewall)

### In Chapter 4: NTP
- [What is NTP? (ntp.org)](http://www.ntp.org/ntpfaq/NTP-s-def.htm)

### In Chapter 5: File systems
- [Restricting Access to Process Directories (redhat.com)](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/5/html/deployment_guide/ch-proc#s2-Restricting_Access_to_Process_Directories)

### In Chapter 7: Reports
- [What is a rootkit, and how to stop them (norton.com)](https://us.norton.com/internetsecurity-malware-what-is-a-rootkit-and-how-to-stop-them.html)

#### In Section 7.2: ClamAV
- [Installation on Debian and Ubuntu Linux Distributions (clamav.net)](https://www.clamav.net/documents/installation-on-debian-and-ubuntu-linux-distributions)

#### In Section 7.6: AIDE
- [The AIDE Manual (aide.github.io)](https://aide.github.io/doc/#config)

### In Chapter 8: Kernel `sysctl`
- [`sysctl` - Arch Linux Wiki (archlinux.org)](https://wiki.archlinux.org/index.php/Sysctl#TCP/IP_stack_hardening)

### In Chapter 9: Sandboxes
- [`man firejail` (firejail.wordpress.com)](https://firejail.wordpress.com/features-3/man-firejail/)
- [Building Custom Profiles (firejail.wordpress.com)](https://firejail.wordpress.com/documentation-2/building-custom-profiles/)

<hr />

## Table of Contents
### Chapter 0: [Beginning](#chapter-0-beginning-1)
Create a `sudo` user so root account can be disabled.

  - 0.0 [SSH to root account](#00-ssh-to-root-account)
  - 0.1 [Update Ubuntu](#01-update-ubuntu)
  - 0.2 [Create secure password](#02-create-secure-password)
  - 0.3 [Create `sudo` user](#03-create-sudo-user)
  - 0.4 [Limit `su` command](#04-limit-su-command)

### Chapter 1: [Local SSH](#chapter-1-local-ssh-1)
Create SSH key login for local machine.

  - 1.0 [Generate SSH key](#10-generate-ssh-key)
  - 1.1 [Set safer permissions](#11-set-safer-permissions)
  - 1.2 [Create alias](#12-create-alias)
  - 1.3 [Copy public key](#13-copy-public-key)
  - 1.4 [Authorize public key](#14-authorize-public-key)
  - 1.5 [Login with SSH key](#15-login-with-ssh-key)

### Chapter 2: [SSH](#chapter-2-ssh-1)
Tweak `sshd`'s configuration to provide much better security.

  - 2.0 [Disable root user](#20-disable-root-user)
  - 2.1 [Create SSH group](#21-create-ssh-group)
  - 2.2 [Secure `sshd`](#22-secure-sshd)
  - 2.3 [Check for errors in `/etc/ssh/sshd_config`](#23-check-for-errors-in-etcsshd_config)
  - 2.4 [Only use long Diffie-Hellman moduli](#24-only-use-long-diffie-hellman-moduli)

### Chapter 3: [Firewall](#chapter-3-firewall-1)
Use `ufw` to block all traffic by default, then explicitly allow certain services.

  - 3.0 [Block everything by default](#30-block-everything-by-default)
  - 3.1 [Allow services out: DNS, FTP, HTTP(S), NTP, `exim4`](#31-allow-services-out-dns-ftp-https-ntp-exim4)
  - 3.2 [Allow services in: SSH](#32-allow-services-in-ssh)
  - 3.3 [Enable UFW](#33-enable-ufw)

### Chapter 4: [NTP](#chapter-4-ntp-1)
Synchronize system time with the internet via Network Time Protocol.

*Note: NTP requires an open port specified in [Chapter 3: Firewall](#chapter-3-firewall).*

  - 4.0 [Edit NTP configuration](#40-edit-ntp-configuration)
  - 4.1 [Restart service](#41-restart-service)

### Chapter 5: [File systems](#chapter-6-file-systems-1)
Hide process ID file descriptors in `/proc`, and set stricter default file and folder permissions.

  - 5.0 [Hide process files in `/proc`](#50-hide-process-files-in-proc)
  - 5.1 [Set default permissions](#51-set-default-permissions)

### Chapter 6: [Email](#chapter-5-email-1)
Allow the server to send email logs securely to Gmail.

*Note: Email requires an open port specified in [Chapter 3: Firewall](#chapter-3-firewall).*

  - 6.0 [Install mail server (`exim4`)](#60-install-mail-server-exim4)
  - 6.1 [Configure `exim4`](#61-configure-exim4)
  - 6.2 [Create Gmail login](#62-create-gmail-login)
  - 6.3 [Protect Gmail login](#63-protect-gmail-login)
  - 6.4 [Generate login certificate](#64-generate-login-certificate)
  - 6.5 [Login to Gmail](#65-login-to-gmail)
  - 6.6 [Edit `/etc/aliases`](#66-edit-etcaliases)
  - 6.7 [Restart `exim4`](#67-restart-exim4)
  - 6.8 [Send test email](#68-send-test-email)

### Chapter 7: [Reports](#chapter-7-reports-1)
Run scans for viruses, monitor intrusions, and more. Email results in human-readable format ondemand and daily.

  - 7.0 [Daily reports about everything (`logwatch`)](#70-daily-reports-about-everything-logwatch)
  - 7.1 [Automatic updates (`unattended-upgrades`)](#71-automatic-updates-unattended-upgrades)
    - 7.1.0 [Install `unattended-upgrades`](#710-install-unattended-upgrades)
    - 7.1.1 [Edit `/etc/apt/apt.conf.d/51myunattended-upgrades`](#711-edit-etcaptaptconfd51myunattended-upgrades)
  - 7.2 [Antivirus (`clamav`)](#72-antivirus-clamav)
  - 7.3 [Rootkit detection (`rkhunter`, `chkrootkit`)](#73-rootkit-detection-rkhunter-chkrootkit)
    - 7.3.0 [Install packages](#730-install-packages)
    - 7.3.1 [Enable cron scripts](#731-enable-cron-scripts)
    - 7.3.2 [Edit `/etc/rkhunter.conf`](#732-edit-etcrkhunterconf)
    - 7.3.3 [Update `rkhunter`](#733-update-rkhunter)
  - 7.4 [Host intrusion detection (`ossec`)](#74-host-intrusion-detection-ossec)
    - 7.4.0 [Prepare to build from source](#740-prepare-to-build-from-source)
    - 7.4.1 [Install `ossec`](#741-install-ossec)
  - 7.5 [App intrusion detection (`fail2ban`)](#75-app-intrusion-detection-fail2ban)
    - 7.5.0 [Install `fail2ban`](#750-install-fail2ban)
    - 7.5.1 [Edit `/etc/fail2ban/jail.local`](#751-edit-etcfail2banjaillocal)
    - 7.5.2 [Create jails](#752-create-jails)
    - 7.5.3 [Enable `fail2ban`](#753-enable-fail2ban)
    - 7.5.4 [Check jail statuses](#754-check-jail-statuses)
  - 7.6 [File system integrity monitoring (`aide`)](#76-file-system-integrity-monitoring-aide)
    - 7.6.0 [Install `aide`](#760-install-aide)
    - 7.6.1 [Create initial database](#761-create-initial-database)
    - 7.6.2 [Configure daily checks](#762-configure-daily-checks)
  - 7.7 [ARP monitoring (`arpwatch`)](#77-arp-monitoring-arpwatch)

### Chapter 8: [Kernel `sysctl`](#chapter-8-kernel-sysctl-1)
Edit `/etc/sysctl.conf` kernel options to comply with stricter security standards.

  - 8.0 [Edit `/etc/sysctl.conf`](#80-edit-etcsysctlconf) #TODO
  - 8.1 [Test new settings](#81-test-new-settings) #TODO
  - 8.2 [Restart server](#82-restart-server) #TODO

### Chapter 9: [Sandboxes](#chapter-9-sandboxes-1)
Isolate programs in their own virtual machine to limit access to real resources. The guide uses Firejail, but Docker is a great alternative.

  - 9.0 [Install `firejail`](#90-install-firejail)
  - 9.1 [Run programs with `firejail`](#91-run-programs-with-firejail)
  - 9.2 [Create profiles for programs in `firejail`](#92-create-profiles-for-programs-in-firejail) 
  - 9.3 [Run programs with `firejail` and jail options](#93-run-programs-with-firejail-and-jail-options)

### Chapter 10: [Audits](#chapter-10-audits-1)
Check the security of the server by running standardized audit software to report common weaknesses.

  - 10.0 [`lynis`](#100-lynis)

### Chapter 98: [Keep local system safe](#chapter-98-keep-local-system-safe-1)
It's fun to set up a `firejail` for every process and receive daily reports about file system integrity, but none of that matters if the local machine used to connect is breached. The SSH key and sudoer password are essential to the security of the system. Systems used to connect should ideally be just as safe as the server itself.

### Chapter 99: [Optional extras](#chapter-99-optional-extras-1)
There's all sorts of other things to do beyond the scope of this guide. It's just a starting point. Some feature may provide more security at the cost of being too inconvenient. For example, good password policy on a personal server is pointless. Some features may not be possible on virtual private server providers, like disk encryption.

  - 99.0 [Disk encryption](#990-disk-encryption) #TODO
  - 99.1 [Separate partitions](#991-separate-partitions) #TODO
  - 99.2 [Good password policy](#992-good-password-policy) #TODO
  - 99.3 [Process accounting](#993-process-accounting) #TODO
  - 99.4 [Two-factor authentication in SSH](#994-two-factor-authentication-in-ssh) #TODO
  - 99.5 [Restrict USB devices with `usbguard`](#995-restrict-usb-devices-with-usbguard) #TODO
  - 99.6 [Hardware security](#996-hardware-security) #TODO

<hr />

## Chapter 0: Beginning
Create a `sudo` user so root account can be disabled.

### **Objectives**
&#9745; **Update Ubuntu**<br>
&#9745; **Create `sudo` user**<br>
&#9745; **Limit `su` command**

### **Why...**
**Create `sudo` user**? Using root account means all programs are run by root account. Root lets a program do *anything*, but most programs need very little access. `sudo` can be used before a command to run that command as root,  eliminating the need to login as root at all.<br>
**Limit `su` command**? `su` allows users to switch to other accounts, including root. That's a powerful privilege.

### 0.0 SSH to root account
```bash
ssh root@myserver.net
```

### 0.1 Update Ubuntu
```bash
apt update
apt upgrade
```

### 0.2 Create secure password
Use a password manager to generate a long, unpredictable password for the new `sudo` user.

### 0.3 Create `sudo` user
*Note: By default, `/etc/ssh/sshd_config` gives members of group `sudo` full permissions (`%sudo	ALL=(ALL:ALL) ALL`)*
```bash
NEWUSER=`admin` # Username
# By default, `/etc/ssh/sshd_config` gives members of group `sudo` full permissions (`%sudo	ALL=(ALL:ALL) ALL`)
addgroup sudo # Create group for sudoers
adduser $NEWUSER # Create new user
usermod -a -G sudo $NEWUSER # Add user to sudoers group
passwd $NEWUSER # Set secure password
su - $NEWUSER # Login to new account
```

### 0.4 Limit `su` command
With a `sudo` user now in place, limit use of `su` to just them.
```bash
sudo addgroup suers
sudo usermod -a -G suers $USER
sudo dpkg-statoverride --update --add root suers 4750 /bin/su # Now `su` can only be run by members of group `suers`
```

<hr />

## Chapter 1: Local SSH
Create SSH key login for local machine.

### **Objectives**
&#9745; **Generate SSH key**<br>
&#9745; **Authorize public key**<br>
&#9745; **Login with SSH key**

### **Why...**
**Login with SSH key**? SSH keys are 256 bits, longer than most passwords, and do not need to be sent to the server like a password. **However, anyone who can read the private key file can login.** Secure these files, and the machine(s) storing them! **SSH keys can also be secured by a password, creating another layer.**

*Note: `id_some`, `id_some.pub`, and `config` all belong on local machine. Server only needs `authorized_keys`.*

### 1.0 Generate SSH key
Use a custom Gmail account for the server instead of a personal address. **This guide relies on Gmail to send mail**, but everything will work just as well on Yahoo, for example, with some extra work not covered here.<br>
*Note: When prompted, "Enter a file in which to save the key", provide path: `/home/$USER/.ssh/id_some` where `some` is something memorable*
```bash
# When prompted, "Enter a file in which to save the key", provide path: `/home/$USER/.ssh/id_some` where `some` is something memorable
# When prompted, please consider providing another unique password for the SSH key
ssh-keygen -t ed25519 -C "myserver@gmail.com" # Generate SSH keypair
ssh-add ~/.ssh/id_some # Register new keypair with sshd
```

### 1.1 Set safer permissions
In Linux, every file has rules for what the (1) user and (2) group who owns the file can do, and what (3) everyone else can do. These comprise the three consecutive numbers in `chmod` commands. For example, `700` gives full access to (1) the owner but no access to (2) the owner's groups or (3) other users - `0` denotes no access, `7` full access.

SSH uses public key cryptography for "SSH keys". **TL;DR**: private key must be protected at all costs, public key is innocuous.
```bash
chmod 644 ~/.ssh/id_some.pub # Limit public key access - someone else reading this is not dangerous
chmod 600 ~/.ssh/id_some # Lock down private key - this is dangerous
chmod 700 ~/.ssh
```

### 1.2 Create alias
Allow connection via `ssh some` instead of `ssh user:ip`.

```bash
touch ~/.ssh/config
chmod 600 ~/.ssh/config
```

Edit `~/.ssh/config`:

```
Host myalias
  User admin
  HostName myserver.net
  Port 22
  IdentityFile ~/.ssh/id_some
```

### 1.3 Copy public key
Ensure trailing whitespace is not included in copy-paste.
```bash
cat ~/.ssh/id_some.pub
```

### 1.4 Authorize public key
Return to server SSH shell for this step.
```bash
touch ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
echo "(public key from clipboard)" > ~/.ssh/authorized_keys
```

### 1.5 Login with SSH key
Close existing SSH to `root` upon success.
```bash
ssh some
```

<hr />

## Chapter 2: SSH
Tweak `sshd`'s configuration to provide much better security.

### **Objectives**
&#9745; **Disable root user**<br>
&#9745; **Secure `sshd`**

### **Why...**
**Disable root user**? SSH keys are 256 bits, longer than most passwords, and do not need to be sent to the server like a password. Note that SSH keys are stored in `~/.ssh/`: the security of these files on local machine is essential.<br>
**Secure `sshd`**? SSH port must be open to public all the time, and home network IP changes dynamically, so whitelists are not an option for the average person.

### 2.0 Disable root user
With a `sudo` user, any command that needs root access can be run without the root account itself. Thus, root account can be safely disabled.

*Note: Technically, this just makes it impossible to login to root shell.*

```bash
sudo usermod -s /bin/false root # Technically, this just makes it impossible to login to root shell
```

### 2.1 Create SSH group
It's a good habit to limit who can use what by creating specialized groups for programs like SSH.

```bash
sudo addgroup sshers
sudo usermod -a -G sshers $USER
```

### 2.2 Secure `sshd`
Secure `sshd` by editing its configuration file. There are two sections: suggestions by the guide, and suggestions by Mozilla InfoSec.

*Note: See https://infosec.mozilla.org/guidelines/openssh#modern-openssh-67 for latest recommendations.*<br>
*Also note: Duplicate entries in `/etc/ssh/sshd_config` will fail or cause an error. Check existing entries before copying.*<br>
*Also note: If setting `Port #`, closed firewalls will block this port until it is opened. Default SSH port is generally already open. This guide illustrates how to open the port, but closing connection prior might lock the keys forever.*

Edit `/etc/ssh/sshd_config`:

```bash
# ++++ The following are recommendations by the guide
# ++++ See https://github.com/connergdavis/secure-ubuntu-server

# Only allow `sshers`, which currently only contains sudo user
AllowGroups sshers

# Do not send keep alive messages to clients that do not respond
ClientAliveCountMax 0

# Wait after one failure
ClientAliveInterval 300

# Close connections failing auth aggressively
MaxAuthTries 2

# Limit parallel sessions
MaxSessions 2
MaxStartups 2

# Disable SSH without SSH key
PasswordAuthentication no

# Switch to some other unused port
# NOTE: Closed firewalls will block this port until it is opened. Default SSH port is generally already open.
# If set, ensure firewall is updated before logging out of current SSH session.
Port 54321

# Disable GUI SSH connections
X11Forwarding no

# ---- The following are recommendations by Mozilla
# ---- See https://infosec.mozilla.org/guidelines/openssh#modern-openssh-67

# Supported HostKey algorithms by order of preference.
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key

KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256

Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com

# Password based logins are disabled - only public key based logins are allowed.
AuthenticationMethods publickey

# LogLevel VERBOSE logs user's key fingerprint on login. Needed to have a clear audit track of which key was using to log in.
LogLevel VERBOSE

# Log sftp level file access (read/write/etc.) that would not be easily logged otherwise.
Subsystem sftp  /usr/lib/ssh/sftp-server -f AUTHPRIV -l INFO

# Root login is not allowed for auditing reasons. This is because it's difficult to track which process belongs to which root user:
#
# On Linux, user sessions are tracking using a kernel-side session id, however, this session id is not recorded by OpenSSH.
# Additionally, only tools such as systemd and auditd record the process session id.
# On other OSes, the user session id is not necessarily recorded at all kernel-side.
# Using regular users in combination with /bin/su or /usr/bin/sudo ensure a clear audit track.
PermitRootLogin No

# Use kernel sandbox mechanisms where possible in unprivileged processes
# Systrace on OpenBSD, Seccomp on Linux, seatbelt on MacOSX/Darwin, rlimit elsewhere.
UsePrivilegeSeparation sandbox
```

### 2.3 Check for errors in `/etc/ssh/sshd_config`
Errors will be returned if there are any. Successful output will list every entry and value found in `sshd_config`, e.g. `permitrootlogin no`.

```bash
sudo sshd -T
```

### 2.4 Only use long Diffie-Hellman moduli
An additional requirement of Firefox InfoSec guidelines on OpenSSH.

*Note: See https://infosec.mozilla.org/guidelines/openssh#intermediate-openssh-53 for latest recommendations.*

```bash
sudo awk '$5 >= 3071' /etc/ssh/moduli | sudo tee /etc/ssh/moduli.tmp # Strip moduli < 3072 bits long
sudo mv /etc/ssh/moduli.tmp /etc/ssh/moduli
```

<hr />

## Chapter 3: Firewall
Use `ufw` to block all traffic by default, then explicitly allow certain services.

### **Objectives**
&#9745; **Block everything by default**<br>
&#9745; **Allow services (NTP, HTTP(S), DNS, FTP, `exim4`) out**<br>
&#9745; **Allow services (SSH) in**

### **Why...**
**Block everything by default?** Explicit control over traffic in and out of the server. Being "online" is a substantial security threat.

### 3.0 Block everything by default
```bash
sudo apt install ufw
sudo ufw default deny outgoing # Denies all outgoing traffic by default
sudo ufw default deny incoming
```

### 3.1 Allow services out: DNS, FTP, HTTP(S), NTP, `exim4`
The format of simple port rules is `allow/deny` `in/out` `port`. This can be more complex if restricting IPs, for example.

```bash
sudo ufw allow out 53 comment 'DNS' # A universal need
sudo ufw allow out 123 comment 'NTP' # Required to use NTP as described in the guide
sudo ufw allow out 465/tcp comment 'exim4' # Required to send email via exim4

# The following are generally required to do `apt update`
sudo ufw allow out http comment 'HTTP'
sudo ufw allow out https comment 'HTTPS'
sudo ufw allow out ftp comment 'FTP'
sudo ufw allow out whois comment 'WHOIS'
```

### 3.2 Allow services in: SSH
*Note: SSH connections are set to `limit` instead of `allow` to use UFW's built in rate-limiting to mitigate attacks.*

```bash
sudo ufw limit in 54321 comment 'SSH' # Replace 54321 by custom SSH port, or ssh if using default
```

### 3.3 Enable UFW
**Before proceeding**, open another SSH connection. `ufw enable` will close current SSH terminal if rules were set incorrectly.

```bash
sudo ufw enable # Turns on firewall rules
sudo ufw status
```

<hr />

## Chapter 4: NTP
Synchronize system time with the internet via Network Time Protocol.

*Note: NTP requires an open port specified in [Chapter 3: Firewall](#chapter-3-firewall).*

### **Objectives**
&#9745; **Enable NTP**

### **Why...**
**Enable NTP?** Servers rely on exact time and the best way to accomplish that is to synchronize with Internet time servers.

### 4.0 Edit NTP configuration
```bash
sudo sed -i -r -e "s/^((server|pool).*)/# \1" /etc/ntp.conf
echo -e "\npool pool.ntp.org iburst" /etc/ntp.conf | sudo tee -a /etc/ntp.conf
```

### 4.1 Restart service
To catch errors should they come up.

```bash
sudo service ntp restart # Restarts NTP service, which is running constantly in background
sudo service ntp status # Checks on status of service with latest stdout, will report errors
sudo ntpq -p # Prints NTP peer status
```

<hr />

## Chapter 5: File systems
Hide process ID file descriptors in `/proc`, and set stricter default file and folder permissions.

### **Objectives**
&#9745; **Hide process files in `/proc`**<br>
&#9745; **Set default permissions**

### **Why...**
**Hide process files in `/proc`?** In Linux, a file is created in `/proc` for every active process. By default, those are readable by all users. We can change this behavior so only root can see them.<br>
**Set default permissions?** The default permissions set for new files is quite permissive. Generally speaking most files can be limited to at least exclude other users. If someone gains control of one account, the damage is heavily mitigated.

### 5.0 Hide process files in `proc`
Per [`man proc`](https://linux.die.net/man/5/proc), by default there is a file for every process running on the system inside `/proc/`, e.g., `/proc/1`, and that file happens to be readable by all users.

```bash
echo -e "\nproc    /proc    proc    defaults,hidepid=2    0    0" | sudo tee -a /etc/fstab
sudo reboot
```

### 5.1 Set default permissions
Permissions sets can be described in a few different formats, but the most common number format representation of the following defaults is `027` or `0027`.

It is worth learning about permissions to further restrict files where possible (e.g., `.ssh` folder).

```bash
# Equivalent to code "027" or "0027"
#
# u=rwx | User can do anything
# g=rx | User's groups can read and execute
# o= | Other users can't do anything
umask u=rwx,g=rx,o= # Sets default permissions for files created going forward
```

<hr />

## Chapter 6: Email
Allow the server to send email logs securely to Gmail.

*Note: Email requires an open port specified in [Chapter 3: Firewall](#chapter-3-firewall).*

### **Objectives**
&#9745; **Install mail server**<br>
&#9745; **Login to Gmail**

### **Why...**
**Login to Gmail?** Gmail is easy and free to set up. Also eliminates the need to run a full mail server (our `exim4` is send-only).

### 6.0 Install mail server (`exim4`)
`openssl` and `ca-certificates` are also needed to log into Gmail servers.

```bash
sudo apt install exim4 openssl ca-certificates
```

### 6.1 Configure `exim4`
When prompted, continue with the default setting for all but the following options:

| Please enter | ... |
| -- | -- |
| **General type of mail configuration** | `mail sent by smarthost; no local mail` |
| **System mail name** | `localhost` |
| **Visible domain name for local users** | `localhost` |
| **IP-address or host name of the outgoing smarthost** | `smtp.gmail.com::465` |

```bash
sudo dpkg-reconfigure exim4-config # Visual config instead of a file; navigate with arrow keys, Enter to go forward, Esc to go back
```

### 6.2 Create Gmail login
Provide login credentials so `exim4` can send email on your behalf.

Edit `/etc/exim4/passwd.client`:

```bash
smtp.gmail.com:address@gmail.com:password
*.google.com:address@gmail.com:password
```

### 6.3 Protect Gmail login

Lock the new password file down.

*Note: `Debian-exim` is the default group used by `exim4` to send mail*

```bash
sudo chown root:Debian-exim /etc/exim4/passwd.client # `Debian-exim` is the default group used by `exim4` to send mail
sudo chmod 640 /etc/exim4/passwd.client
```

### 6.4 Generate login certificate
Create a TLS certificate `exim4` can use to login to Gmail servers.

When prompted, provide the following specific answers:

| []: | .. |
| -- | -- |
| Server name | `localhost` |
| Email Address | `email@gmail.com` |

```bash
sudo bash /usr/share/doc/exim4-base/examples/exim-gencert # exim4 provides a script to do this automatically
```

### 6.5 Login to Gmail
Finally, configure `exim4` to connect to Gmail servers using your account.

Edit `/etc/exim4/exim4.conf.localmacros`:

```
MAIN_TLS_ENABLE = 1
REMOTE_SMTP_SMARTHOST_HOSTS_REQUIRE_TLS = *
TLS_ON_CONNECT_PORTS = 465
REQUIRE_PROTOCOL = smtps
IGNORE_SMTP_LINE_LENGTH_LIMIT = true
```

Now slightly reconfigure `exim4` to use TLS.

```bash
sudo sed -i -r -e '/^.ifdef REMOTE_SMTP_SMARTHOST_HOSTS_REQUIRE_TLS$/I { :a; n; /^.endif$/!ba; a\n .ifdef REQUIRE_PROTOCOL\nprotocol = REQUIRE_PROTOCOL\n .endif\n' -e '}' /etc/exim4/exim4.conf.template
sudo sed -i -r -e "/\.ifdef MAIN_TLS_ENABLE/ a\n .ifdef TLS_ON_CONNECT_PORTS\n tls_on_connect_ports = TLS_ON_CONNECT_PORTS\n.endif\n" /etc/exim4/exim4.conf.template
```

### 6.6 Edit `/etc/aliases`
To avoid copying the email address to every application that will send mail, overwrite the `root` mail alias. That's a lot easier than copying the email address for each program that sends mail.

```
root: address@gmail.com
```

### 6.7 Restart `exim4`
```bash
sudo update-exim4.conf # Will output config errors, if there are any
sudo service exim4 restart
```

### 6.8  Send test email
```bash
echo "Test" | mail -s "Test" address@gmail.com
sudo tail /var/log/exim4/mainlog # Read log results, especially if the test doesn't work!
```

<hr />

## Chapter 7: Reports
Run scans for viruses, monitor intrusions, and more. Email results in human-readable format ondemand and daily.

### **Objectives**
&#9745; **Daily reports about everything**<br>
&#9745; **Automatic updates**<br>
&#9745; **Antivirus**<br>
&#9745; **Rootkit detection**<br>
&#9745; **Host intrusion detection**<br>
&#9745; **App intrusion detection**<br>
&#9745; **File system monitoring**<br>
&#9745; **ARP monitoring**<br>

### **Why...**
**Daily reports about everything?** The server's security depends on its administrator keeping track of it every day. It is painful to bring all the system logs together and create filters on them which extract the most pertinent information (most logs spit out a LOT of data). `logwatch` can do all of that.<br>
**Automatic updates?** Sometimes, the administrator can't be available for some time, but staying up to date is one of the most important objectives.<br>
**Rootkit detection?** _<br>
**Host intrusion detection?** _<br>
**App intrusion detection?** _<br>
**File system monitoring?** _<br>
**ARP monitoring?** _<br>

### 7.0 Daily reports about everything (`logwatch`)
Logwatch is an extremely convenient tool that creates a human readable compilation of reports based on what's found in `/var/log`. By default, Logwatch includes things like disk and network usage and SSH traffic. Notably, Logwatch includes log file filters, e.g. SSH failed connections are printed as one line per user.

```bash
sudo apt install logwatch
# Change Logwatch cron entry to send daily report as email
sudo sed -i -r -e "s,^($(sudo which logwatch).*?),# \1\n$(sudo which logwatch) --output mail --format html --mailto root --range yesterday --service all," /etc/cron.daily/00logwatch
sudo /etc/cron.daily/00logwatch # Test if successful
```

### 7.1 Automatic updates (`unattended-upgrades`)
#### 7.1.0 Install `unattended-upgrades`
```bash
sudo apt install unattended-upgrades apt-listchanges apticron
sudo touch /etc/apt/apt.conf.d/51myunattended-upgrades
```

#### 7.1.1 Edit `/etc/apt/apt.conf.d/51myunattended-upgrades`
Configure `unattended-upgrades` to email automatic update results.

```
// Enable the update/upgrade script (0=disable)
APT::Periodic::Enable "1";

// Do "apt-get update" automatically every n-days (0=disable)
APT::Periodic::Update-Package-Lists "1";

// Do "apt-get upgrade --download-only" every n-days (0=disable)
APT::Periodic::Download-Upgradeable-Packages "1";

// Do "apt-get autoclean" every n-days (0=disable)
APT::Periodic::AutocleanInterval "7";

// Send report mail to root
//     0:  no report             (or null string)
//     1:  progress report       (actually any string)
//     2:  + command outputs     (remove -qq, remove 2>/dev/null, add -d)
//     3:  + trace on    APT::Periodic::Verbose "2";
APT::Periodic::Unattended-Upgrade "1";

// Automatically upgrade packages from these
Unattended-Upgrade::Origins-Pattern {
      "o=Debian,a=stable";
      "o=Debian,a=stable-updates";
      "origin=Debian,codename=${distro_codename},label=Debian-Security";
};

// You can specify your own packages to NOT automatically upgrade here
Unattended-Upgrade::Package-Blacklist {
};

// Run dpkg --force-confold --configure -a if a unclean dpkg state is detected to true to ensure that updates get installed even when the system got interrupted during a previous run
Unattended-Upgrade::AutoFixInterruptedDpkg "true";

//Perform the upgrade when the machine is running because we wont be shutting our server down often
Unattended-Upgrade::InstallOnShutdown "false";

// Send an email to this address with information about the packages upgraded.
Unattended-Upgrade::Mail "root";

// Always send an e-mail
Unattended-Upgrade::MailOnlyOnError "false";

// Remove all unused dependencies after the upgrade has finished
Unattended-Upgrade::Remove-Unused-Dependencies "true";

// Remove any new unused dependencies after the upgrade has finished
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";

// Automatically reboot WITHOUT CONFIRMATION if the file /var/run/reboot-required is found after the upgrade.
Unattended-Upgrade::Automatic-Reboot "true";

// Automatically reboot even if users are logged in.
Unattended-Upgrade::Automatic-Reboot-WithUsers "true";
```

### 7.2 Antivirus (`clamav`)
Default settings run definitions updates once an hour. Installing `clamdscan` enables automatic scanning on network. `freshclam` and `clamd` services automatically start. 

*Note: Never run `clamav` as root. `clamav` works by essentially opening every file it scans.*

```bash
sudo apt install clamav clamav-freshclam clamav-daemon clamdscan
```

### 7.3 Rootkit detection (`rkhunter`, `chkrootkit`)
#### 7.3.0 Install packages
```bash
sudo apt install rkhunter chkrootkit
```

#### 7.3.1 Enable cron scripts
```bash
# Select `Yes` when asked, *Should chkrootkit be run automatically every day?* Use default for everything else
sudo dpkg-reconfigure chkrootkit
# Select `Yes` for all prompts
sudo dpkg-reconfigure rkhunter
```

#### 7.3.2 Edit `/etc/rkhunter.conf`
```bash
UPDATE_MIRRORS=1
MIRRORS_MODE=0 # Use mirrors from the internet
MAIL-ON-WARNING=root # Send mail to `root` alias
COPY_LOG_ON_ERROR=1 # Copy error logs to file
PKGMGR=NONE # Suggested value for Debian by docs
PHALANX_DIRTEST=1 # Suggested by docs
WEB_CMD="" # Suggested value for Debian by docs
USE_LOCKING=1 # Prevents more than one `rkhunter` from running at once
SHOW_SUMMARY_WARNINGS_NUMBER=1
```

#### 7.3.3 Update `rkhunter`
```bash
sudo rkhunter -C # Verify /etc/rkhunter.conf
sudo rkhunter --versioncheck
sudo rkhunter --update
sudo rkhunter --propupd
```

### 7.4 Host intrusion detection (`ossec`)
By default, `ossec` runs a rootkit check every two hours.

#### 7.4.0 Prepare to build from source
```bash
sudo apt install libevent-dev libz-dev libssl-dev libpcre2-dev build-essential
```

#### 7.4.1 Install `ossec`
When prompted by `install.sh`, provide the following specific answers:

| ? | _ |
| -- | -- |
| What kind of installation do you want? | `local` |
| What's your e-mail address? | `address@gmail.com` |

```bash
wget https://github.com/ossec/ossec-hids/archive/3.6.0.tar.gz # Be sure to check https://github.com/ossec/ossec-hids for version
tar xzf 3.6.0.tar.gz # Extracts zip to folder
cd ossec-hids-3.6.0/
sudo ./install.sh
```

### 7.5 App intrusion detection (`fail2ban`)
#### 7.5.0 Install `fail2ban`
```bash
sudo apt install fail2ban
```

#### 7.5.1 Edit `/etc/fail2ban/jail.local`
`fail2ban` will recognize this as a configuration file.
```bash
[DEFAULT]
# Ignore self
ignoreip = 127.0.0.1/8 [LAN SEGMENT]

# Send email
destemail = account@gmail.com
sender = account@gmail.com

# exim4 to send mail
mta = mail

# Get email alerts
action = %(action_mwl)s
```

#### 7.5.2 Create jails
Jails can be created for any program, and presets exist for many, but the easy, obvious example is SSH.

Create an SSH jail at `/etc/fail2ban/jail.d/ssh.local`:
```bash
[sshd]
enabled = true
banaction = ufw
port = 54321 # custom SSH port here
filter = sshd
logpath = %(sshd_log)s
maxretry = 5
```

#### 7.5.3 Enable `fail2ban`
```bash
sudo fail2ban-client start
sudo fail2ban-client reload
sudo fail2ban-client add sshd
```

#### 7.5.4 Check jail statuses
```bash
sudo fail2ban-client status
```

### 7.6 File system integrity monitoring (`aide`)
Monitors files and notifies when changes are detected. 

Understand that **lots** of files get changed all the time, so there is a lot of garbage in the output by default. See [Section 7.6.4](#).

#### 7.6.0 Install `aide`
```bash
sudo apt install aide
```

#### 7.6.1 Create initial database
```bash
sudo aideinit
```

#### 7.6.2 Configure daily checks
Edit `/etc/default/aide`:
```bash
CRON_DAILY_RUN=yes
```

#### 7.6.3 Exclude files and folders
The safest way to exclude files from monitoring is to match regex patterns as closely as possible, avoiding blanket rules. Finding a balance between convenience and actual value from file integrity monitoring is challenging.

To add exclusions, add something like the following to the end of `/etc/aide/aide.conf`:
```bash
# You can also create custom rules - my home made rule definition goes like this
#
MyRule = p+i+n+u+g+s+b+m+c+md5+sha1

# Next decide what directories/files you want in the database

/etc p+i+u+g     #check only permissions, inode, user and group for etc
/bin MyRule      # apply the custom rule to the files in bin
/sbin MyRule     # apply the same custom rule to the files in sbin
/var MyRule
!/var/log/.*     # ignore the log dir it changes too often
!/var/spool/.*   # ignore spool dirs as they change too often
!/var/adm/utmp$  # ignore the file /var/adm/utmp
```

#### 7.6.4 Maintain
Each time a known change is made to a file inside AIDE's scope, update the database with:
```bash
sudo aideinit -y -f
```

### 7.7 ARP monitoring (`arpwatch`)
```bash
sudo apt install arpwatch
sudo service arpwatch start
```

<hr />

## Chapter 8: Kernel `sysctl`
Edit `/etc/sysctl.conf` kernel options to comply with stricter security standards.

### 8.0 Edit `/etc/sysctl.conf`
TODO

### 8.1 Test new settings
TODO

### 8.2 Restart server
TODO

<hr />

## Chapter 9: Sandboxes
Isolate programs in their own virtual machine to limit access to real resources. The guide uses Firejail, but Docker is a great alternative.

### **Objectives**
&#9745; **Run programs with `firejail`**<br>
&#9745; **Create profiles for programs in `firejail`**

### **Why...**
**Run programs with `firejail`?** Most programs do not need access to the vast majority of the resources available to the machine. Allowing that access creates a large area for exposure.<br>
**Create profiles for programs in `firejail`?** Some programs are not compatible with the default `firejail` profile and require custom profiles to function correctly. That isn't a bad thing - `firejail` is designed to adapt because programs have very different sets of requirements.

### 9.0 Install `firejail`
```bash
sudo apt install firejail firejail-profiles
sudo firecfg # Generates profiles automatically for existing programs
```

### 9.1 Run programs with `firejail`
There are a few ways to sandbox with `firejail`. The easiest is to tell `firejail` to open the program with the default profile.

```bash
sudo ln -s /usr/bin/firejail /usr/local/bin/some-program # Where some-program is currently at /usr/bin/ or /bin
```

Now the program will always execute inside a jail.

### 9.2 Run programs with `firejail` and specific jail options
It is also possible to launch an application with the `firejail` command including the jail options, like:
```bash
firejail --noprofile --disable-mnt --no3d ... -- my-program ...
```

See [Building Custom Profiles | Firejail](https://firejail.wordpress.com/documentation-2/building-custom-profiles/) for the full list of options available here.

### 9.3 Create profiles for programs in `firejail`
Some programs do not comply with the default profile and need a custom profile with more refined editing.

Create a custom profile at `/etc/firejail/some-program.profile`. Browse the existing profiles in `/etc/firejail` to get an idea of the syntax and available options.

See [Building Custom Profiles | Firejail](https://firejail.wordpress.com/documentation-2/building-custom-profiles/) for the full list of options available here.

The profile will be loaded automatically assuming the profile's file name is identical to the program's binary name, e.g.: `/etc/firejail/geth.profile` to `/usr/bin/geth`.

### 9.4 Run daemons with `firejail`
`firejail` has a quirk with daemonized programs (eg via `systemctl`). Manually updating `systemctl` to load a service with `firejail` will cause the service to hang indefinitely when started. 

Edit the program's service module:
```bash
sudo systemctl edit program-name
```

And provide the following code:
```bash
[Service]
Type=simple
# "Reset" existing systemctl entry by blanking out first. Required for some reason.
ExecStartPre=
ExecStart=
ExecReload=
# Now prepend the command with firejail
ExecStartPre= # run tests if applicable
ExecStart=/usr/bin/firejail program-name
ExecReload= # reload module if applicable
```

To update the module:
```bash
sudo systemctl daemon-reload
sudo systemctl restart program-name
```

<hr />

## Chapter 10: Audits
Check the security of the server by running standardized audit software to report common weaknesses.

### **Objectives**
&#9745; **Audit system with Lynis**

### **Why...**
**Audit system with Lynis**? Lynis will provide hundreds of suggestions on specific changes that can be made to improve security. A great way to jump into more security subjects.

### 10.0 `lynis`
```
sudo apt install lynis
sudo lynis audit system
```

<hr />

## Chapter 98: Keep local system safe
It's fun to set up a `firejail` for every process and receive daily reports about file system integrity, but none of that matters if the local machine used to connect is breached. The SSH key and sudoer password are essential to the security of the system. Systems used to connect should ideally be just as safe as the server itself.

<hr />

## Chapter 99: Optional extras
There's all sorts of other things to do beyond the scope of this guide. It's just a starting point.

### 99.0 Disk encryption
TODO

### 99.1 Separate partitions
TODO

### 99.2 Good password policy
TODO

### 99.3 Process accounting
TODO

### 99.4 Two-factor authentication in SSH
#TODO 

### 99.5 Restrict USB devices with `usbguard`
#TODO 

### 99.6 Hardware security
#TODO
