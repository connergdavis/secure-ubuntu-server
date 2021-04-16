v# Secure Ubuntu Server
## Disclaimer
**I am not a security professional nor do I have any background in security.**

I am a software engineer who wants to run personal servers secure enough for the real world.

I am not a master or even remotely experienced in the following topics. I gathered knowledge from free online sources and researched what things mean enough for my own understanding.

The following suggestions might not work for you. If something goes wrong, please let us know via [Issues](https://github.com/connergdavis/secure-ubuntu-server/issues)!

## Table of Contents
### Chapter 0: [Beginning](#chapter-0-beginning-1)
Update, create secure sudo user, and disable root access.

  - 0.0 [SSH to root account](#00-ssh-to-root-account)
  - 0.1 [Update Ubuntu packagers](#01-update-ubuntu-packages)
  - 0.2 [Create secure password](#02-create-secure-password)
  - 0.3 [Create sudo user](#03-create-sudo-user)
  - 0.4 [Limit `su` command](#04-limit-su-command)

### Chapter 1: [Local SSH](#chapter-1-local-ssh-1)
Create SSH key login for local machine.

**Note**: `id_some`, `id_some.pub`, and `config` all belong on local machine. Server only needs `authorized_keys`.

  - 1.0 [Generate SSH key](#10-generate-ssh-key)
  - 1.1 [Set safer permissions](#11-set-safer-permissions)
  - 1.2 [Create alias](#12-create-alias)
  - 1.3 [Authorize local machine](#13-authorize-local-machine)
  - 1.4 [Login with SSH key](#14-login-with-ssh-key)

### Chapter 2: [SSH](#chapter-2-ssh-1)
Tweak `sshd`'s configuration to provide much better security.

  - 2.0 [Create SSH group](#20-create-ssh-group)
  - 2.1 [Edit `/etc/ssh/sshd_config`](#21-edit-etcsshsshd_config)
  - 2.2 [Check for errors in `sshd_config`](#22-check-for-errors-in-sshd_config)
  - 2.3 [Only use long Diffie-Hellman moduli](#23-only-use-long-diffie-hellman-moduli)

### Chapter 3: [Firewall](#chapter-3-firewall-1)
Use `ufw` to switch to a block-by-default policy, selecting exactly what is allowed in and out.

  - 3.0 [Block everything by default in `ufw`](#30-block-everything-by-default-in-ufw)
  - 3.1 [Allow services out](#31-allow-services-out)
  - 3.2 [Allow services in](#32-allow-services-in)
  - 3.3 [Enable UFW](#33-enable-ufw)

### Chapter 4: [NTP](#chapter-4-ntp-1)
Network Time Protocol uses global servers to update system time. Servers rely on accurate system time.

*Note: NTP requires a port to be open, which is specified in Chapter 3: Firewall.*

  - 4.0 [Edit `/etc/ntp.conf`](#40-edit-etcntpconf)
  - 4.1 [Restart service](#41-restart-service)

### Chapter 5: [Email](#chapter-5-email-1)
Setup outgoing mail server to Gmail account. Chapters after this one offer or require the ability to send mail.

*Note: exim4 requires a port to be open, which is specified in Chapter 3: Firewall.*

  - 5.0 [Install mail server (`exim4`)](#50-install-mail-server-exim4)
  - 5.1 [Configure `exim4`](#51-configure-exim4)
  - 5.2 [Edit `/etc/exim4/passwd.client`](#52-edit-etcexim4passwdclient)
  - 5.3 [Secure password file](#53-secure-password-file)
  - 5.4 [Create login certificate](#54-create-login-certificate)
  - 5.5 [Login to Gmail](#55-login-to-gmail)
  - 5.6 [Restart `exim4`](#56-restart-exim4)
  - 5.7 [Send test email](#57-send-test-email)

### Chapter 6: [File systems](#chapter-6-file-systems-1)
Limit access to `/proc` and `/home` directories, and set default file and folder permissions.

  - 6.0 [Hide pids in `/proc`](#60-hide-pids-in-proc) # TODO
  - 6.1 [Limit `/home` permissions](#61-limit-home-permissions) # TODO
  - 6.2 [Set default permissions](#62-set-default-permissions) # TODO

### Chapter 7: [Reports](#chapter-7-reports-1)
Run scans for viruses, monitor intrusions, and more. Email results in human-readable format ondemand and daily.

  - 7.0 [Daily reports about everything (`logwatch`)](#70-daily-reports-about-everything-logwatch)
  - 7.1 [Process accounting (`acct`)](#71-process-accounting-acct)
  - 7.2 [Automatic updates (`unattended-upgrades`)](#72-automatic-updates-unattended-upgrades)
  - 7.3 [Antivirus (`clamav`)](#73-antivirus-clamav)
  - 7.4 [Rootkit detection (`rkhunter`, `chkrootkit`)](#74-rootkit-detection-rkhunter-chkrootkit)
  - 7.5 [Host intrusion detection (`ossec`)](#75-host-intrusion-detection-ossec)
  - 7.6 [App intrusion detection (`fail2ban`)](#76-app-intrusion-detection-fail2ban)
  - 7.7 [File system integrity monitoring (`aide`)](#77-file-system-integrity-monitoring-aide)
  - 7.8 [ARP monitoring (`arpwatch`)](#78-arp-monitoring-arpwatch)

### Chapter 8: [Kernel `sysctl`](#chapter-8-kernel-sysctl-1)
Edit `/etc/sysctl.conf` kernel options to comply with stricter security standards.

  - 8.0 [Edit `/etc/sysctl.conf`](#80-edit-etcsysctlconf)
  - 8.1 [Test new settings](#81-test-new-settings)
  - 8.2 [Restart server](#82-restart-server)

### Chapter 9: [Services](#chapter-9-services-1)
TODO

### Chapter 10: [Sandboxes](#chapter-10-sandboxes-1)
Isolate programs in their own virtual machine to limit access to real resources. The guide uses Firejail, but Docker is a great alternative.

  - 10.0 [Install `firejail`](#100-install-firejail)
  - 10.1 [Run programs with `firejail`](#101-run-programs-with-firejail)
  - 10.2 [Create profiles for programs in `firejail`](#102-create-profiles-for-programs-in-firejail)

### Chapter 11: [Audit](#chapter-11-audit-1)
Check the security of the server by running standardized audit software to report common weaknesses.

  - 11.0 [`lynis`](#110-lynis)

### Chapter 98: [Keep local system safe](#chapter-98-keep-local-system-safe-1)
It's fun to set up a `firejail` for every process and receive daily reports about file system integrity, but none of that matters if the local machine used to connect is breached. The SSH key and sudoer password are essential to the security of the system. Systems used to connect should ideally be just as safe as the server itself.

### Chapter 99: [Optional extras](#chapter-99-optional-extras-1)
There's all sorts of other things to do beyond the scope of this guide. It's just a starting point.

  - 99.0 [Disk encryption](#990-disk-encryption)
  - 99.1 [Separate partitions](#991-separate-partitions)
  - 99.2 [Good password policy](#992-good-password-policy)

## Chapter 0: Beginning
Update, create secure sudo user, and disable root access.

### 0.0 SSH to root account
Begin on a trusted local device.

```bash
ssh root@127.0.0.1 # 127.0.0.1 is server IP
```

### 0.1 Update Ubuntu packages
```bash
apt update
apt upgrade
```

### 0.2 Create secure password
A password manager should ideally be used to control server passwords. We want passwords that are ridiculously difficult to crack and like to isolate different purposes of the server to different accounts (so lots of passwords). 

### 0.3 Create sudo user
By default, `sudo` gives users in the group `sudo` full permission. It may not exist yet, that's OK.

```bash
NEWUSER=`openssl rand -hex 12` # Create random username, or use a memorable name if you like
addgroup sudo # Create group for sudoers (only for this account)
adduser $NEWUSER # Create new user
usermod -a -G sudo $NEWUSER # Add user to sudoers group
passwd $NEWUSER # Update their password
su - $NEWUSER # Login to new account
```

### 0.4 Limit `su` command
With a `sudo` user now in place, limit use of `su` to just them.

```bash
sudo addgroup suers
sudo usermod -a -G suers $USER
sudo dpkg-statoverride --update --add root suers 4750 /bin/su
```

## Chapter 1: Local SSH
Create SSH key login for local machine.

**Note**: `id_some`, `id_some.pub`, and `config` all belong on local machine. Server only needs `authorized_keys`.

### 1.0 Generate SSH key
Create an email address for the server, rather than using a personal email, especially since logs will be emailed too.

*Note: When prompted, "Enter a file in which to save the key", provide path: `/home/$USER/.ssh/id_some` where `some` is anything.*

```bash
# When prompted, "Enter a file in which to save the key", 
# provide path: `/home/$USER/.ssh/id_some` where `some` is anything
ssh-keygen -t ed25519 -C "email@example.com" # Generate SSH keypair
ssh-add ~/.ssh/id_some # Register new keypair with sshd
```

### 1.1 Set safer permissions
```bash
chmod 644 ~/.ssh/id_some.pub # Limit public key access
chmod 600 ~/.ssh/id_some
chmod 700 ~/.ssh
```

### 1.2 Create alias
Allows connection via `ssh some` instead of `ssh user:ip`.

```bash
MY_ALIAS=some # `ssh some` to connect
MY_IP=127.0.0.1 # Server IP
touch ~/.ssh/config
echo $'Host $MY_ALIAS\n\tUser $NEWUSER\n\tHostName $MY_IP\n\tPort 22\n\tIdentityFile ~/.ssh/id_some' > ~/.ssh/config
chmod 600 ~/.ssh/config
```

### 1.3 Copy public key
```bash
cat ~/.ssh/id_some.pub
```

### 1.4 Authorize local machine
Return to the server SSH terminal to authorize local machine.

```bash
touch ~/.ssh/authorized_keys
echo "(public key from clipboard)" > ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

### 1.5 Login with SSH key
*Note: Close existing SSH to `root` upon success.*

```bash
ssh some
```

## Chapter 2: SSH
### 2.0 Disable root user
Now that a sudo user exists and can login with SSH, there's no need for the root user.

*Note: Technically, this just makes it impossible to login to root shell. It is possible to fully "disable" root.*

```bash
sudo usermod -s /bin/false root
```

### 2.1 Create SSH group
It's a good habit to limit who can use what by creating specialized groups for programs like SSH.

```bash
sudo addgroup sshers
sudo usermod -a -G sshers $USER
```

### 2.2 Edit `/etc/ssh/sshd_config`
The SSH configuration file.

*Note: See https://infosec.mozilla.org/guidelines/openssh#modern-openssh-67 for latest recommendations.*

*Also note: Duplicate entries in `/etc/ssh/sshd_config` will fail or cause an error. Check existing entries before copying.*

*Also note: If setting `Port #`, closed firewalls will block this port until it is opened. Default SSH port is generally already open. This guide illustrates how to open the port, but closing connection prior might lock the keys forever.*

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

### 2.3 Check for errors in `sshd_config`
Errors will be returned if there are any. Otherwise, successful output will list every entry and value, e.g. `permitrootlogin no`.

```bash
# Successful output will list every entry and value, e.g. `permitrootlogin no`
sudo sshd -T
```

### 2.4 Only use long Diffie-Hellman moduli
*Note: See https://infosec.mozilla.org/guidelines/openssh#intermediate-openssh-53 for latest recommendations.*

```bash
sudo awk '$5 >= 3071' /etc/ssh/moduli | sudo tee /etc/ssh/moduli.tmp
sudo mv /etc/ssh/moduli.tmp /etc/ssh/moduli
```

Optionally, consider also meeting [Mozilla recommendations for SSH *client* on local machine](https://infosec.mozilla.org/guidelines/openssh#configuration-1).

## Chapter 3: Firewall
Use ufw to switch to a block-by-default policy, selecting exactly what is allowed in and out.

### 3.0 Block everything by default in `ufw`
```bash
sudo apt install ufw
sudo ufw default deny outgoing
sudo ufw default deny incoming
```

### 3.1 Allow services out
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

### 3.2 Allow services in
*Note: SSH connections are set to `limit` instead of `allow` to use UFW's built in rate-limiting to prevent attacks.*

```bash
sudo ufw limit in 54321 comment 'SSH' # Replace 54321 by custom SSH port, or ssh if using default
```

### 3.3 Enable UFW
**Before proceeding**, open another SSH connection. `ufw enable` will close current SSH terminal if rules were set incorrectly.

```bash
sudo ufw enable
sudo ufw status
```

## Chapter 4: NTP
Network Time Protocol uses global servers to update system time. Servers rely on accurate system time.

*Note: NTP requires a port to be open, which is specified in Chapter 3: Firewall.*

### 4.0 Edit `/etc/ntp.conf`
Optionally, make the changes by commenting out lines beginning with `server` or `pool`, and add `pool pool.ntp.org iburst` to the end on a new line.

```bash
sudo sed -i -r -e "s/^((server|pool).*)/# \1         # $(whoami) did this on $(date +"%Y-%m-%d %H:%M:%S")" /etc/ntp.conf
echo -e "\npool pool.ntp.org iburst         # $(whoami) did this on $(date +"%Y-%m-%d %H:%M:%S")" /etc/ntp.conf | sudo tee -a /etc/ntp.conf
```

### 4.1 Restart service
To catch errors should they come up.

```bash
sudo service ntp restart # Restarts NTP service, which is running constantly in background
sudo service ntp status # Checks on status of service with latest stdout, will report errors
sudo ntpq -p # Prints NTP peer status
```

## Chapter 5: Email
Setup outgoing mail server to Gmail account. Chapters after this one offer or require the ability to send mail.

*Note: exim4 requires a port to be open, which is specified in Chapter 3: Firewall.*

### 5.0 Install mail server (`exim4`)

`openssl` and `ca-certificates` are also needed to log into Gmail servers.

```bash
sudo apt install exim4 openssl ca-certificates
```

### 5.1 Configure `exim4`

When prompted, continue with the default setting for all but the following options:

| Please enter | ... |
| -- | -- |
| **General type of mail configuration** | `mail sent by smarthost; no local mail` |
| **System mail name** | `localhost` |
| **Visible domain name for local users** | `localhost` |
| **IP-address or host name of the outgoing smarthost** | `smtp.gmail.com::465` |

```bash
sudo dpkg-reconfigure exim4-config
```

### 5.2 Edit `/etc/exim4/passwd.client`

Provide login credentials so `exim4` can send email from your account to itself.

```bash
smtp.gmail.com:address@gmail.com:password
*.google.com:address@gmail.com:password
```

### 5.3 Secure password file

`Debian-exim` is the default group used by `exim4` to send mail.

```bash
sudo chown root:Debian-exim /etc/exim4/passwd.client
sudo chmod 640 /etc/exim4/passwd.client
```

### 5.4 Create login certificate

Create a TLS certificate `exim4` can use to login to Gmail servers.

When prompted, provide the following specific answers:

| []: | .. |
| -- | -- |
| Server name | `localhost` |
| Email Address | `email@gmail.com` |

```bash
sudo bash /usr/share/doc/exim4-base/examples/exim-gencert
```

### 5.5 Login to Gmail

Finally, configure `exim4` to connect to Gmail servers using your account.

```bash
cat << EOF | sudo tee /etc/exim4/exim4.conf.localmacros
MAIN_TLS_ENABLE = 1
REMOTE_SMTP_SMARTHOST_HOSTS_REQUIRE_TLS = *
TLS_ON_CONNECT_PORTS = 465
REQUIRE_PROTOCOL = smtps
IGNORE_SMTP_LINE_LENGTH_LIMIT = true
EOF
sudo sed -i -r -e '/^.ifdef REMOTE_SMTP_SMARTHOST_HOSTS_REQUIRE_TLS$/I { :a; n; /^.endif$/!ba; a\n .ifdef REQUIRE_PROTOCOL\nprotocol = REQUIRE_PROTOCOL\n .endif\n' -e '}' /etc/exim4/exim4.conf.template
sudo sed -i -r -e "/\.ifdef MAIN_TLS_ENABLE/ a\n .ifdef TLS_ON_CONNECT_PORTS\n tls_on_connect_ports = TLS_ON_CONNECT_PORTS\n.endif\n" /etc/exim4/exim4.conf.template
```

### 5.6 Restart `exim4`

```bash
sudo update-exim4.conf
sudo service exim4 restart
```

### 5.7  Send test email

```bash
echo "Test" | mail -s "Test" address@gmail.com
sudo tail /var/log/exim4/mainlog
```

## Chapter 6: File systems
Limit access to `/proc` and `/home` directories, and set default file and folder permissions.

### 6.0 Hide pids in `proc`


### 6.1 Limit `/home` permissions


### 6.2 Set default permissions


## Chapter 7: Reports
Run scans for viruses, monitor intrusions, and more. Email results in human-readable format ondemand and daily.

### 7.0 Daily reports about everything (`logwatch`)


### 7.1 Process accounting (`acct`)


### 7.2 Automatic updates (`unattended-upgrades`)


### 7.3 Antivirus (`clamav`)


### 7.4 Rootkit detection (`rkhunter`, `chkrootkit`)


### 7.5 Host intrusion detection (`ossec`)


### 7.6 App intrusion detection (`fail2ban`)


### 7.7 File system integrity monitoring (`aide`)


## Chapter 8: Kernel `sysctl`
Edit `/etc/sysctl.conf` kernel options to comply with stricter security standards.

### 8.0 Edit `/etc/sysctl.conf`


### 8.1 Test new settings


### 8.2 Restart server


## Chapter 9: Services
TODO

## Chapter 10: Sandboxes
Isolate programs in their own virtual machine to limit access to real resources. The guide uses Firejail, but Docker is a great alternative.

### 10.0 Install `firejail`


### 10.1 Run programs with `firejail`


### 10.2 Create profiles for programs in `firejail`


## Chapter 11: Audit
Check the security of the server by running standardized audit software to report common weaknesses.

### 11.0 `lynis`

## Chapter 98: Keep local system safe
It's fun to set up a `firejail` for every process and receive daily reports about file system integrity, but none of that matters if the local machine used to connect is breached. The SSH key and sudoer password are essential to the security of the system. Systems used to connect should ideally be just as safe as the server itself.

## Chapter 99: Optional extras
There's all sorts of other things to do beyond the scope of this guide. It's just a starting point.

### 99.0 Disk encryption


### 99.1 Separate partitions


### 99.2 Good password policy

