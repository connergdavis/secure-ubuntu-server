# Secure Ubuntu Server

## Table of Contents

### Chapter 0: [Beginning](#beginning)

Update, create secure sudo user, and disable root access.

  - 0.1 [SSH to root account](#ssh-to-root-account)
  - 0.2 [Update Ubuntu packagers](#update-ubuntu-packages)
  - 0.3 [Create secure password](#create-secure-password)
  - 0.4 [Create sudo user](#create-sudo-user)
  - 0.5 [Limit `su` command](#limit-su-command)
  - 0.6 [Disable root user](#disable-root-user)

### Chapter 1: [SSH](#ssh)

Create SSH key login for local machine.

**Note**: `id_some`, `id_some.pub`, and `config` all belong on local machine. Server only needs `authorized_keys`.

  - 1.1 [Generate SSH key](#generate-ssh-key)
  - 1.2 [Set safer permissions](#set-safer-permissions)
  - 1.3 [Create alias](#create-alias)
  - 1.4 [Authorize local machine](#authorize-local-machine)
  - 1.5 [Login with SSH key](#login-with-ssh-key)

### Chapter 2: [Harden SSH](#harden-ssh)

Tweak `sshd`'s configuration to provide much better security.

  - 2.1 [Create SSH group](#create-ssh-group)
  - 2.2 [Edit `/etc/ssh/sshd_config`](#edit-etcsshsshd_config)
  - 2.3 [Check for errors in `sshd_config`](check-for-errors-in-sshd_config)
  - 2.4 [Only use long Diffie-Hellman moduli](only-use-long-diffie-hellman-moduli)
  - 2.5 # TODO PAM

### Chapter 3: [Firewall](#firewall)

Use `ufw` to switch to a block-by-default policy, selecting exactly what is allowed in and out.

  - 3.1 [Block everything by default in `ufw`](#block-everything-by-default-in-ufw)
  - 3.2 [Allow services out](#allow-services-out)
  - 3.3 [Allow services in](#allow-services-in)
  - 3.4 [Enable UFW](#enable-ufw)

### Chapter 4: [NTP](#ntp)

Sync server to Internet time with **Network Time Protocol**. Servers rely on accurate system time.

*Note: NTP requires a port to be open, which is specified in Chapter 3: Firewall.*

  - 4.1 [Edit `/etc/ntp.conf`](#edit-etcntpconf)
  - 4.2 [Restart service](#restart-service)

### Chapter 5: [Email](#email)

Setup outgoing mail server to Gmail account. Chapters after this one offer or require the ability to send mail.

*Note: exim4 requires a port to be open, which is specified in Chapter 3: Firewall.*

  - 5.1 [Install mail server (`exim4`)](#install-mail-server-exim4) # TODO
  - 5.2 [Send test email](#send-test-email) # TODO

### Chapter 6: [File Systems](#file-systems)

Limit access to `/proc`, which can contain sensitive info, restrict `/home` directories, set default umasks.

  - 6.1 [Hide pids in `/proc`](#hide-pids-in-proc) # TODO
  - 6.2 [Limit `/home` permissions](#home-permissions) # TODO
  - 6.3 [Set default umasks](#default-umasks) # TODO

### Chapter 7: [Reports](#logging)

Run scans for viruses, intrusions and more, and email results in human-readable format ondemand and daily.

  - 7.1 [Daily reports about everything (`logwatch`)](#daily-reports-about-everything-logwatch)
  - 7.2 [Process accounting (`acct`)](#process-accounting)
  - 7.3 [Automatic updates (`unattended-upgrades`)](#automatic-updates-unattended-upgrades)
  - 7.4 [Antivirus (`clamav`)](#antivirus-clamav)
  - 7.5 [Rootkit detection (`rkhunter`, `chkrootkit`)](#rootkit-detection-rkhunter-chkrootkit)
  - 7.6 [Host intrusion detection (`ossec`)](#host-intrusion-detection-ossec)
  - 7.4 [App intrusion detection (`fail2ban`)](#app-intrusion-detection-fail2ban)
  - 7.5 [File system integrity monitoring (`aide`)](#file-system-integrity-monitoring-aide)
  - 7.6 [ARP monitoring (`arpwatch`)](#arp-monitoring-arpwatch)

### Chapter 8: [Harden kernel](#harden-kernel)

### Chapter 9: [Harden services](#harden-services)

### Chapter 10: [Sandbox processes](#sandbox-processes)

### Chapter 11: [Audit](#audit)

### Chapter 98: [Keep local system safe](#keep-local-system-safe)

It's fun to set up a `firejail` for every process and receive daily reports about file system integrity, but none of that matters if the local machine used to connect is breached. The SSH key and sudoer password are essential to the security of the system. Systems used to connect should ideally be just as safe as the server itself.

### Chapter 99: [Optional extras](#optional-extras)

There are a lot more things you can do to tighten up a server, but they are a little more opinionated.

- You *can* use disk encryption, but that only helps if someone breaks in and steals your PC;
- You *may be able to* create separate partitions for `/home`, `/var`, etc., but VPS images may install automatically, preventing this;
- You *could* set a password reset age, but with a sufficiently long password will this really help?
- And many more.

Here are some useful extra avenues with their benefits and drawbacks.

  - 99.1 [Disk encryption](#disk-encryption)
  - 99.2 [Separate partitions](#separate-partitions)
  - 99.3 [Verify `ntpq` peers](#verify-ntpq-peers)

## Beginning

Update, create secure sudo user, and disable root access.

#### SSH to root account

Begin on a trusted local device.

```bash
ssh root@127.0.0.1 # 127.0.0.1 is server IP
```

### Update Ubuntu packages

```bash
apt update
apt upgrade
```

### Create secure password

A password manager should ideally be used to control server passwords. We want passwords that are ridiculously difficult to crack and like to isolate different purposes of the server to different accounts (so lots of passwords). 

### Create sudo user

By default, `sudo` gives users in the group `sudo` full permission. It may not exist yet, that's OK.

```bash
NEWUSER=`openssl rand -hex 12` # Create random username
addgroup sudo # Create group for sudoers (only for this account)
adduser $NEWUSER # Create new user
usermod -a -G sudo $NEWUSER # Add user to sudoers group
passwd $NEWUSER # Update their password
su - $NEWUSER # Login to new account
```

### Limit `su` command

With a `sudo` user now in place, limit use of `su` to just them.

```bash
sudo addgroup suers
sudo usermod -a -G suers $USER
sudo dpkg-statoverride --update --add root suers 4750 /bin/su
```

## SSH

Create SSH key login for local machine.

**Note**: `id_some`, `id_some.pub`, and `config` all belong on local machine. Server only needs `authorized_keys`.

### Generate SSH key

Create an email address for the server, especially since logs will be emailed too.

*Note: When prompted, "Enter a file in which to save the key", provide path: `/home/$USER/.ssh/id_some` where `some` is anything.*

```bash
# When prompted, "Enter a file in which to save the key", 
# provide path: `/home/$USER/.ssh/id_some` where `some` is anything
ssh-keygen -t ed25519 -C "email@example.com" # Generate SSH keypair
ssh-add ~/.ssh/id_some # Register new keypair with sshd
```

### Set safer permissions

```bash
chmod 644 ~/.ssh/id_some.pub # Limit public key access
chmod 600 ~/.ssh/id_some
chmod 700 ~/.ssh
```

### Create alias

Allows connection via `ssh some` instead of `ssh user:ip`.

```bash
MY_ALIAS=some # `ssh some` to connect
MY_IP=127.0.0.1 # Server IP
touch ~/.ssh/config
echo $'Host $MY_ALIAS\n\tUser $NEWUSER\n\tHostName $MY_IP\n\tPort 22\n\tIdentityFile ~/.ssh/id_some' > ~/.ssh/config
chmod 600 ~/.ssh/config
```

### Copy public key

```bash
cat ~/.ssh/id_some.pub
```

### Authorize local machine

Return to the server SSH terminal to authorize local machine.

```bash
touch ~/.ssh/authorized_keys
echo "(public key from clipboard)" > ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

### Login with SSH key

*Note: Close existing SSH to `root` upon success.*

```bash
ssh some
```

## Harden SSH

### Disable root user

Now that a sudo user exists and can login with SSH, there's no need for the root user.

*Note: Technically, this just makes it impossible to login to root shell. It is possible to fully "disable" root.*

```bash
sudo usermod -s /bin/false root
```

### Create SSH group

It's a good habit to limit who can use what by creating specialized groups for programs like SSH.

```bash
sudo addgroup sshers
sudo usermod -a -G sshers $USER
```

### Edit `/etc/ssh/sshd_config`

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

### Check for errors in `sshd_config`

Errors will be returned if there are any. Otherwise, successful output will list every entry and value, e.g. `permitrootlogin no`.

```bash
# Successful output will list every entry and value, e.g. `permitrootlogin no`
sudo sshd -T
```

### Only use long Diffie-Hellman moduli

*Note: See https://infosec.mozilla.org/guidelines/openssh#intermediate-openssh-53 for latest recommendations.*

```bash
sudo awk '$5 >= 3071' /etc/ssh/moduli | sudo tee /etc/ssh/moduli.tmp
sudo mv /etc/ssh/moduli.tmp /etc/ssh/moduli
```

Optionally, consider also meeting [Mozilla recommendations for SSH *client* on local machine](https://infosec.mozilla.org/guidelines/openssh#configuration-1).

## Firewall

Use ufw to switch to a block-by-default policy, selecting exactly what is allowed in and out.

### Block everything by default in `ufw`

```bash
sudo apt install ufw
sudo ufw default deny outgoing
sudo ufw default deny incoming
```

### Allow services out

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

### Allow services in

*Note: SSH connections are set to `limit` instead of `allow` to use UFW's built in rate-limiting to prevent attacks.*

```bash
sudo ufw limit in 54321 comment 'SSH' # Replace 54321 by custom SSH port, or ssh if using default
```

### Enable UFW

**Before proceeding**, open another SSH connection. `ufw enable` will close current SSH terminal if rules were set incorrectly.

```bash
sudo ufw enable
sudo ufw status
```

## NTP

**Network Time Protocol** uses global servers to update system time. Servers rely on accurate system time.

*Note: NTP requires a port to be open, which is specified in Chapter 3: Firewall.*

### Edit `/etc/ntp.conf`

Optionally, make the changes by commenting out lines beginning with `server` or `pool`, and add `pool pool.ntp.org iburst` to the end on a new line.

```bash
sudo sed -i -r -e "s/^((server|pool).*)/# \1         # $(whoami) did this on $(date +"%Y-%m-%d %H:%M:%S")" /etc/ntp.conf
echo -e "\npool pool.ntp.org iburst         # $(whoami) did this on $(date +"%Y-%m-%d %H:%M:%S")" /etc/ntp.conf | sudo tee -a /etc/ntp.conf
```

### Restart service

To catch errors should they come up.

```bash
sudo service ntp restart # Restarts NTP service, which is running constantly in background
sudo service ntp status # Checks on status of service with latest stdout, will report errors
sudo ntpq -p # Prints NTP peer status
```

## Email

Setup outgoing mail server to Gmail account. Chapters after this one offer or require the ability to send mail.

*Note: exim4 requires a port to be open, which is specified in Chapter 3: Firewall.*

### Install mail server (`exim4`)

### Send test email

## File Systems

Limit access to `/proc`, which can contain sensitive info, restrict `/home` directories, set default umasks.

### Hide pids in `proc`

### Limit `/home` permissions

### Set default umasks

## Chapter 7: Reports

Run scans for viruses, intrusions and more, and email results in human-readable format ondemand and daily.

### 7.1 Daily reports about everything (`logwatch`)
### 7.2 Process accounting (`acct`)
### 7.3 Automatic updates (`unattended-upgrades`)
### 7.4 Antivirus (`clamav`)
### 7.5 Rootkit detection (`rkhunter`, `chkrootkit`)
### 7.6 Host intrusion detection (`ossec`)
### 7.7 App intrusion detection (`fail2ban`)
### 7.8 File system integrity monitoring (`aide`)

## Chapter 99: Optional extras

There are a lot more things you can do to tighten up a server, but they are a little more opinionated.

- You *can* use disk encryption, but that only helps if someone breaks in and steals your PC;
- You *may be able to* create separate partitions for `/home`, `/var`, etc., but VPS images may install automatically, preventing this;
- You *could* set a password reset age, but with a sufficiently long password will this really help?
- And many more.

Here are some useful extra avenues with their benefits and drawbacks.

### 99.1 Disk encryption

#TODO

### 99.2 Separate partitions
