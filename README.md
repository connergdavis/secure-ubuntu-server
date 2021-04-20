# "Secure" Ubuntu Server
## <strong>Please read this before proceeding to the guide.</strong>
## Disclaimer
1. I am not a security professional
2. I have no formal education in information security
3. I am not an expert on the following topics
4. All my knowledge comes from free online resources
5. You should not execute the commands in the guide without understanding them
6. You should follow this guide completely in an environment that can stop working or completely lock up at any time without consequence, prior to a production environment

## Motivation
I am a software engineer who wants to run servers that are "secure". I assumed the default settings were probably bad and started researching what the professionals recommend.

## Target audience
This guide is intended as a starting point for people who want to run a server or two and thought learning security would be nice.

You may not be that person, and this guide may still be helpful. That's just where I'm coming from.

## Requirements
#### A computer with
- Ubuntu 20.04
- Internet
- ??? storage
  - New machines use 4 GB *in my experience*
- ??? RAM
  - I have completed this guide with as little as 2 GB *personally*

## Recommended
### Recovery
There are several ways to recover a broken system.

**If the machine doesn't run**, external backups can restore everything<br>
**If it still runs**, VNC will let you connect to a shell, circumventing SSH issues
- However if the machine blocks VNC port this will not work,
- And VNC can also be considered a massive security issue of its own

**If it's a virtual machine**, you can create restore points at different stages to prevent total loss

### Basic Linux experience
- `su` and `sudo`
- Root vs. normal users
- SSH, SSH keys
- Shell text editors
  - I use `nano`
- `echo`, `cd`, `chmod`, `chown`, `ls`, `awk`, `sed`, `grep`, etc.
- `systemctl` services
- File permissions

### Basic networking experience
- Ports
- Firewalls

