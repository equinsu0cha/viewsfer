# Viewsfer

Remote monitoring & management tool for Windows computers, built with Django and Vue.


### [Discord Chat](https://discord.gg/upGTkWp)

## Features

- Teamviewer-like remote desktop control
- Real-time remote shell
- Remote file browser (download and upload files)
- Remote command and script execution (batch, powershell and python scripts)
- Event log viewer
- Services management
- Windows patch management
- Automated checks with email/SMS alerting (cpu, disk, memory, services, scripts, event logs)
- Automated task runner (run scripts on a schedule)
- Remote software installation via chocolatey
- Software and hardware inventory

## Windows versions supported

- Windows 7, 8.1, 10, Server 2008R2, 2012R2, 2016, 2019

## Installation

### Requirements
- VPS with 4GB ram (an install script is provided for Ubuntu Server 20.04)
- A domain you own with at least 3 subdomains
- Google Authenticator app (2 factor is NOT optional)

### Installation (Ubuntu server 20.04 LTS)

Fresh VPS with latest updates\
login as root and create a user and add to sudoers group (we will be creating a user called vsf)
```
apt update && apt -y upgrade
adduser vsf
usermod -a -G sudo vsf
```

switch to the vsf user and setup the firewall
```
su - vsf
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow http
sudo ufw allow https
sudo ufw allow proto tcp from any to any port 4505,4506
sudo ufw enable && sudo ufw reload
```


In the DNS manager of wherever our domain is hosted, we will create three A records, all pointing to the public IP address of our VPS

Create A record ```api.viewsfer.com``` for the api rest backend\
Create A record ```accounts.viewsfer.com``` for the vue frontend\
Create A record ```console.viewsfer.com``` for meshcentral

Download the install script and run it

```
wget https://raw.githubusercontent.com/Softicious/viewsfer/main/install.sh
chmod +x install.sh
./install.sh
```

 Links will be provided at the end of the install script.\
 Download the executable from the first link, then open ```accounts.viewsfer.com``` and login.\
 Upload the executable when prompted during the initial setup page.


### Install an agent
From the app's dashboard, choose Agents > Install Agent to generate an installer.


## Using another ssl certificate
During the install you can opt out of using the Let's Encrypt certificate. If you do this the script will create a self-signed certificate, so that https continues to work. You can replace the certificates in /certs/example.com/(privkey.pem | pubkey.pem) with your own. 

If you are migrating from Let's Encrypt to another certificate provider, you can create the /certs directory and copy your certificates there. It is recommended to do this because this directory will be backed up with the backup script provided. Then modify the nginx configurations to use your new certificates

The cert that is generated is a wildcard certificate and is used in the nginx configurations: rmm.conf, api.conf, and mesh.conf. If you can't generate wildcard certificates you can create a cert for each subdomain and configure each nginx configuration file to use its own certificate. Then restart nginx:

```
sudo systemctl restart nginx
```