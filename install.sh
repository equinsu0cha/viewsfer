#!/bin/bash


GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

UBU20=$(grep 20.04 "/etc/"*"release")
if ! [[ $UBU20 ]]; then
  echo -ne "\033[0;31mThis script will only work on Ubuntu 20.04\e[0m\n"
  exit 1
fi

if [ $EUID -eq 0 ]; then
  echo -ne "\033[0;31mDo NOT run this script as root. Exiting.\e[0m\n"
  exit 1
fi

if [[ "$LANG" != *".UTF-8" ]]; then
  printf >&2 "\n${RED}System locale must be ${GREEN}<some language>.UTF-8${RED} not ${YELLOW}${LANG}${NC}\n"
  printf >&2 "${RED}Run the following command and change the default locale to your language of choice${NC}\n\n"
  printf >&2 "${GREEN}sudo dpkg-reconfigure locales${NC}\n\n"
  printf >&2 "${RED}You will need to log out and back in for changes to take effect, then re-run this script.${NC}\n\n"
  exit 1
fi

# prevents logging issues with some VPS providers like Vultr if this is a freshly provisioned instance that hasn't been rebooted yet
sudo systemctl restart systemd-journald.service


ADMINURL='vsf'
VSF_USR='vsf'
VSF_PWD='as35673'
VSF_EMAIL='support@viewsfer.com'

apidomain='api.viewsfer.com'
consoledomain='console.viewsfer.com'
accountsdomain='accounts.viewsfer.com'
rootdomain='viewsfer.com'

cls() {
  printf "\033c"
}

print_green() {
  printf >&2 "${GREEN}%0.s-${NC}" {1..80}
  printf >&2 "\n"
  printf >&2 "${GREEN}${1}${NC}\n"
  printf >&2 "${GREEN}%0.s-${NC}" {1..80}
  printf >&2 "\n"
}

cls




# if server is behind NAT we need to add the 3 subdomains to the host file 
# so that nginx can properly route between the frontend, backend and console
# EDIT 8-29-2020
# running this even if server is __not__ behind NAT just to make DNS resolving faster
# this also allows the install script to properly finish even if DNS has not fully propagated
CHECK_HOSTS=$(grep 127.0.1.1 /etc/hosts | grep "$apidomain" | grep "$consoledomain" | grep "$accountsdomain")
HAS_11=$(grep 127.0.1.1 /etc/hosts)

if ! [[ $CHECK_HOSTS ]]; then
    echo -ne "${GREEN}We need to append your 3 subdomains to the line starting with 127.0.1.1 in your hosts file.${NC}\n"
    until [[ $edithosts =~ (y|n) ]]; do
        echo -ne "${GREEN}Would you like me to do this for you? [y/n]${NC}: "
        read edithosts
    done

    if [[ $edithosts == "y" ]]; then
        if [[ $HAS_11 ]]; then
          sudo sed -i "/127.0.1.1/s/$/ ${apidomain} $accountsdomain $consoledomain/" /etc/hosts
        else
          echo "127.0.1.1 ${apidomain} $accountsdomain $consoledomain" | sudo tee --append /etc/hosts > /dev/null
        fi
    else 
        if [[ $HAS_11 ]]; then
          echo -ne "${GREEN}Please manually edit your /etc/hosts file to match the line below and re-run this script.${NC}\n"
          sed "/127.0.1.1/s/$/ ${apidomain} $accountsdomain $consoledomain/" /etc/hosts | grep 127.0.1.1
        else
          echo -ne "\n${GREEN}Append the following line to your /etc/hosts file${NC}\n"
          echo "127.0.1.1 ${apidomain} $accountsdomain $consoledomain"
        fi
        exit 1
    fi
fi


BEHIND_NAT=false
IPV4=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)
if echo "$IPV4" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
    BEHIND_NAT=true 
fi

echo -ne "${YELLOW}Create a username for console${NC}: "


sudo apt install -y software-properties-common
sudo apt update
sudo apt install -y certbot openssl

until [[ $LETS_ENCRYPT =~ (y|n) ]]; do
    echo -ne "${YELLOW}Do you want to generate a Let's Encrypt certificate?[y,n]${NC}: "
    read LETS_ENCRYPT
done
sudo mkdir -p /accounts/certs
if [[ $LETS_ENCRYPT == "y" ]]; then
	
    print_green 'Getting wildcard cert'

    sudo certbot certonly --manual -d *.${rootdomain} --agree-tos --no-bootstrap --manual-public-ip-logging-ok --preferred-challenges dns -m ${VSF_EMAIL} --no-eff-email
    while [[ $? -ne 0 ]]
    do
    sudo certbot certonly --manual -d *.${rootdomain} --agree-tos --no-bootstrap --manual-public-ip-logging-ok --preferred-challenges dns -m ${VSF_EMAIL} --no-eff-email
    done
	

	mv /etc/letsencrypt/live/${rootdomain}/privkey.pem /accounts/certs
	mv /etc/letsencrypt/live/${rootdomain}/fullchain.pem /accounts/certs

else

    read -n 1 -s -r -p "Upload the *.${rootdomain} to /accounts/certs/"
	


fi

CERT_PRIV_KEY=/accounts/certs/privkey.pem
CERT_PUB_KEY=/accounts/certs/fullchain.pem

print_green 'Creating vsfapi user'

sudo adduser --no-create-home --disabled-password --gecos "" vsfapi
echo "vsfapi:${VSF_PWD}" | sudo chpasswd

print_green 'Installing golang'

sudo apt install -y curl wget

sudo mkdir -p /usr/local/accountsgo
go_tmp=$(mktemp -d -t accountsgo-XXXXXXXXXX)
wget https://golang.org/dl/go1.15.linux-amd64.tar.gz -P ${go_tmp}

tar -xzf ${go_tmp}/go1.15.linux-amd64.tar.gz -C ${go_tmp}

sudo mv ${go_tmp}/go /usr/local/accountsgo/
rm -rf ${go_tmp}

print_green 'Installing Nginx'

sudo apt install -y nginx
sudo systemctl stop nginx

print_green 'Installing server_names_hash_bucket_size 128'
hash_bucket_size="$(cat << EOF
server_names_hash_bucket_size = "128"
EOF
)"
echo "${hash_bucket_size}" | tee --append /etc/nginx/nginx.conf > /dev/null


print_green 'Installing NodeJS'

curl -sL https://deb.nodesource.com/setup_12.x | sudo -E bash -
sudo apt update
sudo apt install -y gcc g++ make
sudo apt install -y nodejs

print_green 'Installing MongoDB'

wget -qO - https://www.mongodb.org/static/pgp/server-4.2.asc | sudo apt-key add -
echo "deb [ arch=amd64 ] https://repo.mongodb.org/apt/ubuntu bionic/mongodb-org/4.2 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.2.list
sudo apt update
sudo apt install -y mongodb-org
sudo systemctl enable mongod
sudo systemctl restart mongod

print_green 'Installing Console'

sudo mkdir -p /console/meshcentral-data
sudo chown ${USER}:${USER} -R /console
cd /console
npm install meshcentral
sudo chown ${USER}:${USER} -R /console

meshcfg="$(cat << EOF
{
  "settings": {
    "Cert": "${consoledomain}",
    "MongoDb": "mongodb://127.0.0.1:27017",
    "MongoDbName": "console",
    "WANonly": false,
    "LANonly": false,
    "Minify": 1,
    "Port": 4430,
    "AliasPort": 443,
    "RedirPort": 800,
    "AllowLoginToken": true,
    "AllowFraming": true,
    "AgentPong": 300,
    "AllowHighQualityDesktop": true,
    "TlsOffload": "127.0.0.1",
	"Plugins": { "enabled": true }
    "MaxInvalidLogin": { "time": 5, "count": 5, "coolofftime": 30 }
  },
  "domains": {
    "": {
      "Title": "Viewsfer",
      "Title2": "Console",
      "NewAccounts": false,
      "CertUrl": "https://${consoledomain}:443/",
      "GeoLocation": true,
	  "agentInviteCodes": true,
      "agentNoProxy": true,
      "novnc": true,
      "mstsc": true,
      "CookieIpCheck": false,
	  "consentMessages": {
        "title": "Viewsfer",
        "desktop": "{0} requesting remote desktop access. Grant access?",
        "terminal": "{0} requesting remote terminal access. Grant access?",
        "files": "{0} requesting remote files access. Grant access?"
      },
	  "desktopPrivacyBarText": "Viewsfer.com uses cookies. By using our site you agree to our privacy policy.",
      "httpheaders": {
        "Strict-Transport-Security": "max-age=360000",
        "x-frame-options": "sameorigin",
        "Content-Security-Policy": "default-src 'none'; script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-src 'self'; media-src 'self'"
      }
    }
  }
}
EOF
)"
echo "${meshcfg}" > /console/meshcentral-data/config.json

print_green 'Installing python, redis and git'

sudo apt update
sudo apt install -y python3.8-venv python3.8-dev python3-pip python3-cherrypy3 python3-setuptools python3-wheel ca-certificates redis git

print_green 'Installing postgresql'

sudo sh -c 'echo "deb https://apt.postgresql.org/pub/repos/apt/ $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list'
wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo apt-key add -
sudo apt update
sudo apt install -y postgresql-13

print_green 'Creating database for the accounts'

sudo -u postgres psql -c "CREATE DATABASE viewsfer"
sudo -u postgres psql -c "CREATE USER ${VSF_USR} WITH PASSWORD '${VSF_PWD}'"
sudo -u postgres psql -c "ALTER ROLE ${VSF_USR} SET client_encoding TO 'utf8'"
sudo -u postgres psql -c "ALTER ROLE ${VSF_USR} SET default_transaction_isolation TO 'read committed'"
sudo -u postgres psql -c "ALTER ROLE ${VSF_USR} SET timezone TO 'UTC'"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE viewsfer TO ${VSF_USR}"

# sudo mkdir /accounts
# sudo chown ${USER}:${USER} /accounts
# sudo mkdir -p /var/log/celery
# sudo chown ${USER}:${USER} /var/log/celery
# git clone https://github.com/wh1te909/viewsfer.git /accounts/
cd /accounts


localvars="$(cat << EOF
SECRET_KEY = "${VSF_PWD}"

DEBUG = False

ALLOWED_HOSTS = ['${apidomain}']

ADMIN_URL = "${ADMINURL}/"

CORS_ORIGIN_WHITELIST = [
    "https://${accountsdomain}"
]

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'viewsfer',
        'USER': '${VSF_USR}',
        'PASSWORD': '${VSF_PWD}',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}

REST_FRAMEWORK = {
    'DATETIME_FORMAT': "%b-%d-%Y - %H:%M",

    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'knox.auth.TokenAuthentication',
    ),
}

if not DEBUG:
    REST_FRAMEWORK.update({
        'DEFAULT_RENDERER_CLASSES': (
            'rest_framework.renderers.JSONRenderer',
        )
    })

SALT_USERNAME = "vsfapi"
SALT_PASSWORD = "${VSF_PWD}"
SALT_HOST     = "127.0.0.1"
MESH_USERNAME = "${VSF_USR}"
MESH_SITE = "https://${consoledomain}"
REDIS_HOST    = "localhost"
EOF
)"
echo "${localvars}" > /accounts/api/viewsfer/viewsfer/local_settings.py

/usr/local/accountsgo/go/bin/go get github.com/josephspurrier/goversioninfo/cmd/goversioninfo
sudo cp /accounts/api/viewsfer/core/goinstaller/bin/goversioninfo /usr/local/bin/
sudo chown ${USER}:${USER} /usr/local/bin/goversioninfo
sudo chmod +x /usr/local/bin/goversioninfo

print_green 'Installing the backend'

cd /accounts/api
python3 -m venv env
source /accounts/api/env/bin/activate
cd /accounts/api/viewsfer
pip install --no-cache-dir --upgrade pip
pip install --no-cache-dir setuptools==49.6.0 wheel==0.35.1
pip install --no-cache-dir -r /accounts/api/viewsfer/requirements.txt
python manage.py migrate
python manage.py collectstatic --no-input
python manage.py load_chocos
python manage.py load_community_scripts
printf >&2 "${YELLOW}%0.s*${NC}" {1..80}
printf >&2 "\n"
printf >&2 "${YELLOW}Please create your login for the RMM website and django admin${NC}\n"
printf >&2 "${YELLOW}%0.s*${NC}" {1..80}
printf >&2 "\n"
echo -ne "Username: "
python manage.py createsuperuser --username ${VSF_USR} --email ${VSF_EMAIL}
RANDBASE=$(python manage.py generate_totp)
cls
python manage.py generate_barcode ${RANDBASE} ${VSF_USR} ${accountsdomain}
deactivate
read -n 1 -s -r -p "Press any key to continue..."


uwsgini="$(cat << EOF
[uwsgi]

logto = /accounts/api/viewsfer/viewsfer/private/log/uwsgi.log
chdir = /accounts/api/viewsfer
module = viewsfer.wsgi
home = /accounts/api/env
master = true
processes = 6
threads = 6
enable-threads = True
socket = /accounts/api/viewsfer/viewsfer.sock
harakiri = 300
chmod-socket = 660
# clear environment on exit
vacuum = true
die-on-term = true
max-requests = 500
max-requests-delta = 1000
EOF
)"
echo "${uwsgini}" > /accounts/api/viewsfer/app.ini


accountsservice="$(cat << EOF
[Unit]
Description=viewsfer uwsgi daemon
After=network.target

[Service]
User=${USER}
Group=www-data
WorkingDirectory=/accounts/api/viewsfer
Environment="PATH=/accounts/api/env/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=/accounts/api/env/bin/uwsgi --ini app.ini
Restart=always
RestartSec=10s

[Install]
WantedBy=multi-user.target
EOF
)"
echo "${accountsservice}" | sudo tee /etc/systemd/system/accounts.service > /dev/null


nginxaccounts="$(cat << EOF
server_tokens off;

upstream viewsfer {
    server unix:////accounts/api/viewsfer/viewsfer.sock;
}

server {
    listen 80;
    server_name ${apidomain};
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl;
    server_name ${apidomain};
    client_max_body_size 300M;
    access_log /accounts/api/viewsfer/viewsfer/private/log/access.log;
    error_log /accounts/api/viewsfer/viewsfer/private/log/error.log;
    ssl_certificate ${CERT_PUB_KEY};
    ssl_certificate_key ${CERT_PRIV_KEY};
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';

    location /static/ {
        root /accounts/api/viewsfer;
    }

    location /private/ {
        internal;
        add_header "Access-Control-Allow-Origin" "https://${accountsdomain}";
        alias /accounts/api/viewsfer/viewsfer/private/;
    }

    location /saltscripts/ {
        internal;
        add_header "Access-Control-Allow-Origin" "https://${accountsdomain}";
        alias /accounts/api/salt/scripts/userdefined/;
    }

    location /builtin/ {
        internal;
        add_header "Access-Control-Allow-Origin" "https://${accountsdomain}";
        alias /softicious/salt/scripts/;
    }


    location / {
        uwsgi_pass  viewsfer;
        include     /etc/nginx/uwsgi_params;
        uwsgi_read_timeout 9999s;
        uwsgi_ignore_client_abort on;
    }
}
EOF
)"
echo "${nginxaccounts}" | sudo tee /etc/nginx/sites-available/accounts.conf > /dev/null


nginxmesh="$(cat << EOF
server {
  listen 80;
  server_name ${consoledomain};
  location / {
     proxy_pass http://127.0.0.1:800;
     proxy_http_version 1.1;
     proxy_set_header X-Forwarded-Host \$host:\$server_port;
     proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
     proxy_set_header X-Forwarded-Proto \$scheme;
  }

}

server {

    listen 443 ssl;
    proxy_send_timeout 330s;
    proxy_read_timeout 330s;
    server_name ${consoledomain};
    ssl_certificate ${CERT_PUB_KEY};
    ssl_certificate_key ${CERT_PRIV_KEY};
    ssl_session_cache shared:WEBSSL:10m;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    location / {
        proxy_pass http://127.0.0.1:4430/;
        proxy_http_version 1.1;

        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Forwarded-Host \$host:\$server_port;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
)"
echo "${nginxmesh}" | sudo tee /etc/nginx/sites-available/console.conf > /dev/null

sudo ln -s /etc/nginx/sites-available/accounts.conf /etc/nginx/sites-enabled/accounts.conf
sudo ln -s /etc/nginx/sites-available/console.conf /etc/nginx/sites-enabled/console.conf

print_green 'Installing Salt Master'

wget -O - https://repo.saltstack.com/py3/ubuntu/20.04/amd64/latest/SALTSTACK-GPG-KEY.pub | sudo apt-key add -
echo 'deb http://repo.saltstack.com/py3/ubuntu/20.04/amd64/latest focal main' | sudo tee /etc/apt/sources.list.d/saltstack.list

sudo apt update
sudo apt install -y salt-master

print_green 'Waiting 30 seconds for salt to start'
sleep 30

saltvars="$(cat << EOF
timeout: 20
worker_threads: 15
gather_job_timeout: 25
max_event_size: 30485760
external_auth:
  pam:
    vsfapi:
      - .*
      - '@runner'
      - '@wheel'
      - '@jobs'

rest_cherrypy:
  port: 8123
  disable_ssl: True
  max_request_body_size: 30485760
  thread_pool: 300
  socket_queue_size: 100

EOF
)"
echo "${saltvars}" | sudo tee /etc/salt/master.d/accounts-salt.conf > /dev/null

# fix the stupid 1 MB limit present in msgpack 0.6.2, which btw was later changed to 100 MB in msgpack 1.0.0
# but 0.6.2 is the default on ubuntu 20
sudo sed -i 's/msgpack_kwargs = {"raw": six.PY2}/msgpack_kwargs = {"raw": six.PY2, "max_buffer_size": 2147483647}/g' /usr/lib/python3/dist-packages/salt/transport/ipc.py



print_green 'Installing Salt API'
sudo apt install -y salt-api

sudo mkdir /etc/conf.d

celeryservice="$(cat << EOF
[Unit]
Description=Celery Service
After=network.target
After=redis-server.service

[Service]
Type=forking
User=${USER}
Group=${USER}
EnvironmentFile=/etc/conf.d/celery.conf
WorkingDirectory=/accounts/api/viewsfer
ExecStart=/bin/sh -c '\${CELERY_BIN} multi start \${CELERYD_NODES} -A \${CELERY_APP} --pidfile=\${CELERYD_PID_FILE} --logfile=\${CELERYD_LOG_FILE} --loglevel=\${CELERYD_LOG_LEVEL} \${CELERYD_OPTS}'
ExecStop=/bin/sh -c '\${CELERY_BIN} multi stopwait \${CELERYD_NODES} --pidfile=\${CELERYD_PID_FILE}'
ExecReload=/bin/sh -c '\${CELERY_BIN} multi restart \${CELERYD_NODES} -A \${CELERY_APP} --pidfile=\${CELERYD_PID_FILE} --logfile=\${CELERYD_LOG_FILE} --loglevel=\${CELERYD_LOG_LEVEL} \${CELERYD_OPTS}'
Restart=always
RestartSec=10s

[Install]
WantedBy=multi-user.target
EOF
)"
echo "${celeryservice}" | sudo tee /etc/systemd/system/celery.service > /dev/null

celeryconf="$(cat << EOF
CELERYD_NODES="w1"

CELERY_BIN="/accounts/api/env/bin/celery"

CELERY_APP="viewsfer"

CELERYD_MULTI="multi"

CELERYD_OPTS="--time-limit=2900 --autoscale=50,5"

CELERYD_PID_FILE="/accounts/api/viewsfer/%n.pid"
CELERYD_LOG_FILE="/var/log/celery/%n%I.log"
CELERYD_LOG_LEVEL="INFO"

CELERYBEAT_PID_FILE="/accounts/api/viewsfer/beat.pid"
CELERYBEAT_LOG_FILE="/var/log/celery/beat.log"
EOF
)"
echo "${celeryconf}" | sudo tee /etc/conf.d/celery.conf > /dev/null

celerywinupdatesvc="$(cat << EOF
[Unit]
Description=Celery WinUpdate Service
After=network.target
After=redis-server.service

[Service]
Type=forking
User=${USER}
Group=${USER}
EnvironmentFile=/etc/conf.d/celery-winupdate.conf
WorkingDirectory=/accounts/api/viewsfer
ExecStart=/bin/sh -c '\${CELERY_BIN} multi start \${CELERYD_NODES} -A \${CELERY_APP} --pidfile=\${CELERYD_PID_FILE} --logfile=\${CELERYD_LOG_FILE} --loglevel=\${CELERYD_LOG_LEVEL} -Q wupdate \${CELERYD_OPTS}'
ExecStop=/bin/sh -c '\${CELERY_BIN} multi stopwait \${CELERYD_NODES} --pidfile=\${CELERYD_PID_FILE}'
ExecReload=/bin/sh -c '\${CELERY_BIN} multi restart \${CELERYD_NODES} -A \${CELERY_APP} --pidfile=\${CELERYD_PID_FILE} --logfile=\${CELERYD_LOG_FILE} --loglevel=\${CELERYD_LOG_LEVEL} -Q wupdate \${CELERYD_OPTS}'
Restart=always
RestartSec=10s

[Install]
WantedBy=multi-user.target
EOF
)"
echo "${celerywinupdatesvc}" | sudo tee /etc/systemd/system/celery-winupdate.service > /dev/null

celerywinupdate="$(cat << EOF
CELERYD_NODES="w2"

CELERY_BIN="/accounts/api/env/bin/celery"
CELERY_APP="viewsfer"
CELERYD_MULTI="multi"

CELERYD_OPTS="--time-limit=4000 --autoscale=40,1"

CELERYD_PID_FILE="/accounts/api/viewsfer/%n.pid"
CELERYD_LOG_FILE="/var/log/celery/%n%I.log"
CELERYD_LOG_LEVEL="ERROR"
EOF
)"
echo "${celerywinupdate}" | sudo tee /etc/conf.d/celery-winupdate.conf > /dev/null

celerybeatservice="$(cat << EOF
[Unit]
Description=Celery Beat Service
After=network.target
After=redis-server.service

[Service]
Type=simple
User=${USER}
Group=${USER}
EnvironmentFile=/etc/conf.d/celery.conf
WorkingDirectory=/accounts/api/viewsfer
ExecStart=/bin/sh -c '\${CELERY_BIN} beat -A \${CELERY_APP} --pidfile=\${CELERYBEAT_PID_FILE} --logfile=\${CELERYBEAT_LOG_FILE} --loglevel=\${CELERYD_LOG_LEVEL}'
Restart=always
RestartSec=10s

[Install]
WantedBy=multi-user.target
EOF
)"
echo "${celerybeatservice}" | sudo tee /etc/systemd/system/celerybeat.service > /dev/null

sudo mkdir -p /softicious/salt
sudo cp -r /accounts/_modules /softicious/salt/
sudo cp -r /accounts/scripts /softicious/salt/
sudo mkdir /softicious/salt/scripts/userdefined
sudo chown ${USER}:${USER} -R /softicious/salt/
sudo chown ${USER}:www-data /softicious/salt/scripts/userdefined
sudo chmod 750 /softicious/salt/scripts/userdefined
sudo chown ${USER}:${USER} -R /etc/conf.d/

meshservice="$(cat << EOF
[Unit]
Description=MeshCentral Server
After=network.target
After=mongod.service
After=nginx.service
[Service]
Type=simple
LimitNOFILE=1000000
ExecStart=/usr/bin/node node_modules/console
Environment=NODE_ENV=production
WorkingDirectory=/console
User=${USER}
Group=${USER}
Restart=always
RestartSec=10s

[Install]
WantedBy=multi-user.target
EOF
)"
echo "${meshservice}" | sudo tee /etc/systemd/system/console.service > /dev/null

sudo systemctl daemon-reload


sudo systemctl enable salt-master
sudo systemctl enable salt-api

sudo systemctl restart salt-api

sudo chown -R $USER:$GROUP /home/${USER}/.npm
sudo chown -R $USER:$GROUP /home/${USER}/.config

quasarenv="$(cat << EOF
PROD_URL = "https://${apidomain}"
DEV_URL = "https://${apidomain}"
EOF
)"
echo "${quasarenv}" | tee /accounts/web/.env > /dev/null

print_green 'Installing the accounts'

cd /accounts/web
npm install
npm run build

sudo chown www-data:www-data -R /accounts/web/dist

nginxfrontend="$(cat << EOF
server {
    server_name ${accountsdomain};
    charset utf-8;
    location / {
        root /accounts/web/dist;
        try_files \$uri \$uri/ /index.html;
        add_header Cache-Control "no-store, no-cache, must-revalidate";
        add_header Pragma "no-cache";
    }
    error_log  /var/log/nginx/accounts-error.log;
    access_log /var/log/nginx/accounts-access.log;

    listen 443 ssl;
    ssl_certificate ${CERT_PUB_KEY};
    ssl_certificate_key ${CERT_PRIV_KEY};
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';
}

server {
    if (\$host = ${accountsdomain}) {
        return 301 https://\$host\$request_uri;
    }

    listen      80;
    server_name ${accountsdomain};
    return 404;
}
EOF
)"
echo "${nginxfrontend}" | sudo tee /etc/nginx/sites-available/accounts.conf > /dev/null

sudo ln -s /etc/nginx/sites-available/accounts.conf /etc/nginx/sites-enabled/accounts.conf


print_green 'Enabling Services'

for i in nginx celery.service celerybeat.service celery-winupdate.service accounts.service
do
  sudo systemctl enable ${i}
  sudo systemctl restart ${i}
done
sleep 5
sudo systemctl enable console

print_green 'Starting console and waiting for it to install plugins'

sudo systemctl restart console

sleep 3

# The first time we start console, it will need some time to generate certs and install plugins.
# This will take anywhere from a few seconds to a few minutes depending on the server's hardware
# We will know it's ready once the last line of the systemd service stdout is 'MeshCentral HTTP server running on port.....'
while ! [[ $CHECK_MESH_READY ]]; do
  CHECK_MESH_READY=$(sudo journalctl -u console.service -b --no-pager | grep "MeshCentral HTTP server running on port")
  echo -ne "${GREEN}Mesh Central not ready yet...${NC}\n"
  sleep 3
done

print_green 'Generating console login token key'

MESHTOKENKEY=$(node /console/node_modules/meshcentral --logintokenkey)

meshtoken="$(cat << EOF
MESH_TOKEN_KEY = "${MESHTOKENKEY}"
EOF
)"
echo "${meshtoken}" | tee --append /accounts/api/viewsfer/viewsfer/local_settings.py > /dev/null


print_green 'Creating console account and group'

sudo systemctl stop console
sleep 3
cd /console

node node_modules/meshcentral --createaccount ${VSF_USR} --pass ${VSF_PWD} --email ${VSF_EMAIL}
sleep 2
node node_modules/meshcentral --adminaccount ${VSF_USR}

sudo systemctl start console
sleep 5

while ! [[ $CHECK_MESH_READY2 ]]; do
  CHECK_MESH_READY2=$(sudo journalctl -u console.service -b --no-pager | grep "MeshCentral HTTP server running on port")
  echo -ne "${GREEN}Mesh Central not ready yet...${NC}\n"
  sleep 3
done

node node_modules/meshcentral/meshctrl.js --url wss://${consoledomain}:443 --loginuser ${VSF_USR} --loginpass ${VSF_PWD} AddDeviceGroup --name Viewsfer
sleep 5
MESHEXE=$(node node_modules/meshcentral/meshctrl.js --url wss://${consoledomain}:443 --loginuser ${VSF_USR} --loginpass ${VSF_PWD} GenerateInviteLink --group Viewsfer --hours 8)

cd /accounts/api/viewsfer
source /accounts/api/env/bin/activate
python manage.py initial_db_setup
deactivate


print_green 'Restarting services'
for i in celery.service celerybeat.service celery-winupdate.service accounts.service
do
  sudo systemctl restart ${i}
done

print_green 'Restarting salt-master and waiting 30 seconds'
sudo systemctl restart salt-master
sleep 30
sudo systemctl restart salt-api

printf >&2 "${YELLOW}%0.s*${NC}" {1..80}
printf >&2 "\n\n"
printf >&2 "${YELLOW}Installation complete!${NC}\n\n"
printf >&2 "${YELLOW}Download the viewsfer agent 64 bit EXE from:\n\n${GREEN}"
echo ${MESHEXE} | sed 's/{.*}//'
printf >&2 "${NC}\n\n"
printf >&2 "${YELLOW}Access your accounts at: ${GREEN}https://${accountsdomain}${NC}\n\n"
printf >&2 "${YELLOW}Api admin url: ${GREEN}https://${apidomain}/${ADMINURL}${NC}\n\n"
printf >&2 "${YELLOW}Console password: ${GREEN}${VSF_PWD}${NC}\n\n"

if [ "$BEHIND_NAT" = true ]; then
    echo -ne "${YELLOW}Read below if your router does NOT support Hairpin NAT${NC}\n\n"  
    echo -ne "${GREEN}If you will be accessing the web interface of the RMM from the same LAN as this server,${NC}\n"
    echo -ne "${GREEN}you'll need to make sure your 3 subdomains resolve to ${IPV4}${NC}\n"
    echo -ne "${GREEN}This also applies to any agents that will be on the same local network as the accounts.${NC}\n"
    echo -ne "${GREEN}You'll also need to setup port forwarding in your router on ports 80, 443, 4505 and 4506 tcp.${NC}\n\n"
fi

printf >&2 "${YELLOW}Please refer to the github README for next steps${NC}\n\n"
printf >&2 "${YELLOW}%0.s*${NC}" {1..80}
printf >&2 "\n"
