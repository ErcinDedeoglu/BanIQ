repomix --no-file-summary --no-security-check \
  --include "src/**" \
  --output "repopack.yml"


docker build -t dublok/baniq:latest -f src/Dockerfile .

# Run BanIQ
docker run -d \
  --name baniq \
  --restart unless-stopped \
  --network host \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  -v /var/run/docker.sock:/var/run/docker.sock \
  dublok/baniq:latest

# Example protected container
docker run -d \
  --name nginx \
  -p 80:80 \
  --label baniq.enabled=true \
  --label baniq.nginx.logpath=/var/log/nginx/access.log \
  --label baniq.nginx.filter=nginx-auth \
  --label baniq.nginx.maxretry=5 \
  nginx

# Example container labels
baniq.enabled: "true"
baniq.nginx.logpath: "/var/log/nginx/access.log"
baniq.nginx.filter: "nginx-auth"
baniq.nginx.findtime: "10m"
baniq.nginx.maxretry: "5"
baniq.nginx.bantime: "1h"
baniq.nginx.port: "80,443"
baniq.nginx.protocol: "tcp"


# Nginx Web Server with Multiple Protection Rules:
docker run -d \
  --name nginx \
  -p 80:80 -p 443:443 \
  --label "baniq.enabled=true" \
  # Auth failure protection
  --label "baniq.nginx-auth.logpath=/var/log/nginx/access.log" \
  --label "baniq.nginx-auth.filter=nginx-auth" \
  --label "baniq.nginx-auth.maxretry=3" \
  --label "baniq.nginx-auth.findtime=5m" \
  --label "baniq.nginx-auth.bantime=1h" \
  --label "baniq.nginx-auth.port=80,443" \
  # Rate limiting protection
  --label "baniq.nginx-ratelimit.logpath=/var/log/nginx/access.log" \
  --label "baniq.nginx-ratelimit.filter=nginx-ratelimit" \
  --label "baniq.nginx-ratelimit.maxretry=60" \
  --label "baniq.nginx-ratelimit.findtime=1m" \
  --label "baniq.nginx-ratelimit.bantime=30m" \
  --label "baniq.nginx-ratelimit.port=80,443" \
  # Bad bot protection
  --label "baniq.nginx-badbots.logpath=/var/log/nginx/access.log" \
  --label "baniq.nginx-badbots.filter=nginx-badbots" \
  --label "baniq.nginx-badbots.maxretry=1" \
  --label "baniq.nginx-badbots.findtime=1m" \
  --label "baniq.nginx-badbots.bantime=1d" \
  --label "baniq.nginx-badbots.port=80,443" \
  nginx

# SSH Server with Multiple Security Layers:
docker run -d \
  --name ssh-server \
  -p 22:22 \
  --label "baniq.enabled=true" \
  # Failed login attempts
  --label "baniq.sshd.logpath=/var/log/auth.log" \
  --label "baniq.sshd.filter=sshd" \
  --label "baniq.sshd.maxretry=3" \
  --label "baniq.sshd.findtime=5m" \
  --label "baniq.sshd.bantime=1h" \
  --label "baniq.sshd.port=22" \
  # Invalid users
  --label "baniq.sshd-ddos.logpath=/var/log/auth.log" \
  --label "baniq.sshd-ddos.filter=sshd-ddos" \
  --label "baniq.sshd-ddos.maxretry=5" \
  --label "baniq.sshd-ddos.findtime=2m" \
  --label "baniq.sshd-ddos.bantime=2h" \
  --label "baniq.sshd-ddos.port=22" \
  openssh-server

# WordPress Container with Multiple Protections:
docker run -d \
  --name wordpress \
  -p 80:80 \
  --label "baniq.enabled=true" \
  # WordPress login protection
  --label "baniq.wp-login.logpath=/var/log/apache2/access.log" \
  --label "baniq.wp-login.filter=wordpress-auth" \
  --label "baniq.wp-login.maxretry=3" \
  --label "baniq.wp-login.findtime=5m" \
  --label "baniq.wp-login.bantime=1h" \
  --label "baniq.wp-login.port=80" \
  # XML-RPC protection
  --label "baniq.wp-xmlrpc.logpath=/var/log/apache2/access.log" \
  --label "baniq.wp-xmlrpc.filter=wordpress-xmlrpc" \
  --label "baniq.wp-xmlrpc.maxretry=2" \
  --label "baniq.wp-xmlrpc.findtime=2m" \
  --label "baniq.wp-xmlrpc.bantime=2h" \
  --label "baniq.wp-xmlrpc.port=80" \
  # Comment spam protection
  --label "baniq.wp-comments.logpath=/var/log/apache2/access.log" \
  --label "baniq.wp-comments.filter=wordpress-comments" \
  --label "baniq.wp-comments.maxretry=3" \
  --label "baniq.wp-comments.findtime=15m" \
  --label "baniq.wp-comments.bantime=12h" \
  --label "baniq.wp-comments.port=80" \
  wordpress

# MongoDB with API Authentication Protection:
docker run -d \
  --name mongodb \
  -p 27017:27017 \
  --label "baniq.enabled=true" \
  # Authentication failures
  --label "baniq.mongo-auth.logpath=/var/log/mongodb/mongodb.log" \
  --label "baniq.mongo-auth.filter=mongodb-auth" \
  --label "baniq.mongo-auth.maxretry=3" \
  --label "baniq.mongo-auth.findtime=5m" \
  --label "baniq.mongo-auth.bantime=30m" \
  --label "baniq.mongo-auth.port=27017" \
  # Connection flood protection
  --label "baniq.mongo-conn.logpath=/var/log/mongodb/mongodb.log" \
  --label "baniq.mongo-conn.filter=mongodb-connections" \
  --label "baniq.mongo-conn.maxretry=50" \
  --label "baniq.mongo-conn.findtime=1m" \
  --label "baniq.mongo-conn.bantime=15m" \
  --label "baniq.mongo-conn.port=27017" \
  mongo

#Mail Server with Multiple Security Rules:
docker run -d \
  --name mailserver \
  -p 25:25 -p 587:587 -p 993:993 \
  --label "baniq.enabled=true" \
  # SMTP authentication failures
  --label "baniq.postfix-auth.logpath=/var/log/mail.log" \
  --label "baniq.postfix-auth.filter=postfix-auth" \
  --label "baniq.postfix-auth.maxretry=3" \
  --label "baniq.postfix-auth.findtime=5m" \
  --label "baniq.postfix-auth.bantime=1h" \
  --label "baniq.postfix-auth.port=25,587" \
  # IMAP authentication failures
  --label "baniq.dovecot-auth.logpath=/var/log/mail.log" \
  --label "baniq.dovecot-auth.filter=dovecot-auth" \
  --label "baniq.dovecot-auth.maxretry=3" \
  --label "baniq.dovecot-auth.findtime=5m" \
  --label "baniq.dovecot-auth.bantime=1h" \
  --label "baniq.dovecot-auth.port=993" \
  # SMTP ratelimit
  --label "baniq.postfix-ratelimit.logpath=/var/log/mail.log" \
  --label "baniq.postfix-ratelimit.filter=postfix-ratelimit" \
  --label "baniq.postfix-ratelimit.maxretry=30" \
  --label "baniq.postfix-ratelimit.findtime=1m" \
  --label "baniq.postfix-ratelimit.bantime=30m" \
  --label "baniq.postfix-ratelimit.port=25,587" \
  mailserver


# Key Points about Multiple Rules:
# Naming Convention:
# Each rule set needs a unique name (e.g., nginx-auth, nginx-ratelimit)
# Names are used in the label prefix: baniq.<rulename>.<parameter>
# Common Parameters:
# logpath: Path to the log file
# filter: Fail2Ban filter name
# maxretry: Number of failures before ban
# findtime: Time window for counting failures
# bantime: Duration of the ban
# port: Port(s) to block
# protocol: Protocol (tcp/udp, defaults to tcp)