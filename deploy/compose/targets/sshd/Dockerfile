# Dev-only SSH target. Its host key is generated at build time, not committed:
# clients trust the Limen host CA (known_hosts @cert-authority), not this key.
FROM alpine:3.23
RUN apk add --no-cache openssh-server openssh-keygen bash \
 && adduser -D -s /bin/bash ubuntu \
 && adduser -D -s /bin/bash ec2-user \
 # Unlock the accounts (no password is set; only certificates can log in).
 && sed -i -e 's/^ubuntu:!/ubuntu:*/' -e 's/^ec2-user:!/ec2-user:*/' /etc/shadow \
 && mkdir -p /etc/ssh/limen \
 && ssh-keygen -q -t ed25519 -N "" -C limen-dev-sshd-target -f /etc/ssh/ssh_host_ed25519_key
COPY sshd_config /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
