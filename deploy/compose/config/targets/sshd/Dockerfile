# Dev-only SSH target. The host key is committed so the example policy can
# pin it; never reuse it anywhere else.
# Set from SSHD_BASE_IMAGE in deploy/compose/.env (see stacks/ssh.yml); no default here.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
RUN apk add --no-cache openssh-server bash \
 && adduser -D -s /bin/bash ubuntu \
 && adduser -D -s /bin/bash ec2-user \
 # Unlock the accounts (no password is set; only certificates can log in).
 && sed -i -e 's/^ubuntu:!/ubuntu:*/' -e 's/^ec2-user:!/ec2-user:*/' /etc/shadow \
 && mkdir -p /etc/ssh/limen
COPY sshd_config /etc/ssh/sshd_config
COPY --chmod=600 ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key
COPY ssh_host_ed25519_key.pub /etc/ssh/ssh_host_ed25519_key.pub
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
