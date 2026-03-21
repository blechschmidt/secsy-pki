FROM alpine:latest
RUN apk add --no-cache openssh-server
RUN ssh-keygen -A

# Create test user
RUN adduser -D -s /bin/ash testuser && echo "testuser:testpassword" | chpasswd

# CA public key for certificate-based auth
COPY ca_user_key.pub /etc/ssh/ca_user_key.pub

# sshd config: trust the CA for user authentication
# AuthorizedPrincipalsFile maps certificate principals to allowed users
RUN echo "TrustedUserCAKeys /etc/ssh/ca_user_key.pub" >> /etc/ssh/sshd_config && \
    echo "PasswordAuthentication no" >> /etc/ssh/sshd_config && \
    echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config && \
    echo "AuthorizedPrincipalsFile /etc/ssh/authorized_principals/%u" >> /etc/ssh/sshd_config && \
    echo "LogLevel DEBUG" >> /etc/ssh/sshd_config

# Allow testuser principal for testuser account
RUN mkdir -p /etc/ssh/authorized_principals && \
    echo "testuser" > /etc/ssh/authorized_principals/testuser

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
