FROM alpine:latest
RUN apk add --no-cache openssh-server
RUN ssh-keygen -A

# Create test user
RUN adduser -D -s /bin/ash testuser && echo "testuser:testpassword" | chpasswd

# CA public key for certificate-based auth
COPY ca_user_key.pub /etc/ssh/ca_user_key.pub

# sshd config: trust the CA for user authentication
RUN echo "TrustedUserCAKeys /etc/ssh/ca_user_key.pub" >> /etc/ssh/sshd_config && \
    echo "PasswordAuthentication no" >> /etc/ssh/sshd_config && \
    echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config && \
    echo "LogLevel DEBUG" >> /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
