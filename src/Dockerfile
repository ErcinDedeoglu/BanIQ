FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY src/go.mod .
COPY src/go.sum .

# Copy source code
COPY src/*.go ./

# Build the application
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux go build -o baniq .

FROM alpine:3.17

# Install Fail2Ban and iptables
RUN apk add --no-cache fail2ban iptables ip6tables

# Create required directories
RUN mkdir -p /var/run/fail2ban /etc/fail2ban/jail.d /etc/fail2ban/filter.d

# Copy the binary from the builder stage
COPY --from=builder /app/baniq /usr/local/bin/baniq

# Make sure the binary is executable
RUN chmod +x /usr/local/bin/baniq

# Copy default fail2ban configuration
COPY src/fail2ban.conf /etc/fail2ban/fail2ban.conf
COPY src/jail.conf /etc/fail2ban/jail.conf
# Disable default sshd jails
COPY src/disable-sshd.conf /etc/fail2ban/jail.d/disable-sshd.conf

# Start fail2ban and the BanIQ monitor
CMD ["sh", "-c", "fail2ban-client start && /usr/local/bin/baniq"]