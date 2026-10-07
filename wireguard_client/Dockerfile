FROM alpine:3.23
RUN apk add --no-cache python3 iproute2 wireguard-tools socat iptables tcpdump
ARG BUILD_VERSION=0.3.0
ARG BUILD_ARCH
ENV ADDON_VERSION=${BUILD_VERSION}
LABEL io.hass.version="${BUILD_VERSION}" io.hass.type="addon" io.hass.arch="${BUILD_ARCH}"
COPY client.py public_key_ui.py diagnostics.py gateway.py health.py status.py dashboard.html /opt/
CMD ["python3", "-u", "/opt/client.py"]
