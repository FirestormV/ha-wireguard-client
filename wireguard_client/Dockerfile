FROM alpine:3.23
RUN apk add --no-cache python3 iproute2 wireguard-tools socat iptables tcpdump
ARG BUILD_VERSION=0.2.5
ARG BUILD_ARCH
LABEL io.hass.version="${BUILD_VERSION}" io.hass.type="addon" io.hass.arch="${BUILD_ARCH}"
COPY client.py public_key_ui.py diagnostics.py /opt/
CMD ["python3", "-u", "/opt/client.py"]
