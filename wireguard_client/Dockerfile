FROM alpine:3.23
RUN apk add --no-cache python3 iproute2 wireguard-tools
ARG BUILD_VERSION=0.1.2
ARG BUILD_ARCH
LABEL io.hass.version="${BUILD_VERSION}" io.hass.type="addon" io.hass.arch="${BUILD_ARCH}"
COPY client.py /opt/client.py
CMD ["python3", "-u", "/opt/client.py"]
