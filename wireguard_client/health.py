"""WireGuard is connectionless; an old idle handshake is not a disconnect."""
def peer_health(stamp, keepalive, now, uptime):
    age = max(0, now - stamp) if stamp else None
    if age is not None and age <= 180:
        return 'Healthy', 'Recent WireGuard handshake.'
    if keepalive and (age if age is not None else uptime) > max(180, keepalive * 3 + 30):
        return 'Warning', 'No recent handshake despite configured keepalive; check peer and endpoint.'
    return 'Idle', 'No recent handshake; the peer may be idle. This alone does not prove a failure.'
