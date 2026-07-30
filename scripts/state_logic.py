import secrets

PORT_MODE_RANDOM = "random"
PORT_MODE_VISION_443 = "vision-443"
PORT_MODE_XHTTP_443 = "xhttp-443"
PORT_MODE_MANUAL = "manual"
VISION_PORT = 443


def bot_port_pattern(port):
    value = str(port)
    if any(value[index] == value[index + 1] for index in range(len(value) - 1)):
        return True
    if any(sequence in value for sequence in ("01234", "12345", "23456", "34567", "45678", "56789")):
        return True
    if len(value) >= 5 and any(
        value[index] == value[index + 2] == value[index + 4]
        for index in range(len(value) - 4)
    ):
        return True
    if len(value) == 5:
        if value[0] == value[4] and value[1] == value[3]:
            return True
        if value[0] == value[3] and value[1] == value[4]:
            return True
    return len(value) >= 4 and any(
        value[index] == value[index + 2]
        and value[index + 1] == value[index + 3]
        for index in range(len(value) - 3)
    )


def generated_port(used):
    while True:
        port = secrets.randbelow(40001) + 20000
        value = str(port)
        if port in used or bot_port_pattern(port):
            continue
        if any(
            abs(int(value[index]) - int(value[index + 1])) < 2
            for index in range(len(value) - 1)
        ):
            continue
        used.add(port)
        return port


def generated_vpn_ports(used, mode=PORT_MODE_RANDOM, manual_ports=None):
    if mode == PORT_MODE_RANDOM:
        return generated_port(used), generated_port(used)
    if mode == PORT_MODE_VISION_443:
        return VISION_PORT, generated_port(used)
    if mode == PORT_MODE_XHTTP_443:
        return generated_port(used), VISION_PORT
    if mode == PORT_MODE_MANUAL:
        if manual_ports is None or len(manual_ports) != 2:
            raise ValueError("manual mode requires Vision and XHTTP ports")
        vision_port, xhttp_port = manual_ports
        ports = (vision_port, xhttp_port)
        if any(not isinstance(port, int) or not 1 <= port <= 65535 for port in ports):
            raise ValueError("manual VPN ports must be between 1 and 65535")
        if vision_port == xhttp_port:
            raise ValueError("manual VPN ports must be different")
        if any(port in used for port in ports):
            raise ValueError("manual VPN ports must not overlap existing ports")
        used.update(ports)
        return ports
    raise ValueError(f"unsupported VPN port mode: {mode}")
