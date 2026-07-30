import secrets

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


def generated_vpn_ports(used):
    return VISION_PORT, generated_port(used)
