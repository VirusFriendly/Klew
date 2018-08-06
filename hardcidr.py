import socket
import sys

UDP_LOW = 33434
UDP_HIGH = 33535


def gen_port():
    while True:
        for udp_port in xrange(UDP_LOW, UDP_HIGH):
            yield udp_port


def apple(dst, port, ttl):
    """
    Run the tracer

    Raises:
        IOError

    """

    # Create error catching socket
    receiver = socket.socket(
        family=socket.AF_INET,
        type=socket.SOCK_RAW,
        proto=socket.IPPROTO_ICMP
    )

    receiver.bind(('', port))
    receiver.settimeout(3.0)

    # Create sender socket
    sender = socket.socket(
        family=socket.AF_INET,
        type=socket.SOCK_DGRAM,
        proto=socket.IPPROTO_UDP
    )

    sender.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
    sender.sendto(b'', (dst, port))

    data, addr = receiver.recvfrom(1024)
    receiver.close()
    sender.close()

    if addr:
        return addr
    else:
        raise IOError('Socket error')


def log(x):
    if __debug__:
        print x


if __name__ == '__main__':
    max_ttl = 30
    x = gen_port()
    log("Throwing apples @ %s" % sys.argv[1])

    if len(sys.argv) > 2:
        max_ttl = int(sys.argv[2])

    onion = list()

    for y in xrange(1, max_ttl + 1):
        log(y)
        hits = list()
        error = 0
        hit = ''

        while len(hits) < 3 or (len([ip for ip in hits if ip == hit]) < 3):
            try:
                hit = apple(sys.argv[1], x.next(), y)[0]
            except socket.timeout:
                log("*")
                error = error + 1

                if error > 2:
                    break

                continue
            else:
                if error != 0:
                    error = 0

            hits.append(hit)

        log([hit for hit in set(hits)])
        onion.append([hit for hit in set(hits)])

        if sys.argv[1] in hits:
            break

    print onion[-1]
