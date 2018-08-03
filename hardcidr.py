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

    try:
        receiver.bind(('', port))
    except socket.error as e:  # Todo: Raise better errors
        raise IOError('Unable to bind receiver socket: {}'.format(e))

    # Create sender socket
    sender = socket.socket(
        family=socket.AF_INET,
        type=socket.SOCK_DGRAM,
        proto=socket.IPPROTO_UDP
    )

    sender.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
    sender.sendto(b'', (dst, port))

    try:
        # Todo: Add Timeout
        data, addr = receiver.recvfrom(1024)
    except socket.error as e:  # Todo: Raise better errors
        raise IOError('Socket error: {}'.format(e))
    finally:
        receiver.close()
        sender.close()

    if addr:
        return addr
    else:
        raise IOError('Socket error')


if __name__ == '__main__':
    x = gen_port()
    print "Launching apple @ %s" % sys.argv[1]

    for y in xrange(1, int(sys.argv[2]) + 1):
        print y,
        hits = list()

        for z in xrange(3):
            hit = apple(sys.argv[1], x.next(), y)[0]
            if hit not in hits:
                hits.append(hit)

        print hits
