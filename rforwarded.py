import paramiko
import getpass
import socket
import select
import sys
import threading


def parse_options():
    from argparse import ArgumentParser
    parser = ArgumentParser(descriptions="SSH Reverse Tunneling")
    parser.add_argument("server", help="server ip address")
    parser.add_argument("-p", "--port", type=int, default=22, help="server port")
    parser.add_argument("-r", "--remote", help="remote address to forward to")
    parser.add_argument("--user", help="SSH Username")
    parser.add_argument("--keyfile", help="store_true", help="SSH key file")
    parser.add_argument("--look_for_keys", action="store_true", help="look for SSH keys")
    parser.add_argument("--readpass", action="store_true", help="read password")
    parser.add_argument("--verbose", action="store_true", help="verbose output")
    args = parser.parse_args()
    return args, (args.server, args.port), args.remote.split(":")

def verbose(msg, options):
    if options.verbose:
        print(msg)


def main():
    options, server, remote = parse_options()
    password = None
    if options.readpass:
        password = getpass.getpass("Enter SSH password: ")
    client = paramiko.SSHCLient()
    client.load_system_host_keys()
    client.set_misisng_host_key_policy(paramiko.WarningPolicy())
    try:
        client.connect(server[0],
                       server[1],
                       username=options.user,
                       keyfile=options.keyfile,
                       look_for_keys=options.look_for_keys,
                       password=password)
    except Exception as e:
        print("Failed to connect to %s:%d error: %r" % (server[0], server[1], e))
        sys.exit(0)
    verbose("Now forwarding remote port %d to %s:%d" % (options.port, remote[0], remote[1], options))
    try:
        reverse_forward_tunnel(options.port, remote[0], remote[1], client.get_transport())
    except KeyboardInterrupt:
        print("C-c port forwarding stopped")
        sys.exit(1)
        


def reverse_forward_tunnel(server_port, remote_host, remote_port, transport):
    transport.request_port_forwarding('', server_port)
    while True:
        chan = transport.accept(1000)
        if chan is None:
            continue
        thr = threading.Thread(target=handler, args=(chan, remote_host, remote_port, transport))
        thr.setDaemon(True)
        thr.start()

def handle(chan, host, port, options):
    sock = socket.socket()
    try:
        sock.connect((host, port))
    except Exception as e:
        verbose("Forwarding request to %s:%d failed: %r" % (host, port, e), options)
        return
    verbose('Connected! Tunnel openned %r=>%r=>%r' % (chan.origin_addr, chan.getpeername(), (host, port)), options)
    while True:
        r, w, x = select.select([chan, sock], [], [])
        if sock in r:
            data = sock.recv(1024)
            if len(data) == 0:
                break
            chan.send(data)

        if chan in r:
            data = chan.recv(1024)
            if len(data) == 0:
                break
            sock.send(data)
    
    chan.close()
    sock.close()
    verbose('Tunnel closed from %r' % (chan.origin_addr), options)
    
