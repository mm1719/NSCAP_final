# ref : https://datatracker.ietf.org/doc/html/rfc1928
# ref : https://datatracker.ietf.org/doc/html/rfc1929
# ref : https://kuanyuchen.gitbooks.io/python3-tutorial/content/er_jin_zhi_chu_li_fang_shi.html
import socket
import select
import struct
import logging
import threading

# SOCKS5 constants
SOCKS_VERSION = 5
NO_AUTHENTICATION_REQUIRED = 0
USERNAME_PASSWORD = 2
COMMAND_CONNECT = 1
COMMAND_UDP_ASSOCIATE = 3
ADDRESS_TYPE_IPV4 = 1
ADDRESS_TYPE_DOMAIN = 3
ADDRESS_TYPE_IPV6 = 4

# Cofigure logging
logging.basicConfig(filename="socks_proxy.log", level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

def log_connection(client_address, traget_address):
    logging.info(f"Connection from {client_address} to {traget_address}")

def log_error(client_address, error):
    logging.error(f"Error with client {client_address}: {error}")

def handle_auth(client_socket):
    try:
        auth_data = client_socket.recv(2)
        #logging.debug(f"Username/Password auth data: {auth_data}")
        
        if len(auth_data) < 2:
            #logging.error("Username/Password auth data too short")
            return False
        
        version, uname_len = struct.unpack("!BB", auth_data)
        uname = client_socket.recv(uname_len).decode("utf-8")
        pass_len = struct.unpack("!B", client_socket.recv(1))[0]
        password = client_socket.recv(pass_len).decode("utf-8")

        logging.debug(f"Received username: {uname}, password: {password}")

        """
        The server verifies the supplied UNAME and PASSWD, and sends the
        following response:
        +----+--------+
        |VER | STATUS |
        +----+--------+
        | 1  |   1    |
        +----+--------+
        A STATUS field of X'00' indicates success. If the server returns a
        `failure' (STATUS value other than X'00') status, it MUST close the
        connection.
        """
        if uname == "user" and password == "password":
            client_socket.sendall(struct.pack("!BB", 1, 0)) # Success
            return True
        else:
            client_socket.sendall(struct.pack("!BB", 1, 1)) # Failure
            return False
    
    except Exception as e:
        logging.error(f"Error during authentication: {e}")
        return False
    
def resolve_domain_name(domain):
    try:
        ip = socket.gethostbyname(domain)
        logging.debug(f"Resolved {domain} to {ip}")
        return ip
    except socket.gaierror as e:
        logging.error(f"DNS resolution error for {domain}: {e}")
        return None

def handle_udp_associate(client_socket):
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("0.0.0.0", 0)) # port 0 to let the OS choose a random port
    udp_socket_port = udp_socket.getsockname()[1]

    logging.debug(f"UDP socket bound to port {udp_socket_port}")

    """
    The server evaluates the request, and returns a reply 
    formed as follows:
    +----+-----+-------+------+----------+----------+
    |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    +----+-----+-------+------+----------+----------+
    | 1  |  1  | X'00' |  1   | Variable |    2     |
    +----+-----+-------+------+----------+----------+
    o  VER    protocol version: X'05'
    o  REP    Reply field:
        o  X'00' succeeded
        o  X'01' general SOCKS server failure
        o  X'02' connection not allowed by ruleset
        o  X'03' Network unreachable
        o  X'04' Host unreachable
        o  X'05' Connection refused
        o  X'06' TTL expired
        o  X'07' Command not supported
        o  X'08' Address type not supported
        o  X'09' to X'FF' unassigned
    o  RSV    RESERVED
    o  ATYP   address type of following address
        o  IP V4 address: X'01'
        o  DOMAINNAME: X'03'
        o  IP V6 address: X'04'
    o  BND.ADDR       server bound address
    o  BND.PORT       server bound port in network octet order
    """
    # Send the UDP associate response to the client
    client_socket.sendall(struct.pack("!BBBBIH", SOCKS_VERSION, 0, 0, ADDRESS_TYPE_IPV4, 0, udp_socket_port)) # address = 0.0.0.0

    while True:
        try:
            data, addr = udp_socket.recvfrom(4096)
            #logging.debug(f"Received data from {addr}: {data}")
            if not data:
                break

            # Parse the SOCKS5 UDP header
            header = struct.unpack_from("!BBH", data[:4])
            frag = header[0]
            addr_type = header[1]

            if addr_type == ADDRESS_TYPE_IPV4:
                dst_addr = socket.inet_ntoa(data[4:8])
                dst_port = struct.unpack("!H", data[8:10])[0]
                payload = data[10:]
            elif addr_type == ADDRESS_TYPE_IPV6:
                dst_addr = socket.inet_ntop(socket.AF_INET6, data[4:20])
                dst_port = struct.unpack("!H", data[20:22])[0]
                payload = data[22:]
            elif addr_type == ADDRESS_TYPE_DOMAIN:
                domain_length = data[4]
                dst_addr = data[5:5+domain_length].decode('utf-8')
                dst_port = struct.unpack("!H", data[5+domain_length:7+domain_length])[0]
                payload = data[7+domain_length:]
            else:
                print("Unsupported address type")
                continue

            # Send the payload to the destination
            #logging.debug(f"Sending payload to {dst_addr}:{dst_port}")
            udp_socket.sendto(payload, (dst_addr, dst_port))

            # Receive the response
            response, response_addr = udp_socket.recvfrom(4096)
            #logging.debug(f"Received response from {response_addr}: {response}")

            # Construct the SOCKS5 UDP response header
            response_header = struct.pack("!BBH", 0, ADDRESS_TYPE_IPV4, 0) # No fragmentation, IPv4 address, Reserved
            response_packet = response_header + socket.inet_aton(response_addr[0]) + struct.pack("!H", response_addr[1]) + response

            #logging.debug(f"Sending response packet to {addr}")
            # Send the response back to the client
            udp_socket.sendto(response_packet, addr)
        except socket.timeout:
            logging.warning("UDP socket timeout")
            break
        except Exception as e:
            logging.error(f"Error handling UDP associate: {e}")
            break

def handle_client(client_socket):
    client_address = client_socket.getpeername()
    try:
        # SOCKS5 handshake
        """
        The client connects to the server, and sends a version
        identifier/method selection message:
        +----+----------+----------+
        |VER | NMETHODS | METHODS  |
        +----+----------+----------+
        | 1  |    1     | 1 to 255 |
        +----+----------+----------+
        The VER field is set to X'05' for this version of the protocol.  The
        NMETHODS field contains the number of method identifier octets that
        appear in the METHODS field.

        The server selects from one of the methods given in METHODS, and
        sends a METHOD selection message:
        +----+--------+
        |VER | METHOD |
        +----+--------+
        | 1  |   1    |
        +----+--------+
        If the selected METHOD is X'FF', none of the methods listed by the
        client are acceptable, and the client MUST close the connection.
        The values currently defined for METHOD are:
        o  X'00' NO AUTHENTICATION REQUIRED
        o  X'01' GSSAPI
        o  X'02' USERNAME/PASSWORD
        o  X'03' to X'7F' IANA ASSIGNED
        o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
        o  X'FF' NO ACCEPTABLE METHODS
        """
        greeting = client_socket.recv(262)  # Receive client greeting
        #logging.debug(f"Client greeting: {greeting}")
        if len(greeting) < 3 or greeting[0] != SOCKS_VERSION:
            logging.error("Unsupported SOCKS version")
            client_socket.close()
            return
        
        methods = greeting[2:]
        logging.debug(f"Client authentication methods: {methods}")

        if USERNAME_PASSWORD in methods:
            """
            +----+------+----------+------+----------+
            |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
            +----+------+----------+------+----------+
            | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
            +----+------+----------+------+----------+
            The VER field contains the current version of the subnegotiation,
            which is X'01'.
            """
            client_socket.sendall(struct.pack("!BB", SOCKS_VERSION, USERNAME_PASSWORD))
        else:
            client_socket.sendall(struct.pack("!BB", SOCKS_VERSION, 0xFF))
            client_socket.close()
            return

        # Perform authentication
        if not handle_auth(client_socket):
            client_socket.close()
            return

        # SOCKS5 connection request
        """
        The SOCKS request is formed as follows:
        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+
        o  VER    protocol version: X'05'
        o  CMD
            o  CONNECT X'01'
            o  BIND X'02'
            o  UDP ASSOCIATE X'03'
        o  RSV    RESERVED
        o  ATYP   address type of following address
            o  IP V4 address: X'01'
                o  the address is a version-4 IP address, with a length of 4 octets
            o  DOMAINNAME: X'03'
                o  the address field contains a fully-qualified domain name. The first
                octet of the address field contains the number of octets of name that
                follow, there is no terminating NUL octet.
            o  IP V6 address: X'04'
        o  DST.ADDR       desired destination address
        o  DST.PORT desired destination port in network octet order
        """
        # SOCKS5 connection request
        request = client_socket.recv(4)
        #logging.debug(f"Client request: {request}")
        _, command, _, address_type = struct.unpack("!BBBB", request)
        logging.debug(f"Command: {command}, Address type: {address_type}")

        if address_type == ADDRESS_TYPE_IPV4:
            address = socket.inet_ntoa(client_socket.recv(4))
            logging.debug(f"Resolved IPv4 address: {address}")
        elif address_type == ADDRESS_TYPE_IPV6:
            address = socket.inet_ntop(socket.AF_INET6, client_socket.recv(16))
            logging.debug(f"Resolved IPv6 address: {address}")
        elif address_type == ADDRESS_TYPE_DOMAIN:
            domain_length = struct.unpack("!B", client_socket.recv(1))[0]
            address = client_socket.recv(domain_length).decode("utf-8")
            address = resolve_domain_name(address)
            if not address:
                log_error(client_address, "DNS resolution failed")
                client_socket.close()
                return
        port = struct.unpack("!H", client_socket.recv(2))[0]

        logging.debug(f"Connecting to {address}:{port}")

        if command == COMMAND_CONNECT:  
            try:
                remote_socket = socket.socket(socket.AF_INET6 if address_type == ADDRESS_TYPE_IPV6 else socket.AF_INET, socket.SOCK_STREAM)
                remote_socket.connect((address, port))
            except Exception as e:
                log_error(client_address, f"Connection error: {str(e)}")
                client_socket.close()
                return
            
            # Send successful connection response
            """
            +----+-----+-------+------+----------+----------+
            |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
            +----+-----+-------+------+----------+----------+
            | 1  |  1  | X'00' |  1   | Variable |    2     |
            +----+-----+-------+------+----------+----------+
            o  VER    protocol version: X'05'
            o  REP    Reply field:
                o  X'00' succeeded
                o  X'01' general SOCKS server failure
                o  X'02' connection not allowed by ruleset
                o  X'03' Network unreachable
                o  X'04' Host unreachable
                o  X'05' Connection refused
                o  X'06' TTL expired
                o  X'07' Command not supported
                o  X'08' Address type not supported
                o  X'09' to X'FF' unassigned
            o  RSV    RESERVED
            o  ATYP   address type of following address
                o  IP V4 address: X'01'
                o  DOMAINNAME: X'03'
                o  IP V6 address: X'04'
            o  BND.ADDR       server bound address
            o  BND.PORT       server bound port in network octet order
            """
            client_socket.sendall(struct.pack("!BBBBIH", SOCKS_VERSION, 0, 0, ADDRESS_TYPE_IPV4, 0, 0))

            # Relay traffic between client and remote server
            sockets = [client_socket, remote_socket]
            while True:
                readable, _, _ = select.select(sockets, [], [])
                if client_socket in readable:
                    data = client_socket.recv(4096)
                    if not data:
                        break
                    remote_socket.sendall(data)
                if remote_socket in readable:
                    data = remote_socket.recv(4096)
                    if not data:
                        break
                    client_socket.sendall(data)

            client_socket.close()
            remote_socket.close()

        
        elif command == COMMAND_UDP_ASSOCIATE:
            logging.debug(f"UDP socket allocation requested by {client_address}")
            handle_udp_associate(client_socket)


    except Exception as e:
        log_error(client_address, e)
    finally:
        client_socket.close()

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", 1080))
    server_socket.listen(5)
    print("SOCKS5 proxy server listening on port 1080")

    while True:
        client_socket, client_address  = server_socket.accept()
        logging.debug(f"Accepted connection from {client_address}")
        threading.Thread(target=handle_client, args=(client_socket,)).start()

if __name__ == "__main__":
    main()