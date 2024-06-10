import socket
import struct

SOCKS_VERSION = 5
COMMAND_UDP_ASSOCIATE = 3
USERNAME_PASSWORD = 2
ADDRESS_TYPE_IPV4 = 1

def send_udp_associate_request(proxy_host, proxy_port, username, password):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((proxy_host, proxy_port))
    
    # Send greeting
    client_socket.sendall(struct.pack("!BBB", SOCKS_VERSION, 1, USERNAME_PASSWORD))
    auth_response = client_socket.recv(2)
    print(f"Auth response: {auth_response}")

    # Send username/password authentication
    client_socket.sendall(struct.pack("!BB", 1, len(username)) + username.encode() + struct.pack("!B", len(password)) + password.encode())
    auth_status = client_socket.recv(2)
    print(f"Auth status: {auth_status}")

    if auth_status[1] != 0:  # Authentication failed
        client_socket.close()
        return

    # Send UDP ASSOCIATE request
    request = struct.pack("!BBBBIH", SOCKS_VERSION, COMMAND_UDP_ASSOCIATE, 0, ADDRESS_TYPE_IPV4, 0, 0)
    client_socket.sendall(request)
    
    # Receive UDP ASSOCIATE response
    response = client_socket.recv(10)
    print(f"UDP ASSOCIATE response: {response}")
    bnd_port = struct.unpack("!H", response[8:10])[0]
    print(f"Bound UDP port: {bnd_port}")
    
    # Close the TCP connection
    client_socket.close()
    
    # Send UDP packet
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.sendto(b'Hello, this is a test message', ('127.0.0.1', 12345))
    
    try:
        data, server = udp_socket.recvfrom(4096)
        print(f"Received response from {server}: {data.decode('utf-8')}")
    except socket.timeout:
        print("Request timed out")
    finally:
        udp_socket.close()

send_udp_associate_request('127.0.0.1', 1080, 'user', 'password')