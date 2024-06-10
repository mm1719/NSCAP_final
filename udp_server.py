import socket

def udp_server(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((host, port))
    print(f"UDP server listening on {host}:{port}")
    
    while True:
        data, addr = server_socket.recvfrom(4096)
        print(f"Received message from {addr}: {data.decode('utf-8')}")
        server_socket.sendto(b"Hi this is the response from UDP server", addr)

udp_server('0.0.0.0', 12345)