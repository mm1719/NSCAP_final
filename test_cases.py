import os
import subprocess
import socket
import sys
import struct
import time
import argparse


SOCKS_VERSION = 5
COMMAND_UDP_ASSOCIATE = 3
USERNAME_PASSWORD = 2
ADDRESS_TYPE_IPV4 = 1

def run_command(command, description):
    print(f"Running: {description}", flush=True)
    result = subprocess.run(command, shell=True, capture_output=True, text=True) 
    print(result.stdout, flush=True)
    if result.stderr:
        print(result.stderr, flush=True)

########################################################################################
# Test Case 1: Basic HTTP Request
def basic_http_request():
    run_command(
        "curl -U user:password --socks5 localhost:1080 http://example.com",
        "Basic HTTP Request"
    )
    
########################################################################################
# Test Case 2: Basic HTTPS Request
def basic_https_request():
    run_command(
        "curl -U user:password --socks5 localhost:1080 https://example.com",
        "Basic HTTPS Request"
    )
    
########################################################################################
# Test Case 3: Large File Download
def large_file_download():
    run_command(
        "curl -U user:password --socks5 localhost:1080 -O http://ipv4.download.thinkbroadband.com/100MB.zip",
        "Large File Download"
    )
    
########################################################################################
# Test Case 4: HTTP POST Request
def http_post_request():
    run_command(
        "curl -U user:password --socks5 localhost:1080 -d 'param1=value1&param2=value2' -X POST http://httpbin.org/post",
        "HTTP POST Request"
    )
    
########################################################################################
# Test Case 5: Concurrent Connections Test using ab
def concurrent_connections_test():
    run_command(
        "proxychains ab -n 100 -c 10 http://example.com/",
        "Concurrent Connections Test using Apache Benchmark (ab)"
    )
    
########################################################################################
# Test Case 6: DNS Resolution Test
def dns_resolution_test():
    run_command(
        "proxychains nslookup example.com",
        "DNS Resolution Test"
    )
    
########################################################################################
# Test Case 7: DNS over UDP
def dns_over_udp():
    def dns_query_udp(proxy_host, proxy_port, target_domain):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # DNS query packet
        transaction_id = b'\xaa\xbb'  # Arbitrary transaction ID
        flags = b'\x01\x00'           # Standard query
        questions = b'\x00\x01'       # One question
        answer_rrs = b'\x00\x00'      # No answers
        authority_rrs = b'\x00\x00'   # No authority records
        additional_rrs = b'\x00\x00'  # No additional records
        
        # Query section
        query = b''.join(bytes([len(part)]) + part.encode('utf-8') for part in target_domain.split('.'))
        query += b'\x00'  # End of query section
        query_type = b'\x00\x01'  # Type A query
        query_class = b'\x00\x01'  # Class IN
        
        # DNS packet
        packet = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs + query + query_type + query_class
        
        # Send the DNS query to the Google DNS server (8.8.8.8) on port 53
        sock.sendto(packet, ('8.8.8.8', 53))
        
        # Receive the DNS response
        data, _ = sock.recvfrom(512)  # Buffer size is 512 bytes
        print("DNS Response:", data, flush=True)

    print("Running: DNS over UDP", flush=True)
    dns_query_udp('127.0.0.1', 1080, 'example.com')

    
########################################################################################
# Test Case 8: UDP traffic testing
def udp_traffic_test():
    def send_udp_associate_request(proxy_host, proxy_port, username, password):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((proxy_host, proxy_port))
        
        client_socket.sendall(struct.pack("!BBB", SOCKS_VERSION, 1, USERNAME_PASSWORD))
        auth_response = client_socket.recv(2)

        client_socket.sendall(struct.pack("!BB", 1, len(username)) + username.encode() + struct.pack("!B", len(password)) + password.encode())
        auth_status = client_socket.recv(2)

        if auth_status[1] != 0:  # Authentication failed
            client_socket.close()
            return

        # Send UDP ASSOCIATE request
        request = struct.pack("!BBBBIH", SOCKS_VERSION, COMMAND_UDP_ASSOCIATE, 0, ADDRESS_TYPE_IPV4, 0, 0)
        client_socket.sendall(request)
        
        # Receive UDP ASSOCIATE response
        response = client_socket.recv(10)
        bnd_port = struct.unpack("!H", response[8:10])[0]
        
        client_socket.close()
        
        # Send UDP packet
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.sendto(b'Hello, this is a test message', ('127.0.0.1', 12345))
        
        try:
            data, server = udp_socket.recvfrom(4096)
            print(f"Received response from {server}: {data.decode('utf-8')}", flush=True)
        except socket.timeout:
            print("Request timed out", flush=True)
        finally:
            udp_socket.close()

    send_udp_associate_request('127.0.0.1', 1080, 'user', 'password')

    
########################################################################################
# Test Case 9: Invalid Authentication
def invalid_authentication():
    run_command(
        "curl -U wronguser:wrongpassword --socks5 localhost:1080 http://example.com",
        "Invalid Authentication Test"
    )
    
########################################################################################
# Test Case 10: Unreachable Destination
def unreachable_destination():
    run_command(
        "curl -U user:password --socks5 localhost:1080 http://unreachable.example.com",
        "Unreachable Destination Test"
    )
    
########################################################################################
# Test Case 11: httperf
def httperf_test():
    run_command(
        "proxychains httperf --server=93.184.215.14 --port=80 --uri=/ --rate=10 --num-conns=100",
        "HTTP Performance Test using httperf"
    )
    
########################################################################################
# Test Case 12: siege
def siege_test():
    run_command(
        "proxychains siege -c 10 -r 10 http://example.com",
        "Load Testing using siege"
    )
    
########################################################################################
# Test Case 13: iperf3
# Start iperf3 server in another terminal or machine: iperf3 -s -p 5201
def iperf3_test():
    run_command(
        "proxychains iperf3 -c localhost -u -b 1M -p 5201",
        "Bandwidth Test using iperf3"
    )
    
########################################################################################

def main():
    parser = argparse.ArgumentParser(description="Run specific test cases")
    parser.add_argument("test_case", type=int, help="Test case number to run (1-13)")
    args = parser.parse_args()

    test_cases = {
        1: basic_http_request,
        2: basic_https_request,
        3: large_file_download,
        4: http_post_request,
        5: concurrent_connections_test,
        6: dns_resolution_test,
        7: dns_over_udp,
        8: udp_traffic_test,
        9: invalid_authentication,
        10: unreachable_destination,
        11: httperf_test,
        12: siege_test,
        13: iperf3_test
    }

    test_case = test_cases.get(args.test_case)
    if test_case:
        test_case()
    else:
        print("Invalid test case number. Please provide a number between 1 and 13.", flush=True)

if __name__ == "__main__":
    main()