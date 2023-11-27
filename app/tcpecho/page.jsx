import React from "react";
import { Light as SyntaxHighlighter } from "react-syntax-highlighter";
import { github } from "react-syntax-highlighter/dist/esm/styles/hljs";

const codeString = `
#tcpecho
import socket

def server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = '127.0.0.1'
    port = 8080

    server_socket.bind((host, port))
    server_socket.listen(5)

    print(f'Listening on port {host}:{port}')

    while True:
        client_socket, addr = server_socket.accept()
        print(f'Connected to: {addr}')

        data = client_socket.recv(1024)
        if not data:
            break
        print(f'Received data from client: {data.decode()}')
        processed_message = data.decode().lower()
        client_socket.sendall(processed_message.encode())
        client_socket.close()

if __name__ == "__main__":
    server()


import socket

def client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = '127.0.0.1'
    port = 8080

    client_socket.connect((host, port))
    message = input("Enter a message to Server: ")
    client_socket.sendall(message.encode())
    data = client_socket.recv(1024)

    print(f'Message from Server: {data.decode()}')
    client_socket.close()

if __name__ == "__main__":
    client()

#UDP Echo
import socket

def udp_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    host = '127.0.0.1'
    port = 12345

    server_socket.bind((host, port))
    print(f'UDP Echo Server listening on {host}:{port}')

    while True:
        data, client_address = server_socket.recvfrom(1024)
        print(f'Received data from {client_address}: {data.decode()}')

        processed_message = data.decode().lower()
        server_socket.sendto(processed_message.encode(), client_address)

if __name__ == "__main__":
    udp_server()


import socket

def udp_echo_client():
    server_ip = '127.0.0.1'
    server_port = 12345

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
        message = input("Enter a message to send to the server: ")
        client_socket.sendto(message.encode(), (server_ip, server_port))

        data, server_address = client_socket.recvfrom(1024)
        received_message = data.decode()
        print(f"Received response from {server_address}: {received_message}")

        if message == received_message:
            print("Verification: The received message is the same as the sent message.")
        else:
            print("Verification: The received message is different from the sent message.")

if __name__ == "__main__":
    udp_echo_client()


#tcpchat
import socket
import threading

def handle_client(client_socket):
    while True:
        # Receive data from the client
        data = client_socket.recv(1024)
        if not data:
            break  # If no data is received, the connection is probably closed

        print(f"Received from client: {data.decode('utf-8')}")

        # Reply back to the client
        response = input("Enter your response: ")
        client_socket.send(response.encode('utf-8'))

    # Close the client socket when the loop exits
    client_socket.close()

def start_server():
    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to a specific address and port
    server_socket.bind(('127.0.0.1', 5555))

    # Listen for incoming connections
    server_socket.listen(5)
    print("Server listening on port 5555...")

    while True:
        # Accept a connection from a client
        client_socket, addr = server_socket.accept()
        print(f"Accepted connection from {addr}")

        # Start a new thread to handle the client
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

if __name__ == "__main__":
    start_server()

import socket

def start_client():
    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    client_socket.connect(('127.0.0.1', 5555))

    while True:
        # Send a message to the server
        message = input("Enter your message: ")
        client_socket.send(message.encode('utf-8'))

        # Receive the server's response
        response = client_socket.recv(1024)
        print(f"Received from server: {response.decode('utf-8')}")

    # Close the socket
    client_socket.close()

if __name__ == "__main__":
    start_client()


#udpdns
import socket
import struct

def build_dns_query(domain):
    transaction_id, flags, questions = 0x1234, 0x0100, 0x0001
    header = struct.pack('!HHHHHH', transaction_id, flags, questions, 0, 0, 0)

    qname = b''.join(bytes([len(part)]) + part.encode('utf-8') for part in domain.split('.'))
    qname += b'\x00'
    qtype, qclass = 0x0001, 0x0001
    question = struct.pack('!HH', qtype, qclass)

    return header + qname + question

def parse_dns_response(response):
    answer_count = struct.unpack('!H', response[6:8])[0]
    offset = len(response) - 4

    if answer_count == 0:
        return None

    return socket.inet_ntoa(response[offset:offset + 4])

def dns_query(domain, server_ip, port=53):
    query = build_dns_query(domain)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(query, (server_ip, port))
        response, _ = sock.recvfrom(1024)

    return parse_dns_response(response)

if __name__ == "__main__":
    domain, server_ip = input("Enter the domain to query: "), input("Enter the DNS server IP address: ")
    ip_address = dns_query(domain, server_ip)

    print(f"The IP address for {domain} is: {ip_address}" if ip_address else f"Unable to resolve {domain}")



#webtcp
import socket

def download_web_page(host, port, path="/"):
    # Create a TCP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Connect to the server
        s.connect((host, port))

        # Prepare the HTTP GET request
        request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"

        # Send the request
        s.sendall(request.encode())

        # Receive and print the response
        response = b""
        while True:
            data = s.recv(1024)
            if not data:
                break
            response += data

    # Split the response into headers and body
    headers, body = response.split(b"\r\n\r\n", 1)

    # Print the headers
    print(headers.decode())

    # Save the body to a file or print it
    # For simplicity, we'll just print the body here
    print(body.decode())

if __name__ == "__main__":
    # Example usage: Download Google's homepage
    download_web_page("www.google.com", 80, "/")

#ARP
class ARPSimulator:
    def __init__(self):
        self.arp_table = {}

    def add_entry(self, ip_address, mac_address):
        self.arp_table[ip_address] = mac_address

    def get_mac_address(self, ip_address):
        return self.arp_table.get(ip_address, "MAC address not found")

def main():
    arp_simulator = ARPSimulator()

    # Adding some entries to the ARP table
    arp_simulator.add_entry("192.168.0.1", "00:1a:2b:3c:4d:5e")
    arp_simulator.add_entry("192.168.0.2", "00:5e:6d:7c:8b:9a")

    # Simulating ARP request
    user_ip = input("Enter the IP address to query: ")
    mac_address = arp_simulator.get_mac_address(user_ip)

    print(f"The MAC address for IP address {user_ip} is: {mac_address}")

if __name__ == "__main__":
    main()


#rarp
import socket

class RARPServer:
    def __init__(self):
        self.mac_to_ip_mapping = {}

    def add_mapping(self, mac_address, ip_address):
        self.mac_to_ip_mapping[mac_address] = ip_address

    def handle_request(self, mac_address):
        return self.mac_to_ip_mapping.get(mac_address, "IP address not found")

def main():
    rarp_server = RARPServer()

    # Adding some sample mappings to the RARP server
    rarp_server.add_mapping("00:1a:2b:3c:4d:5e", "192.168.0.1")
    rarp_server.add_mapping("00:5e:6d:7c:8b:9a", "192.168.0.2")

    # UDP Server setup
    server_address = ("127.0.0.1", 8888)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
        udp_socket.bind(server_address)

        print("RARP server is listening on", server_address)

        while True:
            data, client_address = udp_socket.recvfrom(1024)
            mac_address = data.decode('utf-8')

            ip_address = rarp_server.handle_request(mac_address)

            # Sending the response back to the client
            udp_socket.sendto(ip_address.encode('utf-8'), client_address)
            print(f"RARP Request received from {client_address}. Mapping {mac_address} to {ip_address}")

if __name__ == "__main__":
    main()


#snw
import socket

def stop_and_wait_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ('127.0.0.1', 12345)

    server_socket.bind(server_address)

    print(f"Stop-and-Wait Server is listening on {server_address}")

    while True:
        data, client_address = server_socket.recvfrom(1024)
        print(f"Received from client {client_address}: {data.decode()}")

        # Acknowledge the received packet
        server_socket.sendto(b"ACK", client_address)

if __name__ == "__main__":
    stop_and_wait_server()

import socket

def stop_and_wait_client(message):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ('127.0.0.1', 12345)

    # Send data to the server
    client_socket.sendto(message.encode(), server_address)

    # Receive acknowledgment from the server
    ack, _ = client_socket.recvfrom(1024)

    print(f"Acknowledgment from server: {ack.decode()}")

    client_socket.close()

if __name__ == "__main__":
    user_message = input("Enter a message to send to the server: ")
    stop_and_wait_client(user_message)


#sw
import socket

def sliding_window_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ('127.0.0.1', 12345)

    server_socket.bind(server_address)

    print(f"Sliding Window Server is listening on {server_address}")

    window_size = 3
    expected_sequence_number = 0

    while True:
        data, client_address = server_socket.recvfrom(1024)
        sequence_number, message = data.decode().split(':')

        sequence_number = int(sequence_number)

        if sequence_number == expected_sequence_number:
            print(f"Received from client {client_address}: {message}")

            # Simulate processing time
            # ...

            # Acknowledge the received packet
            server_socket.sendto(str(sequence_number).encode(), client_address)

            expected_sequence_number = (expected_sequence_number + 1) % window_size

if __name__ == "__main__":
    sliding_window_server()


import socket
import time

def sliding_window_client(messages):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ('127.0.0.1', 12345)

    window_size = 3
    base = 0
    next_sequence_number = 0

    while base < len(messages):
        for i in range(base, min(base + window_size, len(messages))):
            message = f"{next_sequence_number}:{messages[i]}"
            client_socket.sendto(message.encode(), server_address)
            next_sequence_number += 1

        try:
            client_socket.settimeout(1.0)  # Set a timeout for acknowledgment
            while True:
                ack, _ = client_socket.recvfrom(1024)
                ack_number = int(ack.decode())
                if ack_number == base:
                    base = (base + 1) % window_size
                    break
        except socket.timeout:
            print("Timeout. Resending window...")
            next_sequence_number = base  # Resend the window from the base
    client_socket.close()

if __name__ == "__main__":
    user_messages = input("Enter messages (comma-separated): ").split(',')
    sliding_window_client(user_messages)


#crc
def calculate_crc(data, divisor):
    data += '0' * (len(divisor) - 1)
    data = list(data)

    for i in range(len(data) - len(divisor) + 1):
        if data[i] == '1':
            for j in range(len(divisor)):
                data[i + j] = str(int(data[i + j]) ^ int(divisor[j]))

    return ''.join(data[-(len(divisor) - 1):])

def detect_errors(received_data, divisor):
    crc_checksum = calculate_crc(received_data, divisor)
    return "No errors detected" if crc_checksum == '0' * (len(divisor) - 1) else "Errors detected"

if __name__ == "__main__":
    data = "110110101"
    divisor = "1011"
    
    data_with_crc = data + calculate_crc(data, divisor)

    received_data = "110111101"  # Intentional error

    result = detect_errors(received_data, divisor)

    print(f"Original Data: {data}")
    print(f"Divisor: {divisor}")
    print(f"Transmitted Data (with CRC): {data_with_crc}")
    print(f"Received Data: {received_data}")
    print(f"Error Detection Result: {result}")


#f2f
import socket

def receive_file(server_ip, server_port, file_name):
    # Create a TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to a specific IP address and port
    server_socket.bind((server_ip, server_port))

    # Listen for incoming connections
    server_socket.listen(1)
    print(f"Server listening on {server_ip}:{server_port}")

    # Accept a connection from the client
    client_socket, client_address = server_socket.accept()
    print(f"Connection established with {client_address}")

    # Receive the file content
    with open(file_name, 'wb') as file:
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            file.write(data)

    print("File received successfully")

    # Close the sockets
    client_socket.close()
    server_socket.close()

if __name__ == "__main__":
    server_ip = '127.0.0.1'
    server_port = 12345
    file_name = 'received_file.txt'

    receive_file(server_ip, server_port, file_name)

import socket

def send_file(server_ip, server_port, file_name):
    # Create a TCP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    client_socket.connect((server_ip, server_port))
    print(f"Connected to {server_ip}:{server_port}")

    # Send the file content
    with open(file_name, 'rb') as file:
        data = file.read(1024)
        while data:
            client_socket.send(data)
            data = file.read(1024)

    print("File sent successfully")

    # Close the socket
    client_socket.close()

if __name__ == "__main__":
    server_ip = '127.0.0.1'
    server_port = 12345
    file_name = 'sample_file.txt'

    send_file(server_ip, server_port, file_name)
    
`;

const Page = () => {
  return (
    <div>
      <SyntaxHighlighter language="python" style={github}>
        {codeString}
      </SyntaxHighlighter>
    </div>
  );
};

export default Page;
