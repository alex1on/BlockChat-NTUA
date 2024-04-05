import socket
import threading
import sys
from blockchain import Blockchain

class BootStrapNode:
    def __init__(self, port, host="localhost"):
        self.blockchain = Blockchain()
        self.blockchain.print_blockchain_contents()
        self.open_connection(host, port)
        self.server_socket = None
        self.threads = []
        self.running = True

    def handle_client(self, conn, addr, blockchain):
        with conn:
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                print(f"Received from {addr}: {data.decode()}")
                blockchain.add_block(data.decode())
                print(f"Current Blockchain: {blockchain.chain}")

    def node_server(self, host, port, blockchain):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.server_socket:
            self.server_socket.bind((host, port))
            self.server_socket.listen()
            print(f"Bootstrap node listening on {host}:{port}")

            while self.running:
                print("here")
                #self.server_socket.settimeout(1.0)  # Allow checking the running flag -- comments: might not be needed
                try:
                    conn, addr = self.server_socket.accept()
                except socket.timeout:
                    continue
                if not self.running:
                    break
                thread = threading.Thread(
                    target=self.handle_client, args=(conn, addr, blockchain)
                )
                thread.start()
                self.threads.append(thread)

    def open_connection(self, host, port):
        server_thread = threading.Thread(target=self.node_server, args=(host, port, self.blockchain))
        server_thread.start()

    def shutdown(self):
        print("Shutting down the server...")
        self.running = False
        if self.server_socket:
            self.server_socket.close()  # Close the listening socket
        for thread in self.threads:
            thread.join()  # Wait for all threads to complete

    def signal_handler(self, signal, frame):
        print('Signal received, shutting down...')
        self.shutdown()
        sys.exit(0)