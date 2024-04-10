from Crypto.PublicKey import RSA
import hashlib
import random
import socket
import threading
import sys
import json
from blockchain import Blockchain
from transaction import Transaction
from utils import generate_wallet


class node:
    """
    Class that represents a node.

    id          -> The id of the node - not known on node creation - sent by bootstrap
    ip          -> The ip address of the node - ok
    port        -> The port that the node listens to - ok
    N           -> Naximum number of nodes - ok
    network     -> Keeps information about the network - again sent by bootstrap
    chain       -> The blockchain - ok
    wallet      -> The node's wallet - created by the constructor
    """

    def __init__(self, ip, port, N, bootstrap=False):
        # self.id = id
        self.ip = ip
        self.port = port
        self.N = N
        # self.network = network
        self.chain = []
        self.bootstrap = bootstrap
        self.wallet = generate_wallet()

        self.net_nodes = []

        if self.bootstrap:
            self.id = 0
            self.next_id = 1
            self.chain = Blockchain(N, self.wallet)
            self.bootstraps()

        else:
            self.advertise_node("bootstrap_node", 5001)
            for node in self.net_nodes:
                self.advertise_node(node.ip, node.port)

        self.server_socket = None
        self.threads = []
        self.running = True
        self.open_connection("0.0.0.0", port)
        # self.open_connection(ip, port)

    def is_bootstrap(self):
        return self.id == 0

    def bootstraps(self):
        self.add_node_to_network(
            self.id,
            self.ip,
            self.port,
            self.wallet.public_key.export_key("PEM").decode(),
        )
        # not needed Blockchain() creates already the genesis_block
        # if self.is_bootstrap():
        #     self.chain.create_genesis_block(self.N, self.wallet)

    def add_node_to_network(self, node_id, ip, port, public_key):
        """
        Adds a node into the network
        """
        if len(self.net_nodes) == self.N:
            raise Exception("Cannot add more nodes. Network is full!")

        ## this json object should not be the network nodes information imo
        self.net_nodes.append(
            {
                "id": node_id,
                "ip": ip,
                "port": port,
                "public_key": public_key,
            }
        )

    def create_transaction(self, type, amount=None, message=None, receiver="0"):
        """
        Creates a transaction
        """
        if self.wallet.public_key == receiver:
            raise Exception("Recipient can't be the sender.")
        if amount and amount <= 0:
            raise Exception("Invalid Transaction: Amount can't be negative or zero!")

        nonce = self.wallet.increment_nonce()
        transaction = Transaction(
            self.wallet.public_key, receiver.public_key, type, nonce, amount, message
        )
        # self.wallet.transactions.append(transaction)

        # Sign the transaction
        transaction.sign_transaction(self.wallet.private_key)

        # Broadcast the transaction
        self.broadcast_transaction(transaction)

    def validate_transaction(self, transaction):
        """
        Validates the transaction by:
            a) Verifying the signature,
            b) Checking the account balance and
            c) Checking the nonce for transaction replay protection
        """

        # a) Verify Signature
        sender_public_key = RSA.import_key(transaction.sender_address.encode())
        if not transaction.verify_signature(sender_public_key):
            raise Exception("Invalid transaction: Signature verification failed.")

        # Retrieve the sender's network information
        sender_info = next(
            (
                node
                for node in self.network
                if node["public_key"] == transaction.sender_address
            ),
            None,
        )
        if not sender_info:
            raise Exception("Invalid transaction: Sender not found in the network.")

        # b) Check the account balance
        if sender_info["balance"] < transaction.cost():
            raise Exception("Invalid transaction: Insufficient balance.")

        # c) Check nonce for replay protection
        if sender_info["nonce"] != transaction.nonce:
            raise Exception("Invalid transaction: Incorrect nonce.")

        return True

    def broadcast_transaction(self, transaction):
        """
        Broadcasts the transaction to every node
        """
        for node in self.network:
            pass

    def stake(self, amount):
        """
        Stakes amount for the proof-of-stake process.
        """
        self.wallet.set_stake(amount)
        self.update_network("stake", self.wallet.stake)
        self.update_network("balance", self.wallet.balance)
        # self.create_transaction('coins', amount=amount)

    def proof_of_stake(self):
        """
        Selects a validator for the next block based on their stake.
        """
        # Seed the random number generator with the hash of the last block
        if len(self.chain.blocks) > 0:
            last_block_hash = self.chain.blocks[-1].hash
            random.seed(int(hashlib.sha256(last_block_hash.encode()).hexdigest(), 16))

            # Create a list of tuples (public_key, stake) for all nodes that have a stake
            stakes = [
                (node.public_key, node.stake) for node in self.network if node.stake > 0
            ]
            if not stakes:
                return None

            # Flatten the list to simulate a lottery: each "ticket" is an entry in the list
            lottery_pool = [
                public_key for public_key, stake in stakes for _ in range(stake)
            ]

            if not lottery_pool:
                return None

            # Randomly select a "ticket"
            selected_validator = random.choice(lottery_pool)
            return selected_validator

        else:
            return None

    ###############
    ### Below here are functions regarding network connectivity between nodes ###
    ### might be refractored later...
    ###############
    def handle_client_response(self, ip, port, data):
        if data["type"] == "initialization":
            self.update_and_broadcast_network(data)
        elif data["type"] == "set up ready":
            self.net_nodes = data["nodes"]
            print(json.dumps(self.net_nodes, sort_keys=True, indent=4))


    def update_and_broadcast_network(self, data):
        self.add_node_to_network(
            self.next_id,
            data["node"]["ip"],
            data["node"]["port"],
            data["node"]["public"],
        )
        self.next_id += 1

        message = {
            "type": "set up ready",
            "nodes": self.net_nodes
        }

        # TODO: send_message on network info should only be called when all the nodes are inserted in the network.
        # TODO: also the send_message function in this case should broadcast the message instead of simply sending it to a specific host. 
        # INFO: Check multicast implementation on udp / tcp packets.        
        # if(len(self.net_nodes) == self.N): 

        send_message(data["node"]["ip"], data["node"]["port"], message)

    def handle_client(self, conn, addr, blockchain):
        with conn:
            while True:
                # TODO: Check what happens when string message is bigger than buffer size, implement for bigger messages
                data_received = conn.recv(2048)

                if not data_received:
                    break
                #print(data_received)

                data = json.loads(data_received.decode())
                print(f"Received from {addr}: {data}")
                # blockchain.add_block(data)
                #print(data)

                self.handle_client_response(addr[0], addr[1], data)

        #print(f"Current Blockchain: {blockchain.chain}")

    def node_server(self, host, port, blockchain):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.server_socket:
            self.server_socket.bind((host, port))
            self.server_socket.listen()
            print(f"Bootstrap node listening on {host}:{port}")

            while self.running:
                print("here")
                # self.server_socket.settimeout(1.0)  # Allow checking the running flag -- comments: might not be needed
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
        server_thread = threading.Thread(
            target=self.node_server, args=(host, port, self.chain)
        )
        server_thread.start()

    def advertise_node(self, host, port):
        message = {
            "type": "initialization",
            "node": {
                "ip": self.ip,
                "port": self.port,
                "public": self.wallet.public_key.export_key(format="PEM").decode(),
            },
        }
        send_message(host, port, message)

    def shutdown(self):
        print("Shutting down the server...")
        self.running = False
        if self.server_socket:
            self.server_socket.close()  # Close the listening socket
        for thread in self.threads:
            thread.join()  # Wait for all threads to complete

    def signal_handler(self, signal, frame):
        print("Signal received, shutting down...")
        self.shutdown()
        sys.exit(0)


# TODO: Implement the broadcast method
def send_message_broadcast(data):
    return


def send_message(host, port, data):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((host, port))
            print(f"Connected to {host}:{port}")
            client_socket.sendall(json.dumps(data).encode())
            print(f"JSON data sent: {json.dumps(data).encode()}")

    except Exception as e:
        print(f"An error occurred: {e}")
