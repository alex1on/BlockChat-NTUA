from Crypto.PublicKey import RSA
import hashlib
import random
import socket
import threading
import sys
import json
from blockchain import Blockchain
from transaction import Transaction
from block import BlockChatCoinBlock
from utils import generate_wallet, add_transactions_to_wallet


class node:
    """
    Represents a network node with functionalities including transaction creation,
    blockchain management, and network communication.

    Attributes:
        id              -> Unique identifier for the node, assigned during network setup.
        ip              -> IP address of the node.
        port            -> Network port the node listens on.
        N               -> Maximum allowed nodes in the network.
        net_nodes       -> Information about the network nodes (IDs, IPs, Ports, Public Keys).
        valid_state     -> Stores wallet information (nonces, balances, stakes) after validating a block.
        local_state     -> Tracks wallet information, updated with each transaction.
        blockchain      -> The blockchain managed by this node.
        wallet:         -> The wallet associated with this node.
        bootstrap       -> Flag indicating if the node is the bootstrap node.
    """

    def __init__(self, ip, port, N, bootstrap=False):
        self.ip = ip
        self.port = port
        self.N = N
        self.net_nodes = []
        self.valid_state = []
        self.local_state = []
        self.wallet = generate_wallet()
        self.blockchain = Blockchain()
        self.bootstrap = bootstrap

        self.setup_complete = False
        self.transaction_queue = []

        self.setup_complete = False
        self.transaction_queue = []

        # TODO: Update local_state and/or valid_state after adding a new node. local_state and valid_state should be identical after network initialization.

        if self.bootstrap:
            self.id = 0
            self.next_id = 1
            self.blockchain = Blockchain(True, N, self.wallet)
            self.bootstraps()
            self.setup_complete = True
        else:
            self.advertise_node("bootstrap_node", 5001)
            for node in self.net_nodes:
                self.advertise_node(node.ip, node.port)

        self.server_socket = None
        self.threads = []
        self.running = True
        self.open_connection("0.0.0.0", port)
        self.open_connection_broadcast("0.0.0.0", port + 1)
        # self.open_connection(ip, port)

    def set_node_id(self, id):
        """
        Sets the id of the node.
        """
        self.id = id

    def bootstraps(self):
        """
        Initializes the network by adding the bootstrap node to the network and valid state lists.
        """
        self.add_node_to_network(
            self.id,
            self.ip,
            self.port,
            self.wallet.public_key.export_key("PEM").decode(),
        )
        self.add_node_to_valid_state(
            self.id,
            self.wallet.public_key.export_key("PEM").decode(),
            self.wallet.balance,
            self.wallet.stake,
            self.wallet.nonce,
        )

    def add_node_to_network(self, id, ip, port, public_key):
        """
        Adds a node's details to the network nodes list. Raises an exception if the network is full.
        """
        if len(self.net_nodes) == self.N:
            raise Exception("Cannot add more nodes. Network is full!")

        self.net_nodes.append(
            {
                "id": id,
                "ip": ip,
                "port": port,
                "public_key": public_key,
            }
        )

    def add_node_to_valid_state(self, id, public_key, balance, stake, nonce):
        """
        Adds a node's wallet information to the valid state list. Raises an exception if the state is full.
        """
        if len(self.valid_state) == self.N:
            raise Exception("Cannot add more nodes. State if full!")

        self.valid_state.append(
            {
                "id": id,
                "public_key": public_key,
                "balance": balance,
                "stake": stake,
                "nonce": nonce,
            }
        )

    def create_transaction(self, type, amount=None, message=None, receiver=0):
        """
        Creates a new transaction and broadcasts it to the network.
        """
        # print(self.id)
        # print(self.net_nodes)
        if not self.setup_complete:
            self.transaction_queue.append((type, amount, message, receiver))
            return
        if self.id == receiver:
            raise Exception("Recipient can't be the sender.")
        if amount is not None and amount <= 0:
            raise Exception("Invalid Transaction: Amount can't be negative or zero.")

        # Find the receiver node details
        receiver_node = self.net_nodes[receiver]

        # Update the nonce for the transaction
        nonce = self.wallet.increment_nonce()

        # Create the transaction object
        transaction = Transaction(
            self.wallet.public_key,
            RSA.import_key(receiver_node["public_key"].encode()),
            type,
            nonce,
            amount,
            message,
        )

        # Sign the transaction
        transaction.sign_transaction(self.wallet.private_key)

        # TODO: Names are missleading change either node blockchain name or block list on blockchain
        self.chain.chain[-1].add_transaction(transaction)
        # self.chain.print()

        # Broadcast the transaction
        self.broadcast_transaction(receiver_node, transaction)

    def validate_transaction(self, transaction):
        """
        Validates a transaction by:
            a) Verifying its signature,
            b) Checking account balance and
            c) Ensuring nonce is correct for replay protection
        """

        # Verify the transaction's signature
        sender_public_key = RSA.import_key(transaction.sender_address.encode())
        if not transaction.verify_signature(sender_public_key):
            raise Exception("Invalid transaction: Signature verification failed.")

        # Retrieve the sender's state index and then access the state
        sender_state_index = self.find_index(sender_public_key, "state")
        sender_state = self.local_state[sender_state_index]

        # Check the sender's account balance
        if sender_state["balance"] < transaction.cost():
            raise Exception("Invalid transaction: Insufficient balance.")

        # Check the sender's account balance
        if sender_state["nonce"] != transaction.nonce:
            raise Exception("Invalid transaction: Incorrect nonce.")

        return True

    def find_index(self, public_key, type):
        """
        Finds the index of a node's information in the network or state lists based on a public key.

        Args:
            public_key (RSA key): The public key to search for.
            type (str): Specifies whether to search in 'node' or 'state' list.

        Returns:
            int: The index of the node's information if found.

        Raises:
            Exception: If the node cannot be found in the specified list.
        """
        public_key = public_key.export_key("PEM").decode()

        if type == "node":
            for index, node in enumerate(self.net_nodes):
                if node["public_key"] == public_key:
                    return index
            raise Exception("Node couldn't be found in the network.")
        elif type == "state":
            for index, state in enumerate(self.local_state):
                if state["public_key"] == public_key:
                    return index
            raise Exception("State couldn't be found!")

        else:
            raise ValueError("Invalid type specified. Use 'node' or 'state'.")

    def run_transaction(self, transaction, update_blockchain=True):
        """
        Processes a transaction by updating the sender's and receiver's states,
        optionally adding the transaction to the current block in the blockchain.

        Args:
            transaction (Transaction): The transaction to process.
            update_blockchain (bool): If True, add the transaction to the blockchain's current block.
        """

        # Find sender and receiver
        sender_public_key = RSA.import_key(transaction.sender_address.encode())
        receiver_public_key = RSA.import_key(transaction.receiver_address.encode())
        sender_state_index = self.find_index(sender_public_key, "state")
        receiver_state_index = self.find_index(receiver_public_key, "state")

        # Update sender's balance (reduce by transaction's cost)
        self.local_state[sender_state_index]["balance"] -= transaction.cost()
        self.local_state[sender_state_index]["nonce"] += 1

        # If the transaction is a coin transfer, update the receiver's balance
        if transaction.type == "coins":
            self.local_state[receiver_state_index]["balance"] += transaction.amount

        # Add the transaction to the blockchain's current block if specified
        if update_blockchain:
            self.blockchain.chain[-1].add_transaction(transaction)
            self.blockchain.print()

        # Check if the current block is full and mint a new block if necessary
        if update_blockchain and self.blockchain.chain[-1].is_full():
            self.mint_block()

    def run_block(self, block):
        """
        Processes each transaction within a block without adding them to the blockchain,
        as the block itself will be added to the blockchain.
        """
        for transaction in block.transactions:
            self.run_transaction(transaction, update_blockchain=False)

    # TODO: Receiver is temp as it will be changed to all the nodes later
    def broadcast_transaction(self, receiver_node, transaction):
        """
        Broadcasts a transaction to all nodes in the network.
        """
        message = {
            "type": "broadcast_transaction",
            "transaction": transaction.to_json(),
        }
        # send_message(receiver_node["ip"], receiver_node["port"], message)
        send_message_broadcast(receiver_node["port"] + 1, message)
        # for node in self.network:
        #     pass

    def process_transaction_queue(self):
        for transaction in self.transaction_queue:
            self.create_transaction(*transaction)
        self.transaction_queue = []

    def broadcast_block(self, receiver_node=0, block=None):
        """
        Broadcasts a block to all nodes in the network.
        """
        block = self.dummy_block_creator()
        self.blockchain.add_block(block)
        receiver_node = self.net_nodes[receiver_node]

        message = {"type": "broadcast_block", "block": block.to_json()}
        # send_message(receiver_node["ip"], receiver_node["port"], message)
        send_message_broadcast(receiver_node["port"] + 1, message)

    def stake(self, amount):
        """
        Stakes a specified amount for the proof-of-stake process. This increases the chance
        of the node being selected as the validator for the next block.
        """
        self.wallet.set_stake(amount)
        # public_key = RSA.import_key(self.wallet.public_key.encode())
        public_key = self.wallet.public_key
        index = self.find_index(public_key, "state")
        self.local_state[index]["stake"] = self.wallet.stake
        # self.local_state[index]["balance"] -= amount

        # self.broadcast_stake(public_key, amount)

    def proof_of_stake(self):
        """
        Selects a validator for the next block based on their stake.
        """
        # Seed the random number generator with the hash of the last block
        if len(self.blockchain.chain) > 0:
            last_block_hash = self.blockchain.chain[-1].hash
            random.seed(int(hashlib.sha256(last_block_hash.encode()).hexdigest(), 16))

            # Create a list of tuples (public_key, stake) for all states that have a stake
            stakes = [
                (state["public_key"], state["stake"])
                for state in self.local_state
                if state["stake"] > 0
            ]
            if stakes:
                # Flatten the list to simulate a lottery: each "ticket" is an entry in the list
                lottery_pool = [pk for pk, stake in stakes for _ in range(stake)]
                # Randomly select a "ticket" (public_key)
                selected_validator_public_key = random.choice(lottery_pool)
                return selected_validator_public_key
        return None

    def mint_block(self):
        """
        This method is called only after capacity transactions have been received. It:
            a) Finds the validator using the proof of stake algorithm,
            b) If the node is the validator it:
                1) Validates the block,
                2) Collects the block's total fees,
                3) Updates the global state,
                4) Broadcasts the block,
                5) Updates its wallet's transaction list with transactions related to its wallet,
                6) Updates the wallet's balance and
                7) Broadcasts the global state.
        """
        # Retrieve the public key of the selected validator via the proof of stake process
        validator_public_key = self.proof_of_stake()

        # Check if the current node is the selected validator
        if validator_public_key and self.wallet.public_key == validator_public_key:
            candidate_block = self.blockchain.chain[-1]

            validator = RSA.import_key(validator_public_key)

            # Validate the block
            if candidate_block.validate_block(
                candidate_block.previous_block, validator
            ):
                # Compute the fees
                total_fees = candidate_block.total_fees()

                # Find the validator index in the local state to update the balance with fees
                validator_index = self.find_index(validator, "state")
                self.local_state[validator_index]["balance"] += total_fees

                # Update the global state
                self.valid_state = self.local_state.copy()

                # Broadcast the validated block to the network
                self.broadcast_block(candidate_block)

                # Add transactions related to this node's wallet
                add_transactions_to_wallet(self.wallet, candidate_block.transactions)

                # Update wallet's balance
                self.wallet.wallet_balance()

                print("Block minted and broadcasted successfully.")
            else:
                print("Failed to validate the candidate block. Block not minted.")
        else:
            print("Node is not the selected validator or no validator selected.")

        # TODO: When receiving the block, each node needs to add transactions to its wallet
        # TODO: Also the balance needs to get updated (but this can happen when state is broadcasted and also update nonce)
        # TODO: Perhaps remove the balance and stake from wallet class since they are persisted in node's local/valid state

    ###############
    ### Below here are functions regarding network connectivity between nodes ###
    ### might be refractored later...
    ###############
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

    def send_new_node_info(self, host, port, data):
        message = {
            "type": "init_response",
            "id": self.next_id,
            "blockchain": self.blockchain.to_json(),
        }
        send_message(host, port, message)
        self.update_and_broadcast_network(data)

    def update_and_broadcast_network(self, data):
        self.add_node_to_network(
            self.next_id,
            data["node"]["ip"],
            data["node"]["port"],
            data["node"]["public"],
        )
        self.next_id += 1

        message = {"type": "set up ready", "nodes": self.net_nodes}
        with open("output.txt", "a") as f:
            print(message, file=f)

        # TODO: send_message on network info should only be called when all the nodes are inserted in the network.
        # TODO: also the send_message function in this case should broadcast the message instead of simply sending it to a specific host.
        # INFO: Check multicast implementation on udp / tcp packets.
        if len(self.net_nodes) >= self.N:
            send_message_broadcast(self.port + 1, message)
        # send_message(data["node"]["ip"], data["node"]["port"], message)

    def node_finish_init(self, data):
        self.set_node_id(data["id"])
        self.chain = Blockchain.from_json(data["blockchain"])
        # print(self.id)
        # self.chain.print()
        self.blockchain = Blockchain.from_json(data["blockchain"])
        print(self.id)
        self.blockchain.print()

    def handle_new_transaction(self, data):
        """
        Handles a new incoming transaction.
        """
        transaction = Transaction.from_json(data["transaction"])
        if self.validate_transaction(transaction):
            self.run_transaction(transaction)

    def handle_new_block(self, data):
        """
        Handles a new incoming block.
        """
        new_block = BlockChatCoinBlock.from_json(data["block"])

        # Removes last block and adds the validated block
        self.blockchain.chain.pop()
        self.blockchain.add_block(new_block)
        self.blockchain.print()

        # Restores old state
        self.local_state = self.valid_state.copy()

        # Runs the block updating the local state and updates valid_state
        self.run_block(self.blockchain.chain[-1])

        # Find validator's index in local_state
        validator_index = None
        for index, state in enumerate(self.local_state):
            if state["public_key"] == new_block.validator:
                validator_index = index
                break

        # Add the total fees in validator's balance
        if validator_index is not None:
            total_fees = new_block.total_fees()
            self.local_state[validator_index]["balance"] += total_fees

        # Update the valid_state
        self.valid_state = self.local_state.copy()

    def handle_client_response(self, host, port, data):
        # TODO: The way host & port is handled need to be remade.
        if data["type"] == "initialization":
            # self.update_and_broadcast_network(data)
            self.send_new_node_info(host, data["node"]["port"], data)
        elif data["type"] == "init_response":
            self.node_finish_init(data)
        elif data["type"] == "set up ready":
            self.net_nodes = data["nodes"]
            print(json.dumps(self.net_nodes, sort_keys=True, indent=4))
            self.setup_complete = True
            self.process_transaction_queue()
        elif data["type"] == "broadcast_transaction":
            self.handle_new_transaction(data)
        elif data["type"] == "broadcast_block":
            self.handle_new_block(data)

    def handle_client(self, conn, addr, blockchain):
        """
        Handles an incoming client connection.
        """
        with conn:
            while True:
                # TODO: Check what happens when string message is bigger than buffer size, implement for bigger messages
                data_received = conn.recv(4096)

                if not data_received:
                    break
                # print(data_received)

                data = json.loads(data_received.decode())
                print(f"Received from {addr}: {data}")
                # blockchain.add_block(data)
                # print(data)
                with open("output_received.txt", "a") as f:
                    print(data, file=f)

                # TODO: The way it works right now is not ideal. Fix inc.
                self.handle_client_response(addr[0], addr[1], data)

        # print(f"Current Blockchain: {blockchain.chain}")

    def node_server(self, host, port, blockchain):
        """
        Runs the server that listens for incoming connections and handles incoming data.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.server_socket:
            self.server_socket.bind((host, port))
            self.server_socket.listen()
            if self.bootstrap:
                print(f"Bootstrap listening on {host}:{port}")
            else:
                print(f"Node listening on {host}:{port}")

            while self.running:
                # print("here")
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
            target=self.node_server, args=(host, port, self.blockchain)
        )
        server_thread.start()

    def open_connection_broadcast(self, host, port):
        """Initializes the UDP socket for listening and sending."""
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Allow reusing addresses
        self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Enable broadcasting mode
        self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.udp_socket.bind((host, port))
        print(f"Node listening for UDP messages on port {port}")
        # Start listening in a new thread
        threading.Thread(target=self.listen_for_udp_messages, daemon=True).start()

    def listen_for_udp_messages(self):
        """Listens for messages from other nodes and processes them."""
        while self.running:
            try:
                data, addr = self.udp_socket.recvfrom(
                    4096
                )  # Adjust buffer size as needed
                if data:
                    message_data = json.loads(data.decode())
                    print(f"Received message from {addr}: {message_data}")
                    # Process the message
                    self.handle_client_response(addr[0], addr[1], message_data)
            except Exception as e:
                print(f"Error receiving UDP message: {e}")
                break

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

    def dummy_block_creator(self):
        block = BlockChatCoinBlock(
            len(self.chain.chain) + 1, [], self.chain.chain[-1].hash
        )
        block.add_transaction(
            Transaction(
                self.wallet.public_key,
                RSA.import_key(self.net_nodes[0]["public_key"].encode()),
                "coins",
                1,
                10,
            )
        )
        block.add_transaction(
            Transaction(
                self.wallet.public_key,
                RSA.import_key(self.net_nodes[0]["public_key"].encode()),
                "coins",
                2,
                20,
            )
        )

        return block


# TODO: Implement the broadcast method
def send_message_broadcast(port, data):
    broadcast_address = (
        "172.20.255.255"  # Broadcast address for the 172.20.0.0/16 subnet
    )
    serialized_data = json.dumps(data).encode()

    with open("output.txt", "a") as f:
        print(serialized_data, file=f)

    # Create a UDP socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        # Set the option to allow broadcasting
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # Send the data to the broadcast address
        sock.sendto(serialized_data, (broadcast_address, port))
        print(f"Broadcasted message to {broadcast_address}:{port}")
        with open("output.txt", "a") as f:
            print(f"Broadcasted message to {broadcast_address}:{port}", file=f)
    return


def send_message(host, port, data):
    """
    Sends a message to a specific host and port.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((host, port))
            print(f"Connected to {host}:{port}")
            client_socket.sendall(json.dumps(data).encode())
            # print(f"JSON data sent: {json.dumps(data).encode()}")

    except Exception as e:
        print(f"An error occurred: {e}")
