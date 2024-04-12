from Crypto.PublicKey import RSA
import contextlib
import hashlib
import random
import socket
import threading
import sys
import json
from blockchain import Blockchain
from transaction import Transaction
from block import BlockChatCoinBlock
from utils import generate_wallet, add_transactions_to_wallet, send_message, send_message_broadcast


class node:
    """
    Represents a network node with functionalities including transaction creation,
    blockchain management, and network communication.

    Attributes:
        id              -> Unique identifier for the node, assigned during network setup.
        ip              -> IP address of the node.
        port            -> Network port the node listens on.
        N               -> Maximum number of allowed nodes in the network.
        net_nodes       -> Information about the network nodes (IDs, IPs, Ports, Public Keys).
        valid_state     -> Stores wallet information (nonces, balances, stakes) after validating a block.
        local_state     -> Tracks wallet information, updated with each transaction.
        blockchain      -> The blockchain managed by this node.
        wallet:         -> The wallet associated with this node.
        bootstrap       -> Flag indicating if the node is the bootstrap node.
        block_capacity  -> Blockchain's block capacity
    """

    def __init__(self, ip, port, N, block_capacity, bootstrap=False):
        self.ip = ip
        self.port = port
        self.N = N
        self.net_nodes = []
        self.valid_state = []
        self.local_state = []
        self.wallet = generate_wallet()
        self.blockchain = Blockchain(block_capacity)
        self.bootstrap = bootstrap
        self.block_capacity = block_capacity

        self.setup_complete = False
        self.transaction_queue = []

        if self.bootstrap:
            self.bootstraps()
        else:
            # Get the container's hostname (which is also the container's name within the Docker network)
            hostname = "bootstrap_node"
            # Resolve the hostname to an IP address
            ip_address = socket.gethostbyname(hostname)
            self.advertise_node(ip_address, 5001)

        self.server_socket = None
        self.threads = []
        self.running = True
        self.open_connection("0.0.0.0", port)
        self.open_connection_broadcast("0.0.0.0", port + 1)

    def set_node_id(self, id):
        """
        Sets the id of the node.
        """
        self.id = id

    def bootstraps(self):
        """
        Initializes bootstrap's node fields.
        It also initializes the network by adding the bootstrap node to the network and valid state lists.
        """
        self.id = 0
        self.next_id = 1
        self.blockchain = Blockchain(self.block_capacity, True, self.N, self.wallet)
        
        self.add_node_to_network(
            self.id,
            self.ip,
            self.port,
            self.wallet.public_key.export_key("PEM").decode(),
        )

        self.add_node_to_valid_state(
            self.id,
            1000,
            10,
            0,
        )
        
        self.setup_complete = True

    def finish_setup(self, data):
        """
        Handles a "set up ready" message by:
            - Updating the local and valid state after initialization and
            - Setting the setup_complete flag to True.
        """
        self.net_nodes = data["nodes"]
        for node in self.net_nodes:
            self.add_node_to_valid_state(node["id"], 1000, 10, 0)
        self.local_state = self.valid_state.copy()
        
        self.setup_complete = True

    def add_node_to_network(self, id, ip, port, public_key):
        """
        Adds a node's details to the network list. Raises an exception if the network is full.
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

    def add_node_to_valid_state(self, id, balance, stake, nonce):
        """
        Adds a node's wallet information to the valid state list. Raises an exception if the state is full.
        """
        if len(self.valid_state) == self.N:
            raise Exception("Cannot add more nodes. State if full!")

        self.valid_state.append(
            {
                "id": id,
                "balance": balance,
                "stake": stake,
                "nonce": nonce,
            }
        )

    def create_transaction(self, type, amount=None, message=None, receiver=0):
        """
        Creates a new transaction and broadcasts it to the network.
        """
        if not self.setup_complete:
            self.transaction_queue.append((type, amount, message, receiver))
            return
        if self.id == receiver:
            raise Exception("Recipient can't be the sender.")
        if amount is not None and amount <= 0:
            raise Exception("Invalid Transaction: Amount can't be negative or zero.")

        # Find the receiver node details
        receiver_node = self.net_nodes[receiver]

        nonce = self.wallet.nonce

        # Create the transaction object
        transaction = Transaction(
            self.wallet.public_key,
            RSA.import_key(receiver_node["public_key"].encode()),
            type,
            nonce,
            amount,
            message,
        )

        # Update the nonce for the transaction
        self.wallet.increment_nonce()

        # Sign the transaction
        transaction.sign_transaction(self.wallet.private_key)

        # Validate the transaction
        if self.validate_transaction(transaction):
            # Run the transaction
            self.run_transaction(transaction)
            # Add the transaction in blockchain's last block
            self.blockchain.chain[-1].add_transaction(transaction)

            # Broadcast the transaction
            self.broadcast_transaction(receiver_node, transaction)

            # Check if the current block is full and mint a new block if necessary
            self.blockchain.print()
            if self.blockchain.chain[-1].is_full():
                self.mint_block()

        else:
            print("Invalid transaction! Will not broadcast.")

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
        sender_state_index = self.find_index(sender_public_key)
        sender_state = self.local_state[sender_state_index]

        if not sender_state:
            raise Exception("Invalid transaction: Sender not found in the network.")

        # Check the sender's account balance
        if sender_state["balance"] < transaction.cost():
            raise Exception("Invalid transaction: Insufficient balance.")

        # Check nonce for replay protection
        if sender_state["nonce"] != transaction.nonce:
            raise Exception("Invalid transaction: Incorrect nonce.")

        return True

    def find_index(self, public_key):
        """
        Finds the index of a node's information in the network based on a public key.

        Args:
            public_key (RSA key): The public key to search for.

        Returns:
            int: The index of the node's information if found.

        Raises:
            Exception: If the node cannot be found in the specified list.
        """
        public_key = public_key.export_key("PEM").decode()

        for index, node in enumerate(self.net_nodes):
            if node["public_key"] == public_key:
                return index
        raise Exception("Node couldn't be found in the network.")

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
        sender_state_index = self.find_index(sender_public_key)
        receiver_state_index = self.find_index(receiver_public_key)

        # Update sender's balance (reduce by transaction's cost)
        self.local_state[sender_state_index]["balance"] -= transaction.cost()
        self.local_state[sender_state_index]["nonce"] += 1

        # If the transaction is a coin transfer, update the receiver's balance
        if transaction.type == "coins":
            self.local_state[receiver_state_index]["balance"] += transaction.amount

        # # Add the transaction to the blockchain's current block if specified
        # if update_blockchain:
        #     self.blockchain.chain[-1].add_transaction(transaction)

        # # Check if the current block is full and mint a new block if necessary
        # if update_blockchain and self.blockchain.chain[-1].is_full():
        #     self.mint_block()

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
        print(receiver_node["port"] + 1)
        send_message_broadcast(receiver_node["port"] + 1, message)

    def process_transaction_queue(self):
        for transaction in self.transaction_queue:
            self.create_transaction(*transaction)
        self.transaction_queue = []

    def broadcast_block(self, block=None):
        """
        Broadcasts a block to all nodes in the network.
        """
        # block = self.dummy_block_creator()
        # self.blockchain.add_block(block)
        port = self.port + 1

        if block is not None:
            message = {"type": "broadcast_block", "block": block.to_json()}

        # send_message(receiver_node["ip"], receiver_node["port"], message)
        send_message_broadcast(port, message)

    def stake(self, amount):
        """
        Stakes a specified amount for the proof-of-stake process. This increases the chance
        of the node being selected as the validator for the next block.
        """
        # TODO: Perhaps also broadcast stake
        self.wallet.set_stake(amount)
        # public_key = RSA.import_key(self.wallet.public_key.encode())
        public_key = self.wallet.public_key
        index = self.find_index(public_key)
        self.local_state[index]["stake"] = self.wallet.stake
        # self.local_state[index]["balance"] -= amount

        # self.broadcast_stake(public_key, amount)

    def proof_of_stake(self):
        """
        Selects a validator for the next block based on their stake.
        """
        # Seed the random number generator with the hash of the last block
        if len(self.blockchain.chain) > 0:
            last_block_hash = self.blockchain.chain[-1].previous_hash
            random.seed(int(hashlib.sha256(last_block_hash.encode()).hexdigest(), 16))

            # Create a list of tuples (index, stake) for all states that have a stake
            stakes = [
                (index, state["stake"])
                for index, state in enumerate(self.local_state)
                if state["stake"] > 0
            ]
            if stakes:
                # Flatten the list to simulate a lottery: each "ticket" is an entry in the list
                lottery_pool = [index for index, stake in stakes for _ in range(stake)]
                # Randomly select a "ticket" (public_key)
                selected_validator_index = random.choice(lottery_pool)
                selected_validator_public_key = self.net_nodes[
                    selected_validator_index
                ]["public_key"]
                self.expected_validator = selected_validator_public_key
                print("Selected validator ->", selected_validator_public_key)
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
        self.expected_validator = validator_public_key

        # Check if the current node is the selected validator
        if (
            validator_public_key
            and self.wallet.public_key.export_key("PEM").decode()
            == validator_public_key
        ):
            candidate_block = self.blockchain.chain[-1]

            # Assign the validator to the block
            validator = RSA.import_key(validator_public_key)
            self.blockchain.chain[-1].validator = validator

            # Compute the fees
            total_fees = candidate_block.total_fees()

            # Find the validator index in the local state to update the balance with fees
            validator_index = self.find_index(validator)
            self.local_state[validator_index]["balance"] += total_fees

            # Update the global state
            self.valid_state = self.local_state.copy()

            # Broadcast the validated block to the network
            self.broadcast_block(self.blockchain.chain[-1])

            # Add transactions related to this node's wallet
            add_transactions_to_wallet(self.wallet, candidate_block.transactions)

            # Update wallet's balance
            self.wallet.wallet_balance()

            # Add an empty block
            self.blockchain.add_block(self.blockchain.empty_block())

            print("Block minted and broadcasted successfully.")
        else:
            print("Node is not the selected validator or no validator selected.")

    def view_block(self):
        """
        Finds the most recently validated block where the validator is not None and prints its transactions
        and the id of its validator.
        """
        validated_block = None
        for block in reversed(self.blockchain.chain):
            if block.validator is not None:
                validated_block = block
                break

        if validated_block is None:
            print("No validated blocks found.")
            return

        validator = RSA.import_key(validated_block.validator)
        validator_index = self.find_index(validator, 'node')
        validator_id = self.net_nodes[validator_index]["id"]

        print("Last validated block info:")
        print("Transactions:")
        for transaction in validated_block.transactions:
            transaction.print()
        print("Validator id: ", validator_id)

    ###############
    ### Below here are functions regarding network connectivity between nodes ###
    ###############
    def advertise_node(self, host, port):
        """
        Advertises itself to other node (bootstrap) hy sending an initialization message.
        """
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
        """
        Creates and sends a "init_response" message and updates the network.
        """
        message = {
            "type": "init_response",
            "id": self.next_id,
            "blockchain": self.blockchain.to_json(),
        }
        send_message(host, port, message)
        self.update_and_broadcast_network(data)

    def update_and_broadcast_network(self, data):
        """
        Receives and handles an "init_response" message. It:
            - Adds the received node in the network list,
            - Adds node's wallet info in valid_state.
            - Updates the next_id
            - If network reach its full node capacity, it creates and broadcasts a "set up ready" message
        """
        self.add_node_to_network(
            self.next_id,
            data["node"]["ip"],
            data["node"]["port"],
            data["node"]["public"],
        )

        self.add_node_to_valid_state(self.next_id, 1000, 10, 0)
        self.next_id += 1

        # Broadcast network node info after all nodes have been initialized.
        if len(self.net_nodes) == self.N:
            # Prepare the "set up "ready" message
            message = {"type": "set up ready", "nodes": self.net_nodes}
            with open("output.txt", "a") as f:
                print(message, file=f)
            
            # Broadcast the message
            send_message_broadcast(self.port + 1, message)
            self.local_state = self.valid_state.copy()
            with open("output_bootstrap_states.txt", "a") as f:
                print(self.net_nodes, file=f)
                print(self.local_state, file=f)

    def node_finish_init(self, data):
        """
        Handles a "init_response" message. It:
            - Sets the node's id.
            - Copies the received blockchain.
            - Adds an empty block if the last block is already full.
        """
        self.set_node_id(data["id"])
        self.blockchain = Blockchain.from_json(data["blockchain"])
        
        last_block = self.blockchain.chain[-1]

        if last_block.is_full():
            print("CAPACITY")
            print(self.blockchain.block_capacity)
            empty_block = self.blockchain.empty_block()
            self.blockchain.add_block(empty_block)
        self.blockchain.print()

    def handle_new_transaction(self, data):
        """
        Handles a new incoming transaction.
        """
        transaction = Transaction.from_json(data["transaction"])
        if self.validate_transaction(transaction):
            self.blockchain.chain[-1].add_transaction(transaction)
            self.run_transaction(transaction)

            with open("blockchain.txt", "a") as f:
                with contextlib.redirect_stdout(f):
                    self.blockchain.print()
            if self.blockchain.chain[-1].is_full():
                self.mint_block()


    def handle_new_block(self, data):
        """
        Handles a new incoming block.
        """
        print("Handle new block")
        new_block = BlockChatCoinBlock.from_json(data["block"])

        #validator = self.expected_validator

        # Validates the new block, removes the last block and adds the validated block
        if new_block.validate_block(
            self.blockchain.chain[-1],
            self.expected_validator,
        ):
            print("Blockchain BEFORE!")
            self.blockchain.print()

            x = self.blockchain.chain.pop()

            print("Blockchain AFTER")
            self.blockchain.print()
            print("Popped block ->")
            x.print()

            self.blockchain.add_block(new_block)

            # Restores old state
            self.local_state = self.valid_state.copy()

            # Runs the block updating the local state and updates valid_state
            self.run_block(self.blockchain.chain[-1])

            # Add transactions related to this node's wallet
            add_transactions_to_wallet(self.wallet, new_block.transactions)

            # Update wallet's balance
            self.wallet.wallet_balance()

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

            # Add an empty block
            self.blockchain.add_block(self.blockchain.empty_block())
        else:
            print("Block validation failed.")

    def handle_client_response(self, host, port, data):
        """
        Handles a received message based on its type:
            "initialization":           -> Sent by a new node to the bootstrap. The new node advertises itself and the bootstrap updates its network list.
            "init_response":            -> Bootstrap's response to "initialization message". It sends the next_id and the blockchain to the new node.
            "set up ready":             -> Broadcast message with info about the ips / ports / public key of each node. Sent when all nodes have communicated with the bootstrap node.
            "broadcast_transaction":    -> Broadcasts a transaction to all blockchain nodes.
            "broadcast_block":          -> Broadcasts a block to all blockchain nodes from the validator node.
        """
        # TODO: The way host & port is handled need to be remade.
        if host == self.ip:
            return
        if data["type"] == "initialization":
            self.send_new_node_info(host, data["node"]["port"], data)

        elif data["type"] == "init_response":
            self.node_finish_init(data)

        elif data["type"] == "set up ready":
            self.finish_setup(data)
            # print(json.dumps(self.net_nodes, sort_keys=True, indent=4))
            # print(json.dumps(self.local_state, sort_keys=True, indent=4))
            # print(json.dumps(self.valid_state, sort_keys=True, indent=4))
            print(self.net_nodes)
            print(self.local_state)
            print(self.valid_state)
            self.wallet.print()
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
                data_received = conn.recv(32768)

                if not data_received:
                    break

                data = json.loads(data_received.decode())
                print(f"Received from {addr}: {data}")
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
        if self.bootstrap:
            print(f"Bootstrap listening for UDP messages on port {host}:{port}")
        else:
            print(f"Node listening for UDP messages on port {host}:{port}")
        # Start listening in a new thread
        threading.Thread(target=self.listen_for_udp_messages, daemon=True).start()

    def listen_for_udp_messages(self):
        """Listens for messages from other nodes and processes them."""
        while self.running:
            try:
                data, addr = self.udp_socket.recvfrom(
                    32768
                )  # Adjust buffer size as needed
                if data:
                    message_data = json.loads(data.decode())
                    with open("udp.txt", "a") as f:
                        print(f"Received message from {addr}: {message_data}", file=f)
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
            len(self.blockchain.chain) + 1, [], self.blockchain.chain[-1].hash
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


