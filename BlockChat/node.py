from Crypto.PublicKey import RSA
import hashlib
import random
from blockchain import Blockchain
from transaction import Transaction
from BlockChat.utils import generate_wallet


class node:
    """
    Class that represents a node.
    
    id          -> The id of the node
    ip          -> The ip address of the node
    port        -> The port that the node listens to
    N           -> Naximum number of nodes
    network     -> Keeps information about the network
    chain       -> The blockchain
    wallet      -> The node's wallet
    """
    
    def __init__(self, id, ip, port, N, network=[], chain=None, wallet=None):
        
        self.id = id
        self.ip = ip
        self.port = port
        self.N = N
        self.network = network
        self.chain = chain if chain else Blockchain()
        self.wallet = wallet if wallet else generate_wallet()
        
        self.bootstrap()
    
    def is_bootstrap(self):
        return self.id == 0
                
    def bootstrap(self):
        self.add_node_to_network(self.id, self.ip, self.port, self.wallet.public_key, self.wallet.stake, self.wallet.balance, self.wallet.nonce)
        if self.is_bootstrap():
            self.chain.create_genesis_block(self.N, self.wallet)

    def add_node_to_network(self, id, ip, port, public_key, stake, balance, nonce):
        """
        Adds a node into the network
        """
        if len(self.network) == self.N:
            raise Exception('Cannot add more nodes. Network is full!')
        
        self.network.append({
            'id': id,
            'ip': ip,
            'port': port,
            'public_key': public_key,
            'stake': stake,
            'balance': balance,
            'nonce': nonce
        })
        
    def update_network(self, attribute, new_value):
        """
        Updates an attribute for a node in the network.

        :param attribute: The attribute to update.
        :param new_value: The new value to set for the attribute.
        """
        for network_node in self.network:
            if network_node['id'] == self.id:
                if attribute in network_node:
                    network_node[attribute] = new_value
                    print(f"Updated node {self.id}'s {attribute} to {new_value}.")
                else:
                    raise ValueError(f"Attribute {attribute} not found in network node.")
                break
        else:
            print(f"Node with id {self.id} not found in network.")

        # TODO: Implement a method to broadcast the changes
        
    def create_transaction(self, type, amount=None, message=None, receiver="0"):
        """
        Creates a transaction
        """
        if self.wallet.public_key == receiver:
            raise Exception("Recipient can't be the sender.")
        if amount and amount <= 0:
            raise Exception('Invalid Transaction: Amount can\'t be negative or zero!')
        
        nonce = self.wallet.increment_nonce()
        transaction = Transaction(self.wallet.public_key, receiver.public_key, type, nonce, amount, message)
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
        sender_info = next((node for node in self.network if node['public_key'] == transaction.sender_address), None)
        if not sender_info:
            raise Exception("Invalid transaction: Sender not found in the network.")

        # b) Check the account balance
        if sender_info['balance'] < transaction.cost():
            raise Exception("Invalid transaction: Insufficient balance.")

        # c) Check nonce for replay protection
        if sender_info['nonce'] != transaction.nonce:
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
        self.update_network('stake', self.wallet.stake)
        self.update_network('balance', self.wallet.balance)
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
            stakes = [(node.public_key, node.stake) for node in self.network if node.stake > 0]
            if not stakes:
                return None

            # Flatten the list to simulate a lottery: each "ticket" is an entry in the list
            lottery_pool = [public_key for public_key, stake in stakes for _ in range(stake)]
            
            if not lottery_pool:
                return None

            # Randomly select a "ticket"
            selected_validator = random.choice(lottery_pool)
            return selected_validator

        else:
            return None