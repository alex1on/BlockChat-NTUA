import hashlib
import time
import json
from datetime import datetime
from transaction import Transaction
from Crypto.PublicKey import RSA

class BlockChatCoinBlock:
    """
    Class that represents a BlockChat Block.
    
    index           -> The serial number of the block
    timestamp       -> The timestamp of block's creation
    transactions    -> A list containing block's tranasactions
    validator       -> The public key of the node that validated the block
    hash            -> Block's hash
    previous_hash   -> The hash of the preivous block in the blockchain
    capacity        -> The maximum number of transactions that a block can contain
    """
    
    def __init__(self, index, transactions, previous_hash, capacity=10, validator=None):
        self.index = index
        self.timestamp = time.time()
        self.transactions = transactions
        self.validator = validator.export_key(format='PEM').decode() if validator else None
        self.previous_hash = previous_hash
        self.capacity = capacity
        self.hash = self.compute_hash()

    def compute_hash(self):
        """
        Generates a SHA-256 hash for the block.
        """
        # exclude hash for validation purposes
        self_string = json.dumps( # TODO: transactions is excludes as it cannot be serialized
            {k: v for k, v in self.__dict__.items() if k != "hash" and k != "transactions" and k!= "validator"}, sort_keys=True
        )
        return hashlib.sha256(self_string.encode()).hexdigest()

    def validate_block(self, prev_block, validator):
        """
        Validates the block by:
            a) Ensuring that the validator is the correct one (the one provided by proof of stake algorithm) TODO and
            b) The field previous_hash is indeed the hash of the previous block
        """
        
        # Extra (trivial) check -> current hash should match the computed hash
        if self.hash != self.compute_hash():
            print("Current hash does not match the computed hash")
            return False
        
        # a) Verify that the validator is correct
        if validator != self.validator:
            print("Couldn't validate the block! Wrong validator!")
            return False
        
        # b) Check the previous hash
        print("self ->", self.previous_hash)
        print("prev ->", prev_block.hash)
        if self.previous_hash != prev_block.hash:
            print("Previous block's hash doesn't match with current block's previous hash")
            return False
        
        print("Block validated!")

        return True
    
    def add_transaction(self, transaction):
        """
        Adds the transaction to the block
        """
        self.transactions.append(transaction)
        
    def is_full(self):
        """
        Returns True if the block is full.
        # """
        if self.capacity < len(self.transactions):
            raise ValueError("Total capacity exceeded! This shouldn't happen!")
        return self.capacity == len(self.transactions)
    
    def total_fees(self):
        """
        Calculates the total fees for the transactions included in this block.
        """
        fees = 0
        for transaction in self.transactions:
            if transaction.type == 'coins':
                fees += transaction.amount * 0.03
            elif transaction.type == 'message':
                fees += transaction.cost()
        return fees
    
    def to_json(self):
        """
        Serializes the entire block into a JSON string for Transmission,
        including the serialization of each transaction within the block
        """
        block_dict = {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": [json.loads(t.to_json()) for t in self.transactions],
            "validator": self.validator.export_key("PEM").decode() if self.validator is not None else None,
            "hash": self.hash,
            "previous_hash": self.previous_hash,
            "capacity": self.capacity
        }
        return json.dumps(block_dict)
    
    @staticmethod
    def from_json(json_str):
        """
        Deserializes a JSON string back into a BlockChatCoinBlock object.
        Also, reconstructs transactions from their JSON representation.
        """
        data = json.loads(json_str)
        transactions = [Transaction.from_json(json.dumps(t)) for t in data["transactions"]]
        block = BlockChatCoinBlock(
            index=data["index"],
            transactions=transactions,
            previous_hash=data["previous_hash"],
            capacity=data["capacity"],
            validator=RSA.import_key(data["validator"].encode()) if data["validator"] else None
        )
        block.timestamp = data["timestamp"]
        block.hash = data["hash"]
        return block
    
    def print(self):
        """
        Prints blocks info
        """
        readable_timestamp = datetime.fromtimestamp(self.timestamp).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        print(f"Block Index: {self.index}")
        print(f"Capacity: {self.capacity}")
        print(f"Timestamp: {readable_timestamp}")
        for transaction in self.transactions:
            print("Transaction: ")
            transaction.print()
            print("---")
        print(f"Validator: {self.validator}")
        print(f"Current Hash: {self.hash}")
        print(f"Previous Hash: {self.previous_hash}\n")
        