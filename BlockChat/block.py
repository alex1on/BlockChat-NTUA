import hashlib
import time
import json
from datetime import datetime


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
        self.validator = validator
        self.hash = self.compute_hash()
        self.previous_hash = previous_hash
        self.capacity = capacity

    def compute_hash(self):
        """
        Generates a SHA-256 hash for the block.
        """
        # exclude hash for validation purposes
        self_string = json.dumps( # TODO: transactions is excludes as it cannot be serialized
            {k: v for k, v in self.__dict__.items() if k != "hash" and k != "transactions"}, sort_keys=True
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
        if self.previous_hash != prev_block.hash:
            print("Previous block's hash doesn't match with current block's previous hash")
            return False

        # Update validator's balance and stake
        validator.balance -= validator.stake
        validator.stake = 0
        return True
    
    def add_transaction(self, transaction):
        """
        Adds the transaction to the block
        """
        self.transactions.append(transaction)
        
    def full_block(self):
        """
        Returns True if the block is full.
        """
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
    
    def print(self):
        """
        Prints blocks info
        """
        readable_timestamp = datetime.fromtimestamp(self.timestamp).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        print(f"Block Index: {self.index}")
        print(f"Timestamp: {readable_timestamp}")
        print(f"Transactions: {self.transactions}")
        print(f"Validator: {self.validator}")
        print(f"Current Hash: {self.hash}")
        print(f"Previous Hash: {self.previous_hash}\n")
        