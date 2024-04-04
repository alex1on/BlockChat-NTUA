import hashlib
import time
import json
from datetime import datetime


class BlockChatCoinBlock:
    def __init__(self, index, transactions, validator, previous_hash):
        self.index = index
        self.timestamp = time.time()
        self.transactions = transactions
        self.validator = validator
        self.previous_hash = previous_hash
        self.hash = self.compute_hash()

    def compute_hash(self):
        # exclude hash for validation purposes
        self_string = json.dumps(
            {k: v for k, v in self.__dict__.items() if k != "hash"}, sort_keys=True
        )
        return hashlib.sha256(self_string.encode()).hexdigest()

    def print_self(self):
        readable_timestamp = datetime.fromtimestamp(self.timestamp).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        print(f"Block Index: {self.index}")
        print(f"Timestamp: {readable_timestamp}")
        print(f"Transactions: {self.transactions}")
        print(f"Validator: {self.validator}")
        print(f"Current Hash: {self.hash}")
        print(f"Previous Hash: {self.previous_hash}\n")

    def validate_block(self, prev_block):
        if self.hash != self.compute_hash():
            print("Current hash does not match the computed hash")
            return False

        if self.previous_hash != prev_block.hash:
            print("Previous block's hash doesn't match with current block's previous hash")
            return False

        return True
