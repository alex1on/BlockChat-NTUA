import hashlib
import time
import json

class BlockChatCoinBlock:
    def __init__(self, index, transactions, validator, previous_hash):
        self.index = index
        self.timestamp = time.time()
        self.transactions = transactions
        self.validator = validator
        self.previous_hash = previous_hash
        self.current_hash = self.compute_hash()

    def compute_hash(self):
        # exclude current_hash for validation purposes
        block_string = json.dumps({k: v for k, v in self.__dict__.items() if k != 'current_hash'}, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()