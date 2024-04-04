from block import BlockChatCoinBlock
from datetime import datetime

def print_block(block):
        readable_timestamp = datetime.fromtimestamp(block.timestamp).strftime("%Y-%m-%d %H:%M:%S")
        print(f"Block Index: {block.index}")
        print(f"Timestamp: {readable_timestamp}")
        print(f"Transactions: {block.transactions}")
        print(f"Validator: {block.validator}")
        print(f"Current Hash: {block.current_hash}")
        print(f"Previous Hash: {block.previous_hash}\n")

class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = BlockChatCoinBlock(0, "1000*n BCC coins from wallet 0", 0, "1")
        self.chain.append(genesis_block)

    def add_block(self, transactions, validator):
        previous_block = self.chain[-1]
        new_block = BlockChatCoinBlock(len(self.chain), transactions, validator, previous_block.current_hash)
        self.chain.append(new_block)

    def is_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]

            if current_block.current_hash != current_block.compute_hash():
                print(f"Current hash {i} does not match the computed hash")
                return False

            if current_block.previous_hash != previous_block.current_hash:
                print(
                    f"Previous block's hash doesn't match with current block's {i} previous hash"
                )
                return False

        return True
