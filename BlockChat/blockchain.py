from block import BlockChatCoinBlock


class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = BlockChatCoinBlock(0, "1000*n BCC coins from wallet 0", 0, "1")
        self.chain.append(genesis_block)

    def add_block(self, transactions, validator):
        previous_block = self.chain[-1]
        new_block = BlockChatCoinBlock(
            len(self.chain), transactions, validator, previous_block.hash
        )
        self.chain.append(new_block)

    def is_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if current_block.hash != current_block.compute_hash():
                print(f"Current hash {i} does not match the computed hash")
                return False

            if current_block.previous_hash != previous_block.hash:
                print(
                    f"Previous block's hash doesn't match with current block's {i} previous hash"
                )
                return False

        return True

    def print_blockchain_contents(self):
        for block in self.chain:
            block.print_self()
