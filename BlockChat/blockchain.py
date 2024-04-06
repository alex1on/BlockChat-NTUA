from block import BlockChatCoinBlock
from transaction import Transaction
from wallet import Wallet


class Blockchain:
    """
    Class that represents a BlockChat blockchain.
    
    chain -> list of blocks
    """
    
    def __init__(self):
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self, N=5, wallet=None):
        """
        Creates the genesis block.
        """
        transaction = Transaction(wallet.public_key, wallet.public_key, 'coins', 0, 1000 * N)
        genesis_block = BlockChatCoinBlock(0,[transaction], 0, "1")
        self.chain.append(genesis_block)

    def add_block(self, block):
        """
        Adds a new block in the chain.
        """
        self.chain.append(block)
        # previous_block = self.chain[-1]
        # new_block = BlockChatCoinBlock(len(self.chain), transactions, validator, previous_block.hash)
        # self.chain.append(new_block)

    def validate_chain(self):
        """
        Validates the blockchain.
        """
        for i in range(1, len(self.chain) - 1):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if not current_block.validate_block(previous_block):
                return False

        return True

    def print(self):
        """
        Prints blockchain's info.
        """
        for block in self.chain:
            block.print()
