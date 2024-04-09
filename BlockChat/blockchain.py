import json
from block import BlockChatCoinBlock
from transaction import Transaction
from wallet import Wallet


class Blockchain:
    """
    Class that represents a BlockChat blockchain.
    
    chain -> list of blocks
    """
    
    def __init__(self, N=5, wallet=None):
        self.chain = []
        self.create_genesis_block(N, wallet)

    def create_genesis_block(self, N=5, wallet=None):
        """
        Creates the genesis block.
        """
        transaction = Transaction(wallet.public_key, wallet.public_key, 'coins', 0, 1000 * N)
        genesis_block = BlockChatCoinBlock(0,[transaction], 0, 1)
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
    
    def to_json(self):
        """
        Serializes the entire blockchain into a JSON string for transmission,
        including the serialization of each block within the chain.
        """
        blockchain_dict = {
            "chain": [json.loads(block.to_json()) for block in self.chain]
        }
        return json.dumps(blockchain_dict)
    
    @staticmethod
    def from_json(json_str):
        """
        Deserializes a JSON string back into a Blockchain object,
        including reconstructing each BlockChatCoinBlock from its JSON representation.
        """
        data = json.loads(json_str)
        blockchain = Blockchain()
        blockchain.chain = [BlockChatCoinBlock.from_json(json.dumps(block)) for block in data["chain"]]
        return blockchain

    
    def print(self):
        """
        Prints blockchain's info.
        """
        for block in self.chain:
            block.print()
