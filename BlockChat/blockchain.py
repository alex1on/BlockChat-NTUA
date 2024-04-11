import json
from block import BlockChatCoinBlock
from transaction import Transaction
from wallet import Wallet


class Blockchain:
    """
    Class that represents a BlockChat blockchain.

    chain -> list of blocks
    """

    def __init__(self, block_capacity, genesis=False, N=5, wallet=None):
        self.chain = []
        self.block_capacity = block_capacity
        if genesis:
            self.create_genesis_block(wallet, N)

    def create_genesis_block(self, wallet, N):
        """
        Creates the genesis block.
        """
        # TODO: Change the sender to 0
        # TODO: Handle Initial Transactions
        transaction = Transaction(
            wallet.public_key, wallet.public_key, "coins", 0, 1000 * N
        )
        wallet.balance = 1000
        genesis_block = BlockChatCoinBlock(0, [transaction], 0, 1)
        self.chain.append(genesis_block)

    def add_block(self, block):
        """
        Adds a new block in the chain.
        """
        self.chain.append(block)

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
            "chain": [json.loads(block.to_json()) for block in self.chain],
            "block_capacity" : self.block_capacity
        }
        return json.dumps(blockchain_dict)

    @staticmethod
    def from_json(json_str):
        """
        Deserializes a JSON string back into a Blockchain object,
        including reconstructing each BlockChatCoinBlock from its JSON representation.
        """
        data = json.loads(json_str)
        blockchain = Blockchain(data["block_capacity"])
        blockchain.chain = [
            BlockChatCoinBlock.from_json(json.dumps(block)) for block in data["chain"]
        ]
        return blockchain

    def empty_block(self):
        index = self.chain[-1].index + 1
        previous_hash = self.chain[-1].hash
        return BlockChatCoinBlock(index, [], previous_hash, self.block_capacity, None)

    def print(self):
        """
        Prints blockchain's info.
        """
        for block in self.chain:
            block.print()
