from Crypto.PublicKey import RSA

class Wallet:
    """
    Class that represents a BlockChat wallet
    
    private_key     -> wallet's private key
    public_key      -> wallet's public key
    nonce           -> number of transactions sent by this wallet
    transactions    -> a list of all the transaction perfromed by this wallet
    """
    def __init__(self, public_key, private_key):
        self.public_key = public_key
        self.private_key = private_key
        self.transactions = []
        self.nonce = 0
        
    def wallet_balance(self):
        """
        Returns the balance (in BlockChat Coins) of the wallet
        """
        balance = 0
        """
        TO DO
        """
        return balance
    
    def print(self):
        """
        Prints information about the wallet
        """
        print('Public Key: \n', self.public_key)
        print('Private Key: \n', self.private_key)
        print('Nonce ', self.nonce)
        print('Transactions: ')
        for transaction in self.transactions:
            transaction.print()

def generate_wallet():
    """
    It creates a new wallet
    """
    key = RSA.generate(2048)
    
    private_key = key.export_key()
    public_key = key.public_key().export_key()
    
    return Wallet(public_key, private_key)

# generate_wallet().print()