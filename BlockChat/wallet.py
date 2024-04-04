class Wallet:
    """
    Class that represents a BlockChat Wallet.
    
    private_key     -> wallet's private key (RSA)
    public_key      -> wallet's public key  (RSA)
    nonce           -> number of transactions sent by the wallet
    transactions    -> a list of all the transactions of the wallet
    """
    def __init__(self, public_key, private_key):
        self.public_key = public_key
        self.private_key = private_key
        self.transactions = []
        self.nonce = 0
        self.balance = self.wallet_balance()
        
    def wallet_balance(self):
        """
        Computes and returns the balance (in BlockChat Coins) of the wallet.
        """
        balance = 0
        # TODO: Calculate balance
        return balance
    
    def add_coins(self, ammount):
        self.balance += ammount
    
    def remove_coins(self, ammount):
        self.balance -= ammount
    
    def increment_nonce(self):
        """
        Increments nonce by 1.
        This method is called for each transaction sent from this wallet.
        """
        self.nonce += 1
        
    def print(self):
        """
        Prints information about the wallet.
        """
        print('Public Key: \n', self.public_key)
        print('Private Key: \n', self.private_key)  # TODO: Remove private key from printing!
        print('Nonce ', self.nonce)
        print('Balance: ', self.balance)
        print('Transactions: ')
        for transaction in self.transactions:
            transaction.print()
