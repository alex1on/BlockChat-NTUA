from transaction import Transaction

class Wallet:
    """
    Class that represents a BlockChat Wallet.
    
    private_key     -> wallet's private key (RSA)
    public_key      -> wallet's public key  (RSA)
    nonce           -> number of transactions sent by the wallet
    transactions    -> a list of all the transactions of the wallet
    balance         -> wallet's balance (in BCC)
    stake           -> wallet's stake used for proof of stake
    """
    
    def __init__(self, public_key, private_key):
        self.public_key = public_key
        self.private_key = private_key
        self.transactions = []
        self.nonce = 0
        self.balance = 0
        self.stake = 0
        
    def wallet_balance(self):
        """
        Computes and returns the balance (in BlockChat Coins) of the wallet.
        """
        balance = 0
        # self.balance = 0
        for transaction in self.transactions:
            if transaction.sender_address == self.public_key:
                balance -= transaction.cost()
                # self.remove_coins(transaction.cost())
            elif transaction.receiver_address == self.public_key and transaction.type == 'coins': 
                balance += transaction.amount
                # self.add_coins(transaction.amount)
        if balance < 0:
            raise ValueError("Balance shouldn't be negative! Something went wrong! 😕")
        return balance
    
    def set_stake(self, amount):
        if amount <= self.balance:
            self.stake = amount
            # TODO: Validator should update the balance 
        else:
            raise ValueError("Insufficient balance to stake this amount")
    
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
        
        return self.nonce
                
    def print(self):
        """
        Prints information about the wallet.
        """
        print('Public Key: \n', self.public_key)
        print('Private Key: \n', self.private_key)  # TODO: Remove private key from printing!
        print('Nonce ', self.nonce)
        print('Balance: ', self.balance)
        print('Stake: ', self.stake)
        print('Transactions: ')
        for transaction in self.transactions:
            transaction.print()
