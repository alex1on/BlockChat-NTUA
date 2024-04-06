from Crypto.PublicKey import RSA
from wallet import Wallet
from transaction import Transaction
from block import BlockChatCoinBlock
from blockchain import Blockchain

def generate_wallet():
    """
    Creates a new wallet.
    """
    key = RSA.generate(2048)
    
    private_key = key
    public_key = key.publickey()
    
    return Wallet(public_key, private_key)

def add_transactions_to_wallet(wallet, transactions):
    """
    Adds transactions related to the given wallet from a list of transactions.

    Args:
        wallet (Wallet): The wallet to which transactions are added.
        transactions (list): A list of Transaction objects.
    """
    for transaction in transactions:
        if transaction.sender_address == wallet.public_key or transaction.receiver_address == wallet.public_key:
            wallet.transactions.append(transaction)
            
