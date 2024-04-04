from Crypto.PublicKey import RSA
from wallet import Wallet

def generate_wallet():
    """
    Creates a new wallet.
    """
    key = RSA.generate(2048)
    
    private_key = key
    public_key = key.publickey()
    
    return Wallet(public_key, private_key)
