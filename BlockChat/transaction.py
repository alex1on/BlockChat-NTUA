import json
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
# from wallet import generate_wallet

class Transaction:
    """
    Class that represents a BlockChat Transaction.
    
    sender_address      -> sender's public key
    receiver_address    -> receiver's public key
    type                -> type of transaction (coins or message)
    amount              -> amount of coins to transfer
    message             -> message to transfer 
    nonce               -> sender's counter
    transaction_id      -> the hash of the transaction
    signature           -> signature of the transaction
    """
    def __init__(self, sender_address, receiver_address, type, nonce, amount=None, message=None, signature=None, transaction_id=None):
        self.sender_address = sender_address.decode()
        self.receiver_address = receiver_address.decode()
        self.type = type
        self.nonce = nonce
        self.amount = amount
        self.message = message
        self.transaction_id = transaction_id if transaction_id else self.transaction_hash()
        self.signature = signature
        
    def serialize_transaction_data(self):
        """
        Serializes transaction's data, preparing them for hashing and signing.
        """
        transaction_data = {
            "sender_address": self.sender_address,
            "receiver_address": self.receiver_address,
            "type": self.type,
            "cost": self.cost(),
            "nonce": self.nonce
        }
        return json.dumps(transaction_data, sort_keys=True).encode()
        
    def transaction_hash(self):
        """
        Generates a SHA-256 hash for the transaction.
        """
        return SHA256.new(self.serialize_transaction_data()).hexdigest()
        
    def cost(self):
        """
        Calculates the total cost (in BlockChat Coins) of the transaction.
        TODO: Consider 3% fee
        """
        return self.amount if self.amount else len(self.message)
    
    def sign_transaction(self, private_key):
        """
        Signs the transaction using the sender's RSA private key.
        """
        hash_obj = SHA256.new(self.serialize_transaction_data())
        signer = pss.new(private_key)
        self.signature = signer.sign(hash_obj)
        
    def verify_signature(self, public_key):
        """
        Verifies the signature using the RSA public key.
        """
        hash_obj = SHA256.new(self.serialize_transaction_data())
        verifier = pss.new(public_key)
        try:
            verifier.verify(hash_obj, self.signature)
            return True
        except (ValueError, TypeError):
            return False
        
    def validate_transaction(self, id):
        """
        Validates the transaction by:
            a) Verifying the signature and
            b) Check the account balance
        """
        self.verify_signature()
        """
        TODO: 1) Check the account balance & 2) Check nonce (?)
        """
        
    def print(self):
        """
        Prints information about the transaction.
        """
        print('Transaction ID: ', self.transaction_id)
        print('Sender Address: ', self.sender_address)
        print('Receiver Address: ', self.receiver_address)
        print('Type: ', self.type)
        print('Cost (in coins): ', self.cost())
        print('Message: ', self.message) if self.message else None
        print('Nonce:', self.nonce)
