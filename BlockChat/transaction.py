import json
from Crypto.Hash import SHA256
from Crypto.Signature import pss
from Crypto.PublicKey import RSA

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

    def __init__(
        self,
        sender_address,
        receiver_address,
        type,
        nonce,
        amount=None,
        message=None,
        signature=None,
        transaction_id=None,
    ):
        self.sender_address = sender_address.export_key(format="PEM").decode()
        self.receiver_address = receiver_address.export_key(format="PEM").decode()
        # self.sender_address = sender_address
        # self.receiver_address = receiver_address
        self.type = type
        self.nonce = nonce
        self.amount = amount
        self.message = message
        self.transaction_id = (
            transaction_id if transaction_id else self.transaction_hash()
        )
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
            "nonce": self.nonce,
        }
        return json.dumps(transaction_data, sort_keys=True).encode()

    def to_json(self):
        """
        Serializes the entire transaction into a JSON string for transmission.
        """
        transaction_dict = {
            "sender_address": self.sender_address,
            "receiver_address": self.receiver_address,
            "type": self.type,
            "nonce": self.nonce,
            "amount": self.amount,
            "message": self.message,
            "transaction_id": self.transaction_id,
            "signature": self.signature.hex() if self.signature else None,
        }
        return json.dumps(transaction_dict)

    @staticmethod
    def from_json(json_str):
        """
        Deserializes a JSON string back into a Transaction object.
        """
        data = json.loads(json_str)
        transaction = Transaction(
            sender_address=RSA.import_key(data["sender_address"].encode()),
            receiver_address=RSA.import_key(data["receiver_address"].encode()),
            type=data["type"],
            nonce=data["nonce"],
            amount=data["amount"],
            message=data["message"],
            signature=bytes.fromhex(data["signature"]) if data["signature"] else None,
            transaction_id=data["transaction_id"],
        )
        return transaction

    def transaction_hash(self):
        """
        Generates a SHA-256 hash for the transaction.
        """
        return SHA256.new(self.serialize_transaction_data()).hexdigest()

    def cost(self):
        """
        Calculates the total cost (in BlockChat Coins) of the transaction.
        """
        if self.sender_address == self.receiver_address:
            return self.amount
        return self.amount * 1.03 if self.amount else len(self.message) if self.message else 0

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

    def print(self):
        """
        Prints information about the transaction.
        """
        print("Transaction ID: ", self.transaction_id)
        print("Sender Address: ", self.sender_address)
        print("Receiver Address: ", self.receiver_address)
        print("Type: ", self.type)
        print("Cost (in coins): ", self.cost())
        print("Message: ", self.message) if self.message else None
        print("Nonce:", self.nonce)
