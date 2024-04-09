from Crypto.PublicKey import RSA
from transaction import Transaction
from utils import generate_wallet

"""
This scripts is used for testing purposes.
"""

sender = generate_wallet()
receiver = generate_wallet()

sender.print()
print('\n')
receiver.print()

print('\n')

t1 = Transaction(sender.public_key, receiver.public_key, 'coin', sender.nonce, amount=9)

# Use the RSA private key object for signing
t1.sign_transaction(sender.private_key)

# Use the RSA public key object for verification
print(t1.verify_signature(sender.public_key))
print(t1.verify_signature(receiver.public_key))

print('\n')

t2 = Transaction(receiver.public_key, sender.public_key, 'coin', receiver.nonce, message="Test message")
t2.sign_transaction(receiver.private_key)

print(t2.verify_signature(receiver.public_key))
print(t2.verify_signature(sender.public_key))

print('\n')

print("Another test")

print("T R A N S A C T I O N   T 1")
t1.print()

print("T R A N S A C T I O N   T1   I N   J S O N")
t1_json = t1.to_json()
print(t1_json)

print("T R A N S A C T I O N   T1   F R O M   J S O N")
Transaction.from_json(t1_json).print()
