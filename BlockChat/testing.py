from wallet import *
from transaction import *

"""
This scripts is used for testing purposes.
"""

sender = generate_wallet()
receiver = generate_wallet()

sender.print()
print('\n')
receiver.print()

print('\n')

t1 = Transaction(sender.public_key.export_key(), receiver.public_key.export_key(), 'coin', sender.nonce, amount=9)

# Use the RSA private key object for signing
t1.sign_transaction(sender.private_key)

# Use the RSA public key object for verification
print(t1.verify_signature(RSA.import_key(sender.public_key.export_key())))
print(t1.verify_signature(RSA.import_key(receiver.public_key.export_key())))

print('\n')

t2 = Transaction(receiver.public_key.export_key(), sender.public_key.export_key(), 'coin', receiver.nonce, message="Test message")
t2.sign_transaction(receiver.private_key)

print(t2.verify_signature(RSA.import_key(receiver.public_key.export_key())))
print(t2.verify_signature(RSA.import_key(sender.public_key.export_key())))
