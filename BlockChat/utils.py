import json
import socket
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
            
            
def send_message_broadcast(port, data):
    """
    Broadcast a message in the networks (subnet's) broadcast address.
    """
    broadcast_address = (
        "172.20.255.255"  # Broadcast address for the 172.20.0.0/16 subnet
    )
    serialized_data = json.dumps(data).encode()

    with open("output.txt", "a") as f:
        print(serialized_data, file=f)

    # Create a UDP socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        # Set the option to allow broadcasting
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # Send the data to the broadcast address
        sock.sendto(serialized_data, (broadcast_address, port))
        print(f"Broadcasted message to {broadcast_address}:{port}")
        with open("output.txt", "a") as f:
            print(f"Broadcasted message to {broadcast_address}:{port}", file=f)
    return


def send_message(host, port, data):
    """
    Sends a message to a specific host and port.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((host, port))
            print(f"Connected to {host}:{port}")
            client_socket.sendall(json.dumps(data).encode())
            # print(f"JSON data sent: {json.dumps(data).encode()}")

    except Exception as e:
        print(f"An error occurred: {e}")
