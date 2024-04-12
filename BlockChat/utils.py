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


def print_help():
    print("""
        Available commands:
        t <recipient_address> <amount> - Transfer amount of BTC coins to recipient_address.
        t <recipient_address> <message> - Send a message to recipient_address.
        stake <amount> - Stake amount of coins for proof of stake.
        view - View transactions in the last block.
        balance - Show wallet balance.
        help - Show this help message.
    """)
    
def handle_coin_transaction(node, recipient_address, amount):
    """
    Handles creating and processing a coin transaction through cli.
    """
    print(f"Creating coin transaction: {amount} to {recipient_address}")
    message = {
        "type": "valid_transaction"
    }
    try:
        node.create_transaction('coins', amount, None, recipient_address)
    except Exception as e:
        message = {
            "type": "fail_transaction",
            "error": e
        }
    send_message("localhost", 3000, message)
        
def handle_message_transaction(node, recipient_address, message):
    """
    Handles creating and processing a message transaction.
    """
    print(f"Sending message to {recipient_address}: {message}")
    message = {
        "type": "valid_transaction"
    }
    try:
        node.create_transaction('message', None, message, recipient_address)
    except Exception as e:
        message = {
            "type": "fail_transaction",
            "error": e
        }
    send_message("localhost", 3000, message)
    
def handle_stake(node, amount):
    """
    Handles stake amount command from cli.
    """
    print(f"Staking {amount}...")
    message = {
        "type": "valid_staking"
    }
    try:
        node.stake(amount)
    except Exception as e:
        message = {
            "type": "fail_staking",
            "error": e
        }
    send_message("localhost", 3000, message)
    
def handle_balance(node):
    """
    Handles balance command from cli.
    """
    message = {
        "amount": node.wallet.balance
    }
    send_message("localhost", 3000, message)

def handle_view(node):
    """
    Handles view command from cli.
    """
    send_message("localhost", 3000, node.view_block())
