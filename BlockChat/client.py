import os
import sys
import signal
from node_v2 import node

current_node = None

def start_node(ip, port, N, is_bootstrap=False):
    """
    Initiates a node.
    """
    global current_node
    current_node = node(ip, port, N, is_bootstrap)
    signal.signal(signal.SIGINT, current_node.signal_handler)
    print(f"Node started on {ip}:{port} {'as bootstrap' if is_bootstrap else ''}")

def handle_coin_transaction(recipient_address, amount):
    """
    Handles creating and processing a coin transaction.
    """
    print(f"Creating coin transaction: {amount} to {recipient_address}")
    current_node.create_transaction('coins', amount, None, recipient_address)

def handle_message_transaction(recipient_address, message):
    """
    Handles creating and processing a message transaction.
    """
    print(f"Sending message to {recipient_address}: {message}")
    current_node.create_transaction('message', None, message, recipient_address)

def print_help():
    print("""
        Available commands:
        t <recipient_address> <amount> - Transfer amount of BTC coins to recipient_address.
        m <recipient_address> <message> - Send a message to recipient_address.
        stake <amount> - Stake amount of coins for proof of stake.
        view - View transactions in the last block.
        balance - Show wallet balance.
        help - Show this help message.
    """)
    
def interactive_cli():
    """
    Provides an interactive command line interface for node operations.
    """
    global current_node
    if current_node is None:
        print("Node has not been initialized. Exiting.")
        return

    print("Interactive CLI mode. Type 'help' for available commands.")
    while True:
        try:
            raw_input = input("> ")
            args = raw_input.split()
            if not args:
                continue

            cmd = args[0].lower()
            if cmd == "quit":
                #  Quit command
                print("Exiting interactive CLI.")
                break
            elif cmd == "help":
                # Help command
                print_help()            
            elif cmd == "t":
                # Transaction command
                if len(args) == 3:
                    _, recipient_address, third_arg = args
                    try:
                        # If the third argument can be converted to an integer, it's a coin transaction
                        amount = int(third_arg)
                        handle_coin_transaction(recipient_address, amount)
                    except ValueError:
                        # If not, it's assumed to be a message transaction with a single-word message
                        message = third_arg
                        handle_message_transaction(recipient_address, message)
                elif len(args) > 3:
                    # Assume it's a message transaction if there are more than 3 arguments
                    recipient_address = args[1]
                    message = ' '.join(args[2:])
                    handle_message_transaction(recipient_address, message)
                else:
                    print("Invalid usage. For coin transfer: t <recipient_address> <amount>. For message: t <recipient_address> <message>")
            elif cmd == "stake":
                # Stake command
                if len(args) != 2:
                    print("Usage: stake <amount>")
                else:
                    amount = int(args[1])
                    print(f"Staking {amount}")
                    current_node.stake(amount)
            elif cmd == "view":
                # View command
                if len(args) != 1:
                    print("Usage: view")
                else:
                    print(f"Viewing last block")
                    current_node.view_block()
            elif cmd == "balance":
                # Balance command
                if len(args) != 1:
                    print("Usage: balance")
                else:
                    print(f"Wallet balance: {current_node.wallet.balance}")
            else:
                print("Unknown command. Type 'help' for a list of commands.")
        except EOFError:
            break
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
  
    # Check if script is run with arguments for node configuration
    if len(sys.argv) > 4:
        _, mode, ip, port, N = sys.argv
        port = int(port)
        N = int(N)
        is_bootstrap = mode.lower() == "bootstrap"
        start_node(ip, port, N, is_bootstrap)
        
    else:
        print("Insufficient arguments provided.")
        sys.exit(1)

    # Check if running inside Docker to start CLI automatically
    if os.getenv("DOCKER_ENV"):
        interactive_cli()