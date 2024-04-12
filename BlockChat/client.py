import socket
import json
import sys

class Client:
    """
    A client to communicate with a node server handling cli operations.
    
    Attributes:
        host (str): The server's hostname or IP address.
        port (int): The port on which the server is listening.
        socket (socket.socket): The socket object used for communication.
    """
    def __init__(self, host, port):
        """
        Initializes the Client with a specific server address and port.
        
        Args:
            host (str): The server's hostname or IP address.
            port (int): The port on which the server is listening.
        """
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect()

    def connect(self):
        """
        Establishes a connection to the node server.
        """
        try:
            self.socket.connect((self.host, self.port))
            print("Connected to node server at {}:{}".format(self.host, self.port))
        except Exception as e:
            print("Failed to connect to the server: ", e)
            sys.exit(1)

    def send_message(self, message):
        """
        Sends a message to the server and prints the response.
        
        Args:
            message (dict): The message to be sent in JSON format.
        """
        try:
            self.socket.sendall(json.dumps(message).encode('utf-8'))
            response = self.socket.recv(32768).decode('utf-8')
            print("Server response:", response)
        except Exception as e:
            print("Failed to send message: ", e)

    def send_transaction(self, recipient_address, amount=None, message=None):
        """
        Sends a transaction request to the node server.
        
        Args:
            recipient_address (str): The address of the transaction recipient.
            amount (int, optional): The amount of coins to be transferred, for coin transactions.
            message (str, optional): The message for message transactions.
        """
        transaction_type = 'coin' if amount is not None else 'message'
        self.send_message({
            "type": "transaction",
            "transaction_type": transaction_type,
            "recipient_address": recipient_address,
            "amount": amount,
            "message": message
        })

    def stake(self, amount):
        """
        Sends a staking request to the node server.
        
        Args:
            amount (int): The amount of coins to stake.
        """
        self.send_message({
            "type": "stake",
            "amount": amount
        })

    def check_balance(self):
        """
        Requests the current balance from the node server.
        """
        self.send_message({
            "type": "balance"
        })

    def view_block(self):
        """
        Requests to view the transactions in the last block and block's id from the node server.
        """
        self.send_message({
            "type": "view"
        })

    def close_connection(self):
        """
        Closes the socket connection to the node server.
        """
        self.socket.close()

def main():
    client = Client('localhost', 3001)
    try:
        while True:
            command = input("Enter command (type 'exit' to quit): ").strip()
            if command.lower() == 'exit':
                break

            args = command.split()
            if args[0] == 't' and len(args) == 3:
                recipient, value = args[1], args[2]
                if value.isdigit():
                    client.send_transaction(recipient, amount=int(value))
                else:
                    client.send_transaction(recipient, message=value)
            elif args[0] == 'stake' and len(args) == 2:
                amount = int(args[1])
                client.stake(amount)
            elif args[0] == 'balance':
                client.check_balance()
            elif args[0] == 'view':
                client.view_block()
            else:
                print("Invalid command")
    finally:
        client.close_connection()

if __name__ == "__main__":
    main()
