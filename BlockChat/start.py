import os
from node_v2 import node

if __name__ == "__main__":
    node_ip = os.environ.get('NODE_IP', '0.0.0.0')
    node_port = int(os.environ.get('NODE_PORT', '5000'))
    network_size = int(os.environ.get('NETWORK_SIZE', '3'))
    is_bootstrap = os.environ.get('IS_BOOTSTRAP', 'False').lower() in ('true', '1', 't')

    # Initialize and start the node
    blockchain_node = node(node_ip, node_port, network_size, is_bootstrap)
    blockchain_node.start()  # Assuming your node class has a start method to initialize its operations
