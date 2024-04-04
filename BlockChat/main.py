from blockchain import Blockchain
from proof_of_stake import select_validator
from datetime import datetime

bcc_blockchain = Blockchain()

validators = {"validator1": 100, "validator2": 200}

selected_validator = select_validator(validators)
bcc_blockchain.add_block("500 BCC coins from wallet 1 to wallet 2", selected_validator)
selected_validator = select_validator(validators)
bcc_blockchain.add_block("200 BCC coins from wallet 3 to wallet 1", selected_validator)
selected_validator = select_validator(validators)
bcc_blockchain.add_block("10 BCC coins from wallet 1 to wallet 2", selected_validator)
selected_validator = select_validator(validators)
bcc_blockchain.add_block("20 BCC coins from wallet 1 to wallet 3", selected_validator)
selected_validator = select_validator(validators)
bcc_blockchain.add_block("30 BCC coins from wallet 1 to wallet 4", selected_validator)
selected_validator = select_validator(validators)
bcc_blockchain.add_block("40 BCC coins from wallet 1 to wallet 5", selected_validator)
selected_validator = select_validator(validators)
bcc_blockchain.add_block("50 BCC coins from wallet 1 to wallet 6", selected_validator)

bcc_blockchain.print_blockchain_contents()

print("Blockchain is valid:", bcc_blockchain.is_valid())