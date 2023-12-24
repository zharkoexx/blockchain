from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import hashlib
import time

class Block:
    def __init__(self, index, previous_hash, timestamp, transactions, merkle_root, hash):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.transactions = transactions
        self.merkle_root = merkle_root
        self.hash = hash

class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.create_genesis_block()

    def create_genesis_block(self):
        # Create the genesis block (the first block in the blockchain)
        genesis_block = self.create_block([], '0')
        self.chain.append(genesis_block)

    def create_block(self, transactions, previous_hash):
        # Create a new block with current transactions, the hash of the previous block, and the Merkle root
        merkle_root = self.calculate_merkle_root(transactions)
        block_data = str(transactions) + str(previous_hash) + str(merkle_root)
        block_hash = hashlib.sha256(block_data.encode()).hexdigest()

        return Block(
            index=len(self.chain),
            previous_hash=previous_hash,
            timestamp=time.time(),
            transactions=transactions,
            merkle_root=merkle_root,
            hash=block_hash
        )

    def add_block(self, block):
        # Add a new block to the chain
        self.chain.append(block)
        # Clear current transactions after adding a block
        self.current_transactions = []

    def add_transaction(self, sender, recipient, amount):
        # Add a transaction to the current transactions
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        })

    def calculate_merkle_root(self, transactions):
        if not transactions:
            # No transactions to calculate Merkle root, handle this case (return None or raise an exception)
            return None  # You can modify this to raise an exception if needed

        hashes = [hashlib.sha256(str(tx).encode()).hexdigest() for tx in transactions]

        while len(hashes) > 1:
            next_level = []
            for i in range(0, len(hashes), 2):
                combined = hashes[i] + (hashes[i + 1] if i + 1 < len(hashes) else '')
                next_level.append(hashlib.sha256(combined.encode()).hexdigest())
            hashes = next_level

        return hashes[0]

class BlockchainCLI:
    def __init__(self):
        # Use your Blockchain class
        self.blockchain = Blockchain()

    def run(self):
        while True:
            user_input = input("Enter a command: ")
            args = user_input.split()

            if not args:
                continue

            command = args[0].lower()

            if command == 'add_transaction' and len(args) == 4:
                sender, recipient, amount = args[1], args[2], args[3]
                self.blockchain.add_transaction(sender, recipient, amount)
                print("Transaction added.")

            elif command == 'add_block' and len(args) == 1:
                # Create a block and add it to the chain
                new_block = self.blockchain.create_block(
                    self.blockchain.current_transactions,
                    self.blockchain.chain[-1].hash if self.blockchain.chain else '0'
                )
                self.blockchain.add_block(new_block)
                print("Block added.")

            elif command == 'show_blockchain' and len(args) == 1:
                print("Blockchain state:")
                for block in self.blockchain.chain:
                    print(f"Block #{block.index}")
                    print(f"Timestamp: {block.timestamp}")
                    print(f"Transactions: {block.transactions}")
                    print(f"Merkle Root: {block.merkle_root}")
                    print(f"Hash: {block.hash}")
                    print("--------------------")

            elif command in ['exit', 'quit']:
                print("Program terminated.")
                break

            else:
                print("Invalid command. Please try again.")

if __name__ == "__main__":
    # Create and run the command-line interface
    cli = BlockchainCLI()
    cli.run()
