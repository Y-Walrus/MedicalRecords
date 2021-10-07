class Account:
    def __init__(self, nonce, code_hash):
        this.nonce = nonce  # a counter that indicates the number of transactions sent from the account. This ensures transactions are only processed once. In a contract account, this number represents the number of contracts created by the account.
        this.code_hash = code_hash  # this hash refers to the code of an account on the Ethereum virtual machine (EVM). Contract accounts have code fragments programmed in that can perform different operations. This EVM code gets executed if the account gets a message call. It cannot be changed unlike the other account fields. All such code fragments are contained in the state database under their corresponding hashes for later retrieval. This hash value is known as a codeHash. For externally owned accounts, the codeHash field is the hash of an empty string.

    def generate_private_key(self):
        pass

    def generate_public_address(self):
        pass

    def make_transaction(self, recipient, data):
        pass


class Transaction:
    def __init__(self, recipient, signature, data):
        this.recipient = recipient  # the receiving address
        this.signature = signature  # the identifier of the sender. This is generated when the sender's private key signs the transaction and confirms the sender has authorised this transaction
        this.data = data


class Block:
    def __init__(self, timestamp, block_number, difficulty, mix_hash, parent_hash, transactions, state_root, nonce):
        this.timestamp = timestamp  # the time when the block was mined.
        this.block_number = block_number  # the length of the blockchain in blocks.
        this.difficulty = difficulty  # the effort required to mine the block.
        this.mix_hash = mix_hash  # a unique identifier for that block.
        this.parent_hash = parent_hash  # the unique identifier for the block that came before (this is how blocks are linked in a chain).
        this.transactions = transactions  # the transactions included in the block.
        this.state_root = state_root  # the entire state of the system: account balances, contract storage, contract code and account nonces are inside.
        this.nonce = nocne  # a hash that, when combined with the mixHash, proves that the block has gone through proof of work.


# class Pool


def mine():
    pass


a1 = Account(0, "")
