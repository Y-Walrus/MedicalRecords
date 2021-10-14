# from cryptography.fernet import Fernet # symmetric encryption
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


# watch videos in ethereum documentation

# with open('private_key.pem', 'wb') as f:
#    f.write(pem)

# choice of asymmetric algorithm - why RSA?

class Account:  # get/set functions, _private_key
    def __init__(self, nonce=0, code_hash=""):
        self.nonce = nonce  # a counter that indicates the number of transactions sent from the account. This ensures transactions are only processed once. In a contract account, this number represents the number of contracts created by the account.
        self.code_hash = code_hash  # this hash refers to the code of an account on the Ethereum virtual machine (EVM). Contract accounts have code fragments programmed in that can perform different operations. This EVM code gets executed if the account gets a message call. It cannot be changed unlike the other account fields. All such code fragments are contained in the state database under their corresponding hashes for later retrieval. This hash value is known as a codeHash. For externally owned accounts, the codeHash field is the hash of an empty string.
        self.private_key = generate_private_key()

    def generate_public_address(self):
        pass

    def create_transaction(self, recipient, data):
        return Transaction(self, recipient, data)


class Transaction:  # public key here?
    def __init__(self, sender, recipient, data):
        self.recipient = recipient  # the receiving address
        self.signature = sign(data,
                              sender.private_key)  # the identifier of the sender. This is generated when the sender's private key signs the transaction and confirms the sender has authorised this transaction
        self.data = data


class Block:
    # generator for block_number?
    def __init__(self, timestamp, block_number, difficulty, mix_hash, parent_hash, transactions, state_root, nonce):
        self.timestamp = timestamp  # the time when the block was mined.
        self.block_number = block_number  # the length of the blockchain in blocks.
        self.difficulty = difficulty  # the effort required to mine the block.
        self.mix_hash = mix_hash  # a unique identifier for that block.
        self.parent_hash = parent_hash  # the unique identifier for the block that came before (this is how blocks are linked in a chain).
        self.transactions = transactions  # the transactions included in the block.
        self.state_root = state_root  # the entire state of the system: account balances, contract storage, contract code and account nonces are inside.
        self.nonce = nonce  # a hash that, when combined with the mixHash, proves that the block has gone through proof of work.

    def add_transaction(self):
        pass


# class Pool


def mine():
    pass


def generate_private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())


def generate_public_key(private_key):
    return private_key.public_key()


def sign(data, private_key):
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verify_signature(data, signature, public_key):
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except InvalidSignature:
        return False

    return True


def encrypt(data, public_key):
    return public_key.encrypt(data,
                              padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                           algorithm=hashes.SHA256(),
                                           label=None))


def decrypt(data, private_key):
    return private_key.decrypt(data,
                               padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                            algorithm=hashes.SHA256(),
                                            label=None))


def print_private_key(private_key):
    print(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())
    )


def print_public_key(public_key):
    print(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1)
    )


def cryptography_check():
    a1 = Account()

    data = "Hello".encode()
    public_key = generate_public_key(a1.private_key)
    e_data = encrypt(data, public_key)
    signature = sign(data, a1.private_key)
    is_signature_valid = verify_signature(data, signature, public_key)
    d_data = decrypt(e_data, a1.private_key)

    print_private_key(a1.private_key)
    print_public_key(public_key)
    print(signature)
    print(data)
    print(is_signature_valid)
    print(e_data)
    print(d_data)


def execute_transaction(transaction):  # or execute block?
    pass


# cryptography_check()

a1 = Account()
a2 = Account()

print_private_key(a1.private_key)
print_private_key(a2.private_key)

# what happens with the block after creation? mining somewhere
b1 = Block()

t1 = a1.create_transaction(a2, "Hello world!".encode())
b1.add_transaction(t1)
