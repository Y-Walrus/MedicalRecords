# from cryptography.fernet import Fernet # symmetric encryption
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from hashlib import sha256
import time
import json
import base64
import codecs

# with open('private_key.pem', 'wb') as f:
#    f.write(pem)

# choice of asymmetric algorithm - RSA?

# broadcasting a mined block
# do i send the whole chain every time? or only when person joins?
# store chain in files. json? every transaction in a different json?

# do some private info?
# how to make a transaction not have sender public address in it? makes problems in verification
# make a Blockchain class?


class Account:  # get/set functions, _private_key
    def __init__(self, nonce=0, code_hash=""):
        self.nonce = nonce  # a counter that indicates the number of transactions sent from the account. This ensures transactions are only processed once. In a contract account, this number represents the number of contracts created by the account.
        self.code_hash = code_hash  # this hash refers to the code of an account on the Ethereum virtual machine (EVM). Contract accounts have code fragments programmed in that can perform different operations. This EVM code gets executed if the account gets a message call. It cannot be changed unlike the other account fields. All such code fragments are contained in the state database under their corresponding hashes for later retrieval. This hash value is known as a codeHash. For externally owned accounts, the codeHash field is the hash of an empty string.
        self.private_key = generate_private_key()
        self.public_key = generate_public_key(self.private_key)
        self.address = derive_address(self.public_key)

    # def __str__(self):

    def generate_public_address(self):
        pass

    def create_transaction(self, recipient, data):
        signature = sign(data, self.private_key)
        print(str(signature))
        #print(codecs.decode(signature, "hex"))
        print(bytearray.fromhex(str(signature)).decode())
        return Transaction(self.public_key, recipient, data, signature)


class Transaction:
    def __init__(self, sender, recipient, data, signature):
        # self.sender = sender
        self.sender = sender  # sender public key
        self.recipient = recipient  # the receiving address
        self.data = data
        self.signature = signature  # the identifier of the sender. This is generated when the sender's private key signs the transaction and confirms the sender has authorised this transaction

    def __str__(self):
        s = ""
        s += "Transaction {0} to {1}: {2}".format(derive_address(self.sender), self.recipient, self.data)
        return s


class Block:
    # generator for block_number?
    # nonce can be a hash
    def __init__(self, block_number, parent_hash):
        self.timestamp = 0  # the time when the block was mined.
        self.block_number = block_number  # the length of the blockchain in blocks.
        self.difficulty = DIFFICULTY  # the effort required to mine the block.
        self.parent_hash = parent_hash  # the unique identifier for the block that came before (this is how blocks are linked in a chain).
        self.transactions = []  # the transactions included in the block.
        # self.state_root = state_root  # the entire state of the system: account balances, contract storage, contract code and account nonces are inside.

        self.mix_hash = ""  # a unique identifier for that block.
        self.nonce = 0  # a hash that, when combined with the mixHash, proves that the block has gone through proof of work.

    def __str__(self):
        s = ""
        s += "Block No. {0}\n".format(self.block_number)
        ts = time.gmtime(self.timestamp)
        s += "Mined: {0}/{1}/{2} {3:02}:{4:02}:{5:02} UTC\n".format(
            ts.tm_mday, ts.tm_mon, ts.tm_year, ts.tm_hour, ts.tm_min, ts.tm_sec)
        s += "MixHash: {0}\n".format(self.mix_hash)
        for t in self.transactions:
            # s += "Transaction ({0} to {1}): {2}\n".format(t.sender, t.recipient, t.data)
            s += str(t) + "\n"
        s += "Diff: {0}\n".format(self.difficulty)
        s += "Nonce: {}\n".format(self.nonce)
        s += "Parent hash: {0}".format(self.parent_hash)
        return s

    def set_mix_hash(self):
        s = str(self.block_number) + str(self.timestamp) + str(self.difficulty) + str(self.parent_hash)
        for t in self.transactions:
            # is str good enough here?
            s += str(t.sender) + str(t.recipient) + str(t.data)
        self.mix_hash = sha256(s.encode()).hexdigest()

    def add_transaction(self, transaction):
        # public key attribute for Account?
        if verify_signature(transaction.data, transaction.signature,
                            transaction.sender):
            self.transactions.append(transaction)
        else:
            print("NOT VALID TRANSACTION: " + str(transaction))


# class Pool on mining side / just list?

DIFFICULTY = 5


def generate_private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())


def generate_public_key(private_key):  # rename to derive
    return private_key.public_key()


def derive_address(public_key):
    return sha256(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1)
    ).hexdigest()[-40:]


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


def hashing_check():
    h = sha256("a".encode())
    print(h)
    print(h.digest())
    print(h.hexdigest())
    print(h.hexdigest().startswith("00"))
    i = 0
    while not sha256(str(i).encode()).hexdigest().startswith("00000000"):
        i += 1
    print(i)
    print(sha256(str(i).encode()).hexdigest())


def mine_block(block):
    block.set_mix_hash()
    nonce = 0
    # while not sha256((block.mix_hash + str(nonce)).encode()).hexdigest().startswith("0" * block.difficulty):
    while not sha256((block.mix_hash + str(nonce)).encode()).hexdigest().startswith("0" * block.difficulty):
        nonce += 1
    block.nonce = nonce
    block.timestamp = time.time()
    return True  # break in the middle if takes too long?


def save_chain(chain):
    data = {}
    data["blocks"] = []
    for b in chain:
        data["blocks"].append({
            "timestamp": b.timestamp,
            "block_number": b.block_number,
            "difficulty": b.difficulty,
            "parent_hash": b.parent_hash,
            "transactions": [],
            "mix_hash": b.mix_hash,
            "nonce": b.nonce
        })
        for t in b.transactions:
            data["blocks"][-1]["transactions"].append({
                "sender": t.sender.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode(),
                "recipient": t.recipient,
                "data": t.data,
                "signature": bytearray.fromhex(t.signature).decode()
            })
    with open("data.txt", "w") as outfile:
        json.dump(data, outfile)


# cryptography_check()
# hashing_check()

# print_private_key(a1.private_key)
# print_private_key(a2.private_key)


if __name__ == "__main__":
    genesis_block = Block(0, "GENESIS")
    mine_block(genesis_block)

    chain_state = [genesis_block]
    pending_transactions = []

    a1 = Account()
    a2 = Account()
    a1_addr = a1.address
    a2_addr = a2.address

    b1 = ""
    while True:
        cmd = input("> ")
        if cmd == "create block":
            b1 = Block(len(chain_state), chain_state[-1].mix_hash)
            print("Block created successfully")
            # print(b1)

        elif cmd == "mine block":
            if isinstance(b1, Block) and mine_block(b1):
                chain_state.append(b1)
                b1 = ""
                print("Mined successfully and added to the current state")

        elif cmd == "create transaction":
            data = input("data -> ")
            pending_transactions.append(a1.create_transaction(a2_addr, data.encode()))
            print("Transaction created successfully and appended to pending transactions")

        elif cmd == "add to block":
            if isinstance(b1, Block):
                if len(pending_transactions):
                    while len(pending_transactions):
                        b1.add_transaction(pending_transactions[0])
                        pending_transactions.pop(0)
                    print("Added transaction(s) to block successfully")
                else:
                    print("No pending transactions")
            else:
                print("No block created")

        elif cmd == "print chain":
            for b in chain_state:
                print(b)
                if b != chain_state[-1]:
                    print()

        elif cmd == "print pending":
            if len(pending_transactions):
                for t in pending_transactions:
                    print(t)
            else:
                print("No pending transactions")

        elif cmd == "verify last block":
            block = chain_state[-1]
            mix_hash = block.mix_hash
            nonce = str(block.nonce)
            print("Verification of block No. " + str(block.block_number))
            print("MixHash: " + mix_hash)
            print("Nonce: " + nonce)
            print("Hash of " + mix_hash + nonce + " is:")
            print(sha256((mix_hash + nonce).encode()).hexdigest())

        elif cmd == "save chain":
            save_chain(chain_state)
            print("Saved")

        else:
            print("No such command")

        print()
