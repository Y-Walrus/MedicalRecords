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
import pickle
from threading import Thread
from threading import Lock
import socket
import select


# log, 2p2, add user, threads

# with open('private_key.pem', 'wb') as f:
#    f.write(pem)

# how to make a transaction not have sender public address in it? makes problems in verification
# pip install rsa

# TODO: share pool for new user
# TODO: verify new transactions that enter pool
# TODO: remove from pool transactions that are in a verified block (for this write equal in Transaction)

class Account:  # TODO: get/set functions, _private_key (for all classes)
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
        # print(str(signature))
        # print(codecs.decode(signature, "hex"))
        # print(bytearray.fromhex(str(signature)).decode())
        # print(signature)
        # print(type(signature))
        # print(signature.decode("utf-16"))
        return Transaction(self.public_key, recipient, data, signature)

    def save_private_key(self):
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
            # TODO: add password logic!! encryption_algorithm = serialization.BestAvailableEncryption(b'mypassword')
        )
        with open('private_key.pem', 'wb') as f:
            f.write(pem)


class Pool:
    def __init__(self):
        self.transactions = []

    def add_transaction(self, transaction):
        # TODO: check duplicates (with is_equal() in Transaction)
        # TODO: verify here
        self.transactions.append(transaction)

    def add_transaction_list(self, transaction_list):
        for t in transaction_list:
            self.add_transaction(t)

    def length(self):
        return len(self.transactions)

    def add_to_block(self, block):
        while self.length():
            block.add_transaction(self.transactions[0])
            self.transactions.pop(0)

    def transaction_location(self, t):
        pass
        # return -1 if not found, else location in self.transactions

    def remove_transaction(self, t):
        # if t.is_equal(self.transactions[i]):
        pass

    def remove_transactions_of_block(self, b):
        pass

    def save_pool(self):
        for t in self.transactions:
            t.sender_key_to_bytes()

        with open("pool.pkl", "wb") as f:
            pickle.dump(self.transactions, f, pickle.HIGHEST_PROTOCOL)

        for t in self.transactions:
            t.sender_bytes_to_key()

    def __str__(self):
        if self.length():
            s = ""
            for t in self.transactions:
                s += str(t) + "\n"
            return s[:-1]

        else:
            return "No pending transactions"


class Blockchain:
    def __init__(self):
        self.chain_state = []
        self.next_block_number = 0
        genesis_block = Block(0, "GENESIS")
        mine_block(genesis_block)
        self.add_block(genesis_block)

    def last_block(self):
        return self.chain_state[-1]

    def add_block(self, block):  # verification required before adding if block wasn't just mined
        self.chain_state.append(block)
        self.next_block_number += 1
        # THIS IS A SMART CONTRACT!
        for t in block.transactions:
            if t.data == "hello123".encode():
                recipeint = t.recipient_address
                data = "We saw you got a hello123 from a certified doctor, " \
                       "now you have our permission to do anything you want! Doctor address: " \
                       + derive_address(t.sender_public_key)
                new_transaction = smart_contract.create_transaction(recipeint, data.encode())
                pool.add_transaction(new_transaction)
                add_log_entry("Smart contract created a transaction")
                print("Smart contract transaction created successfully and appended to pending transactions")

                new_transaction.save_transaction()
                for user_sock in write_socks:  # TODO: thread??
                    pending_messages.append((user_sock, "transaction.pkl"))
                add_log_entry("Shared a smart contract transaction")
                print("Shared smart contract transaction with other users")

    def read_from_export(self):
        for block in self.chain_state:
            block.read_from_export()

    def save_chain(self):
        for block in self.chain_state:
            block.prepare_to_export()

        with open("chain.pkl", "wb") as f:
            # pickle.dump(self, f, pickle.DEFAULT_PROTOCOL)
            pickle.dump(self, f, pickle.HIGHEST_PROTOCOL)

        for block in self.chain_state:
            block.read_from_export()

        """
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
                    "recipient": t.recipient.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ).decode(),
                    "data": t.data.decode()
                    # "signature": t.signature
                })
        with open("data.txt", "w") as f:
            json.dump(data, f)
            # k = json.dumps(data)
            # f.write(k.encode())
        """

    def __str__(self):
        s = ""
        for b in self.chain_state:
            s += str(b) + "\n"
            if b != self.last_block():
                s += "\n"
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

    def calculate_mix_hash(self):
        s = str(self.block_number) + str(self.timestamp) + str(self.difficulty) + str(self.parent_hash)

        for t in self.transactions:
            # is str good enough here?
            # maybe sender address (it is an object here)
            s += str(derive_address(t.sender_public_key)) + str(t.recipient_address) + str(t.data)
            # print(str(derive_address(t.sender_public_key)) + str(t.recipient_address) + str(t.data))
        return sha256(s.encode()).hexdigest()

    def set_mix_hash(self):
        self.mix_hash = self.calculate_mix_hash()

    def verify_mix_hash(self):
        return self.mix_hash == self.calculate_mix_hash()

    def verify_nonce(self):
        return sha256((self.mix_hash + str(self.nonce)).encode()).hexdigest().startswith("0" * self.difficulty)

    def verify_difficulty(self):
        return self.difficulty == DIFFICULTY

    def verify_transactions(self):
        return all(transaction.verify_signature() for transaction in self.transactions)

    def add_transaction(self, transaction):
        # public key attribute for Account?
        if transaction.verify_signature():
            self.transactions.append(transaction)
        else:
            print("NOT VALID TRANSACTION: " + str(transaction))

    def verify_block(self):
        return self.verify_mix_hash() and self.verify_nonce() and self.verify_difficulty() \
               and self.verify_transactions()

    def prepare_to_export(self):
        for transaction in self.transactions:
            transaction.sender_key_to_bytes()

    def read_from_export(self):
        for transaction in self.transactions:
            transaction.sender_bytes_to_key()

    def save_block(self):
        self.prepare_to_export()

        with open("block.pkl", "wb") as f:
            # pickle.dump(chain, f, pickle.DEFAULT_PROTOCOL)
            pickle.dump(self, f, pickle.HIGHEST_PROTOCOL)

        self.read_from_export()


class Transaction:  # not found way to verify with sender address (rsa verify function problematic)
    def __init__(self, sender_public_key, recipient_address, data, signature):
        # self.sender = sender
        self.sender_public_key = sender_public_key
        self.recipient_address = recipient_address
        self.data = data
        self.signature = signature  # the identifier of the sender. This is generated when the sender's private key signs the transaction and confirms the sender has authorised this transaction

    def __str__(self):
        s = ""
        s += "Transaction {0} to {1}: {2}".format(
            derive_address(self.sender_public_key), self.recipient_address, self.data)
        return s

    def verify_signature(self):
        try:
            self.sender_public_key.verify(
                self.signature,
                self.data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except InvalidSignature:
            return False
        return True

    def sender_bytes_to_key(self):
        self.sender_public_key = serialization.load_pem_public_key(self.sender_public_key.encode())

    def sender_key_to_bytes(self):
        self.sender_public_key = self.sender_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    def save_transaction(self):
        self.sender_key_to_bytes()

        with open("transaction.pkl", "wb") as f:
            pickle.dump(self, f, pickle.HIGHEST_PROTOCOL)

        self.sender_bytes_to_key()


DIFFICULTY = 5

# for socket that is used for receiving data from others in the network
RECEIVE_HOST = "loopback"
RECEIVE_PORT = 21568
RECEIVE_ADDR = (RECEIVE_HOST, RECEIVE_PORT)

# for socket that is used for sharing data with others in the network
SHARE_HOST = "loopback"
SHARE_START_PORT = 21567
SHARE_PORT_AMOUNT = 1  # option to open several connection ports

REQUEST_CHAIN_LOCK = Lock()
REQUEST_BLOCK_LOCK = Lock()


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
    # moved to block verification
    # is_signature_valid = verify_signature(data, signature, public_key)
    d_data = decrypt(e_data, a1.private_key)

    print_private_key(a1.private_key)
    print_public_key(public_key)
    print(signature)
    print(data)
    # print(is_signature_valid)
    print(e_data)
    print(d_data)


def hashing_check():
    h = sha256("a".encode())
    print(h)
    print(h.digest())
    print(h.hexdigest())
    print(h.hexdigest().startswith("00"))
    i = 0
    while not sha256(str(i).encode()).hexdigest().startswith("00000000"):  # whatt???? "0"*256
        i += 1
    print(i)
    print(sha256(str(i).encode()).hexdigest())


def mine_block(block):
    block.timestamp = time.time()  # note this it time of starting to mine, not finishing
    block.set_mix_hash()
    nonce = 0
    # while not sha256((block.mix_hash + str(nonce)).encode()).hexdigest().startswith("0" * block.difficulty):
    while not sha256((block.mix_hash + str(nonce)).encode()).hexdigest().startswith("0" * block.difficulty):
        nonce += 1
    block.nonce = nonce
    # block.timestamp = time.time()  # TODO: set timestamp on creation so it enters the mix hash!! otherwise it isnt defended
    return True  # TODO: break in the middle if takes too long?


def load_chain(file_name="chain.pkl"):
    with open(file_name, "rb") as f:
        chain = pickle.load(f)

    chain.read_from_export()

    """
    chain = []

    with open("data.txt", "r") as f:
        data = json.load(f)

    for b in data["blocks"]:
        block = Block(b["block_number"], b["parent_hash"])
        block.timestamp = b["timestamp"]
        block.difficulty = b["difficulty"]
        block.mix_hash = b["mix_hash"]
        block.nonce = b["nonce"]

        for t in b["transactions"]:
            sender = generate_public_key(a1.private_key)  # BAD!!!
            # sender = serialization.load_pem_public_key(t["sender"]
            recipeint = t["recipient"]
            data = t["data"]
            signature = ""
            block.transactions.append(Transaction(sender, recipeint, data, signature))

        chain.append(block)
    """
    return chain


def load_block(file_name="block.pkl"):
    with open(file_name, "rb") as f:
        block = pickle.load(f)
    block.read_from_export()
    return block


def load_transaction(file_name="transaction.pkl"):
    with open(file_name, "rb") as f:
        transaction = pickle.load(f)
    transaction.sender_bytes_to_key()
    return transaction


def load_account(file_name="private_key.pem"):
    a = Account()
    with open(file_name, "rb") as f:
        a.private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )
    a.public_key = generate_public_key(a.private_key)  # TODO: do it in a constructor
    a.address = derive_address(a.public_key)

    return a


def generate_main_sockets():
    """
    Creates the required amount of connection sockets
    :return: None
    """
    current_port = SHARE_START_PORT
    for i in range(SHARE_PORT_AMOUNT):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind((SHARE_HOST, current_port))
        server_sock.listen(2)
        main_socks.append(server_sock)
        current_port += 1
    read_socks.extend(main_socks)
    write_socks.extend(main_socks)


def share_communication():
    while True:
        readables, writeables, exceptions = select.select(read_socks, write_socks, [])
        for sock_obj in readables:
            if sock_obj in main_socks:  # if the socket is a connection socket and there is a user waiting
                new_sock, address = sock_obj.accept()
                add_log_entry("Connection with new user for sharing")
                print('Connect:', address, id(new_sock))
                read_socks.append(new_sock)
                write_socks.append(new_sock)
            else:  # if the connection is already established
                try:
                    msg_length = int(sock_obj.recv(5))
                    data = sock_obj.recv(msg_length)
                except ConnectionResetError:  # if user has quit connection
                    sock_obj.close()
                    read_socks.remove(sock_obj)
                    write_socks.remove(sock_obj)
                    writeables.remove(sock_obj)
                    add_log_entry("Ended a connection for sharing")
                    print("Connection ended:", id(sock_obj))
                else:
                    if data == "":  # TODO: check if it should be here, what about if not data?? also in receive_communication()
                        pass
                    elif data.startswith("---WHOLE_CHAIN---".encode()):
                        chain.save_chain()
                        pending_messages.append((sock_obj, "chain.pkl"))  # TODO: better file transfer, add pool?

                    elif data.startswith("---LAST_BLOCK---".encode()):
                        chain.last_block().save_block()
                        pending_messages.append((sock_obj, "block.pkl"))  # TODO: better file transfer

        else:  # TODO: understand why else
            for message in pending_messages:
                (user_sock, data) = message
                if user_sock in writeables:
                    if data == "chain.pkl":
                        with open(data, "rb") as f:
                            data = f.read()
                        user_sock.send(str(len("---WHOLE_CHAIN---") + len(data)).zfill(5).encode())
                        user_sock.send("---WHOLE_CHAIN---".encode() + data)
                    elif data == "block.pkl":
                        with open(data, "rb") as f:
                            data = f.read()
                        user_sock.send(str(len("---LAST_BLOCK---") + len(data)).zfill(5).encode())
                        user_sock.send("---LAST_BLOCK---".encode() + data)
                    elif data == "transaction.pkl":
                        with open(data, "rb") as f:
                            data = f.read()
                        user_sock.send(str(len("---TRANSACTION---") + len(data)).zfill(5).encode())
                        user_sock.send("---TRANSACTION---".encode() + data)
                    else:
                        user_sock.send(str(len(data)).zfill(5).encode())
                        user_sock.send(data)

                    pending_messages.remove(message)


def receive_communication():
    while 1:
        try:
            # RECEIVE_LOCK.acquire()
            msg_length = int(receive_socket.recv(5))
            data = receive_socket.recv(msg_length)
            # RECEIVE_LOCK.release()
        except ConnectionResetError:
            print("ConnectionResetError in receive_communication()")
            break
        except ConnectionAbortedError:
            print("ConnectionAbortedError in receive_communication()")
            break
        if not data:
            break

        if data.startswith("---WHOLE_CHAIN---".encode()):
            data = data[len("---WHOLE_CHAIN---"):]
            with open("received_chain.pkl", "wb") as f:
                f.write(data)
                REQUEST_CHAIN_LOCK.release()

        elif data.startswith("---TRANSACTION---".encode()):
            data = data[len("---TRANSACTION---"):]
            with open("received_transaction.pkl", "wb") as f:
                f.write(data)
            add_log_entry("Received a transaction list form a user")
            print("RECEIVED A TRANSACTION LIST")
            transaction = load_transaction("received_transaction.pkl")
            pool.add_transaction(transaction)  # TODO: verification here or included in add_transaction

        elif data.startswith("---LAST_BLOCK---".encode()):
            data = data[len("---LAST_BLOCK---"):]
            with open("received_block.pkl", "wb") as f:
                f.write(data)
                # REQUEST_BLOCK_LOCK.release() # TODO: find a way to avoid RuntimeError: release unlocked lock
            add_log_entry("Received a new block form a user")
            print("RECEIVED A NEW BLOCK")
            new_block = load_block("received_block.pkl")
            add_log_entry(new_block)
            print(new_block)

            # TODO: customized exceptions for each
            print("mixhash, nonce, difficulty, trnasactions -", new_block.verify_mix_hash(), new_block.verify_nonce(),
                  new_block.verify_difficulty(), new_block.verify_transactions())
            if new_block.verify_block():
                chain.add_block(new_block)
                print("Added block to chain after verification")
                add_log_entry("Added block to chain after verification")
            else:
                print("ATTENTION - the received block hasn't passed verification, wasn't added")
                add_log_entry("ATTENTION - the received block hasn't passed verification, wasn't added")
                # TODO: add specific reason, maybe blacklist person if smth bad
        else:
            print(data)


def request_chain():
    REQUEST_CHAIN_LOCK.acquire()
    try:
        msg = "---WHOLE_CHAIN---"
        # RECEIVE_LOCK.acquire()
        receive_socket.send(str(len(msg)).zfill(5).encode())
        receive_socket.send(msg.encode())
        REQUEST_CHAIN_LOCK.acquire()
    except ConnectionResetError:
        return False

    """
    # not used, moving to thread listening to new inputs
    else:
        try:
            msg_length = int(receive_socket.recv(5))
            data = receive_socket.recv(msg_length)
            # RECEIVE_LOCK.release()
        except ConnectionResetError:
            # RECEIVE_LOCK.release()
            print("ConnectionResetError in receive_communication()")
        except ConnectionAbortedError:
            # RECEIVE_LOCK.release()
            print("ConnectionAbortedError in receive_communication()")
        else:
            if not data:
                print("not data in request_chain()")

            with open("received_chain.pkl", "wb") as f:
                f.write(data)
            return True

        return False
    """

    return True


def request_block():
    REQUEST_BLOCK_LOCK.acquire()
    try:
        msg = "---LAST_BLOCK---"
        receive_socket.send(str(len(msg)).encode())
        receive_socket.send(msg.encode())
        REQUEST_BLOCK_LOCK.acquire()
    except ConnectionResetError:
        return False
    return True


def add_log_entry(entry):
    s = ""
    ts = time.localtime(time.time())
    s += "{0}/{1}/{2} {3:02}:{4:02}:{5:02}\n".format(
        ts.tm_mday, ts.tm_mon, ts.tm_year, ts.tm_hour, ts.tm_min, ts.tm_sec)
    s += str(entry)
    s += "\n\n"
    with open("log.txt", "ab") as f:
        f.write(s.encode())


# cryptography_check()
# hashing_check()

# print_private_key(a1.private_key)
# print_private_key(a2.private_key)


if __name__ == "__main__":
    chain = Blockchain()
    add_log_entry("Node is started")

    main_socks = []
    read_socks, write_socks = [], []
    # readables, writeables, exceptions = [], [], []# TODO: understand difference between writeables and write_socks (for loop to broadcast)
    pending_messages = []

    generate_main_sockets()
    add_log_entry("Initialized sharing system")
    print("Ready for connection to share")

    Thread(target=share_communication).start()

    # TODO: move this to a function, call when request for information is needed (open another socket each time?)
    receive_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while 1:
        try:
            print("Waiting for connection to receive")
            receive_socket.connect(RECEIVE_ADDR)
            add_log_entry("Connected to a sharing user")
            print("Connected to sharing user successfully")
            break
        except (ConnectionRefusedError, TimeoutError):
            continue

    Thread(target=receive_communication).start()

    if request_chain():
        chain = load_chain("received_chain.pkl")
        add_log_entry("Got chain from a user")
        print("Successfully got chain from another user")

    """
    if request_chain():
        chain = load_chain("received_chain.pkl")
        print("Successfully got chain from another user")
    else:
        print("Request of chain failed, using new one")
    """

    pool = Pool()

    a1 = Account()  # login logic
    print("My address: " + derive_address(a1.public_key))

    # probably will be separated
    smart_contract = Account()

    b1 = ""
    while True:
        cmd = input("> ")

        if cmd == "create block":
            b1 = Block(chain.next_block_number, chain.last_block().mix_hash)
            add_log_entry("Created a block")
            print("Block created successfully")
            # print(b1)

        elif cmd == "mine block":
            if isinstance(b1, Block) and mine_block(b1):
                chain.add_block(b1)
                add_log_entry("Mined a block")
                print("Mined successfully and added to the current state")
                b1.save_block()
                b1 = ""

                for user_sock in write_socks:  # TODO: thread??
                    pending_messages.append((user_sock, "block.pkl"))
                add_log_entry("Shared a block")
                print("Shared block with other users")

        elif cmd == "create transaction":
            print("Example: " + derive_address(Account().public_key))
            recipeint = input("recipient address -> ")  # input checks
            data = input("data -> ")
            new_transaction = a1.create_transaction(recipeint, data.encode())
            pool.add_transaction(new_transaction)
            add_log_entry("Created a transaction")
            print("Transaction created successfully and appended to pending transactions")

            new_transaction.save_transaction()
            for user_sock in write_socks:  # TODO: thread??
                pending_messages.append((user_sock, "transaction.pkl"))
            add_log_entry("Shared a transaction")
            print("Shared transaction with other users")

        elif cmd == "add to block":
            if isinstance(b1, Block):
                if pool.length():
                    pool.add_to_block(b1)
                    add_log_entry("Added transaction(s) to block")
                    print("Added transaction(s) to block successfully")
                else:
                    print("No pending transactions")
            else:
                print("No block created")

        elif cmd == "print chain":
            print(chain)

        elif cmd == "print pending":
            print(str(pool))

        # used for printing only as there is no need for it in the api
        elif cmd == "verify last block":  # split verify block pow and block signature!
            block = chain.last_block()
            mix_hash = block.mix_hash
            nonce = str(block.nonce)
            print("Verification of block No. " + str(block.block_number))
            print("MixHash: " + mix_hash)
            print("Nonce: " + nonce)
            print("Hash of " + mix_hash + nonce + " is:")
            print(sha256((mix_hash + nonce).encode()).hexdigest())

        elif cmd == "save chain":
            chain.save_chain()
            add_log_entry("Chain saved")
            print("Saved")

        elif cmd == "load chain":
            chain = load_chain()
            try:
                chain = load_chain()
            except Exception as e:
                print("Error loading")
                print(e)
            else:
                add_log_entry("Chain loaded")
                print("Loaded")

        elif cmd == "save account":
            a1.save_private_key()
            add_log_entry("Account private key exported")
            print("Saved account successfully")

        elif cmd == "load account":
            a1 = load_account()
            add_log_entry("Account loaded from private key file")
            print("Loaded account successfully")

        else:
            print("No such command")

        print()
