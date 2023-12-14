import pickle, os
from turtle import stamp
import ecdsa, hashlib
from Crypto.Hash import keccak

DEFAULT_TARGET = "./keypair.pem"

class SECP256k1:
    def __init__(self, target=DEFAULT_TARGET):
        self.target = target
    def store(self, data):
        with open(self.target, 'wb') as f:
            pickle.dump(data, f)
    def load(self):
        with open(self.target, 'rb') as f:
            data = pickle.load(f)
            return {
                "private_key": data["private_key"],
                "public_key_x": data["public_key_x"],
                "public_key_y": data["public_key_y"],
                "public_key_hex": data["public_key_hex"],
                "public_key_hex_compressed": data["public_key_hex_compressed"],
                "public_evm_address": data["public_evm_address"]
            }
    def new(self):
        private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        public_key = private_key.get_verifying_key()
        public_key_hex_uncompressed = public_key.to_string("uncompressed").hex()
        public_key_hex_compressed = public_key.to_string("compressed").hex()
        x_coordinate_bytes = list(bytes.fromhex(public_key_hex_uncompressed)[1:33])
        y_coordinate_bytes = list(bytes.fromhex(public_key_hex_uncompressed)[33:])
        public_evm_address = self.public_key_to_eth_address(public_key_hex_uncompressed)

        return {
            "private_key": private_key,
            "public_key_x": x_coordinate_bytes,
            "public_key_y": y_coordinate_bytes,
            "public_key_hex": public_key_hex_uncompressed,
            "public_key_hex_compressed": public_key_hex_compressed,
            "public_evm_address": public_evm_address
        }
    def sign(self, message):
        data = self.load()
        private_key = data["private_key"]
        encoded_msg = message.encode('utf-8')
        print("encoded_msg: ", encoded_msg)
        # hash the message and sign the hash
        message_hash = hashlib.sha256(encoded_msg).hexdigest()
        message_bytes = bytes.fromhex(message_hash)
        signature = private_key.sign_deterministic(
            message_bytes, 
            extra_entropy=b"",
            # hash the message hash (2x sha256)
            hashfunc=hashlib.sha256
        )
        return {
            "message": message_bytes,
            "signature": signature
        }
    def sign_and_print(self, message, stamp_hash, provider):
        data = self.sign(message)
        print("let message_hash =", list(data["message"]), ";")
        print("----------------------------------------------------")
        print("raw sign: ", data["signature"])
        print("----------------------------------------------------")
        print(data["signature"].hex())
        print("----------------------------------------------------")
        print("let signature = ", list(bytes.fromhex(data["signature"].hex())), ";")
        print("----------------------------------------------------")
        print("hex signature = ", data["signature"].hex(), ";")
        print("----------------------------------------------------")
        keys = self.load()
        print("X coordinate: ", keys["public_key_x"])
        print("----------------------------------------------------")
        print("Y coordinate: ", keys["public_key_y"])
        print("----------------------------------------------------")
        print("Hex Public Uncompressed: ", keys["public_key_hex"])
        print("----------------------------------------------------")
        print("Hex Public Compressed: ", keys["public_key_hex_compressed"])
        print("----------------------------------------------------")
        print("Ethereum Address: ", keys["public_evm_address"])

        print("stamp_hash_bytes: ", list(bytes(stamp_hash, 'utf-8')))
        print("provider_bytes: ", list(bytes(provider, 'utf-8')))

        return {
            "message_hash": list(data["message"]),
            "signature": list(bytes.fromhex(data["signature"].hex())),
            "public_key_x": keys["public_key_x"],
            "public_key_y": keys["public_key_y"],
            "stamp_hash_bytes": list(bytes(stamp_hash, 'utf-8')),
            "provider_bytes": list(bytes(provider, 'utf-8'))
        }


    def public_key_to_eth_address(self, public_key_hex):
        # Decode the hex public key to bytes
        public_key_bytes = bytes.fromhex(public_key_hex[2:])  # Skip the '04' prefix
        # Hash the public key using Keccak-256
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(public_key_bytes)
        # Take the last 20 bytes of the hash and convert to hex
        address = keccak_hash.digest()[-20:].hex()
        return "0x" + address




if not os.path.exists(DEFAULT_TARGET):
    open(DEFAULT_TARGET, 'x')
secp = SECP256k1()
# create new keypair and save at DEFAULT_TARGET
# secp.store(secp.new())
# sign an oversimplified transaction
# There is a length issue if the full address is provided below. Unable to verify signature
# stamp_hash = "v0.0.0:GqmK8ClmCF6E9DaQYe3ei3KGlwyJOWDPNthLX4NRftQ="
# provider = "google"

# message = f"{stamp_hash}:{provider}"

# print("message: ", message)

# secp.sign_and_print(message)

# print("stamp_hash bytes: ", list(bytes("v0.0.0:GqmK8ClmCF6E9DaQYe3ei3KGlwyJOWDPNthLX4NRftQ=", 'utf-8')))
# print("provider bytes: ", list(bytes("google", 'utf-8')))






def prepare_stamp_input(stamp_hash, provider):
    message = f"{stamp_hash}:{provider}"

    print(message, "message")

    signature_data = secp.sign_and_print(message, stamp_hash, provider)

    print("----------------------------------------------------")
    print(signature_data)
    return signature_data

    

print("----------------------------------------------------")
print("----------------------------------------------------")
print("----------------------------------------------------")
print("----------------------------------------------------")


# This is aa google so that a uniform length is used for providers
google = prepare_stamp_input("v0.0.1:samplehash", "aagoogle")
facebook = prepare_stamp_input("v0.0.0:samplehash", "facebook")


pub_key_x = facebook["public_key_x"]
pub_key_y = facebook["public_key_y"]


print("----------------------------------------------------")
print("----------------------------------------------------")
print("----------------------------------------------------")
print("----------------------------------------------------")

print(f"let stamp_hash_bytes_google = {google['stamp_hash_bytes']};")
print(f"let provider_bytes_google = {google['provider_bytes']};")
print(f"let message_hash_google = {google['message_hash']};")
print(f"let signature_google = {google['signature']};")
print(f"let pub_key_x_google = {pub_key_x};")
print(f"let pub_key_y_google = {pub_key_y};")
print("----------------------------------------------------")
print(f"let stamp_hash_bytes_facebook = {facebook['stamp_hash_bytes']};")
print(f"let provider_bytes_facebook = {facebook['provider_bytes']};")
print(f"let message_hash_facebook = {facebook['message_hash']};")
print(f"let signature_facebook = {facebook['signature']};")
print(f"let pub_key_x = {pub_key_x};")
print(f"let pub_key_y = {pub_key_y};")

