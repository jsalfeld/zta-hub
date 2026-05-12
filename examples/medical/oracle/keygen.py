import nacl.signing
import binascii

def generate_keypair():
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key
    
    priv_hex = binascii.hexlify(signing_key.encode()).decode('utf-8')
    pub_hex = binascii.hexlify(verify_key.encode()).decode('utf-8')
    
    print(f"Private key (hex): {priv_hex}")
    print(f"Public key (hex):  {pub_hex}")
    return priv_hex, pub_hex

if __name__ == "__main__":
    print("Generating Ed25519 keypair for Oracle Mock...\n")
    generate_keypair()
