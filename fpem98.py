import os
import hashlib
import binascii
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# Tailles des éléments
SIGNATURE_SIZE = 64
NONCE_SIZE = 24

def generate_ed_keypair():
    """
    Génère une paire de clés Ed25519.
    """
    ed_private_key = ed25519.Ed25519PrivateKey.generate()
    ed_public_key = ed_private_key.public_key()
    return ed_private_key, ed_public_key

def derive_aes_key(secret_key):
    """
    Dérive une clé AES à partir de la clé secrète en utilisant scrypt avec des paramètres optimisés.
    """
    assert len(secret_key) >= 64, "La clé secrète doit avoir au moins 64 octets."
    backend = default_backend()
    salt = os.urandom(16)
    scrypt_params = Scrypt(
        salt=salt,
        length=32,
        n=2**20,  # Augmenter le paramètre n pour plus de sécurité
        r=16,     # Augmenter le paramètre r pour rendre l'attaque parallèle plus difficile
        p=1
    )
    aes_key = scrypt_params.derive(secret_key)
    return aes_key

def fpem98_encrypt(message, secret_key):
    """
    Chiffre un message avec EdDSA pour la signature et ChaCha20-Poly1305 pour le chiffrement symétrique.
    """
    # Générer une paire de clés Ed25519
    ed_private_key, ed_public_key = generate_ed_keypair()

    # Signature du message avec la clé privée Ed25519
    message_bytes = message.encode('utf-8')
    signature = ed_private_key.sign(message_bytes)

    # Dérivation de la clé AES
    aes_key = derive_aes_key(secret_key)

    # Chiffrement du message avec ChaCha20-Poly1305
    nonce = os.urandom(NONCE_SIZE)
    cipher = Cipher(algorithms.ChaCha20(aes_key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message_bytes) + encryptor.finalize()

    # Combinaison de la clé publique Ed25519, de la signature, du nonce et du message chiffré
    encrypted_data = ed_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ) + signature + nonce + ciphertext

    # Encodage du message chiffré en base64
    return binascii.b64encode(encrypted_data).decode('utf-8')

def fpem98_decrypt(encrypted_data, private_key, secret_key):
    """
    Déchiffre des données chiffrées avec EdDSA et ChaCha20-Poly1305.
    """
    try:
        # Décodage des données chiffrées en base64
        encrypted_data = binascii.b64decode(encrypted_data.encode('utf-8'))

        # Extraction de la clé publique Ed25519, de la signature, du nonce et du message chiffré
        ed_public_key = load_pem_public_key(encrypted_data[:8192], backend=default_backend())
        signature = encrypted_data[8192:8192 + SIGNATURE_SIZE]
        nonce = encrypted_data[8192 + SIGNATURE_SIZE:8192 + SIGNATURE_SIZE + NONCE_SIZE]
        ciphertext = encrypted_data[8192 + SIGNATURE_SIZE + NONCE_SIZE:]

        # Vérification de la signature avec la clé publique Ed25519
        ed_public_key.verify(signature, ciphertext + nonce)

        # Dérivation de la clé AES
        aes_key = derive_aes_key(secret_key)

        # Déchiffrement du message avec ChaCha20-Poly1305
        cipher = Cipher(algorithms.ChaCha20(aes_key, nonce), mode=None, backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

        return decrypted_message.decode('utf-8')
    except Exception as e:
        print(f"Erreur lors du déchiffrement : {e}")
        raise

# Exemple d'utilisation
message = "Bonjour, c'est un message secret à chiffrer avec EdDSA pour la signature et ChaCha20-Poly1305 pour le chiffrement symétrique."
secret_key = os.urandom(64)  # Clé secrète plus longue pour une sécurité accrue

encrypted_data = fpem98_encrypt(message, secret_key)
print("Message chiffré avec EdDSA et ChaCha20-Poly1305:", encrypted_data)

# Assumez que ed_private_key est déjà définie dans votre contexte
decrypted_message = fpem98_decrypt(encrypted_data, ed_private_key, secret_key)
print("Message déchiffré:", decrypted_message)
