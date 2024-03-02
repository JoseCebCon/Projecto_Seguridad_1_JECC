#Imports
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import hashlib

# Definir la ruta al archivo del NDA
file_path = r"D:\JOSE EDUARDO\Documents\Informatic security & Forensic Analysis\NDA.pdf"

def calculate_file_hash(file_path, hash_algorithm=hashlib.sha256()):
    with open(file_path, 'rb') as file:
        while chunk := file.read(8192):
            hash_algorithm.update(chunk)
    return hash_algorithm.digest()

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

public_key = private_key.public_key()

pem_private_key = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

private_key_path = "private_key.pem"
with open(private_key_path, "wb") as private_key_file:
    private_key_file.write(pem_private_key)

hash_result = calculate_file_hash(file_path)
print(f"The SHA-256 hash of {file_path} is: {hash_result.hex()}","\n")

# Firmar el hash del documento con la llave privada
signature = private_key.sign(
    hash_result,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
print("Firma generada por Alice:", signature.hex(),"\n")

# Desencriptar la firma utilizando la clave pública
try:
    public_key.verify(
        signature,
        hash_result,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("El documento fue firmado por Alice. El hash del documento coincide con el hash desencriptado.")
except InvalidSignature:
    print("La firma no es válida. El hash del documento no coincide con el hash desencriptado. \n")

ac_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

ac_public_key = ac_private_key.public_key()

pem_ac_private_key = ac_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

ac_private_key_path = "ac_private_key.pem"
with open(ac_private_key_path, "wb") as ac_private_key_file:
    ac_private_key_file.write(pem_ac_private_key)

ac_signature = ac_private_key.sign(
    hash_result,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
print("Firma generada por la AC:", ac_signature.hex(),"\n")

ac_private_key_path = "ac_private_key.pem"
with open(ac_private_key_path, "wb") as ac_private_key_file:
    ac_private_key_file.write(pem_ac_private_key)
    
# Calcular el hash del archivo NDA
hash_result = calculate_file_hash(file_path)
print(f"The SHA-256 hash of {file_path} is: {hash_result.hex()}","\n")

# Firmar el hash del documento con la llave privada de la AC
ac_signature = ac_private_key.sign(
    hash_result,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
print("Firma generada por la AC:", ac_signature.hex(),"\n")