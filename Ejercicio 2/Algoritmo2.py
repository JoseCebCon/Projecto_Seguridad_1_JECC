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

AP = rsa.generate_AP(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

public_key = AP.public_key()

pem_AP = AP.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

AP_path = "AP.pem"
with open(AP_path, "wb") as AP_file:
    AP_file.write(pem_AP)

hash_result = calculate_file_hash(file_path)
print(f"The SHA-256 hash of {file_path} is: {hash_result.hex()}","\n")

# Firmar el hash del documento con la llave privada
firma = AP.sign(
    hash_result,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
print("Firma generada por Alice:", firma.hex(),"\n")

# Desencriptar la firma utilizando la clave pública
try:
    public_key.verify(
        firma,
        hash_result,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("El documento es firmado por Alice. El hash del documento coincide con el hash desencriptado.")
except Invalidfirma:
    print("La firma es incorrectA. El hash del documento no coincide el desincriptado. \n")

ac_AP = rsa.generate_AP(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

ac_public_key = ac_AP.public_key()

ac_AP = ac_AP.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

ac_AP_path = "ac_AP.pem"
with open(ac_AP_path, "wb") as ac_AP_file:
    ac_AP_file.write(ac_AP)

# Calcular el hash del archivo NDA
hash_result = calculate_file_hash(file_path)
print(f"The SHA-256 hash of {file_path} is: {hash_result.hex()}","\n")

# Firmar el hash del documento con la llave privada de la AC
AC_firma = ac_AP.sign(
    hash_result,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
print("La firma generada por la AC es:", AC_firma.hex(),"\n")

AC_firma = ac_AP.sign(
    hash_result,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
print("La firma generada por la AC es:", AC_firma.hex(),"\n")

# Desencriptar la firma utilizando la clave pública de la AC
try:
    # Verificar la firma
    ac_public_key.verify(
        AC_firma,
        hash_result,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("AC confirma que este documento es de Alice. El hash del documento coincide con el desincriptado.")
except Invalidfirma:
    print("La firma de la AC no coincide. El hash del documento no coincide desincriptado.")
    
