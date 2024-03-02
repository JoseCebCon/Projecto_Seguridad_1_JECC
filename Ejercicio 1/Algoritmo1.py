import hashlib
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
import random
import string

# Obtener no. primos y e
p = random.getrandbits(1024)
q = random.getrandbits(1024)
e = 4

# Calcular n = p * q
n = p * q

# Calcular phi = (p-1) * (q-1)
phi = (p-1) * (q-1)

# Calcular d tal que (d * e) % phi = 1
d = pow(e, -1, phi)

# Definir la llave pública y la llave privada
public_key = (e, n)
AP = (d, n)
print("La llave publica: ")
print(public_key)
print("La llave privada: ")
print(AP)

# El mensaje Original
M = ''.join(random.choices(string.ascii_letters + string.digits, k=1050))
print("El mensaje original")
print(M)

# Se divide el mensaje en 128 partes
parts = [M[i:i+128] for i in range(0, len(M), 128)]

# Cifrar cada parte del mensaje con la llave pública de Bob
encrypted_parts = [pow(bytes_to_long(part.encode()), public_key[0], public_key[1]) for part in parts]
print("Mensajes cifrados enviados por parte de llave publica de Bob:")
print(encrypted_parts)

# Descifrar cada parte del mensaje con la llave privada de Bob
decrypted_parts = [long_to_bytes(pow(part, AP[0], AP[1])) for part in encrypted_parts]
print("Mensajes descifrados")
print(decrypted_parts)

#Concatenar las partes descifradas para obtener el mensaje original
M_prime = b"".join(decrypted_parts)

# El hash del mensaje original
h_M = hashlib.sha256(M.encode()).hexdigest()

# El hash del mensaje descifrado
h_M_prime = hashlib.sha256(M_prime).hexdigest()

# Comparar
if h_M == h_M_prime:
    print("El mensaje es auténtico.")
else:
    print("El mensaje no es auténtico.")