# Shadow.py
import hashlib
import base64
from hmac import compare_digest as compare_hash
import os

print("=== PARTIE 1: Hash avec sel aléatoire ===")
# On spécifie le salt.
# On utilise un salt aléatoire de 16 caractères.
salt = os.urandom(16)

# Notre mot de passe en clair.
password = 'password'

# Le nombre d'itérations pour le hash.
iterations = 100000

# On génère notre hash
hash_value = hashlib.pbkdf2_hmac('sha512', password.encode(), salt, iterations)

# On imprime notre salt avec le mot de passe.
# En encode en base64 pour avoir une sortie qui ressemble à shadow.
print("Le mot de passe : ", base64.b64encode(salt).decode(), "$", base64.b64encode(hash_value).decode(), sep='')

print("\n=== PARTIE 2: Problème sans sel (sel vide) ===")
# On spécifie le salt.
# On utilise un salt vide.
salt_empty = ''.encode()

Alice_value = hashlib.pbkdf2_hmac('sha512', password.encode(), salt_empty, iterations)

# On génère le hash de Bob
Bob_value = hashlib.pbkdf2_hmac('sha512', password.encode(), salt_empty, iterations)

# On compare les hash
if compare_hash(Alice_value, Bob_value):
    print("Les hash sont identiques.")
else:
    print("Bummer, ils ne sont pas identiques!")

# On imprime les salts avec les mots de passe.
# En encode en base64 pour avoir une sortie qui ressemble à shadow.
print("Le mot de passe d'Alice : ", base64.b64encode(salt_empty).decode(), "$", base64.b64encode(Alice_value).decode(), sep='')
print("Le mot de passe de Bob : ", base64.b64encode(salt_empty).decode(), "$", base64.b64encode(Bob_value).decode(), sep='')

print("\n=== PARTIE 3: Solution avec sels différents ===")
# On spécifie des sels différents.
# On utilise des sels aléatoires de 16 caractères.
salt_alice = os.urandom(16)
salt_bob = os.urandom(16)

Alice_value_salt = hashlib.pbkdf2_hmac('sha512', password.encode(), salt_alice, iterations)

# On génère le hash de Bob avec un sel différent
Bob_value_salt = hashlib.pbkdf2_hmac('sha512', password.encode(), salt_bob, iterations)

# On compare les hash
if compare_hash(Alice_value_salt, Bob_value_salt):
    print("Les hash sont identiques.")
else:
    print("Les hash sont différents - c'est ce qu'on veut!")

# On imprime les salts avec les mots de passe.
print("Le mot de passe d'Alice : ", base64.b64encode(salt_alice).decode(), "$", base64.b64encode(Alice_value_salt).decode(), sep='')
print("Le mot de passe de Bob : ", base64.b64encode(salt_bob).decode(), "$", base64.b64encode(Bob_value_salt).decode(), sep='')