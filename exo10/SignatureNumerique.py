# SignatureNumerique.py
import hashlib


def modification(m):
    """
    Fonction
    modification(m)
    Modifie un bit de m

    Paramètres:
    m(bytes) : message à modifier

    Return
    (bytes) : message modifié
    """

    # Convertis le message en une liste
    l = list(m)

    # Flip le premier bit
    l[0] = l[0] ^ 1

    return bytes(l)


# Les clés RSA d'Alice généré par le
# script RSA de l'exercice 9
# **********
# Clés publiques (e, n) : 5 199841
# Clé secrète (d) : 4973
# **********

# On assigne ces clés à des variables
n = 199841
e = 5
d = 4973

# Le message qu'Alice veut signer et envoyer à Bob.
message = "A martini. Shaken, not stirred.".encode()

# Étape 1 : hachage du message
# Ajoutez le code manquant pour générer un hash sha256.
# Vous devez créer un objet sha256.
sha256 = hashlib.sha256()
# Faire un « update » de l'objet avec le message.
sha256.update(message)
# Générer le hash et l'assigner à une variable h.
h = sha256.digest()

# La valeur de h est en octets, nous avons
# besoin d'une valeur numérique (un entier).
h = int.from_bytes(h, 'big') % n
print("Hachage du message :", h)

# Étape 2 : "déchiffré" la valeur de hachage.
# Elle utilise sa clé secrète d.
signature = h ** d % n

# Étape 3 : envoyer le message et la signature.
print("Message à Bob et sa signature (message, signature) :", message, signature)

# Eve intercepte le message et le modifie.
message = modification(message)
print("Le message modifié d'Eve :", message)

# Bob reçoit le message.
# Étape 1 : hachage du message

# Ajoutez le code pour trouver la valeur de hachage du message.
sha256_bob = hashlib.sha256()
sha256_bob.update(message)
h_bob = sha256_bob.digest()
h_bob = int.from_bytes(h_bob, 'big') % n

print("Bob, hachage du message :", h_bob)

# Étape 2-3 : vérifier la signature
verification = signature ** e % n
print("Vérification de la signature :", verification)

# Vérification finale
if h_bob == verification:
    print("✓ La signature est valide - le message n'a pas été modifié")
else:
    print("✗ La signature n'est pas valide - le message a été modifié ou falsifié!")