import random


def generate_key_stream(n):
    """
    generate_key_stream(n)
    Génère une clé aléatoire pour le chiffrement

    Paramètres:
    n (int) : la longueur de la clé

    Return:
    Une clé aléatoire d'octets (valeur binaire)
    """
    return bytes([random.randrange(0, 256) for i in range(n)])


def xor_bytes(key_stream, texte):
    """
    xor_bytes(key_stream, texte)
    Fait un XOR d'une clé aléatoire avec un texte

    Paramètres:
    key_stream (int) : clé aléatoire
    texte () : texte à faire un XOR

    Return:
    Texte chiffré ou déchiffré
    """
    # Prends la longueur minimale entre les deux paramètres
    # La clé et le texte doivent être de la même longueur,
    # sinon on utilise le plus court des deux.
    length = min(len(key_stream), len(texte))
    # Le texte est traité octet par octet et retourne en octets
    return bytes([key_stream[i] ^ texte[i] for i in range(length)])


# Test du One Time Pad
print("=== Test du One Time Pad ===")

# Message original
message = "AINSI VA LA VIE"
print(f"Message original: {message}")

# Convertir le message en bytes
message_bytes = message.encode()
print(f"Message en bytes: {message_bytes}")

# Générer une clé aléatoire de la même longueur que le message
key_stream = generate_key_stream(len(message_bytes))
print(f"Clé aléatoire: {key_stream}")

# Chiffrer le message
secret = xor_bytes(key_stream, message_bytes)
print(f"Message chiffré: {secret}")

# Déchiffrer le message
plain_text = xor_bytes(key_stream, secret)
print(f"Message déchiffré (bytes): {plain_text}")
print(f"Message déchiffré (texte): {plain_text.decode()}")

# Vérification
if plain_text.decode() == message:
    print("✓ Chiffrement et déchiffrement réussis!")
else:
    print("✗ Erreur dans le processus!")