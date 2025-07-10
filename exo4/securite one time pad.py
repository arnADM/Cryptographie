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


print("=== Démonstration de la sécurité du One Time Pad ===")

# Message de notre ennemi
message = "UNE ATTAQUE"
print(f"Message original (secret): {message}")

# Le message doit être binaire
message_bytes = message.encode()

# Générer une clé aléatoire. La clé doit être la longueur du message
key_stream = generate_key_stream(len(message_bytes))
print(f"Clé originale: {key_stream}")

# Génère le texte chiffré
secret = xor_bytes(key_stream, message_bytes)
print(f"Le texte chiffré: {secret}")

print("\n--- Tentative de cryptanalyse ---")

# L'équipe 1 essaie avec le texte en clair "PAS ATTAQUE"
print("\nÉquipe 1:")
guess_message1 = "PAS ATTAQUE"
print(f"Hypothèse de l'équipe 1: {guess_message1}")

# Le message doit être binaire
guess_message1_bytes = guess_message1.encode()

# On essaie de générer une clé en utilisant le message chiffré
# et notre texte. Si la clé peut déchiffrer le message
# original, nous avons gagné. Vraiment ?
guess_key_stream1 = xor_bytes(guess_message1_bytes, secret)
print(f"La clé de chiffrement 1: {guess_key_stream1}")
plain_text1 = xor_bytes(guess_key_stream1, secret)
print(f"Le texte original de l'équipe 1: {plain_text1}")
print(f"Décodé: {plain_text1.decode()}")

# L'équipe 2 essaie avec le texte en clair "DES SURPRIS"
print("\nÉquipe 2:")
guess_message2 = "DES SURPRIS"
print(f"Hypothèse de l'équipe 2: {guess_message2}")

# Le message doit être binaire
guess_message2_bytes = guess_message2.encode()

# On essaie de générer une clé en utilisant le message chiffré
# et notre texte. Si la clé peut déchiffrer le message
# original, nous avons gagné. Vraiment ?
guess_key_stream2 = xor_bytes(guess_message2_bytes, secret)
print(f"La clé de chiffrement 2: {guess_key_stream2}")
plain_text2 = xor_bytes(guess_key_stream2, secret)
print(f"Le texte original de l'équipe 2: {plain_text2}")
print(f"Décodé: {plain_text2.decode()}")

print("\n--- Comparaison des clés ---")
print(f"Clé originale:     {key_stream}")
print(f"Clé équipe 1:      {guess_key_stream1}")
print(f"Clé équipe 2:      {guess_key_stream2}")
print(f"Clés identiques (1 vs orig)? {key_stream == guess_key_stream1}")
print(f"Clés identiques (2 vs orig)? {key_stream == guess_key_stream2}")
print(f"Clés identiques (1 vs 2)?    {guess_key_stream1 == guess_key_stream2}")

print("\n--- Conclusion ---")
print("Les deux équipes ont 'réussi' avec des clés différentes!")
print("Ceci démontre que le One Time Pad est incassable:")
