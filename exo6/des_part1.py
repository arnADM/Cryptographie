# DES01.py

# Import l'implémentation de DES
# https://gist.github.com/eigenein/1275094
from pyDes import *

def modification(secret):
    """Fonction pour modifier le texte chiffré (attaque de Bob)"""
    # On fait une copie du texte chiffré pour le modifier
    mod = bytearray(secret)
    
    # Version pour modifier le montant de 10$ à 1000$ (étape 2)
    # Les caractères à modifier sont aux positions 11, 12, 13
    # '1', '0', '$' -> '1', '0', '0', '0', '$'
    # Mais en réalité, on va voir que ça ne marche pas avec DES
    
    # Première tentative : modifier plusieurs caractères
    # mod[11] = mod[11] ^ ord('1') ^ ord('1')  # 1 reste 1
    # mod[12] = mod[12] ^ ord('0') ^ ord('0')  # 0 devient 0
    # mod[13] = mod[13] ^ ord('$') ^ ord('0')  # $ devient 0
    
    # Deuxième tentative : modifier seulement un bit (comme demandé plus tard)
    # On modifie 1 bit, du 2e bloc
    # comme on a déjà des 0,
    # le 1 va mettre seulement
    # un bit à 1.
    mod[8] = 1  # Modifie le 9e octet (index 8)
    
    return bytes(mod)

# Notre message un peu spécial (étape 1)
# message = b"0123456701234567"

# Message d'Alice pour l'étape 2
message = b"Vers Bob:    10$"

# Message plus long pour tester l'effet sur les blocs suivants
# message = b"Vers Bob:    10$ et lui souhaiter bonne chance."

# On utilise la même clé que dans les commentaires
# La clé doit avoir 8 octets, donc les 8 caractères
key = b"DESCRYPT"

# Un vecteur d'initialisation, encore comme
# dans les commentaires, on utilise 8 zéros.
# Ce vecteur n'est pas utilisé dans le
# mode ECB, notre premier mode utilisé.
iv = bytes([0]*8)

# Version avec des 1 pour voir le changement dans les blocs
# iv = bytes([1]*8)

# On crée notre objet clé, on ne met pas de
# caractère de padding et on utilise
# le mode de padding recommandé
k = des(key, ECB, iv, pad=None, padmode=PAD_PKCS5)

# Version CBC pour comparaison
# k = des(key, CBC, iv, pad=None, padmode=PAD_PKCS5)

print("=== ANALYSE DU CHIFFREMENT DES ===")
print("Message original:", message)
print("Clé utilisée:", key)
print("Mode utilisé: ECB")
print("Vecteur d'initialisation:", iv)
print()

# Alice envoie son message à la banque
secret = k.encrypt(message)
print("--- ALICE ENVOIE SON MESSAGE ---")
print("Longueur du texte plain :", len(message))
print("Longueur du texte chiffré :", len(secret))
print("Message chiffré d'Alice :", secret)
print("Message chiffré (hex):", secret.hex())

# Pour l'étape 1 : analyse des blocs
if len(secret) >= 16:
    print()
    print("--- ANALYSE DES BLOCS ---")
    print("Premier bloc chiffré :", secret[0:8])
    print("Deuxième bloc chiffré :", secret[8:16])
    if len(secret) > 16:
        print("Le reste chiffré :", secret[16:])
    
    # Comparaison des deux premiers blocs
    if secret[0:8] == secret[8:16]:
        print("*** Les deux premiers blocs sont IDENTIQUES ***")
        print("Ceci est dû au mode ECB qui chiffre chaque bloc indépendamment")
    else:
        print("*** Les deux premiers blocs sont DIFFÉRENTS ***")
        print("Ceci est normal en mode CBC grâce au chaînage")

print()

# Bob se place entre Alice et la banque
print("--- BOB TENTE DE MODIFIER LE MESSAGE ---")
modified_secret = modification(secret)
print("Message modifié par Bob:", modified_secret)
print("Message modifié (hex):", modified_secret.hex())

# Comparaison des messages chiffrés
print("Différence entre les messages chiffrés:")
for i, (a, b) in enumerate(zip(secret, modified_secret)):
    if a != b:
        print(f"  Position {i}: {a} -> {b}")

print()

# La banque déchiffre ici
print("--- LA BANQUE DÉCHIFFRE LES MESSAGES ---")
try:
    original_decrypted = k.decrypt(secret)
    print("Message original déchiffré :", original_decrypted)
    
    modified_decrypted = k.decrypt(modified_secret)
    print("Message modifié déchiffré :", modified_decrypted)
    
    # Analyse du résultat
    print()
    print("--- ANALYSE DES RÉSULTATS ---")
    if original_decrypted == modified_decrypted:
        print("✓ Bob n'a PAS réussi à modifier le message")
        print("  Les deux messages déchiffrés sont identiques")
    else:
        print("✗ Bob a réussi à modifier le message")
        print("  Mais le résultat n'est pas ce qu'il espérait...")
    
    print(f"Message original : {original_decrypted}")
    print(f"Message modifié  : {modified_decrypted}")
    
    # Vérification caractère par caractère
    print("\nComparaison caractère par caractère:")
    min_len = min(len(original_decrypted), len(modified_decrypted))
    for i in range(min_len):
        orig_char = chr(original_decrypted[i]) if original_decrypted[i] < 128 else f"\\x{original_decrypted[i]:02x}"
        mod_char = chr(modified_decrypted[i]) if modified_decrypted[i] < 128 else f"\\x{modified_decrypted[i]:02x}"
        
        if original_decrypted[i] != modified_decrypted[i]:
            print(f"  Position {i}: '{orig_char}' -> '{mod_char}' *** DIFFÉRENT ***")
        else:
            print(f"  Position {i}: '{orig_char}' -> '{mod_char}'")
    
    # Si les longueurs sont différentes
    if len(original_decrypted) != len(modified_decrypted):
        print(f"\nLongueurs différentes: {len(original_decrypted)} vs {len(modified_decrypted)}")

except Exception as e:
    print(f"Erreur lors du déchiffrement: {e}")

print()
print("=== CONCLUSIONS ===")
print("1. DES ne peut pas être attaqué de la même façon qu'un chiffrement par flux")
print("2. Modifier un bit dans un bloc rend tout le bloc inutilisable")
print("3. En mode ECB, les blocs sont indépendants (blocs identiques visibles)")
print("4. En mode CBC, les blocs sont chaînés (plus sécurisé)")
print("5. La modification d'un bit cause un 'effet avalanche' dans le bloc")