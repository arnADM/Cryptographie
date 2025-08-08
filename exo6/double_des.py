# DoubleDES01.py
from pyDes import *
import random
import time

# Notre message à envoyer
message = b"01234567"

print("=== IMPLÉMENTATION ET ATTAQUE DU DOUBLE DES ===")
print(f"Message à chiffrer: {message}")
print()

# On génère une clé de 1 octet (petite clé)
key_11 = random.randrange(0, 256)

# On inclut la petite clé dans 8 octets.
# C'est ce qui est demandé par l'implémentation
# de DES que l'on utilise.
# On fait du padding avec les autres octets.
key_1 = bytes([key_11, 0, 0, 0, 0, 0, 0, 0])

# On se crée une 2e clé de la même façon.
key_21 = random.randrange(0, 256)
key_2 = bytes([key_21, 0, 0, 0, 0, 0, 0, 0])

# Notre vecteur d'initialisation pour CBC.
iv = bytes([0] * 8)

# Nos objets clés DES
k1 = des(key_1, ECB, iv, pad=None, padmode=PAD_PKCS5)
k2 = des(key_2, ECB, iv, pad=None, padmode=PAD_PKCS5)

print("--- GÉNÉRATION DES CLÉS ---")
print("La clé 1 (8 bits) :", key_11)
print("La clé 2 (8 bits) :", key_21)
print("Clé 1 complète (64 bits):", key_1.hex())
print("Clé 2 complète (64 bits):", key_2.hex())
print()

# Alice envoie un message à Bob
# On chiffre le message 2 fois avec 2 clés différentes.
# Pour une meilleure sécurité. ;)
print("--- ALICE CHIFFRE AVEC DOUBLE DES ---")
intermediate = k1.encrypt(message)
secret = k2.encrypt(intermediate)

print("Chiffrement étape 1 (clé 1):", intermediate.hex())
print("Chiffrement étape 2 (clé 2):", secret.hex())
print("Le message chiffré d'Alice :", secret)
print()

# Bob reçoit le message d'Alice
print("--- BOB DÉCHIFFRE LE MESSAGE ---")
decrypted_step1 = k2.decrypt(secret)
decrypted_message = k1.decrypt(decrypted_step1)
print("Déchiffrement étape 1 (clé 2):", decrypted_step1.hex())
print("Déchiffrement étape 2 (clé 1):", decrypted_message.hex())
print("Le message que Bob reçoit :", decrypted_message)
print()

# Vérification que le déchiffrement est correct
if decrypted_message == message:
    print("✓ Déchiffrement réussi!")
else:
    print("✗ Erreur dans le déchiffrement!")
print()

# Eve s'attaque au Double DES
print("=== ATTAQUE PAR EVE (Meet-in-the-middle) ===")
print("Eve connaît le message en clair et le message chiffré")
print("Elle va utiliser une attaque 'meet-in-the-middle'")
print()

start_time = time.time()

# Nous allons utiliser une table de recherche
lookup = {}

print("--- PHASE 1: CONSTRUCTION DE LA TABLE DE RECHERCHE ---")
print("Chiffrement du message connu avec toutes les clés possibles...")

# Notre première boucle pour trouver la première clé.
# Nous avons une clé de 8 bits, donc 256 possibilités.
# Nous allons remplir une table de recherche
# avec toutes les possibilités de la première clé.
for i in range(256):
    # On se crée une clé
    k = bytes([i, 0, 0, 0, 0, 0, 0, 0])

    # On se crée un objet clé DES
    k_obj = des(k, ECB, iv, pad=None, padmode=PAD_PKCS5)
    
    # On met le texte chiffré du texte connu
    # dans la table de recherche
    encrypted_once = k_obj.encrypt(message)
    lookup[encrypted_once] = i

print(f"Table de recherche construite avec {len(lookup)} entrées")
print()

print("--- PHASE 2: RECHERCHE DE LA DEUXIÈME CLÉ ---")
print("Déchiffrement partiel et recherche dans la table...")

found = False
# Notre deuxième boucle va trouver la deuxième clé.
# On déchiffre une fois avec toutes les possibilités
# de clé. À chaque itération, on vérifie le texte
# déchiffré avec les entrées de notre table de
# recherche. Si on a une équivalence, on a
# trouvé les 2 clés
for i in range(256):
    # On se crée une clé
    k = bytes([i, 0, 0, 0, 0, 0, 0, 0])

    # On se crée un objet clé DES
    k_obj = des(k, ECB, iv, pad=None, padmode=PAD_PKCS5)
    
    # On vérifie si le texte déchiffré
    # une fois est dans notre table
    # de recherche. Si oui, Bingo!
    decrypted_once = k_obj.decrypt(secret)
    if decrypted_once in lookup:
        # On affiche la clé 1
        found_key1 = lookup[decrypted_once]
        found_key2 = i
        
        print(f"*** CLÉS TROUVÉES! ***")
        print("Clé k1 trouvée :", found_key1)
        print("Clé k2 trouvée :", found_key2)
        print("Clé k1 originale :", key_11)
        print("Clé k2 originale :", key_21)
        
        # Vérification si les clés sont exactes ou approximatives
        if found_key1 == key_11 and found_key2 == key_21:
            print("✓ Clés exactement identiques!")
        else:
            print("⚠ Clés approximatives (différence due au bit de parité)")
            print(f"Différence clé 1: {abs(found_key1 - key_11)}")
            print(f"Différence clé 2: {abs(found_key2 - key_21)}")
        
        # Test de déchiffrement avec les clés trouvées
        print("\n--- TEST DE DÉCHIFFREMENT AVEC LES CLÉS TROUVÉES ---")
        # Créer la clé 1 avec la valeur trouvée dans la table de recherche.
        test_key1 = bytes([found_key1, 0, 0, 0, 0, 0, 0, 0])
        # Créer la clé 2 avec la valeur où la boucle est rendue (i).
        test_key2 = bytes([found_key2, 0, 0, 0, 0, 0, 0, 0])
        
        # Générer un objet clé 1 avec la clé 1.
        test_k1 = des(test_key1, ECB, iv, pad=None, padmode=PAD_PKCS5)
        # Générer un objet clé 2 avec la clé 2.
        test_k2 = des(test_key2, ECB, iv, pad=None, padmode=PAD_PKCS5)
        
        # Déchiffrer avec l'objet clé 2 en premier, puis avec l'objet clé 1 (voir Bob).
        test_decrypted = test_k1.decrypt(test_k2.decrypt(secret))
        
        print(f"Message original    : {message}")
        print(f"Message déchiffré   : {test_decrypted}")
        
        if test_decrypted == message:
            print("✓ Déchiffrement réussi avec les clés trouvées!")
        else:
            print("✗ Échec du déchiffrement avec les clés trouvées")
        
        found = True
        break

end_time = time.time()

if not found:
    print("✗ Aucune clé trouvée!")
else:
    print(f"\nTemps d'exécution de l'attaque: {end_time - start_time:.4f} secondes")

print()
print("=== ANALYSE DE L'ATTAQUE ===")
print("1. Complexité théorique du double DES: 2^16 = 65536 opérations")
print("2. Complexité de l'attaque meet-in-the-middle: 2^8 + 2^8 = 512 opérations")
print("3. Le double DES n'ajoute qu'1 bit de sécurité au lieu de 8 bits")
print("4. Raison: deux boucles consécutives au lieu d'une boucle imbriquée")
print("5. Cette attaque ne fonctionne PAS sur 3DES")
print()
print("=== POURQUOI 3DES EST PLUS SÉCURISÉ ===")
print("3DES utilise: Chiffrement(clé1) -> Déchiffrement(clé2) -> Chiffrement(clé3)")
print("- Rétrocompatible avec DES si clé1 = clé2 = clé3")
print("- Résistant à l'attaque meet-in-the-middle")
print("- Clé effective de 112 bits (avec 2 clés) ou 168 bits (avec 3 clés)")
