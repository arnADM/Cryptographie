#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test complet de l'exercice DES
Ce script exécute toutes les étapes de l'exercice avec différentes configurations
"""

from pyDes import *
import random

def test_etape1_blocs_identiques():
    """Test de l'étape 1: blocs identiques en mode ECB"""
    print("=" * 60)
    print("TEST ÉTAPE 1: BLOCS IDENTIQUES EN MODE ECB")
    print("=" * 60)
    
    message = b"0123456701234567"
    key = b"DESCRYPT"
    iv = bytes([0]*8)
    
    # Test avec ECB
    print("Test avec mode ECB:")
    k_ecb = des(key, ECB, iv, pad=None, padmode=PAD_PKCS5)
    secret_ecb = k_ecb.encrypt(message)
    
    print(f"Message: {message}")
    print(f"Longueur texte plain: {len(message)}")
    print(f"Longueur texte chiffré: {len(secret_ecb)}")
    print(f"Premier bloc: {secret_ecb[0:8]}")
    print(f"Deuxième bloc: {secret_ecb[8:16]}")
    
    if secret_ecb[0:8] == secret_ecb[8:16]:
        print("✓ Les blocs sont IDENTIQUES (normal en ECB)")
    else:
        print("✗ Les blocs sont différents (anormal en ECB)")
    
    # Test avec CBC
    print("\nTest avec mode CBC:")
    k_cbc = des(key, CBC, iv, pad=None, padmode=PAD_PKCS5)
    secret_cbc = k_cbc.encrypt(message)
    
    print(f"Premier bloc: {secret_cbc[0:8]}")
    print(f"Deuxième bloc: {secret_cbc[8:16]}")
    
    if secret_cbc[0:8] == secret_cbc[8:16]:
        print("✗ Les blocs sont identiques (anormal en CBC)")
    else:
        print("✓ Les blocs sont DIFFÉRENTS (normal en CBC)")
    
    return secret_ecb, secret_cbc

def test_etape2_modification_bloc():
    """Test de l'étape 2: modification d'un bloc"""
    print("\n" + "=" * 60)
    print("TEST ÉTAPE 2: MODIFICATION D'UN BLOC")
    print("=" * 60)
    
    message = b"Vers Bob:    10$"
    key = b"DESCRYPT"
    iv = bytes([0]*8)
    
    # Test modification avec ECB
    print("Test modification avec mode ECB:")
    k = des(key, ECB, iv, pad=None, padmode=PAD_PKCS5)
    secret = k.encrypt(message)
    
    print(f"Message original: {message}")
    print(f"Message chiffré: {secret.hex()}")
    
    # Modification d'un bit
    modified = bytearray(secret)
    modified[8] = 1  # Modifie le premier octet du 2e bloc
    modified = bytes(modified)
    
    print(f"Message modifié: {modified.hex()}")
    
    # Déchiffrement
    original_decrypted = k.decrypt(secret)
    modified_decrypted = k.decrypt(modified)
    
    print(f"Déchiffré original: {original_decrypted}")
    print(f"Déchiffré modifié: {modified_decrypted}")
    
    # Test avec message plus long
    print("\nTest avec message plus long:")
    long_message = b"Vers Bob:    10$ et lui souhaiter bonne chance."
    secret_long = k.encrypt(long_message)
    
    modified_long = bytearray(secret_long)
    modified_long[8] = 1
    modified_long = bytes(modified_long)
    
    decrypted_long = k.decrypt(modified_long)
    print(f"Message long original: {long_message}")
    print(f"Message long modifié: {decrypted_long}")
    
    return secret, modified

def test_cbc_propagation():
    """Test de la propagation d'erreur en mode CBC"""
    print("\n" + "=" * 60)
    print("TEST PROPAGATION D'ERREUR EN MODE CBC")
    print("=" * 60)
    
    message = b"Vers Bob:    10$ et lui souhaiter bonne chance."
    key = b"DESCRYPT"
    iv = bytes([0]*8)
    
    k = des(key, CBC, iv, pad=None, padmode=PAD_PKCS5)
    secret = k.encrypt(message)
    
    print(f"Message original: {message}")
    
    # Test modification du 8e octet (1er bloc)
    print("\nModification du 8e octet (1er bloc):")
    modified = bytearray(secret)
    modified[8] = 1
    modified = bytes(modified)
    
    decrypted = k.decrypt(modified)
    print(f"Résultat: {decrypted}")
    
    # Test modification du 9e octet (2e bloc)
    print("\nModification du 9e octet (2e bloc):")
    modified = bytearray(secret)
    modified[9] = 1
    modified = bytes(modified)
    
    decrypted = k.decrypt(modified)
    print(f"Résultat: {decrypted}")
    
    return secret

def test_double_des_attack():
    """Test de l'attaque sur double DES"""
    print("\n" + "=" * 60)
    print("TEST ATTAQUE DOUBLE DES")
    print("=" * 60)
    
    message = b"01234567"
    
    # Génération des clés
    key1_val = random.randrange(0, 256)
    key2_val = random.randrange(0, 256)
    
    key1 = bytes([key1_val, 0, 0, 0, 0, 0, 0, 0])
    key2 = bytes([key2_val, 0, 0, 0, 0, 0, 0, 0])
    
    iv = bytes([0] * 8)
    
    k1 = des(key1, ECB, iv, pad=None, padmode=PAD_PKCS5)
    k2 = des(key2, ECB, iv, pad=None, padmode=PAD_PKCS5)
    
    print(f"Clé 1 originale: {key1_val}")
    print(f"Clé 2 originale: {key2_val}")
    print(f"Message: {message}")
    
    # Double chiffrement
    secret = k2.encrypt(k1.encrypt(message))
    print(f"Message chiffré: {secret.hex()}")
    
    # Attaque meet-in-the-middle
    print("\nLancement de l'attaque meet-in-the-middle...")
    
    # Phase 1: table de recherche
    lookup = {}
    for i in range(256):
        k = bytes([i, 0, 0, 0, 0, 0, 0, 0])
        k_obj = des(k, ECB, iv, pad=None, padmode=PAD_PKCS5)
        lookup[k_obj.encrypt(message)] = i
    
    # Phase 2: recherche
    found = False
    for i in range(256):
        k = bytes([i, 0, 0, 0, 0, 0, 0, 0])
        k_obj = des(k, ECB, iv, pad=None, padmode=PAD_PKCS5)
        
        if k_obj.decrypt(secret) in lookup:
            found_key1 = lookup[k_obj.decrypt(secret)]
            found_key2 = i
            
            print(f"✓ Clés trouvées!")
            print(f"Clé 1 trouvée: {found_key1} (originale: {key1_val})")
            print(f"Clé 2 trouvée: {found_key2} (originale: {key2_val})")
            
            # Test de déchiffrement
            test_k1 = des(bytes([found_key1, 0, 0, 0, 0, 0, 0, 0]), ECB, iv, pad=None, padmode=PAD_PKCS5)
            test_k2 = des(bytes([found_key2, 0, 0, 0, 0, 0, 0, 0]), ECB, iv, pad=None, padmode=PAD_PKCS5)
            
            test_result = test_k1.decrypt(test_k2.decrypt(secret))
            
            if test_result == message:
                print("✓ Déchiffrement réussi avec les clés trouvées!")
            else:
                print("✗ Échec du déchiffrement")
            
            found = True
            break
    
    if not found:
        print("✗ Attaque échouée")
    
    return found

def main():
    """Fonction principale pour exécuter tous les tests"""
    print("EXERCICE COMPLET: CHIFFREMENT PAR BLOCS DES")
    print("=" * 60)
    
    # Exécution de tous les tests
    test_etape1_blocs_identiques()
    test_etape2_modification_bloc()
    test_cbc_propagation()
    test_double_des_attack()
    
    print("\n" + "=" * 60)
    print("RÉSUMÉ DES APPRENTISSAGES")
    print("=" * 60)
    print("1. Mode ECB: blocs identiques visibles, vulnérable aux patterns")
    print("2. Mode CBC: blocs chaînés, plus sécurisé")
    print("3. Modification d'un bit: effet avalanche sur tout le bloc")
    print("4. CBC: erreur limitée au bloc affecté et au suivant")
    print("5. Double DES: vulnérable à l'attaque meet-in-the-middle")
    print("6. 3DES: résistant grâce à sa structure chiffre-déchiffre-chiffre")

if __name__ == "__main__":
    main()
