def generate_key(n):
    """
    generate_key(n)
    Fonction qui génère une clé pour le chiffrement
    On passe un entier qui est en fait la vraie clé.
    Paramètres:
    n (int) : entier, clé de chiffrement

    Return
    Dictionnaire : la clé de mappage
    """
    # Lettres utilisées pour le mappage
    letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    # Nous allons utiliser un dictionnaire pour faire le mappage
    key = {}
    cnt = 0

    # Génère la clé
    for c in letters:
        # Le modulo permet de gérer un nombre qui déborde du nombre de lettre
        # Le modulo permet de redémarrer au début si la valeur de c est
        # plus grande que 25
        key[c] = letters[(cnt + n) % len(letters)]
        cnt += 1
    return key


def generate_dkey(key):
    """
    generate_dkey(key)
    Fonction qui génère une clé de déchiffrement en inversant les paires clé:valeur

    Paramètres:
    key (dict): clé de mappage original

    Return:
    dict: clé de déchiffrement (paires inversées)
    """
    dkey = {}
    for original_char, encrypted_char in key.items():
        dkey[encrypted_char] = original_char
    return dkey


def encrypt(key, message):
    """
    encrypt(key, message)
    Fonction qui chiffre le message.

    Paramètres :
    key (dict): clé de mappage.
    message (string): message à chiffrer

    Return :
    string : le message chiffré
    """

    # Va contenir le message chiffré
    secret = ""

    # Vous devez créer une boucle for qui vérifie si le caractère est dans
    # dans la clé de mappage. Si oui, on le substitue. Sinon, on le
    # le remet tel quel.
    for char in message:
        if char in key:
            secret += key[char]
        else:
            secret += char
    return secret


# Vérifions que notre clé est bien générée
key = generate_key(3)
print(key)

# Vérifions que le chiffrement fonctionne
message = "AINSI VA LA VIE"
secret = encrypt(key, message)
print(secret)

# Test du déchiffrement avec la clé inversée
print("--- Test de déchiffrement ---")

# Méthode 1: Utiliser 26-3 comme clf
dkey_method1 = generate_key(26-3)
decrypted1 = encrypt(dkey_method1, secret)
print(f"Déchiffrement méthode 1 (26-3): {decrypted1}")

# Méthode 2: Utiliser la clé inversée
dkey_method2 = generate_dkey(key)
decrypted2 = encrypt(dkey_method2, secret)
print(f"Déchiffrement méthode 2 (clé inversée): {decrypted2}")
print()


# Attaque sur le chiffrement de César
print("####################################")
print("Attaque sur le chiffrement de César")
for i in range(26):
	dkey = generate_key(i)
	message = encrypt(dkey, secret)
	print(message)
print("####################################")
