import random


class KeyStream:
    """
    Classe KeyStream
    Classe pour générer un flux de clés
    """

    def __init__(self, key=1):
        """
        init (self, key=1)
        Initialise l'objet clé

        Paramètres:
        self : notre objet flux de clé
        key (int) : la clé partagée,
        elle est à 1 par défaut

        Return
        Notre objet KeyStream
        """

        # Initialise l'objet à la clé
        self.next = key

    def rand(self):
        """
        rand(self)
        Calcul la valeur aléatoire

        Paramètres:
        self : notre objet flux de clés

        Return:
        self.next (int) : la prochaine valeur aléatoire
        """

        # L'équation pour notre LCG
        # Xnext+1 = (a*Xnext + c) mod m
        self.next = (1103515245 * self.next + 12345) % 2 ** 31
        return self.next

    def get_key_byte(self):
        """
        get_key_byte(self)
        Crée le flux de clé

        Paramètres:
        self : notre objet flux de clé

        Return:
        Retourne une clé aléatoire d'un caractère (le mod 256)
        """

        # Version initiale (avec faille de sécurité)
        # return self.rand() % 256

        # Version corrigée (partie 2, étape 4)
        return (self.rand() // 2 ** 23) % 256


def encryptDecrypt(key, message):
    """
    encryptDecrypt(key, message)
    Chiffre le message

    Paramètres
    key (objet KeyStream): flux de clés
    message (bytes): message à chiffrer

    Return:
    (bytes) : message chiffré
    """

    # On fait un XOR avec chacun des caractères du message
    # Une nouvelle clé est générée à chaque caractère
    return bytes([message[i] ^ key.get_key_byte() for i in range(len(message))])


def transmit(secret, tauxErreurs):
    """
    transmit(secret, tauxErreurs)
    Fonction qui simule des erreurs de transmission.
    On passe le message octet par octet et de
    temps en temps on flip un bit selon le tauxErreur passé.

    Paramètres :
    secret (bytes) : le message qui est transmis
    tauxErreurs () : le niveau d'erreur qu'on veut insérer dans le message

    Return :
    (bytes) : le message avec des erreurs
    """

    # Contiens le message modifié
    b = []

    # On passe chaque octet du message et
    # l'ajoute à b
    for c in secret:
        # Selon notre taux d'erreur, on
        # flip un bit dans l'octet
        if random.randrange(0, tauxErreurs) == 0:
            #
            c = c ^ 2 ** random.randrange(0, 8)
        b.append(c)
    return bytes(b)


def modification(secret):
    """
    modification(secret)
    Fonction qui modifie certains octets du message,
    sans la clé
    Nous allons flipper des bits, mais pas
    n'importe quels bits, ceux en notre faveur

    Paramètres :
    secret (bytes) : le message secret

    Return :
    (bytes) : le message secret modifié
    """

    # On créer une liste de zéro de la même
    # longueur que le secret
    mod = [0] * len(secret)

    # Modification des caractères 18 à 20 pour changer "10$" en "1000$"
    # Transfert a Bob : __10$
    # Transfert a Bob : 1000$
    mod[18] = ord(' ') ^ ord('1')  # Espace -> 1
    mod[19] = ord(' ') ^ ord('0')  # Espace -> 0
    mod[20] = ord('1') ^ ord('0')  # 1 -> 0

    # On fait la même opération que pour chiffrer
    return bytes([mod[i] ^ secret[i] for i in range(len(secret))])


def get_key(message, secret):
    """
    get_key(message, secret)
    Génère un flux de clés à partir d'un message en texte clair
    et d'un message chiffré

    Paramètres :
    message (bytes) : message en clair
    secret (bytes) : message chiffré

    Return :
    (bytes) : flux de clés
    """

    # Fait un XOR octet par octet
    return bytes([message[i] ^ secret[i] for i in range(len(secret))])


def crack(key_stream, secret):
    """
    crack(key_stream, secret)
    Fonction qui utilise un flux de clés pour déchiffrer
    le message chiffré.

    Paramètres :
    key_stream (bytes) : le flux de clés
    secret (bytes) : le message chiffré

    Return :

    """

    # On ne peut déchiffrer plus que la longueur
    # du flux de clés ou de la longueur du
    # message. On recherche le plus petit
    length = min(len(key_stream), len(secret))

    # On refait toujours la même chose :)
    return bytes([key_stream[i] ^ secret[i] for i in range(length)])


def brute_force(plain, secret):
    """
    brute_force(plain, cipher)
    Fonction qui trouve une clé secrète par force brute.

    Paramètres :
    plain (bytes) : Une partie de texte en clair connu.
    secret (bytes) : le texte chiffré.

    Return
    (bytes) : la clé secrète commune
    """

    # On veut faire une attaque force brute.
    # On doit essayer toutes les clés possibles.
    for key in range(2 ** 31):
        # On se crée un flux de clés possible
        bf_key = KeyStream(key)

        # On vérifie si le texte connut XOR avec le texte chiffré
        # retourne une clé secrète égale à notre clé.
        # Sinon, on sort et essaie un autre flux de clé.
        # Si oui, on retourne la clé.
        # Au premier caractère qui ne fonctionne pas, on sort.
        # On vérifie tout le texte clair, même si
        # une clé fonctionne. Au cas où un octet serait bon
        # mais pas le suivant, donc mauvaise clé.
        valid = True
        for i in range(len(plain)):
            xor_value = plain[i] ^ secret[i]
            if xor_value != bf_key.get_key_byte():
                valid = False
                break

        if valid:
            return key

    # Si toutes les clés ne fonctionnent pas
    return False


def test_partie1_etape1():
    """Test de la partie 1, étape 1"""
    print("=== PARTIE 1 - ÉTAPE 1 : Test du LCG ===")

    # Notre objet clé de flux
    key = KeyStream()

    # On génère une série de clés pour notre flux
    print("Génération de 10 clés avec la clé d'initialisation par défaut (1):")
    for i in range(10):
        print(key.get_key_byte())

    print("\nTest avec une clé d'initialisation différente (42):")
    key2 = KeyStream(42)
    for i in range(10):
        print(key2.get_key_byte())

    print("\nVérification de la reproductibilité:")
    key3 = KeyStream(1)
    print("Première exécution avec clé 1:")
    for i in range(5):
        print(key3.get_key_byte())

    key4 = KeyStream(1)
    print("Deuxième exécution avec clé 1:")
    for i in range(5):
        print(key4.get_key_byte())
    print()


def test_partie1_etape2():
    """Test de la partie 1, étape 2"""
    print("=== PARTIE 1 - ÉTAPE 2 : Test du chiffrement ===")

    # On chiffre le message
    # Notre objet clé de flux
    key = KeyStream(23)

    # Notre message à chiffrer
    # Il doit être binaire
    message = "Hello, World!".encode()
    secret = encryptDecrypt(key, message)
    print("Notre message secret : ", secret)

    # On déchiffre le message
    # On doit initialiser notre objet clé de flux de nouveau
    # Notre clé seed est 23.
    key = KeyStream(23)

    # On déchiffre comme on chiffre avec un XOR
    message = encryptDecrypt(key, secret)
    print("Notre message en texte : ", message)
    print()


def test_partie2_etape1():
    """Test de la partie 2, étape 1"""
    print("=== PARTIE 2 - ÉTAPE 1 : Gestion des erreurs de transmission ===")

    # On chiffre le message
    # Notre objet clé de flux
    key = KeyStream(23)

    # Notre message à chiffrer
    # Il doit être binaire
    message = "Nous allons attaquer a 12 h, par le cote Est de la prairie".encode()
    secret = encryptDecrypt(key, message)

    # On veut voir le message original
    print("Notre message est : ", message)
    # On génère les erreurs tous les 6 octets
    secret = transmit(secret, 6)

    # On déchiffre le message
    # On doit initialiser notre objet clé de flux de nouveau
    # Notre clé seed
    key = KeyStream(23)

    # On déchiffre comme on chiffre avec un XOR
    message = encryptDecrypt(key, secret)
    print("Notre message en texte : ", message)
    print()


def test_partie2_etape2():
    """Test de la partie 2, étape 2"""
    print("=== PARTIE 2 - ÉTAPE 2 : Problème d'authentification ===")

    # Alice envoie son message à la banque
    # Les deux se sont accordé pour la clé 10
    key = KeyStream(10)

    # Notre message à chiffrer
    message = "Transfert a Bob : 10$".encode()
    print("Alice : ", message)
    secret = encryptDecrypt(key, message)
    print("Le secret : ", secret)

    # Bob intercepte le message ici
    secret = modification(secret)

    # La banque reçoit le message
    # La banque connait la clé d'Alice
    key = KeyStream(10)
    message = encryptDecrypt(key, secret)
    print("La banque : ", message)
    print()


def test_partie2_etape3():
    """Test de la partie 2, étape 3"""
    print("=== PARTIE 2 - ÉTAPE 3 : Réutilisation de clé ===")

    # Eve donne un message à Alice
    message_Eve = "Ceci est un message super hyper important".encode()

    # Alice communique avec Bob
    # Les deux se sont accordé pour la clé 33
    key = KeyStream(33)
    message = message_Eve
    print("Alice : ", message)
    secret = encryptDecrypt(key, message)
    print("Le secret : ", secret)

    # Eve intercepte et génère son flux de clés
    eves_key_stream = get_key(message, secret)

    # Voilà Bob
    key = KeyStream(33)
    message = encryptDecrypt(key, secret)
    print("Bob : ", message)

    # Alice envoie un nouveau message à Bob
    key = KeyStream(33)
    message2 = "Salut Bob, nous allons dominer le monde et la galaxie".encode()
    print("Alice (nouveau message) : ", message2)
    secret2 = encryptDecrypt(key, message2)
    print("Le secret 2 : ", secret2)

    # Bob déchiffre
    key = KeyStream(33)
    message2_decrypted = encryptDecrypt(key, secret2)
    print("Bob (nouveau message) : ", message2_decrypted)

    # Eve capture le nouveau message secret et le déchiffre
    print("Eve crack : ", crack(eves_key_stream, secret2))
    print()


def test_partie2_etape4():
    """Test de la partie 2, étape 4"""
    print("=== PARTIE 2 - ÉTAPE 4 : Faible entropie ===")

    # Alice communique avec Bob
    # Utilisation d'une clé aléatoire plus grande
    cle_secret = random.randrange(0, 2 ** 20)
    print("La clé secrète entre Alice et Bob : ", cle_secret)

    header = "MESSAGE: "
    message = header + "Un message secret vers Bob"

    key = KeyStream(cle_secret)
    message = message.encode()
    print("Alice : ", message)
    secret = encryptDecrypt(key, message)
    print("Le secret : ", secret)

    # Voilà Bob
    key = KeyStream(cle_secret)
    message = encryptDecrypt(key, secret)
    print("Bob : ", message)

    # Eve tente une attaque par force brute
    print("Eve tente une attaque par force brute...")
    bf_key = brute_force(header.encode(), secret)
    print("La clé force brute d'Eve : ", bf_key)

    if bf_key:
        key = KeyStream(bf_key)
        message = encryptDecrypt(key, secret)
        print("Eve : ", message)
    else:
        print("Eve n'a pas réussi à trouver la clé")
    print()


if __name__ == "__main__":
    # Exécution de tous les tests
    test_partie1_etape1()
    test_partie1_etape2()
    test_partie2_etape1()
    test_partie2_etape2()
    test_partie2_etape3()
    test_partie2_etape4()