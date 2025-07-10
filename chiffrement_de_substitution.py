# SubstitutionCypher1.py - Implémentation complète du chiffrement de substitution

import random
import operator
import sys


# ===============================
# PARTIE 1: CHIFFREMENT DE SUBSTITUTION
# ===============================

def generate_key():
    """
    generate_key()
    Fonction qui génère une clé pour le chiffrement
    On ne passe aucun paramètre, car nous allons utiliser
    une fonction aléatoire pour la générer.

    Paramètres:
    aucun

    Return
    Dictionnaire : la clé de mappage
    """

    # Lettres utilisées pour le mappage
    letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    # Une liste de nos lettres pour utiliser avec
    # la partie aléatoire.
    cletters = list(letters)

    # La clé est toujours un dictionnaire
    key = {}

    # Nous allons faire un mappage, mais plus intelligent.
    # Nous allons utiliser un mappage plus aléatoire.
    # Pour chaque lettre, nous allons utiliser une autre
    # lettre aléatoire de la liste cletters

    for c in letters:
        key[c] = cletters.pop(random.randint(0, len(cletters) - 1))
    return key


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

    # Vous devez créer une boucle for qui vérifie si le
    # caractère est dans la clé de mappage. Si oui, on le substitue. Sinon,
    # on le remet tel quel.
    for c in message:
        # On mappe seulement les caractères
        # de notre alphabète
        if c in key:
            secret += key[c]
        else:
            secret += c
    return secret


def generate_dkey(key):
    """
    generate_dkey(key)
    Fonction qui génère la clé de déchiffrement à partir de la clé de chiffrement

    Paramètres:
    key (dict): clé de chiffrement

    Return:
    dict: clé de déchiffrement (inverse de la clé de chiffrement)
    """
    dkey = {}
    for k, v in key.items():
        dkey[v] = k
    return dkey


def decrypt(key, secret):
    """
    decrypt(key, secret)
    Fonction qui déchiffre le message secret.

    Paramètres :
    key (dict): clé de déchiffrement
    secret (string): message secret à déchiffrer

    Return :
    string : le message déchiffré
    """

    # Va contenir le message déchiffré
    message = ""

    # Pour chaque caractère dans le message secret
    for c in secret:
        # On mappe seulement les caractères de notre alphabet
        if c in key:
            message += key[c]
        else:
            message += c
    return message


# ===============================
# PARTIE 2: CRYPTANALYSE
# ===============================

# Texte chiffré à analyser
secret = """LRVMNIR BPR SUMVBWVR JX BPR LMIWV YJERYRKBI JX QMBM WI
BPR XJVNI MKD YMIBRUT JX IRHX WI BPR RIIRKVR JX
YMBINLMTMIPW UTN QMUMBR DJ W IPMHH BUT BJ RHNVWDMBR BPR
YJERYRKBI JX BPR QMBM MVVJUDWKO BJ YT WKBRUSURBMBWJK
LMIRD JK XJUBT TRMUI JX IBNDT
WB WI KJB MK RMIT BMIQ BJ RASHMWK RMVP YJERYRKB MKD WBI
IWOKWXWVMKVR MKD IJYR YNIB URYMWK NKRASHMWKRD BJ OWER M
VJYSHRBR RASHMKMBWJK JKR CJNHD PMER BJ LR FNMHWXWRD MKD
WKISWURD BJ INVP MK RABRKB BPMB PR VJNHD URMVP BPR IBMBR
JX RKHWOPBRKRD YWKD VMSMLHR JX URVJOKWGWKO IJNKDHRII
IJNKD MKD IPMSRHRII IPMSR W DJ KJB DRRY YTIRHX BPR XWKMH
MNBPJUWBT LNB YT RASRUWRKVR CWBP QMBM PMI HRXB KJ DJNLB
BPMB BPR XJHHJCWKO WI BPR SUJSRU MSSHWVMBWJK MKD
WKBRUSURBMBWJK W JXXRU YT BPRJUWRI WK BPR PJSR BPMB BPR
RIIRKVR JX JQWKMCMK QMUMBR CWHH URYMWK WKBMVB
"""


class Attaque:
    """
    Classe Attaque
    Classe pour analyse cryptographique (attaque) d'un
    texte chiffré par chiffrement de substitution
    """

    def __init__(self):
        # On doit initialiser notre alphabet et
        # la fréquence
        self.alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

        # On utilise un dictionnaire pour enregistrer
        # la fréquence de nos lettres
        self.freq = {}

        # On utilise un dictionnaire pour la
        # correspondance de nos caractères
        self.mappings = {}

        # Notre référence de correspondance des
        # caractères anglais
        self.freq_eng = {
            'A': 0.08167, 'B': 0.01492, 'C': 0.02782, 'D': 0.04253, 'E': 0.12702, 'F': 0.02228,
            'G': 0.02015, 'H': 0.06094, 'I': 0.06966, 'J': 0.00153, 'K': 0.00772, 'L': 0.04025,
            'M': 0.02406, 'N': 0.06749, 'O': 0.07507, 'P': 0.01929, 'Q': 0.00095, 'R': 0.05987,
            'S': 0.06327, 'T': 0.09056, 'U': 0.02758, 'V': 0.00978, 'W': 0.02360, 'X': 0.00150,
            'Y': 0.01974, 'Z': 0.00074
        }

        # Clé de déchiffrement
        self.key = {}

        # Caractères utilisés de l'alphabet
        self.plain_chars_left = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

        # Caractères utilisés dans le texte chiffré
        self.secret_chars_left = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    def calculate_freq(self, secret):
        """
        calculate_freq(self, secret)
        Méthode qui calcule la fréquence d'un
        caractère dans le texte

        Paramètres:
        self : notre objet d'Attaque
        secret (string) : le message secret

        Return
        Dictionnaire : la clé de mappage
        """

        # On va utiliser un compteur pour compter les lettres
        # de notre alphabet dans le texte.
        # On va mettre le compteur à 0 pour chacune des lettres
        for c in self.alphabet:
            self.freq[c] = 0

        # On doit également connaître le nombre
        # de caractères dans le texte
        letter_count = 0

        # Nous allons compter la fréquence de chacun
        # des caractères dans le texte et le
        # nombre de caractères dans le texte
        for c in secret:
            if c in self.freq:
                self.freq[c] += 1
                letter_count += 1

        # On doit maintenant connaître le pourcentage
        # d'utilisation de chacun des caractères
        for c in self.freq:
            self.freq[c] = round(self.freq[c] / letter_count, 4)

    def print_freq(self):
        """
        print_freq(self)
        Méthode qui imprime le résultat
        sur 3 colonnes

        Paramètres:
        self : notre objet d'Attaque

        Return
        Aucun
        """

        # On imprime le résultat sur 3 colonnes
        new_line_count = 0
        for c in self.freq:
            print(c, ":", self.freq[c], " ", end='')
            if new_line_count % 3 == 2:
                print()
            new_line_count += 1
        print()  # Ligne vide à la fin

    def calculate_matches(self):
        """
        calculate_matches(self)
        Calcul la correspondance de chacun de nos
        caractères de notre alphabet dans le texte
        chiffré. Le pourcentage le plus petit
        indique la plus haute probabilité.

        Paramètres:
        self : notre objet d'Attaque

        Return
        Aucun
        """

        for secret_char in self.alphabet:
            # On veut trouver les probabilités de
            # la correspondance de tous
            # les caractères dans notre alphabet
            # dans le texte chiffré.

            # On met la correspondance dans un dictionnaire
            map_dict = {}

            for plain_char in self.alphabet:
                # On veut trouver la différence de probabilité
                # qu'un caractère de notre alphabet se trouve dans le
                # texte secret. Si la différence est petite, ça
                # peut être le caractère
                map_dict[plain_char] = round(abs(self.freq[secret_char] - self.freq_eng[plain_char]), 4)

            # On veut trier la liste par fréquence d'utilisation
            self.mappings[secret_char] = sorted(map_dict.items(), key=operator.itemgetter(1))

    def set_key_mapping(self, secret_char, plain_char):
        """
        set_key_mapping(self, secret_char, plain_char)
        Ajoute des caratères connus à la clé.

        Paramètres:
        self    : notre objet d'Attaque
        secret_char string : le caractère secret
        plain_char string : le caractère de l'alaphabet

        Return
        key (dict) : clés corepondantes (mappage)
        """
        # Vérifions si le caractère existe dans nos caractères
        # Permet également de vérifier si on essaie d'ajouter
        # une correspondance existante.
        if secret_char not in self.secret_chars_left or plain_char not in self.plain_chars_left:
            print("Erreur de mappage de clés : ", secret_char, plain_char)
            # Sortie avec erreur -1
            sys.exit(-1)
        # Ajoute notre caractère et retire les caractères
        # des listes de caractères
        self.key[secret_char] = plain_char
        self.plain_chars_left = self.plain_chars_left.replace(plain_char, '')
        self.secret_chars_left = self.secret_chars_left.replace(secret_char, '')

    def guess_key(self):
        """
        guess_key(self)
        Trouve la clé qui correspond le mieux au texte chiffré.

        Paramètres:
        self    : notre objet d'Attaque

        Return
        Aucun
        """
        # On veut trouver pour chacun des caractères chiffrés
        # lequel a le plus de chance de correspondre à une
        # entrée de notre alphabet.

        for secret_char in self.secret_chars_left:
            # On veut passer toutes les correspondances
            # et la première disponible on veut la
            # faire correspondre.
            # On a deux entrées dans mappings :
            # le caractère que l'on recherche,
            # la différence de probabilité.
            # On ne sert pas de la différence.
            for plain_char, diff in self.mappings[secret_char]:
                # Si ce caractère est toujours dans la liste
                # de caractères, on l'utilise et on l'enlève.
                if plain_char in self.plain_chars_left:
                    self.key[secret_char] = plain_char
                    self.plain_chars_left = self.plain_chars_left.replace(plain_char, '')
                    break

    def get_key(self):
        """
        get_key(self)
        Retourne la clé qui correspond le mieux au texte chiffré.

        Paramètres:
        self    : notre objet d'Attaque

        Return
        key (dict) : clés corepondantes (mappage)
        """
        return self.key


# ===============================
# DÉMONSTRATION ET TESTS
# ===============================

def demo_chiffrement():
    """Démonstration du chiffrement de substitution"""
    print("=== DÉMONSTRATION DU CHIFFREMENT DE SUBSTITUTION ===")

    # Génération d'une clé
    key = generate_key()
    print("Clé générée:", key)

    # Chiffrement d'un message
    message = "AINSI VA LA VIE"
    secret = encrypt(key, message)
    print(f"Message original: {message}")
    print(f"Message chiffré: {secret}")

    # Déchiffrement
    dkey = generate_dkey(key)
    decrypted = encrypt(dkey, secret)
    print(f"Message déchiffré: {decrypted}")
    print()


def demo_cryptanalyse():
    """Démonstration de la cryptanalyse par analyse de fréquence"""
    print("=== CRYPTANALYSE PAR ANALYSE DE FRÉQUENCE ===")

    # Créer un objet d'attaque
    pirate = Attaque()

    # Calcul la fréquence de caractères
    pirate.calculate_freq(secret)
    print("Fréquences des caractères dans le texte chiffré:")
    pirate.print_freq()

    # Calcul des correspondances
    pirate.calculate_matches()

    # Ajout de quelques mappings connus basés sur l'analyse
    print("Ajout de mappings connus...")
    pirate.set_key_mapping('B', 'T')  # B est très fréquent, probablement T
    pirate.set_key_mapping('R', 'E')  # R est très fréquent, probablement E
    pirate.set_key_mapping('M', 'A')  # M est fréquent, probablement A
    pirate.set_key_mapping('V', 'C')  # Pour avoir "BECAUSE" et "FOCUS"

    # Essai de trouver une clé
    pirate.guess_key()
    key = pirate.get_key()

    print("Clé trouvée:", key)
    print()

    # Déchiffre le message secret
    message = decrypt(key, secret)

    # Imprime le message déchiffré P (plain texte)
    # superposé au message chiffré C (chiffré)
    print("Texte déchiffré (P) vs Texte chiffré (C):")
    print("-" * 60)
    message_lines = message.splitlines()
    secret_lines = secret.splitlines()
    for i in range(len(message_lines)):
        print('P:', message_lines[i])
        print('C:', secret_lines[i])
        print()


if __name__ == "__main__":
    # Démonstration du chiffrement
    demo_chiffrement()

    # Démonstration de la cryptanalyse
    demo_cryptanalyse()