import math
import random


def est_premier(p):
    """
    est_premier(p)
    Vérifier si p est un nombre premier

    Paramètres:
    p (int) : le nombre à vérifier

    Return:
    False ou True.
    """
    # On ne vérifie pas 1 et 2.
    # On va jusqu'à la racine carrée
    # du nombre plus 1: la valeur
    # de droite de range n'est pas
    # incluse
    for i in range(2, math.isqrt(p) + 1):
        # Si la division n'a pas de reste
        # donc il n'est pas premier
        if p % i == 0:
            return False
    return True


def trouve_premier(size):
    """
    trouve_premier(p)
    Trouve un nombre premier de manière aléatoire
    On recherche le nombre du début de size jusqu'au
    double. Nous aurions pu mettre les intervalles
    dans l'appel de fonction.

    Paramètres:
    size (int) : le nombre à vérifier

    Return:
    (int) : un nombre premier aléatoire
    """
    while True:
        p = random.randrange(size, 2 * size)
        if est_premier(p):
            return p


def is_generator(g, p):
    """
    is_generator(g, p)
    Vérifie si g est un générateur.
    Essaie toutes les valeurs de 1 à p-1 (on ne teste
    pas p). Tous les éléments du groupe peuvent être
    représentés par g élevé à k pour un entier k.
    Donc, si le g élevé à k divisé par p retourne un reste
    de 1, ce n'est pas un générateur.

    Paramètres:
    p (int) : un nombre premier

    Return:
    (int) : un nombre générateur
    """
    # On vérifie si élevé à une puissance on ne revient pas
    # à 1. Si ça devient 1, alors il recommence. Donc,
    # ce n'est pas un générateur.
    # On vérifie de 1 à p-1 (on ne teste pas p)
    for i in range(1, p - 1):
        if (g ** i) % p == 1:
            return False
    return True


def get_generator(p):
    """
    get_generator(p)
    Retourne un générateur.
    Essaie tous les nombres de 2 à p et
    appelle la fonction is_generator pour
    vérifier si c'est un generator

    Paramètres:
    p (int) : un nombre premier

    Return:
    (int) : un nombre générateur
    """
    # On débute à 2, car 0 ou 1 élève
    # à une puissance ne donne pas grand-chose.
    for g in range(2, p):
        if is_generator(g, p):
            return g


# Tests de la Partie 1
print("=== PARTIE 1: Tests des nombres premiers ===")
# On vérifie avec un nombre non premier et un premier.
print("46 est non premier : ", est_premier(46))
print("23 est premier : ", est_premier(23))

# On génère un nombre premier aléatoire.
print("Nombre premier : ", trouve_premier(1000))
print()

# Tests de la Partie 2
print("=== PARTIE 2: Générateur mathématique ===")
# Créer un nombre premier et trouver son générateur
p_test = trouve_premier(10000)
g_test = get_generator(p_test)
print("Nombre premier : ", p_test, "Générateur : ", g_test)
print()

# Partie 3: Implémentation de Diffie-Hellman
print("=== PARTIE 3: Échange de clés Diffie-Hellman ===")

# Informations publiques
# On génère un nombre premier aléatoire.
p = trouve_premier(10000)

# On génère un générateur
g = get_generator(p)
print("Nombre premier : ", p, "Générateur : ", g)

# Alice 1
# Elle doit générer un nombre aléatoire.
# Normalement, on utiliserait un très
# grand nombre.
a = random.randrange(0, p)

# Elle calcule le nombre à envoyer à Bob
j = (g ** a) % p

# Alice envoie son nombre à Bob
# Elle utilise un canal non sécurisé
print(" Alice j : ", j)

# Bob 1
# Il doit générer un nombre aléatoire.
# Normalement, on utiliserait un très
# grand nombre.
b = random.randrange(0, p)

# Il calcule le nombre à envoyer à Alice
k = (g ** b) % p

# Bob envoie son nombre à Alice
# Il utilise un canal non sécurisé
print(" Bob k : ", k)

# Alice 2
g_ab = (k ** a) % p
print("Alice g_ab : ", g_ab)

# Bob 2
g_ab = (j ** b) % p
print("Bob g_ab : ", g_ab)