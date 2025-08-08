import math
import random


# ========================================
# FONCTIONS UTILITAIRES
# ========================================

def est_premier(p):
    """
    est_premier(p)
    Vérifie si p est un nombre premier.

    Paramètres:
    p (int) : le nombre à vérifier

    Return:
    (bool) : True si premier, False sinon
    """
    if p < 2:
        return False
    for i in range(2, int(math.sqrt(p)) + 1):
        if p % i == 0:
            return False
    return True


def trouve_premier(size):
    """
    trouve_premier(size)
    Trouve un nombre premier aléatoire de taille spécifiée.

    Paramètres:
    size (int) : nombre de bits pour le nombre premier

    Return:
    (int) : un nombre premier
    """
    while True:
        # Génère un nombre aléatoire de 'size' bits
        p = random.getrandbits(size)
        # S'assure que le nombre est impair
        p |= 1
        if est_premier(p):
            return p


def lcm(a, b):
    """
    lcm(a, b)
    Trouve le plus petit multiple commun entre a et b.

    Paramètres:
    a (int)
    b (int)

    Return
    (int)
    """
    # On veut un entier, donc on utilise la division d'entier
    return a * b // math.gcd(a, b)


def trouve_e(lambda_n):
    """
    trouve_e(lambda_n)
    Trouver un entier e tel que 1 < e < λ(n) et
    gcd(e, λ(n)) = 1.

    Paramètres:
    lambda_n (int) : l'extrémité supérieure.

    Return:
    (int)
    (logical) False : si ne trouve pas
    """
    for e in range(2, lambda_n):
        if math.gcd(e, lambda_n) == 1:
            return e
    return False


def trouve_d(e, lambda_n):
    """
    trouve_d(e, lambda_n)
    Trouve un entier qui résout l'équation
    d⋅e ≡ 1 (mod λ(n))

    Paramètres:
    e (int) : e clé publique
    lambda_n : l'extrémité supérieure

    Return:
    (int)
    (logical) False : si ne trouve pas
    """
    # Nous allons par essai.
    # Comme notre échantillon sera petit, ça fonctionne.
    for d in range(2, lambda_n):
        if d * e % lambda_n == 1:
            return d
    return False


def facteurs(n):
    """
    facteurs(n)
    Trouve les facteurs de n.

    Paramètres:
    n (int) : le nombre que l'on veut trouver les facteurs.

    Return:
    p (int) : premier facteur
    q (int) : deuxième facteur
    """
    for p in range(2, n):
        if n % p == 0:
            return p, n // p


# ========================================
# PARTIE 1 : ALGORITHME RSA
# ========================================

print("=" * 50)
print("PARTIE 1 : IMPLÉMENTATION DE L'ALGORITHME RSA")
print("=" * 50)

# Génération de clé par Alice (secret)
# NOTE: On utilise une taille de 10 bits pour la démonstration
# Dans le texte original, il est suggéré 300 bits, mais c'est trop pour une démo
# Pour un vrai système, on utiliserait au moins 1024 ou 2048 bits
size = 10  # Changé de 300 à 10 pour la démonstration

print(f"\nGénération de nombres premiers de {size} bits...")

# Étape 1 : générer 2 nombres premiers distincts
p = trouve_premier(size)
q = trouve_premier(size)
# S'assurer que p et q sont distincts
while p == q:
    q = trouve_premier(size)
print("Nombres premiers p, q:", p, q)

print("\nAvez-vous deux nombres premiers distincts ?")
if p != q and est_premier(p) and est_premier(q):
    print("Réponse : Oui, nous avons deux nombres premiers distincts.")
else:
    print("Réponse : Non, il y a un problème.")

# Étape 2 : calculer n = p*q
n = p * q
print("\nLe modulo n :", n)

print("\nAvez-vous une valeur pour n ?")
if n > 0:
    print(f"Réponse : Oui, n = {n}")
else:
    print("Réponse : Non")

# Étape 3 : calculer lambda(n) (lcm(n) = λ(n) = lcm(λ(p), λ(q)),
# λ(p) = p − 1, λ(q) = q − 1,
# lcm(a, b) = |ab|/gcd(a, b))
lambda_n = lcm(p - 1, q - 1)
print("\nLambda_n :", lambda_n)

# Étape 4 : choisir un entier e tel que 1 < e < λ(n)
# et gcd(e, λ(n)) = 1.
e = trouve_e(lambda_n)
print("\nClé publique (exposant) e :", e)

# Étape 5 : pour trouver d, résoudre pour d l'équation d⋅e ≡ 1 (mod λ(n)).
d = trouve_d(e, lambda_n)
print("Clé secrète (exposant) d :", d)

# Afficher les clés
print("\n--- RÉSUMÉ DES CLÉS ---")
print(f"Clés publiques d'Alice : (e, n) = ({e}, {n})")
print(f"Clé secrète d'Alice : d = {d}")

# ========================================
# ÉTAPE 2 : MISE EN ŒUVRE DE L'ALGORITHME RSA
# ========================================

print("\n" + "=" * 50)
print("ÉTAPE 2 : CHIFFREMENT ET DÉCHIFFREMENT")
print("=" * 50)

# Bob veut envoyer un message à Alice.
# Le message est simple
m = 117

print(f"\nMessage original de Bob : {m}")

# Il chiffre le message
c = m ** e % n
print("Le message chiffré de Bob:", c)

# Alice déchiffre le message
m_dechiffre = c ** d % n
print("Le message pour Alice :", m_dechiffre)

print("\nAvons-nous réussi à implémenter RSA ?")
if m == m_dechiffre:
    print("Réponse : Oui, le message déchiffré correspond au message original!")
else:
    print("Réponse : Non, il y a une erreur dans l'implémentation.")

# ========================================
# PARTIE 2 : ESSAYER DE CASSER L'ALGORITHME RSA
# ========================================

print("\n" + "=" * 50)
print("PARTIE 2 : TENTATIVE DE CASSER RSA")
print("=" * 50)

# ========================================
# ÉTAPE 1 : CASSER LA FACTORISATION DES ENTIERS
# ========================================

print("\n--- Étape 1 : Attaque par factorisation ---")

# Du côté d'Eve
print("\nEve peut voir :")
print(" La clé publique (e, n) :", e, n)
print(" Le message chiffré de Bob :", c)

print("\nEve, voit-elle la clé publique et le message chiffré de Bob ?")
print("Réponse : Oui, ces informations sont publiques.")

print("\nEve essaie de factoriser n pour trouver p et q...")

# Nous allons factoriser n
p_eve, q_eve = facteurs(n)
print("Facteurs d'Eve (p, q) :", p_eve, q_eve)

print("\nAvons-nous trouvé p et q ?")
if (p_eve == p and q_eve == q) or (p_eve == q and q_eve == p):
    print("Réponse : Oui, Eve a trouvé les facteurs secrets!")
else:
    print("Réponse : Non")

# Eve calcul lambda
lambda_n_eve = lcm(p_eve - 1, q_eve - 1)
print("\nLambda_n de Eve :", lambda_n_eve)

# Eve calcul d
d_eve = trouve_d(e, lambda_n_eve)
print("Clé secrète (exposant) d'Eve d :", d_eve)

# Eve déchiffre le message (même code qu'Alice)
m_eve = c ** d_eve % n
print("Le message déchiffré par Eve :", m_eve)

print("\nAvez-vous réussi à déchiffrer le message ?")
if m_eve == m:
    print("Réponse : Oui, Eve a réussi à déchiffrer le message!")
    print("Cela montre que si on peut factoriser n, on peut casser RSA.")
else:
    print("Réponse : Non")

# ========================================
# ÉTAPE 2 : ANALYSE DE FRÉQUENCE
# ========================================

print("\n--- Étape 2 : Attaque par analyse de fréquence ---")

# Bob envoie un vrai message à Alice
# Mais, Bob n'est pas prudent.
print("\n+++++++++++++++++")
print("Bob l'imprudent!")
message = "Alice est plus forte que Bob."

print(f"Message original : '{message}'")
print("\nMessage chiffré (caractère par caractère) :")

# On divise le message en bloc et
# chiffre chacun des blocs.
chiffres = []
for m_c in message:
    c = ord(m_c) ** e % n
    chiffres.append((m_c, c))
    # On affiche le message envoyé
    print(c, " ", end='')

print("\n+++++++++++++++++")

# Analyse détaillée des répétitions
print("\n\nAnalyse des caractères répétés :")
print("-" * 40)

# Créer un dictionnaire pour analyser les occurrences
analyse = {}
for i, (char, chiffre) in enumerate(chiffres):
    if char not in analyse:
        analyse[char] = []
    analyse[char].append((i, chiffre))

# Afficher l'analyse pour les caractères qui apparaissent plus d'une fois
for char, occurrences in sorted(analyse.items()):
    if len(occurrences) > 1:
        positions = [str(pos) for pos, _ in occurrences]
        chiffres_uniques = set([chiffre for _, chiffre in occurrences])
        if len(chiffres_uniques) == 1:
            print(f"Caractère '{char}' (apparaît {len(occurrences)} fois) :")
            print(f"  - Positions : {', '.join(positions)}")
            print(f"  - Toujours chiffré en : {chiffres_uniques.pop()}")
            print(f"  ⚠️  VULNÉRABILITÉ : même chiffrement à chaque fois!")

print("\nQue remarquez-vous (vérifier les caractères 'e' du message) ?")
print("Réponse : Les caractères identiques (comme 'e', 'l', 'o', ' ', etc.) ")
print("sont TOUJOURS chiffrés avec les mêmes codes.")
print("Cela rend le chiffrement vulnérable à l'analyse de fréquence!")

# ========================================
# CONCLUSIONS
# ========================================

print("\n" + "=" * 50)
print("CONCLUSIONS ET RECOMMANDATIONS")
print("=" * 50)

print("""
RÉSUMÉ DES VULNÉRABILITÉS IDENTIFIÉES :

1. FACTORISATION FACILE
   - Avec des petits nombres premiers (10 bits), Eve peut factoriser n
   - Une fois n factorisé, elle retrouve la clé privée d

2. ANALYSE DE FRÉQUENCE
   - Sans padding aléatoire, les mêmes caractères donnent les mêmes chiffrés
   - Un attaquant peut utiliser l'analyse statistique du langage

RECOMMANDATIONS DE SÉCURITÉ :

1. Utiliser des nombres premiers TRÈS GRANDS
   - Minimum RSA-2048 (nombres de 2048 bits)
   - RSA-4096 pour une sécurité à long terme

2. Ajouter du PADDING ALÉATOIRE
   - Utiliser OAEP (Optimal Asymmetric Encryption Padding)
   - Garantit que le même message donne des chiffrés différents

3. GÉNÉRATION ALÉATOIRE SÉCURISÉE
   - Utiliser des générateurs cryptographiquement sûrs
   - Éviter les générateurs prévisibles

NOTE HISTORIQUE :
- RSA-100 (100 chiffres décimaux) a été cassé
- RSA-250 a été cassé en 2020
- La norme actuelle est RSA-2048 minimum
""")

print("\nFIN DE LA DÉMONSTRATION RSA")
print("=" * 50)