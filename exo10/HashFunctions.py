# HashFunctions.py
import hashlib


def modify(m):
    """
    Fonction
    modify(m)
    Modifie un bit du message reçu.

    Paramètres
    m (bytes) : message à modifier.

    Return
    (bytes) : message avec un bit de flippé.
    """

    l = list(m)
    # Flip un bit
    l[0] = l[0] ^ 1

    return bytes(l)


# Notre message, il doit être binaire.
m = "Nobody inspects the spammish repetition".encode()

# On utilise l'algorithme sha256.
sha256 = hashlib.sha256()

# On met à jour l'objet
sha256.update(m)

# On récupère le hash
d = sha256.digest()

# On affiche notre hash
print("Le hash de sha256 :", d)

# On modifie un bit du message
m = modify(m)
print("Notre message modifié :", m)

# Dans votre code, créer un deuxième objet sha256 (sha256bis) et refaire les étapes
sha256bis = hashlib.sha256()
sha256bis.update(m)
d_bis = sha256bis.digest()

print("Le hash de sha256bis :", d_bis)

# Comparaison des deux valeurs
print("Les hash sont-ils identiques ?", d == d_bis)