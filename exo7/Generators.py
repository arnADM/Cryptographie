 #Generators.py

print("=== Partie 2 : Générateurs ===\n")

# Générateur avec g=2, modulo 5, pour 10 itérations
print("1. Générateur avec g=2, modulo 5 (10 itérations):")
print("i\tg^i\t(g^i) % 5")
print("-" * 25)

g = 2
for i in range(10):
    # On affiche i pour comparer les valeurs
    puissance = g**i
    resultat = puissance % 5
    print(f"{i}\t{puissance}\t{resultat}")

print("\nObservation : La séquence générée est [1, 2, 4, 3, 1, 2, 4, 3, ...]")
print("Elle se répète tous les 4 éléments et ne contient jamais 0.\n")

# Générateur avec plus de valeurs (20 itérations)
print("2. Générateur avec g=2, modulo 5 (20 itérations):")
print("i\t(g^i) % 5")
print("-" * 15)

for i in range(20):
    resultat = (g**i) % 5
    print(f"{i}\t{resultat}")

print("\nObservation : Le motif [1, 2, 4, 3] se répète constamment.")
print("La période du générateur est 4.\n")

# Essayons avec un autre générateur
print("3. Comparaison avec g=3, modulo 5:")
print("i\t(2^i) % 5\t(3^i) % 5")
print("-" * 25)

g2 = 3
for i in range(12):
    res2 = (2**i) % 5
    res3 = (g2**i) % 5
    print(f"{i}\t{res2}\t\t{res3}")

print("\nObservation : g=3 génère la séquence [1, 3, 4, 2, 1, 3, 4, 2, ...]")
print("Même période (4) mais ordre différent.\n")

# Testons avec un modulo différent
print("4. Générateur avec g=2, modulo 7:")
print("i\t(2^i) % 7")
print("-" * 15)

for i in range(14):
    resultat = (2**i) % 7
    print(f"{i}\t{resultat}")

print("\nObservation : Avec modulo 7, la période est 3 : [1, 2, 4, 1, 2, 4, ...]")
print("La période dépend à la fois du générateur et du modulo.\n")

print("=== Propriétés importantes ===")
print("- Un bon générateur ne produit jamais 0 (sauf pour i=0 parfois)")
print("- La séquence est périodique")
print("- La période dépend du générateur g et du modulo n")
print("- Ces générateurs sont utilisés en cryptographie pour la distribution de clés")