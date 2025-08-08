# CalculsModulaires.py

print("=== Partie 1 : Calculs modulaires ===\n")

# Premier calcul - sans parenthèses
print("1. Premier calcul : 4 + 7 % 12")
val = 4 + 7 % 12
print("Notre résultat est :", val)
print("Explication : 7 % 12 = 7, puis 4 + 7 = 11")
print("Le modulo est effectué AVANT l'addition (priorité des opérateurs)\n")

# Deuxième calcul pour confirmer
print("2. Deuxième calcul : 4 + 15 % 12")
val = 4 + 15 % 12
print("Notre résultat 2 est :", val)
print("Explication : 15 % 12 = 3, puis 4 + 3 = 7")
print("Confirme que le modulo est fait AVANT l'addition\n")

# Calcul avec parenthèses (ce qu'on veut vraiment)
print("3. Calcul avec parenthèses : (4 + 7) % 12")
val = (4 + 7) % 12
print("Notre résultat avec parenthèses est :", val)
print("Explication : 4 + 7 = 11, puis 11 % 12 = 11\n")

# Autre exemple avec parenthèses
print("4. Autre exemple : (4 + 15) % 12")
val = (4 + 15) % 12
print("Notre résultat est :", val)
print("Explication : 4 + 15 = 19, puis 19 % 12 = 7\n")

# Dernier calcul
print("5. Calcul final : (4 * 5) % 5")
val = (4 * 5) % 5
print("Notre résultat 3 est :", val)
print("Explication : 4 * 5 = 20, puis 20 % 5 = 0")
print("Tout multiple de 5 modulo 5 donne 0\n")

print("=== Conclusion ===")
print("- Sans parenthèses : l'opérateur % a priorité sur +")
print("- Avec parenthèses : on contrôle l'ordre d'évaluation")
print("- Toujours utiliser des parenthèses pour éviter l'ambiguïté")