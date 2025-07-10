def xor(x, s):
    """
    XOR operation entre deux nombres

    Parametres:
    x (int): premier nombre
    s (int): Second nombre
    """
    result = x ^ s
    print(f"{bin(x)} xor {bin(s)} = {bin(result)}")


# Test de la fonction avec des exemples
print("Tests de la fonction XOR:")
xor(4, 8)
xor(4, 4)
xor(255, 1)
xor(255, 128)