import time
import numpy as np
import matplotlib.pyplot as plt

# Fonction pour générer un polynôme ternaire avec df, dg, dr spécifiques
def generate_ternary_polynomial(N, d):
    poly = [0] * N
    ones = np.random.choice(N, d, replace=False)
    neg_ones = np.random.choice([i for i in range(N) if i not in ones], d, replace=False)
    for i in ones:
        poly[i] = 1
    for i in neg_ones:
        poly[i] = -1
    return np.array(poly)

# Inverse modulaire dans l'anneau des polynômes (simplifié ici)
def mod_inverse(f, mod):
    # Implémentation de l'inverse modulaire (ex. algorithme d'Euclide étendu)
    return np.array([1])  # Remplace avec l'inversion réelle

# Génération des clés avec les paramètres spécifiques (N, df, dg)
def generate_keys(N, df, dg):
    f = generate_ternary_polynomial(N, df)  # Clé privée f
    g = generate_ternary_polynomial(N, dg)  # Clé privée g
    Fq = mod_inverse(f, q)  # Inverse de f modulo q
    Fp = mod_inverse(f, p)  # Inverse de f modulo p
    h = (Fq * g) % q  # Clé publique
    return f, Fp, h

# Chiffrement
def encrypt(h, message, N, dr):
    r = generate_ternary_polynomial(N, dr)  # Polynôme aléatoire de taille N
    c = (p * (np.convolve(h, r)[:N] % q) + message) % q  # Convolution mod q, restreinte à N coefficients
    return c

# Déchiffrement
def decrypt(f, Fp, c):
    a = np.convolve(f, c) % q  # Calculer f * c mod q
    a = np.mod(a + q // 2, q) - q // 2  # Réduire les coefficients
    b = np.convolve(Fp, a) % p  # Calculer Fp * a mod p
    return b

# Fonction pour calculer la sécurité estimée basée sur N et q
def security_level(N, q):
    return int(N * np.log2(q))

# Tester et mesurer la performance pour différentes variantes de NTRU
def performance_analysis():
    # Paramètres pour chaque variante NTRU
    params = [
        {'name': 'NTRU167', 'N': 167, 'p': 3, 'q': 128, 'df': 61, 'dg': 20, 'dr': 18},
        {'name': 'NTRU263', 'N': 263, 'p': 3, 'q': 128, 'df': 50, 'dg': 24, 'dr': 16},
        {'name': 'NTRU503', 'N': 503, 'p': 3, 'q': 256, 'df': 216, 'dg': 72, 'dr': 55}
    ]

    results = []
    security_levels = []

    for param in params:
        global p, q
        p = param['p']
        q = param['q']
        N = param['N']
        df = param['df']
        dg = param['dg']
        dr = param['dr']

        # Générer un message
        message = generate_ternary_polynomial(N, df)

        # Mesurer le temps de génération des clés
        start_time = time.time()
        f, Fp, h = generate_keys(N, df, dg)
        key_gen_time = time.time() - start_time

        # Mesurer le temps de chiffrement
        start_time = time.time()
        ciphertext = encrypt(h, message, N, dr)
        encryption_time = time.time() - start_time

        # Mesurer le temps de déchiffrement
        start_time = time.time()
        decrypted_message = decrypt(f, Fp, ciphertext)
        decryption_time = time.time() - start_time

        # Taille des clés
        private_key_size = len(f) + len(Fp)  # Taille totale des clés privées
        public_key_size = len(h)  # Taille de la clé publique
        total_key_size = private_key_size + public_key_size  # Taille totale des clés

        # Calculer le niveau de sécurité
        security = security_level(N, q)
        security_levels.append(security)

        # Ajouter les résultats pour cette variante NTRU
        results.append([param['name'], encryption_time, decryption_time, total_key_size, security])

    # Afficher les résultats sous forme de tableau
    print(f"{'NTRU':<10} {'Encryption Time (s)':<20} {'Decryption Time (s)':<20} {'Key Size (bytes)':<20} {'Security Level':<15}")
    for result in results:
        print(f"{result[0]:<10} {result[1]:<20.5f} {result[2]:<20.5f} {result[3]:<20} {result[4]:<15}")

    # Tracer le niveau de sécurité en fonction de N pour chaque variante NTRU
    plot_security([param['N'] for param in params], security_levels)

# Fonction pour tracer le niveau de sécurité
def plot_security(N_values, security_levels):
    plt.figure(figsize=(10, 6))
    plt.plot(N_values, security_levels, marker='o', linestyle='-', color='b', label='Security Level')
    plt.title("Niveau de sécurité en fonction de N")
    plt.xlabel("Dimension N")
    plt.ylabel("Niveau de sécurité (bits)")
    plt.grid(True)
    plt.legend()
    plt.show()

# Appeler la fonction d'analyse de performance
performance_analysis()
