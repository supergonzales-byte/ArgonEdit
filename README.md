# 🔐 ArgonEdit

Un éditeur de fichiers texte sécurisé avec chiffrement AES-GCM-SIV et dérivation de clé Argon2.

## Description

ArgonEdit est une application de bureau qui permet de **créer, éditer et stocker des fichiers texte chiffrés**. Chaque fichier est protégé par un mot de passe et chiffré avec des algorithmes cryptographiques modernes. Les fichiers chiffrés portent l'extension `.enc`.

Fonctionnalités principales :
- Chiffrement et déchiffrement de fichiers
- Éditeur de texte intégré avec recherche (`Ctrl+F`)
- Mot de passe maître pour ouvrir tous les fichiers d'un coup
- Suppression sécurisée des fichiers temporaires
- Organisation des fichiers par dossiers

## Sécurité

- **Chiffrement : AES-GCM-SIV (256 bits)** — algorithme authentifié résistant aux nonces réutilisés
- **Dérivation de clé : Argon2id** — algorithme résistant aux attaques par force brute et GPU
- **Sel aléatoire (256 bits)** généré à chaque chiffrement
- **Nonce aléatoire (96 bits)** unique par fichier
- Les données associées (AAD) incluent la signature du format pour empêcher toute manipulation

## Dépendances

Installe les dépendances avec `pip` :

```bash
pip install customtkinter
pip install CTkMessagebox
pip install CTkToolTip
pip install cryptography
pip install argon2-cffi
```

## Installation

1. Clone le repository :
```bash
git clone https://github.com/supergonzales-byte/ArgonEdit.git
cd ArgonEdit
```

2. Installe les dépendances (voir ci-dessus)

3. Lance l'application :
```bash
python ArgonEdit.pyw
```

## Utilisation

- **Ouvrir un fichier** : double-clic ou bouton "Ouvrir"
- **Chiffrer un fichier** : bouton "Chiffrer et envoyer au coffre"
- **Déchiffrer un fichier** : bouton "Déchiffrer un fichier"
- **Rechercher dans l'éditeur** : `Ctrl+F`
- **Sauvegarder** : bouton "Sauvegarder" (rechiffre automatiquement)
- **Mot de passe maître** : permet d'ouvrir tous les fichiers sans retaper le mot de passe à chaque fois

## Prérequis

- Python 3.8 ou supérieur
- Windows
