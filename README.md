# login-test

Outil Python d'audit de sécurité pour les pages web. On lui donne une URL, il lance une série de tests de vulnérabilités courantes et produit un rapport (texte ou HTML) qui liste ce qu'il a trouvé, avec le détail et une recommandation de correction pour chaque point.

Je l'ai développé pour automatiser les premières vérifications sur une page de login, la phase où on répète toujours les mêmes tests à la main.

## Ce qu'il teste

- **Injection SQL** : tente de contourner l'authentification avec une série de payloads
- **XSS** : vérifie si une charge injectée est renvoyée sans échappement
- **Injection de commande** : teste l'exécution de commandes système
- **Inclusion de fichiers (LFI)** : cherche l'accès à des fichiers locaux
- **Injection de template (SSTI)** : détecte l'évaluation d'expressions côté serveur
- **Identifiants par défaut** : teste des couples classiques (admin/admin, etc.)
- **En-têtes de sécurité** : repère les en-têtes manquants (CSP, HSTS, X-Frame-Options...)
- **Force brute** (optionnel) : test par dictionnaire sur les identifiants

## Prérequis

- Python 3.x
- La bibliothèque `requests` (`pip install requests`)

## Utilisation

L'outil s'utilise en ligne de commande :

```bash
# Audit simple, rapport texte
python login-test.py --url http://cible/login

# Rapport HTML lisible, avec code couleur par gravité
python login-test.py --url http://cible/login --format html --output rapport.html

# Préciser les noms des champs du formulaire
python login-test.py --url http://cible/login --user-field email --pass-field pwd

# Activer le test de force brute avec dictionnaires
python login-test.py --url http://cible/login --brute --users users.txt --passwords pass.txt
```

## Le rapport

Chaque test produit un résultat avec une gravité (critique, moyenne, info), le détail de ce qui a été trouvé, et une recommandation. Le rapport HTML affiche le tout avec un code couleur (rouge critique, orange moyen, vert info) pour repérer l'essentiel d'un coup d'œil.

## Pistes d'évolution

- Détection automatique des noms de champs du formulaire
- Gestion des sessions et des tokens CSRF avant envoi
- Ajout d'autres familles de failles (IDOR, SSRF)

## Avertissement

Outil destiné à un usage éducatif et à des tests autorisés uniquement. Ne l'utilise que sur des systèmes pour lesquels tu as une autorisation explicite. Je décline toute responsabilité en cas d'usage non autorisé.
