# login-test

Outil Python d'audit de sécurité pour les pages web. On lui donne une URL, il lance une série de tests de vulnérabilités courantes et produit un rapport qui liste ce qu'il a trouvé, le payload utilisé et une recommandation de correction pour chaque faille.

Je l'ai développé pour automatiser les premières vérifications sur une page de login, la phase où on répète toujours les mêmes tests à la main.

## Ce qu'il teste

- **Injection SQL** : tente de contourner l'authentification avec une série de payloads
- **XSS** : vérifie si des scripts injectés sont renvoyés par la page
- **CSRF** : cherche une absence de protection contre les requêtes forgées
- **Injection de commande** : teste l'exécution de commandes système
- **Inclusion de fichiers (LFI / RFI)** : cherche l'accès à des fichiers locaux ou distants
- **SSRF** : vérifie si le serveur peut être poussé à requêter des ressources internes
- **Force brute** (optionnel) : test par dictionnaire sur les identifiants
- **Analyse des en-têtes HTTP** : repère les en-têtes de sécurité manquants (CSP, HSTS, X-Frame-Options, etc.)
- **Analyse du code source** : détecte des mots-clés sensibles exposés (mot de passe, clé API...)
- **Détection d'obfuscation JavaScript** : repère du code potentiellement masqué (eval, document.write...)

## Prérequis

- Python 3.x
- La bibliothèque `requests`

```bash
pip install requests
```

## Utilisation

```bash
python login-test.py
```

Le script est interactif. Il demande :
1. L'URL de la page à tester (ex : http://exemple.com/login)
2. Si tu veux activer le test de force brute, et si oui, le chemin vers tes dictionnaires d'identifiants et de mots de passe

Il déroule ensuite tous les tests et écrit le résultat dans `rapport_test.txt`.

## Le rapport

Pour chaque test, le rapport indique si une faille a été trouvée, le payload qui a fonctionné, et une recommandation pour corriger. Exemple d'une ligne de sortie :

```
[!] Vulnérabilité SQL Injection détectée avec le payload : ' OR '1'='1
    Exploitation : ce payload a permis de contourner l'authentification.
    Solution : utiliser des requêtes préparées et des paramètres.
```

## Limites et pistes d'amélioration

Cet outil fait des premières vérifications, il ne remplace pas un audit manuel. Quelques pistes sur lesquelles je compte le faire évoluer :
- Détection automatique des noms de champs du formulaire (aujourd'hui ils sont fixés à username / password)
- Gestion des sessions et des tokens CSRF avant envoi
- Sortie du rapport en HTML en plus du texte

## Avertissement

Outil destiné à un usage éducatif et à des tests autorisés uniquement. Ne l'utilise que sur des systèmes pour lesquels tu as une autorisation explicite. Je décline toute responsabilité en cas d'usage non autorisé.
