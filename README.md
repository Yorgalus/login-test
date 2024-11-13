Testeur de Vulnérabilités Web
Ce script Python est conçu pour analyser une URL spécifique et identifier diverses vulnérabilités de sécurité dans les applications web. Il peut détecter et exploiter des failles comme les injections SQL, les vulnérabilités XSS, les failles CSRF, et bien plus encore, en produisant un rapport détaillé des résultats.

Fonctionnalités
Test de force brute pour les mots de passe et noms d'utilisateur (en utilisant des dictionnaires).
Injection SQL : Teste si l'application est vulnérable aux injections SQL.
XSS (Cross-Site Scripting) : Vérifie les failles XSS qui permettent l'injection de scripts malveillants.
CSRF (Cross-Site Request Forgery) : Identifie les failles CSRF et les vérifications de tokens.
Injection de commande : Détecte les failles d'exécution de commandes système.
Inclusion de fichiers (LFI/RFI) : Recherche les failles d'inclusion de fichiers locaux ou distants.
SSRF (Server-Side Request Forgery) : Vérifie si l'application peut faire des requêtes vers des ressources internes.
Analyse des en-têtes HTTP : Vérifie si les en-têtes de sécurité recommandés sont manquants.
Détection de données sensibles dans le code source : Recherche des mots-clés sensibles (mot de passe, clé API, etc.).
Détection de l'obfuscation JavaScript : Analyse les scripts pour détecter d’éventuelles obfuscations.


Installation
Assurez-vous que Python 3.x est installé. Installez également les dépendances requises en exécutant :

bash
Copier le code
pip install -r requirements.txt
Utilisation
Exécutez le script en utilisant la commande suivante :

bash
Copier le code
python nom_du_script.py
Entrez l'URL de la page de connexion à tester lorsque le script vous le demande (ex : http://exemple.com/login).

Choisissez d'activer ou non le test de force brute pour les mots de passe et noms d'utilisateur. Si activé, fournissez les chemins vers les fichiers dictionnaires.

Le script va alors exécuter une série de tests sur l'URL spécifiée et enregistrera les résultats dans un rapport.

Exemples
Voici un exemple de commande pour exécuter le script :

bash
Copier le code
python nom_du_script.py
Ensuite, répondez aux invites en fournissant l'URL cible et le choix pour le test de force brute.

Structure du Projet
main.py : Script principal contenant les fonctions de détection et d'exploitation.
requirements.txt : Liste des bibliothèques nécessaires au script.
Rapport
Les résultats de l'analyse sont sauvegardés dans un fichier rapport, détaillant chaque vulnérabilité détectée, le payload utilisé pour l'exploiter, et des recommandations de correction.

Avertissements
Usage légal uniquement : Utilisez ce script uniquement sur des applications que vous avez le droit de tester.
Responsabilité : L'auteur de ce script décline toute responsabilité en cas d'utilisation inappropriée ou illégale de ce script.
