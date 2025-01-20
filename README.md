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
Assurez-vous que Python 3.x est installé.
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




Web Vulnerability Tester
This Python script is designed to analyze a specific URL and identify various security vulnerabilities in web applications. It can detect and exploit issues such as SQL injections, XSS vulnerabilities, CSRF flaws, and more, generating a detailed report of the findings.

Features
Brute-force testing: Tests passwords and usernames using dictionaries.
SQL Injection: Checks if the application is vulnerable to SQL injection.
XSS (Cross-Site Scripting): Identifies XSS vulnerabilities that allow malicious script injection.
CSRF (Cross-Site Request Forgery): Detects CSRF vulnerabilities and verifies token implementations.
Command Injection: Finds system command execution vulnerabilities.
File Inclusion (LFI/RFI): Scans for local or remote file inclusion flaws.
SSRF (Server-Side Request Forgery): Checks if the application can make requests to internal resources.
HTTP Header Analysis: Verifies if recommended security headers are missing.
Sensitive Data Detection in Source Code: Searches for sensitive keywords (e.g., passwords, API keys).
JavaScript Obfuscation Detection: Analyzes scripts to identify potential obfuscations.
Installation
Ensure Python 3.x is installed.
Run the script using the following command:
bash
Copier le code
python script_name.py
Enter the URL of the login page to be tested when prompted (e.g., http://example.com/login).
Choose whether to enable brute-force testing for usernames and passwords. If enabled, provide the paths to the dictionary files.
The script will then perform a series of tests on the specified URL and save the results in a report.

Examples
Here’s an example command to execute the script:

bash
Copier le code
python script_name.py
Then, respond to the prompts by providing the target URL and brute-force testing preference.

Project Structure
main.py: The main script containing detection and exploitation functions.
requirements.txt: A list of libraries required by the script.
Report
The analysis results are saved in a report file detailing:

Each vulnerability detected.
The payload used to exploit it.
Recommendations for remediation.
Warnings
Legal Use Only: Use this script only on applications you have permission to test.
Disclaimer: The author of this script is not responsible for any inappropriate or illegal use of the tool.
