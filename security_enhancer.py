#!/usr/bin/env python3
"""
Script de sécurité avancé pour protéger les sites web
- Protection contre les injections XSS
- Obfuscation du JavaScript
- Protection contre le copier-coller
- Vérification d'intégrité des fichiers
- Gestion des clés de sécurité
"""

import os
import re
import json
import base64
import hashlib
import secrets
import argparse
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import mimetypes

class SecurityEnhancer:
    def __init__(self, config_file: str = "security_config.json"):
        """
        Initialise l'outil de sécurité
        
        Args:
            config_file: Fichier de configuration JSON
        """
        self.config_file = config_file
        self.config = self.load_config()
        self.secure_hashes = {}
        
    def load_config(self) -> Dict:
        """Charge ou crée la configuration"""
        default_config = {
            "security": {
                "xss_protection": True,
                "js_obfuscation": True,
                "anti_copy": True,
                "integrity_checks": True,
                "session_timeout": 30,
                "password_min_length": 12,
                "enable_csp": True,
                "enable_hsts": True,
                "key_rotation_days": 30
            },
            "csp_policies": {
                "default-src": "'self'",
                "script-src": "'self' 'unsafe-inline'",
                "style-src": "'self' 'unsafe-inline'",
                "img-src": "'self' data:",
                "connect-src": "'self'",
                "font-src": "'self'",
                "object-src": "'none'",
                "media-src": "'self'",
                "frame-src": "'none'",
                "base-uri": "'self'"
            },
            "keys": {
                "current_key": None,
                "previous_key": None,
                "key_history": [],
                "last_rotation": None
            }
        }
        
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                # Fusion avec la config par défaut
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
                return config
        except FileNotFoundError:
            return default_config
    
    def save_config(self):
        """Sauvegarde la configuration"""
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=4)
    
    def generate_secure_key(self, length: int = 64) -> str:
        """
        Génère une clé cryptographiquement sécurisée
        
        Args:
            length: Longueur de la clé en caractères
        Returns:
            Clé sécurisée
        """
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?"
        key = ''.join(secrets.choice(alphabet) for _ in range(length))
        return key
    
    def rotate_keys(self):
        """Effectue une rotation des clés de sécurité"""
        current_time = datetime.now().isoformat()
        
        # Sauvegarde l'ancienne clé
        if self.config["keys"]["current_key"]:
            self.config["keys"]["previous_key"] = self.config["keys"]["current_key"]
            self.config["keys"]["key_history"].append({
                "key": self.config["keys"]["current_key"],
                "valid_until": current_time
            })
            # Garde seulement les 10 dernières clés
            if len(self.config["keys"]["key_history"]) > 10:
                self.config["keys"]["key_history"] = self.config["keys"]["key_history"][-10:]
        
        # Génère une nouvelle clé
        self.config["keys"]["current_key"] = self.generate_secure_key()
        self.config["keys"]["last_rotation"] = current_time
        
        self.save_config()
        print(f"[✓] Rotation des clés effectuée à {current_time}")
        return self.config["keys"]["current_key"]
    
    def hash_content(self, content: str) -> str:
        """
        Calcule le hash du contenu pour vérification d'intégrité
        
        Args:
            content: Contenu à hasher
        Returns:
            Hash SHA-256
        """
        return hashlib.sha256(content.encode()).hexdigest()
    
    def sanitize_input(self, input_string: str) -> str:
        """
        Nettoie les entrées utilisateur contre les injections XSS
        
        Args:
            input_string: Chaîne à nettoyer
        Returns:
            Chaîne nettoyée
        """
        # Liste des motifs dangereux
        dangerous_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'on\w+\s*=',
            r'expression\s*\(',
            r'vbscript:',
            r'data:',
            r'<\?php',
            r'<\/?\w+[^>]*>',
            r'--\s*[\w\s]+\s*--',
            r'union\s+select',
            r'select\s+.*\s+from',
            r'insert\s+into',
            r'update\s+.*\s+set',
            r'delete\s+from',
            r'drop\s+table',
            r'exec\s*\(',
            r'xss',
            r'alert\s*\(',
            r'prompt\s*\(',
            r'confirm\s*\(',
            r'document\.cookie',
            r'window\.location',
            r'eval\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\(',
            r'Function\s*\(',
            r'new\s+Function'
        ]
        
        sanitized = input_string
        
        # Supprime les motifs dangereux
        for pattern in dangerous_patterns:
            sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE | re.DOTALL)
        
        # Échappe les caractères HTML spéciaux
        html_escape_table = {
            "&": "&amp;",
            '"': "&quot;",
            "'": "&#x27;",
            ">": "&gt;",
            "<": "&lt;",
            "/": "&#x2F;",
            "\\": "&#x5C;",
            "`": "&#x60;",
            "=": "&#x3D;"
        }
        
        for char, escape in html_escape_table.items():
            sanitized = sanitized.replace(char, escape)
        
        # Limite la longueur (protection contre les attaques par déni de service)
        max_length = 10000
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        return sanitized
    
    def obfuscate_js(self, js_code: str) -> str:
        """
        Obfusque le code JavaScript pour le protéger
        
        Args:
            js_code: Code JavaScript à obfusquer
        Returns:
            Code JavaScript obfusqué
        """
        # Table de mappage des variables
        var_mapping = {}
        counter = 0
        
        # Trouve toutes les variables et fonctions
        patterns = [
            r'var\s+(\w+)\s*=',
            r'let\s+(\w+)\s*=',
            r'const\s+(\w+)\s*=',
            r'function\s+(\w+)\s*\(',
            r'(\w+)\s*:\s*function'
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, js_code)
            for match in matches:
                var_name = match.group(1)
                if var_name not in var_mapping and len(var_name) > 2:
                    var_mapping[var_name] = f"_{counter}"
                    counter += 1
        
        # Remplace les noms de variables
        obfuscated = js_code
        for original, new_name in var_mapping.items():
            obfuscated = re.sub(r'\b' + original + r'\b', new_name, obfuscated)
        
        # Ajoute un wrapper de protection
        protection_wrapper = f"""
// Protection contre la copie - © {datetime.now().year}
(function() {{
    var _0 = function() {{
        {obfuscated}
    }};
    
    // Vérification d'intégrité
    var _1 = '{self.hash_content(js_code)}';
    
    // Anti-debug
    var _2 = new Date();
    var _3 = function() {{
        var _4 = new Date();
        if (_4 - _2 > 5000) {{
            console.error('Debugging detected');
            return false;
        }}
        return true;
    }};
    
    // Anti-copie
    document.addEventListener('copy', function(e) {{
        e.preventDefault();
        console.warn('Copying is disabled for security reasons');
        return false;
    }});
    
    document.addEventListener('contextmenu', function(e) {{
        e.preventDefault();
        return false;
    }});
    
    // Protection contre l'inspection
    Object.defineProperty(window, '_0', {{
        configurable: false,
        writable: false,
        enumerable: false
    }});
    
    // Exécution sécurisée
    try {{
        if (_3()) {{
            _0();
        }}
    }} catch (_5) {{
        console.error('Security violation detected');
        window.location.href = '/security-error.html';
    }}
}})();
"""
        
        return protection_wrapper
    
    def generate_csp_header(self) -> str:
        """
        Génère l'en-tête Content Security Policy
        
        Returns:
            Chaîne CSP
        """
        policies = self.config["csp_policies"]
        csp_parts = []
        
        for directive, sources in policies.items():
            if isinstance(sources, list):
                sources_str = ' '.join(sources)
            else:
                sources_str = sources
            csp_parts.append(f"{directive} {sources_str}")
        
        return '; '.join(csp_parts)
    
    def generate_security_headers(self) -> Dict[str, str]:
        """
        Génère les en-têtes de sécurité HTTP
        
        Returns:
            Dictionnaire d'en-têtes
        """
        headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
        }
        
        if self.config["security"]["enable_csp"]:
            headers["Content-Security-Policy"] = self.generate_csp_header()
        
        if self.config["security"]["enable_hsts"]:
            headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        return headers
    
    def validate_password_strength(self, password: str) -> Tuple[bool, List[str]]:
        """
        Valide la force d'un mot de passe
        
        Args:
            password: Mot de passe à valider
        Returns:
            Tuple (est_valide, messages)
        """
        messages = []
        min_length = self.config["security"]["password_min_length"]
        
        if len(password) < min_length:
            messages.append(f"Le mot de passe doit contenir au moins {min_length} caractères")
        
        if not re.search(r'[A-Z]', password):
            messages.append("Le mot de passe doit contenir au moins une majuscule")
        
        if not re.search(r'[a-z]', password):
            messages.append("Le mot de passe doit contenir au moins une minuscule")
        
        if not re.search(r'\d', password):
            messages.append("Le mot de passe doit contenir au moins un chiffre")
        
        if not re.search(r'[!@#$%^&*()\-_=+\[\]{}|;:,.<>?]', password):
            messages.append("Le mot de passe doit contenir au moins un caractère spécial")
        
        if re.search(r'(.)\1{2,}', password):
            messages.append("Le mot de passe ne doit pas contenir de caractères répétés 3 fois ou plus")
        
        if re.search(r'(012|123|234|345|456|567|678|789|890)', password):
            messages.append("Le mot de passe ne doit pas contenir de séquences de chiffres simples")
        
        common_passwords = ["password", "123456", "qwerty", "admin", "welcome"]
        if password.lower() in common_passwords:
            messages.append("Le mot de passe est trop commun")
        
        is_valid = len(messages) == 0
        return is_valid, messages
    
    def create_secure_login_script(self, output_file: str = "secure_login.js"):
        """
        Crée un script de connexion sécurisé
        
        Args:
            output_file: Fichier de sortie
        """
        secure_js = """
// Script de connexion sécurisé
(function() {
    'use strict';
    
    // Configuration de sécurité
    const SECURITY = {
        maxAttempts: 3,
        lockTime: 300000, // 5 minutes en millisecondes
        sessionDuration: 1800000, // 30 minutes
        enableRateLimit: true,
        enableIPCheck: true
    };
    
    // Stockage sécurisé des tentatives
    let loginAttempts = JSON.parse(localStorage.getItem('login_attempts') || '{}');
    let failedAttempts = 0;
    
    // Fonction de validation d'email
    function validateEmail(email) {
        const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        return emailRegex.test(email) && !email.includes('<script') && !email.includes('javascript:');
    }
    
    // Fonction de validation de mot de passe
    function validatePassword(password) {
        if (password.length < 12) return false;
        if (!/[A-Z]/.test(password)) return false;
        if (!/[a-z]/.test(password)) return false;
        if (!/\d/.test(password)) return false;
        if (!/[!@#$%^&*()\-_=+[\]{}|;:,.<>?]/.test(password)) return false;
        return true;
    }
    
    // Vérification de l'IP (simplifiée)
    function checkIP() {
        return new Promise((resolve) => {
            if (!SECURITY.enableIPCheck) {
                resolve(true);
                return;
            }
            
            // En production, utilisez un service d'IP vérification
            fetch('https://api.ipify.org?format=json')
                .then(response => response.json())
                .then(data => {
                    const suspiciousIPs = ['127.0.0.1', '0.0.0.0']; // À compléter
                    resolve(!suspiciousIPs.includes(data.ip));
                })
                .catch(() => resolve(true));
        });
    }
    
    // Limite de taux
    function checkRateLimit(email) {
        if (!SECURITY.enableRateLimit) return true;
        
        const now = Date.now();
        const attempts = loginAttempts[email] || [];
        
        // Nettoie les tentatives anciennes
        const recentAttempts = attempts.filter(time => now - time < 3600000); // 1 heure
        
        if (recentAttempts.length >= SECURITY.maxAttempts) {
            const oldestAttempt = Math.min(...recentAttempts);
            if (now - oldestAttempt < SECURITY.lockTime) {
                return false;
            }
        }
        
        return true;
    }
    
    // Connexion sécurisée
    async function secureLogin(email, password, securityKey) {
        try {
            // Vérifications de base
            if (!validateEmail(email)) {
                throw new Error('Email invalide');
            }
            
            if (!validatePassword(password)) {
                throw new Error('Mot de passe invalide');
            }
            
            // Vérification de l'IP
            const ipValid = await checkIP();
            if (!ipValid) {
                throw new Error('Connexion bloquée pour des raisons de sécurité');
            }
            
            // Vérification de la limite de taux
            if (!checkRateLimit(email)) {
                throw new Error('Trop de tentatives. Veuillez réessayer dans 5 minutes');
            }
            
            // Enregistrement de la tentative
            loginAttempts[email] = loginAttempts[email] || [];
            loginAttempts[email].push(Date.now());
            localStorage.setItem('login_attempts', JSON.stringify(loginAttempts));
            
            // En production, remplacez par votre logique d'authentification
            const isValid = await authenticate(email, password, securityKey);
            
            if (isValid) {
                // Création de session sécurisée
                const sessionToken = generateSessionToken();
                const sessionData = {
                    email: email,
                    token: sessionToken,
                    expires: Date.now() + SECURITY.sessionDuration,
                    ip: await getIP()
                };
                
                localStorage.setItem('admin_session', JSON.stringify(sessionData));
                sessionStorage.setItem('last_activity', Date.now());
                
                // Réinitialisation des tentatives
                delete loginAttempts[email];
                localStorage.setItem('login_attempts', JSON.stringify(loginAttempts));
                
                return { success: true, token: sessionToken };
            } else {
                failedAttempts++;
                if (failedAttempts >= SECURITY.maxAttempts) {
                    setTimeout(() => {
                        failedAttempts = 0;
                    }, SECURITY.lockTime);
                }
                throw new Error('Identifiants incorrects');
            }
        } catch (error) {
            console.error('Erreur de connexion:', error.message);
            return { success: false, error: error.message };
        }
    }
    
    // Fonctions auxiliaires
    async function authenticate(email, password, securityKey) {
        // Ici, vous devriez implémenter votre propre logique d'authentification
        // Par exemple, une requête à votre API backend
        return new Promise((resolve) => {
            // Simulation - À remplacer par votre logique
            setTimeout(() => {
                // En production, vérifiez contre votre base de données
                resolve(email === 'admin@example.com' && 
                       password === 'YourStrongPassword123!' && 
                       securityKey === 'YourSecurityKey456@');
            }, 1000);
        });
    }
    
    function generateSessionToken() {
        const array = new Uint8Array(32);
        window.crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }
    
    async function getIP() {
        try {
            const response = await fetch('https://api.ipify.org?format=json');
            const data = await response.json();
            return data.ip;
        } catch {
            return 'unknown';
        }
    }
    
    // Protection contre les attaques
    function installProtections() {
        // Anti-injection
        document.addEventListener('input', function(e) {
            if (e.target.type === 'email' || e.target.type === 'password' || e.target.type === 'text') {
                e.target.value = e.target.value.replace(/[<>"'`]/g, '');
            }
        });
        
        // Anti-copie
        document.addEventListener('copy', function(e) {
            if (window.getSelection().toString().includes('securityKey') || 
                window.getSelection().toString().includes('password')) {
                e.preventDefault();
                alert('La copie des informations sensibles est désactivée');
            }
        });
        
        // Anti-inspection
        Object.defineProperty(window, 'secureLogin', {
            configurable: false,
            writable: false,
            enumerable: false
        });
        
        // Détection de DevTools
        setInterval(function() {
            const start = performance.now();
            debugger;
            const end = performance.now();
            if (end - start > 100) {
                console.warn('DevTools détecté');
                document.body.innerHTML = '<h1>Accès non autorisé</h1>';
            }
        }, 1000);
    }
    
    // Initialisation
    window.addEventListener('DOMContentLoaded', function() {
        installProtections();
        
        // Configuration du formulaire de connexion
        const loginForm = document.getElementById('loginForm');
        if (loginForm) {
            loginForm.addEventListener('submit', async function(e) {
                e.preventDefault();
                
                const email = document.getElementById('email').value;
                const password = document.getElementById('password').value;
                const securityKey = document.getElementById('securityKey').value;
                
                const result = await secureLogin(email, password, securityKey);
                
                if (result.success) {
                    window.location.href = '/admin/dashboard.html';
                } else {
                    document.getElementById('errorMessage').textContent = result.error;
                    document.getElementById('errorMessage').style.display = 'block';
                }
            });
        }
    });
    
    // Export des fonctions
    window.SecureAuth = {
        login: secureLogin,
        validateEmail: validateEmail,
        validatePassword: validatePassword
    };
})();
"""
        
        # Obfusque le code si configuré
        if self.config["security"]["js_obfuscation"]:
            secure_js = self.obfuscate_js(secure_js)
        
        with open(output_file, 'w') as f:
            f.write(secure_js)
        
        print(f"[✓] Script de connexion sécurisé créé: {output_file}")
    
    def scan_directory(self, directory: str, output_report: str = "security_report.html"):
        """
        Analyse un répertoire pour détecter les vulnérabilités
        
        Args:
            directory: Répertoire à analyser
            output_report: Fichier de rapport
        """
        vulnerabilities = []
        file_stats = {}
        
        # Extensions à scanner
        scan_extensions = ['.html', '.js', '.php', '.py', '.json']
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                filepath = os.path.join(root, file)
                ext = os.path.splitext(file)[1].lower()
                
                if ext in scan_extensions:
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            content = f.read()
                        
                        issues = self.scan_file_content(content, filepath)
                        if issues:
                            vulnerabilities.extend(issues)
                        
                        file_stats[filepath] = {
                            'size': len(content),
                            'lines': content.count('\n') + 1,
                            'issues': len(issues)
                        }
                        
                    except Exception as e:
                        print(f"[!] Erreur lors de l'analyse de {filepath}: {e}")
        
        # Génère le rapport
        self.generate_security_report(vulnerabilities, file_stats, output_report)
        
        print(f"[✓] Analyse terminée. {len(vulnerabilities)} vulnérabilités trouvées.")
        print(f"[✓] Rapport généré: {output_report}")
    
    def scan_file_content(self, content: str, filepath: str) -> List[Dict]:
        """
        Analyse le contenu d'un fichier pour détecter les vulnérabilités
        
        Args:
            content: Contenu du fichier
            filepath: Chemin du fichier
        Returns:
            Liste des vulnérabilités détectées
        """
        issues = []
        
        # Patterns de vulnérabilités
        vulnerability_patterns = [
            {
                'name': 'XSS Injection',
                'patterns': [
                    r'innerHTML\s*=',
                    r'\.html\(',
                    r'document\.write\(',
                    r'eval\s*\(',
                    r'setTimeout\s*\([^)]*\)',
                    r'setInterval\s*\([^)]*\)'
                ],
                'severity': 'HIGH'
            },
            {
                'name': 'SQL Injection',
                'patterns': [
                    r'SELECT.*FROM.*WHERE.*\$\{',
                    r'INSERT INTO.*VALUES.*\$\{',
                    r'UPDATE.*SET.*WHERE.*\$\{',
                    r'DELETE FROM.*WHERE.*\$\{'
                ],
                'severity': 'CRITICAL'
            },
            {
                'name': 'Hardcoded Credentials',
                'patterns': [
                    r'password\s*=\s*["\'][^"\']{4,}["\']',
                    r'api_key\s*=\s*["\'][^"\']{8,}["\']',
                    r'token\s*=\s*["\'][^"\']{8,}["\']',
                    r'secret\s*=\s*["\'][^"\']{8,}["\']'
                ],
                'severity': 'HIGH'
            },
            {
                'name': 'Weak Cryptography',
                'patterns': [
                    r'Math\.random\(',
                    r'md5\(',
                    r'sha1\(',
                    r'base64\.decode\('
                ],
                'severity': 'MEDIUM'
            }
        ]
        
        for vuln in vulnerability_patterns:
            for pattern in vuln['patterns']:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_no = content[:match.start()].count('\n') + 1
                    line_content = content.split('\n')[line_no - 1].strip()
                    
                    issues.append({
                        'file': filepath,
                        'line': line_no,
                        'vulnerability': vuln['name'],
                        'severity': vuln['severity'],
                        'pattern': match.group(),
                        'context': line_content[:100]
                    })
        
        return issues
    
    def generate_security_report(self, vulnerabilities: List[Dict], file_stats: Dict, output_file: str):
        """
        Génère un rapport de sécurité HTML
        
        Args:
            vulnerabilities: Liste des vulnérabilités
            file_stats: Statistiques des fichiers
            output_file: Fichier de sortie
        """
        # Trie par sévérité
        severity_order = {'CRITICAL': 1, 'HIGH': 2, 'MEDIUM': 3, 'LOW': 4}
        vulnerabilities.sort(key=lambda x: severity_order.get(x['severity'], 5))
        
        # Génère le HTML
        html_content = f"""
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport de Sécurité - {datetime.now().strftime('%d/%m/%Y %H:%M')}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
            color: #333;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 30px;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            text-align: center;
            border-left: 4px solid #667eea;
        }}
        
        .vulnerability-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        
        .vulnerability-table th {{
            background: #f8f9fa;
            padding: 12px;
            text-align: left;
            border-bottom: 2px solid #dee2e6;
        }}
        
        .vulnerability-table td {{
            padding: 12px;
            border-bottom: 1px solid #dee2e6;
        }}
        
        .severity-critical {{ color: #dc3545; font-weight: bold; }}
        .severity-high {{ color: #fd7e14; font-weight: bold; }}
        .severity-medium {{ color: #ffc107; font-weight: bold; }}
        .severity-low {{ color: #28a745; font-weight: bold; }}
        
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
        }}
        
        .badge-critical {{ background: #dc3545; color: white; }}
        .badge-high {{ background: #fd7e14; color: white; }}
        .badge-medium {{ background: #ffc107; color: black; }}
        .badge-low {{ background: #28a745; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Rapport de Sécurité</h1>
            <p>Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M')}</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <h3>{len(vulnerabilities)}</h3>
                <p>Vulnérabilités détectées</p>
            </div>
            <div class="stat-card">
                <h3>{len(file_stats)}</h3>
                <p>Fichiers analysés</p>
            </div>
            <div class="stat-card">
                <h3>{sum(1 for v in vulnerabilities if v['severity'] == 'CRITICAL')}</h3>
                <p>Vulnérabilités critiques</p>
            </div>
            <div class="stat-card">
                <h3>{sum(1 for v in vulnerabilities if v['severity'] == 'HIGH')}</h3>
                <p>Vulnérabilités importantes</p>
            </div>
        </div>
        
        <h2>Vulnérabilités détectées</h2>
        <table class="vulnerability-table">
            <thead>
                <tr>
                    <th>Fichier</th>
                    <th>Ligne</th>
                    <th>Type</th>
                    <th>Sévérité</th>
                    <th>Détails</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for vuln in vulnerabilities:
            severity_class = f"severity-{vuln['severity'].lower()}"
            badge_class = f"badge-{vuln['severity'].lower()}"
            
            html_content += f"""
                <tr>
                    <td>{vuln['file']}</td>
                    <td>{vuln['line']}</td>
                    <td>{vuln['vulnerability']}</td>
                    <td><span class="{badge_class} badge">{vuln['severity']}</span></td>
                    <td>{vuln['context']}</td>
                </tr>
"""
        
        html_content += """
            </tbody>
        </table>
        
        <h2 style="margin-top: 40px;">Recommandations</h2>
        <ul>
            <li>Implémenter une validation des entrées côté serveur</li>
            <li>Utiliser des requêtes préparées pour les bases de données</li>
            <li>Encoder les sorties HTML</li>
            <li>Mettre en œuvre des Content Security Policies</li>
            <li>Effectuer des tests de pénétration réguliers</li>
            <li>Maintenir les dépendances à jour</li>
        </ul>
        
        <div style="margin-top: 40px; padding: 20px; background: #f8f9fa; border-radius: 8px;">
            <p><strong>Note:</strong> Ce rapport est généré automatiquement. 
            Consultez un expert en sécurité pour une analyse approfondie.</p>
        </div>
    </div>
</body>
</html>
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

def main():
    """Fonction principale"""
    parser = argparse.ArgumentParser(description="Outil de sécurité avancé pour sites web")
    parser.add_argument('--scan', type=str, help="Analyse un répertoire pour vulnérabilités")
    parser.add_argument('--obfuscate', type=str, help="Obfusque un fichier JavaScript")
    parser.add_argument('--generate-login', action='store_true', help="Génère un script de connexion sécurisé")
    parser.add_argument('--rotate-keys', action='store_true', help="Effectue une rotation des clés de sécurité")
    parser.add_argument('--validate-password', type=str, help="Valide la force d'un mot de passe")
    parser.add_argument('--generate-headers', action='store_true', help="Génère les en-têtes de sécurité HTTP")
    
    args = parser.parse_args()
    security = SecurityEnhancer()
    
    if args.scan:
        security.scan_directory(args.scan)
    
    elif args.obfuscate:
        with open(args.obfuscate, 'r') as f:
            js_code = f.read()
        obfuscated = security.obfuscate_js(js_code)
        
        output_file = args.obfuscate.replace('.js', '_secured.js')
        with open(output_file, 'w') as f:
            f.write(obfuscated)
        print(f"[✓] JavaScript obfusqué sauvegardé dans: {output_file}")
    
    elif args.generate_login:
        security.create_secure_login_script()
    
    elif args.rotate_keys:
        new_key = security.rotate_keys()
        print(f"[✓] Nouvelle clé générée: {new_key}")
    
    elif args.validate_password:
        is_valid, messages = security.validate_password_strength(args.validate_password)
        if is_valid:
            print("[✓] Mot de passe valide et sécurisé")
        else:
            print("[!] Mot de passe invalide:")
            for msg in messages:
                print(f"  - {msg}")
    
    elif args.generate_headers:
        headers = security.generate_security_headers()
        print("[✓] En-têtes de sécurité HTTP:")
        for key, value in headers.items():
            print(f"{key}: {value}")
    
    else:
        print("""
=== Security Enhancer ===
Commandes disponibles:

1. Analyse de sécurité:
   python security_enhancer.py --scan ./mon-site

2. Obfuscation JavaScript:
   python security_enhancer.py --obfuscate script.js

3. Générer script de connexion:
   python security_enhancer.py --generate-login

4. Rotation des clés:
   python security_enhancer.py --rotate-keys

5. Valider mot de passe:
   python security_enhancer.py --validate-password "MonM0tDeP@sse!"

6. Générer en-têtes HTTP:
   python security_enhancer.py --generate-headers

Configuration: security_config.json
        """)

if __name__ == "__main__":
    main()