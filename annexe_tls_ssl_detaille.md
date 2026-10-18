# Annexe TLS / SSL - Guide technique approfondi

**Auteur :** hackers_tchad  
**Date :** 2026  

---

## A.1 Histoire détaillée de SSL et TLS

### A.1.1 Netscape et la naissance de SSL

En 1994, Netscape Communications Corporation cherche à sécuriser les transactions commerciales sur le web naissant. L'équipe dirigée par **Kipp Hickman**, **Alan Freier** et **Phil Karlton** conçoit SSL (Secure Sockets Layer). SSL 1.0 n'est jamais publié en raison de failles cryptographiques fondamentales, notamment une absence de protection contre les attaques de type "man-in-the-middle" sur le handshake.

SSL 2.0 sort en 1995 avec Netscape Navigator 1.1. Il introduit des concepts novateurs :
- Utilisation de certificats X.509.
- Chiffrement symétrique avec DES, 3DES, RC4.
- Hash MD5 pour l'intégrité.
- Handshake simplifié mais fragile.

Cependant, SSL 2.0 présente des faiblesses structurelles :
- Le même port pour le handshake et les données.
- Pas de protection contre le downgrade.
- MAC faible (MD5 mal utilisé).
- Clés de 40 bits exportables.

SSL 3.0 (1996) corrige plusieurs problèmes mais reste vulnérable au padding CBC. En 2014, l'attaque **POODLE** (CVE-2014-3566) démontre qu'un attaquant peut déchiffrer des données en forçant un downgrade vers SSL 3.0.

### A.1.2 Standardisation par l'IETF

L'IETF reprend le travail en 1996 et renomme le protocole **TLS (Transport Layer Security)** pour des raisons politiques et de neutralité commerciale. TLS 1.0 (RFC 2246, 1999) est très proche de SSL 3.0, mais corrige plusieurs failles.

**Principales versions :**
- TLS 1.0 (1999) : supporte RSA, DSS, DH, suites 3DES, RC4, IDEA.
- TLS 1.1 (2006) : protection contre les attaques sur les CBC, IV explicites.
- TLS 1.2 (2008) : introduction des suites AEAD (AES-GCM), HMAC-SHA256, signatures avec hash négociable.
- TLS 1.3 (2018) : refonte majeure, handshake 1-RTT, suppression des algorithmes obsolètes, forward secrecy par défaut.

### A.1.3 Acteurs clés

- **Netscape** : créateur initial de SSL.
- **IETF TLS Working Group** : standardisation et évolution.
- **Eric Rescorla** : auteur majeur de RFC TLS, notamment RFC 8446 (TLS 1.3).
- **OpenSSL Project** : implémentation de référence historique.
- **Let's Encrypt / ISRG** : démocratisation des certificats TLS gratuits.

---

## A.2 Mathématiques et cryptographie sous-jacentes

### A.2.1 Échange de clés

TLS utilise plusieurs mécanismes d'échange de clés :

**RSA key exchange (obsolète en TLS 1.3)** :
- Le client génère un pré-master secret.
- Il le chiffre avec la clé publique du serveur.
- Le serveur le déchiffre avec sa clé privée.
- Problème : pas de forward secrecy.

**Diffie-Hellman éphémère (DHE/ECDHE)** :
- Les deux parties génèrent des paires de clés éphémères.
- Échange des clés publiques.
- Calcul d'un secret partagé indépendamment des clés statiques.
- Avantage : forward secrecy.

### A.2.2 Forward Secrecy

La **forward secrecy** (ou perfect forward secrecy, PFS) garantit que la compromission future d'une clé privée ne permet pas de déchiffrer les sessions passées. Elle repose sur l'utilisation de clés éphémères DHE ou ECDHE.

### A.2.3 Courbes elliptiques

TLS 1.3 recommande les courbes suivantes :
- x25519 (Curve25519 de Daniel J. Bernstein)
- x448
- secp256r1 (P-256)
- secp384r1 (P-384)
- secp521r1 (P-521)

### A.2.4 Authentification des messages

En TLS 1.2, on utilise HMAC avec SHA-256 ou SHA-384. En TLS 1.3, les suites AEAD (Authenticated Encryption with Associated Data) combinent chiffrement et intégrité :
- AES-128-GCM
- AES-256-GCM
- AES-128-CCM
- ChaCha20-Poly1305

---

## A.3 Le handshake TLS 1.3 en profondeur

### A.3.1 Messages du handshake

1. **ClientHello** : versions supportées, suites, groupes de clés, key_share, extensions.
2. **ServerHello** : version choisie, suite choisie, key_share du serveur.
3. **EncryptedExtensions** : extensions protégées.
4. **CertificateRequest** : optionnel, pour mTLS.
5. **Certificate** : certificat serveur (et chaîne).
6. **CertificateVerify** : signature du handshake par le serveur.
7. **Finished** : MAC du handshake.
8. **Finished** client.

### A.3.2 0-RTT

TLS 1.3 permet un handshake **0-RTT** en réutilisant des paramètres d'une session précédente. Cependant, il expose aux attaques par répétition (replay attacks). Il doit être utilisé avec précaution, notamment pour des requêtes idempotentes.

### A.3.3 HelloRetryRequest

Si le client ne propose pas de key_share compatible, le serveur peut envoyer un **HelloRetryRequest** pour demander un groupe spécifique. Cela ajoute un aller-retour supplémentaire.

---

## A.4 Certificats X.509

### A.4.1 Structure d'un certificat

Un certificat X.509 contient :
- Version
- Numéro de série
- Algorithme de signature
- Émetteur (Issuer)
- Validité (notBefore, notAfter)
- Sujet (Subject)
- Clé publique du sujet
- Extensions (SAN, Key Usage, EKU, CRL Distribution Points, AIA)
- Signature de l'AC

### A.4.2 Types de certificats

- **DV (Domain Validated)** : validation du domaine uniquement.
- **OV (Organization Validated)** : validation de l'organisation.
- **EV (Extended Validation)** : validation renforcée, nom de l'organisation dans la barre d'adresse (moins visible aujourd'hui).
- **Wildcard** : couvre *.example.com.
- **SAN (Subject Alternative Name)** : couvre plusieurs noms de domaine.

### A.4.3 Chaîne de confiance

La confiance s'établit via une chaîne de certificats :
```
Certificat feuille (exemple.com) -> signé par AC intermédiaire -> signé par AC racine
```

Les AC racines sont préinstallées dans les systèmes d'exploitation et les navigateurs.

### A.4.4 Génération de certificats avec OpenSSL

```bash
# Générer une clé privée
openssl genrsa -out server.key 4096

# Créer une CSR
openssl req -new -key server.key -out server.csr -sha256 \
  -subj "/C=FR/O=Mon Entreprise/CN=example.com"

# Générer un certificat auto-signé
openssl req -x509 -nodes -days 365 -key server.key -out server.crt

# Vérifier une CSR
openssl req -in server.csr -text -noout

# Vérifier un certificat
openssl x509 -in server.crt -text -noout
```

### A.4.5 Let's Encrypt et ACME

**ACME (Automatic Certificate Management Environment)** est le protocole utilisé par Let's Encrypt pour automatiser l'émission et le renouvellement de certificats.

Outils clients :
- Certbot
- acme.sh
- lego
- dehydrated

Exemple avec Certbot :
```bash
sudo certbot --nginx -d example.com -d www.example.com
sudo certbot renew --dry-run
```

---

## A.5 Attaques sur TLS/SSL et mitigations

### A.5.1 POODLE (CVE-2014-3566)

Exploite le padding CBC de SSL 3.0. Un attaquant peut déchiffrer un octet de données par requête.
- **Mitigation** : désactiver SSL 3.0.

### A.5.2 BEAST (CVE-2011-3389)

Attaque sur TLS 1.0 en mode CBC.
- **Mitigation** : passer à TLS 1.1+.

### A.5.3 CRIME et BREACH

Attaques sur la compression.
- **Mitigation** : désactiver la compression TLS et HTTP.

### A.5.4 Heartbleed (CVE-2014-0160)

Faille dans OpenSSL permettant de lire la mémoire du serveur.
- **Mitigation** : mettre à jour OpenSSL, révoquer et renouveler les certificats.

### A.5.5 Logjam et FREAK

Downgrade vers des export ciphers faibles.
- **Mitigation** : désactiver les suites export et DHE avec groupes faibles.

### A.5.6 SWEET32

Attaque sur 3DES avec de gros volumes de données.
- **Mitigation** : désactiver 3DES.

### A.5.7 ROBOT

Attaque sur le key exchange RSA.
- **Mitigation** : utiliser ECDHE/DHE, ne pas utiliser RSA key exchange.

### A.5.8 Racine de confiance compromise

Si une AC racine est compromise, toute la chaîne de confiance s'effondre.
- **Mitigation** : certificate pinning (obsolète), CT logs (Certificate Transparency), monitoring.

---

## A.6 Configuration avancée TLS

### A.6.1 mTLS (Mutual TLS)

Le mTLS authentifie à la fois le client et le serveur via des certificats.

**Nginx :**
```nginx
server {
    listen 443 ssl;
    server_name api.example.com;

    ssl_certificate     /etc/nginx/ssl/server.crt;
    ssl_certificate_key /etc/nginx/ssl/server.key;
    ssl_client_certificate /etc/nginx/ssl/ca.crt;
    ssl_verify_client on;

    location / {
        proxy_pass http://backend;
    }
}
```

**Apache :**
```apache
SSLVerifyClient require
SSLVerifyDepth 2
SSLCACertificateFile /etc/apache2/ssl/ca.crt
SSLOptions +StdEnvVars
```

### A.6.2 OCSP Stapling

OCSP Stapling permet au serveur de fournir une preuve de validité du certificat sans que le client ne contacte l'OCSP responder.

```nginx
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /etc/nginx/ssl/chain.crt;
resolver 8.8.8.8 1.1.1.1 valid=300s;
```

### A.6.3 HSTS (HTTP Strict Transport Security)

```nginx
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```

### A.6.4 TLS dans les conteneurs et Kubernetes

- Terminaison TLS au niveau de l'ingress controller (Nginx, Traefik, HAProxy).
- Cert-manager pour Let's Encrypt.
- Service mesh (Istio, Linkerd) pour le mTLS automatique.

### A.6.5 TLS pour IoT

Contraintes : CPU limité, mémoire faible, bande passante réduite.
Solutions :
- mbed TLS, wolfSSL.
- ECDSA pour des signatures plus légères.
- PSK (Pre-Shared Key) en TLS 1.3.
- Session resumption.

---

## A.7 Outils de test et de monitoring

### A.7.1 testssl.sh

```bash
testssl.sh --full https://example.com
testssl.sh -- vulnerabilities https://example.com
testssl.sh --starttls smtp mail.example.com:25
```

### A.7.2 SSL Labs

Site web : https://www.ssllabs.com/ssltest/

### A.7.3 Qualys SSL/TLS Deployment Best Practices

Guide de référence pour la configuration sécurisée de TLS.

### A.7.4 Nmap

```bash
nmap --script ssl-enum-ciphers -p 443 example.com
nmap --script ssl-heartbleed -p 443 example.com
nmap --script ssl-poodle -p 443 example.com
```

### A.7.5 Wireshark

Filtrer le trafic TLS :
```
tls.handshake.type == 1
tls.record.content_type == 23
tls.alert_message.level == 2
```

### A.7.6 OpenSSL

```bash
# Vérifier tous les protocoles
for v in ssl2 ssl3 tls1 tls1_1 tls1_2 tls1_3; do
  echo "Testing $v"
  openssl s_client -connect example.com:443 -$v </dev/null 2>&1 | grep -i "handshake\|protocol"
done
```

---

## A.8 SSL/TLS dans les protocoles applicatifs

### A.8.1 HTTPS

HTTPS = HTTP sur TLS. Port par défaut : 443.

### A.8.2 SMTPS / IMAPS / POP3S

- SMTPS : port 465 (soumission), STARTTLS sur 587.
- IMAPS : port 993.
- POP3S : port 995.

### A.8.3 FTPS

FTPS = FTP sur TLS. Ports 990 (contrôle), 989 (données).

### A.8.4 LDAPS

LDAPS = LDAP sur TLS. Port 636.

### A.8.5 DNS over TLS (DoT)

Port 853. Utilise TLS pour chiffrer les requêtes DNS.

### A.8.6 DNS over HTTPS (DoH)

Encapsule DNS dans HTTPS. Port 443. Utilisé par Firefox, Chrome, Cloudflare.

---

## A.9 Bonnes pratiques de gestion des certificats

1. Inventorier tous les certificats.
2. Utiliser un PKI interne pour les certificats non publics.
3. Automatiser le renouvellement.
4. Surveiller les dates d'expiration.
5. Utiliser des clés RSA 2048 bits minimum (4096 recommandé) ou ECDSA P-256.
6. Protéger les clés privées (HSM, TPM, vault).
7. Journaliser les émissions et révocations.
8. Mettre en place Certificate Transparency monitoring.

---

## A.10 Résumé des commandes essentielles TLS/SSL

```bash
# Connexion et informations
openssl s_client -connect example.com:443 -servername example.com </dev/null

# Détails du certificat
openssl s_client -connect example.com:443 2>/dev/null | openssl x509 -noout -text

# Dates de validité
openssl s_client -connect example.com:443 2>/dev/null | openssl x509 -noout -dates

# Empreinte
openssl s_client -connect example.com:443 2>/dev/null | openssl x509 -noout -fingerprint

# Test TLS 1.3
openssl s_client -connect example.com:443 -tls1_3

# Test STARTTLS SMTP
openssl s_client -starttls smtp -connect mail.example.com:587

# Génération CSR
openssl req -new -newkey rsa:4096 -nodes -keyout server.key -out server.csr

# Vérifier une chaîne
openssl verify -CAfile ca-bundle.crt -untrusted intermediate.crt server.crt
```

---

**Fin de l'annexe TLS/SSL.**
