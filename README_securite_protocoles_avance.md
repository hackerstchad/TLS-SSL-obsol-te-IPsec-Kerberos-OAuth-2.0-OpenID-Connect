# Guide Avancé des Protocoles de Sécurité Réseau et d'Identité

**Auteur :** hackers_tchad  
**Date :** 2026  
**Version :** 1.0  
**Licence :** Usage éducatif et professionnel  

---

## Table des matières

1. [Introduction](#introduction)
2. [TLS - Transport Layer Security](#tls---transport-layer-security)
3. [SSL - Secure Sockets Layer (obsolète)](#ssl---secure-sockets-layer-obsolète)
4. [IPsec - Internet Protocol Security](#ipsec---internet-protocol-security)
5. [Kerberos](#kerberos)
6. [OAuth 2.0](#oauth-20)
7. [OpenID Connect](#openid-connect)
8. [Comparatif global](#comparatif-global)
9. [Architectures et topologies](#architectures-et-topologies)
10. [Commandes de vérification](#commandes-de-vérification)
11. [Applications et implémentations](#applications-et-implémentations)
12. [Ressources et bibliographie](#ressources-et-bibliographie)
13. [Fiches de synthèse](#fiches-de-synthèse)

---

## Introduction

Les protocoles de sécurité constituent le socle numérique de la confiance dans les échanges modernes. Que ce soit pour sécuriser une connexion web, authentifier un utilisateur, chiffrer un tunnel réseau ou fédérer des identités, chaque protocole répond à un besoin précis. Ce guide explore en profondeur **TLS**, **SSL** (obsolète), **IPsec**, **Kerberos**, **OAuth 2.0** et **OpenID Connect**, en couvrant définitions, architectures, configurations, commandes de vérification, cas d'usage, outils, ressources et bonnes pratiques.

> **Objectif pédagogique :** Fournir une référence complète de plus de 2000 lignes pour les administrateurs système, les développeurs, les architectes sécurité et les étudiants en cybersécurité.

---

## TL;DR - Résumé exécutif

| Protocole | Couche OSI | Fonction principale | Statut | Créateur principal |
|-----------|-----------|---------------------|--------|-------------------|
| SSL | 4-7 (transport/application) | Chiffrement des communications web | Obsolète | Netscape (1994) |
| TLS | 4-7 | Successeur de SSL, chiffrement transport | Actif, TLS 1.3 recommandé | IETF (RFC 5246, RFC 8446) |
| IPsec | 3 (réseau) | Chiffrement et authentification au niveau IP | Actif | IETF (RFC 4301 à 4309) |
| Kerberos | 5 (session) | Authentification centralisée par tickets | Actif | MIT / IETF (RFC 4120) |
| OAuth 2.0 | 7 (application) | Délégation d'autorisation | Actif | IETF (RFC 6749) |
| OpenID Connect | 7 | Authentification fédérée basée sur OAuth 2.0 | Actif | OpenID Foundation |

---

## 1. TLS - Transport Layer Security

### 1.1 Définition

**TLS (Transport Layer Security)** est un protocole cryptographique conçu pour assurer la sécurité des communications sur un réseau informatique. Il fournit trois services fondamentaux :

- **Confidentialité** : chiffrement symétrique des données échangées.
- **Intégrité** : authentification des messages via MAC (Message Authentication Code) ou AEAD.
- **Authentification** : vérification de l'identité du serveur (et optionnellement du client) via des certificats X.509.

TLS est utilisé massivement pour sécuriser HTTPS, SMTPS, IMAPS, FTPS, VPN TLS, WebSockets sécurisés, etc.

### 1.2 Historique et créateurs

- **1994** : SSL 1.0 développé en interne par Netscape.
- **1995** : SSL 2.0 publié avec de graves failles.
- **1996** : SSL 3.0 amélioré mais obsolète aujourd'hui (POODLE, 2014).
- **1999** : TLS 1.0 (RFC 2246) standardisé par l'IETF.
- **2006** : TLS 1.1 (RFC 4346) avec meilleure protection contre les attaques sur les CBC.
- **2008** : TLS 1.2 (RFC 5246), introduction de suites AES-GCM et SHA-256.
- **2018** : TLS 1.3 (RFC 8446), handshake rapide, suppression des algorithmes obsolètes, forward secrecy par défaut.

### 1.3 Architecture TLS

```
┌─────────────────────────────────────────────────────────────┐
│                    Application (HTTP, SMTP, etc.)           │
├─────────────────────────────────────────────────────────────┤
│                    TLS (Record Protocol + Handshake)         │
├─────────────────────────────────────────────────────────────┤
│                    Transport (TCP)                           │
├─────────────────────────────────────────────────────────────┤
│                    Internet (IP)                             │
└─────────────────────────────────────────────────────────────┘
```

TLS se compose de deux couches :
- **TLS Handshake Protocol** : négociation des paramètres de sécurité, authentification, échange de clés.
- **TLS Record Protocol** : fragmentation, compression (désactivée en TLS 1.3), chiffrement et intégrité.

### 1.4 Le handshake TLS 1.2

```
Client                              Serveur
  | ------- ClientHello ----------> |
  | <------ ServerHello ---------- |
  | <------ Certificate ---------- |
  | <------ ServerHelloDone ------ |
  | ------- ClientKeyExchange ---> |
  | ------- ChangeCipherSpec ----> |
  | ------- Finished ------------> |
  | <------ ChangeCipherSpec ----- |
  | <------ Finished ------------- |
  | <====== Données chiffrées ===> |
```

### 1.5 Le handshake TLS 1.3

TLS 1.3 réduit le handshake à un aller-retour (1-RTT), ou 0-RTT en cas de reprise de session. Les messages `ChangeCipherSpec`, `ServerHelloDone` et `ClientKeyExchange` disparaissent. Les suites obsolètes (MD5, SHA-1, RC4, DES, 3DES, RSA key exchange) sont supprimées.

### 1.6 Suites cryptographiques TLS 1.3

Les suites TLS 1.3 sont simplifiées :

```
TLS_AES_256_GCM_SHA384
TLS_CHACHA20_POLY1305_SHA256
TLS_AES_128_GCM_SHA256
TLS_AES_128_CCM_8_SHA256
TLS_AES_128_CCM_SHA256
```

### 1.7 Configuration TLS - Nginx

```nginx
server {
    listen 443 ssl http2;
    server_name example.com;

    ssl_certificate     /etc/nginx/ssl/example.com.crt;
    ssl_certificate_key /etc/nginx/ssl/example.com.key;

    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;
    ssl_stapling on;
    ssl_stapling_verify on;
    add_header Strict-Transport-Security "max-age=63072000" always;
}
```

### 1.8 Configuration TLS - Apache

```apache
<VirtualHost *:443>
    ServerName example.com
    SSLEngine on
    SSLCertificateFile      /etc/apache2/ssl/example.com.crt
    SSLCertificateKeyFile   /etc/apache2/ssl/example.com.key
    SSLCertificateChainFile /etc/apache2/ssl/intermediate.crt

    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
    SSLHonorCipherOrder on
    SSLCompression off
    SSLSessionTickets off
    Header always set Strict-Transport-Security "max-age=63072000"
</VirtualHost>
```

### 1.9 Configuration TLS - HAProxy

```haproxy
global
    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets

frontend https_front
    bind *:443 ssl crt /etc/haproxy/certs/example.com.pem alpn h2,http/1.1
    default_backend web_servers
```

### 1.10 Configuration TLS - IIS (Windows)

```powershell
# Activer TLS 1.2 et 1.3, désactiver SSL 2.0/3.0 et TLS 1.0/1.1
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force
New-ItemProperty -Path 'HKLM:\...\TLS 1.2\Server' -Name 'Enabled' -Value 1 -PropertyType DWORD
New-Item 'HKLM:\...\SSL 2.0\Server' -Force
New-ItemProperty -Path 'HKLM:\...\SSL 2.0\Server' -Name 'Enabled' -Value 0 -PropertyType DWORD
```

### 1.11 Où utiliser TLS

- Sites web (HTTPS)
- Messagerie (SMTPS, IMAPS, POP3S)
- Transfert de fichiers (FTPS, SFTP via SSH distinct)
- VPN (OpenVPN, AnyConnect)
- APIs REST/GraphQL sécurisées
- WebSockets sécurisés (wss://)
- IoT et M2M sécurisés
- DNS over TLS (DoT)

### 1.12 Vérification TLS avec OpenSSL

```bash
# Vérifier le certificat et la chaîne
openssl s_client -connect example.com:443 -servername example.com </dev/null

# Tester TLS 1.3 uniquement
openssl s_client -connect example.com:443 -tls1_3

# Afficher les suites supportées
openssl ciphers -v 'HIGH:!aNULL:!MD5'

# Vérifier l'expiration
openssl s_client -connect example.com:443 2>/dev/null | openssl x509 -noout -dates

# Test avec ssllabs.com ou testssl.sh
testssl.sh https://example.com
```

### 1.13 Bonnes pratiques TLS

- Désactiver SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1.
- Préférer TLS 1.3.
- Activer HSTS avec preload.
- Utiliser des certificats valides et renouvelés automatiquement (Let's Encrypt, ACME).
- Activer OCSP Stapling.
- Mettre en place la forward secrecy (ECDHE/DHE).
- Surveiller les logs et utiliser CSP, CSP Reporting.

---

## 2. SSL - Secure Sockets Layer (obsolète)

### 2.1 Définition

**SSL (Secure Sockets Layer)** est l'ancêtre de TLS. Il a été développé par Netscape pour sécuriser les communications sur Internet, principalement le web.

### 2.2 Historique

- **SSL 1.0** : jamais publié publiquement, failles fondamentales.
- **SSL 2.0** (1995) : RFC 6176, obsolète, vulnérable aux attaques de type downgrade.
- **SSL 3.0** (1996) : RFC 6101, obsolète depuis l'attaque POODLE (2014).

### 2.3 Pourquoi SSL est obsolète

SSL souffre de multiples vulnérabilités :
- **POODLE** (Padding Oracle On Downgraded Legacy Encryption) : exploitation du padding CBC.
- **BEAST** : attaque sur TLS 1.0/SSL 3.0 en mode CBC.
- **FREAK** et **Logjam** : downgrade vers des clés RSA faibles.
- Algorithmes obsolètes : MD5, SHA-1, RC4, DES, 3DES.

### 2.4 Migration SSL vers TLS

1. Inventorier tous les points d'écoute SSL/TLS.
2. Désactiver SSL 2.0/3.0 côté serveur et client.
3. Forcer TLS 1.2 minimum, TLS 1.3 recommandé.
4. Mettre à jour les bibliothèques (OpenSSL, GnuTLS, NSS).
5. Tester avec `testssl.sh`, SSL Labs, Nessus.
6. Surveiller les tentatives de downgrade.

### 2.5 Commandes de vérification SSL

```bash
# Vérifier si SSL 3.0 est activé
openssl s_client -connect example.com:443 -ssl3

# Vérifier si TLS 1.0 est activé
openssl s_client -connect example.com:443 -tls1

# Scanner avec nmap
nmap --script ssl-enum-ciphers -p 443 example.com

# Utiliser testssl.sh
testssl.sh --color 3 https://example.com
```

---

## 3. IPsec - Internet Protocol Security

### 3.1 Définition

**IPsec** est un ensemble de protocoles défini par l'IETF pour sécuriser les communications au niveau de la couche réseau (IP). Il permet de construire des VPN site-à-site, des VPN d'accès distant, et de sécuriser des flux réseau machine-à-machine.

### 3.2 Composants d'IPsec

- **AH (Authentication Header)** : authentification et intégrité, RFC 4302.
- **ESP (Encapsulating Security Payload)** : confidentialité, authentification, intégrité, RFC 4303.
- **IKE (Internet Key Exchange)** : négociation des associations de sécurité (SA), IKEv1 RFC 2409, IKEv2 RFC 7296.
- **SAD (Security Association Database)** et **SPD (Security Policy Database)**.

### 3.3 Modes IPsec

- **Transport** : chiffrement de la charge utile IP, les en-têtes IP restent intacts. Utilisé pour les communications hôte-à-hôte.
- **Tunnel** : encapsulation complète du paquet IP dans un nouveau paquet IP. Utilisé pour les VPN.

### 3.4 Architecture IPsec

```
┌──────────────────────────────────────────────────────────────┐
│  Application | Transport | IPsec (AH/ESP) | IP | Liaison     │
└──────────────────────────────────────────────────────────────┘

Site A (192.168.1.0/24)          Internet           Site B (192.168.2.0/24)
        |                                                        |
   [Passerelle IPsec]  <=========== Tunnel IPsec =========>  [Passerelle IPsec]
```

### 3.5 IKEv2 vs IKEv1

| Caractéristique | IKEv1 | IKEv2 |
|-----------------|-------|-------|
| Échanges | 6-9 messages | 4 messages (initiaux) |
| NAT-T | Optionnel, complexe | Intégré |
| Mobilité | Limitée | MOBIKE (RFC 4555) |
| EAP | Non natif | Support EAP natif |
| Résilience | Fragile | DPD et reconnexion intégrés |

### 3.6 Configuration IPsec - strongSwan (site-à-site)

**Serveur A :**
```bash
# /etc/ipsec.conf
conn siteA-siteB
    type=tunnel
    auto=start
    keyexchange=ikev2
    authby=secret
    left=203.0.113.1
    leftsubnet=192.168.1.0/24
    right=203.0.113.2
    rightsubnet=192.168.2.0/24
    ike=aes256-sha256-modp2048!
    esp=aes256-sha256!
```

**Clé partagée :**
```bash
# /etc/ipsec.secrets
203.0.113.1 203.0.113.2 : PSK "votre_cle_partagee_tres_securisee"
```

```bash
ipsec restart
ipsec statusall
```

### 3.7 Configuration IPsec - Cisco ASA

```cisco
crypto ikev2 policy 10
 encryption aes-256
 integrity sha384
 group 21
 prf sha384
 lifetime seconds 86400

crypto ipsec ikev2 ipsec-proposal MY_PROPOSAL
 protocol esp encryption aes-256
 protocol esp integrity sha-1

crypto map MY_MAP 10 match address VPN_TRAFFIC
crypto map MY_MAP 10 set peer 203.0.113.2
crypto map MY_MAP 10 set ikev2 ipsec-proposal MY_PROPOSAL
crypto map MY_MAP 10 set pfs group21
crypto map MY_MAP interface outside
```

### 3.8 Configuration IPsec - MikroTik RouterOS

```rsc
/ip ipsec profile
add name=ikev2-profile hash-algorithm=sha256 enc-algorithm=aes-256 dh-group=ecp384

/ip ipsec proposal
add name=prop1 auth-algorithms=sha256 enc-algorithms=aes-256-cbc pfs-group=ecp384

/ip ipsec peer
add address=203.0.113.2/32 name=peer1 profile=ikev2-profile exchange-mode=ike2

/ip ipsec identity
add peer=peer1 secret="votre_cle"

/ip ipsec policy
add src-address=192.168.1.0/24 dst-address=192.168.2.0/24 sa-dst-address=203.0.113.2 \
    sa-src-address=203.0.113.1 tunnel=yes proposal=prop1
```

### 3.9 Où utiliser IPsec

- VPN site-à-site entre filiales.
- VPN d'accès distant (télétravail).
- Sécurisation de flux réseau critiques (supervision, SCADA).
- Architecture Zero Trust pour l'interconnexion de data centers.
- Mobilité avec MOBIKE (smartphones, clients nomades).

### 3.10 Commandes de vérification IPsec

```bash
# Statut strongSwan
ipsec statusall

# Logs
journalctl -u strongswan -f

# Vérifier les SA
ip xfrm state
ip xfrm policy

# Ping via le tunnel
ping -I 192.168.1.1 192.168.2.1

# Capture Wireshark/tshark
tshark -i eth0 -f "udp port 500 or udp port 4500 or esp"
```

---

## 4. Kerberos

### 4.1 Définition

**Kerberos** est un protocole d'authentification réseau qui utilise des tickets pour prouver l'identité des utilisateurs et des services. Il repose sur la cryptographie symétrique (clés partagées) et, dans ses versions récentes, sur des mécanismes PKINIT (clés publiques).

### 4.2 Créateurs

Développé au **MIT (Massachusetts Institute of Technology)** dans les années 1980, standardisé par l'IETF dans la RFC 4120 (Kerberos V5).

### 4.3 Composants Kerberos

- **KDC (Key Distribution Center)** : serveur central.
  - **AS (Authentication Server)** : délivre le TGT (Ticket Granting Ticket).
  - **TGS (Ticket Granting Server)** : délivre les tickets de service.
- **Principal** : identité (utilisateur ou service).
- **Realm** : domaine d'autorité Kerberos.
- **Ticket** : preuve d'authentification chiffrée.

### 4.4 Architecture Kerberos

```
Utilisateur
    |
    | (1) AS-REQ (identifiant + mot de passe dérivé)
    ▼
┌─────────┐
│   AS    │ ──> (2) AS-REP : TGT chiffré
└─────────┘
    |
    | (3) TGS-REQ : TGT + demande de service
    ▼
┌─────────┐
│   TGS   │ ──> (4) TGS-REP : ticket de service
└─────────┘
    |
    | (5) AP-REQ : ticket de service
    ▼
┌─────────┐
│ Service │ ──> (6) AP-REP : accès autorisé
└─────────┘
```

### 4.5 Fonctionnement détaillé

1. L'utilisateur saisit son mot de passe. Un hash est calculé localement.
2. Il envoie une demande au KDC (AS-REQ).
3. Le KDC vérifie l'identité et renvoie un TGT chiffré avec la clé de l'utilisateur.
4. L'utilisateur présente le TGT au TGS pour obtenir un ticket de service.
5. Le ticket de service est présenté au service cible.
6. Le service déchiffre le ticket avec sa clé secrète et autorise l'accès.

### 4.6 Avantages de Kerberos

- Authentification centralisée et unique (SSO).
- Les mots de passe ne circulent jamais en clair.
- Mutual authentication possible.
- Grande scalabilité dans les environnements Active Directory.

### 4.7 Limites et risques Kerberos

- Dépendance totale au KDC (SPOF si non redondant).
- Nécessite une synchronisation horaire NTP stricte.
- Attaques : Kerberoasting, AS-REP Roasting, Golden Ticket, Silver Ticket.
- Complexité de gestion des SPN (Service Principal Names).

### 4.8 Configuration Kerberos - Linux (MIT)

```bash
# /etc/krb5.conf
[libdefaults]
    default_realm = EXAMPLE.COM
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true

[realms]
    EXAMPLE.COM = {
        kdc = kdc.example.com
        admin_server = kdc.example.com
    }

[domain_realm]
    .example.com = EXAMPLE.COM
    example.com = EXAMPLE.COM
```

```bash
# Obtenir un TGT
kinit username@EXAMPLE.COM

# Lister les tickets
klist

# Renouveler
kinit -R username@EXAMPLE.COM

# Détruire
kdestroy
```

### 4.9 Configuration Kerberos - Active Directory

Dans Active Directory, le rôle KDC est intégré aux contrôleurs de domaine. Chaque DC est un KDC.

```powershell
# Créer un SPN
setspn -S HTTP/web.example.com DOMAIN\webaccount

# Activer la délégation contrainte
Set-ADUser -Identity webaccount -TrustedForDelegation $false -TrustedToAuthForDelegation $true
```

### 4.10 Commandes de vérification Kerberos

```bash
# Vérifier la connectivité KDC
kinit user@REALM

# Lister les tickets en mémoire
klist -e -k -t

# Vérifier les SPN
setspn -L DOMAIN\account

# Diagnostic Windows
klist tickets
klist tgt
nltest /dsgetdc:example.com

# Détection Kerberoasting (surveillance des demandes de TGS service)
```

### 4.11 Où utiliser Kerberos

- Authentification Windows Active Directory.
- SSO pour applications d'entreprise.
- Sécurisation de services web (SPNEGO, HTTP Negotiate).
- Hadoop sécurisé (Kerberos pour HDFS, YARN).
- Bases de données (PostgreSQL, Oracle avec Kerberos).
- SSH avec GSSAPI.

---

## 5. OAuth 2.0

### 5.1 Définition

**OAuth 2.0** est un protocole de délégation d'autorisation. Il permet à un utilisateur d'autoriser une application tierce à accéder à ses ressources sans divulguer ses identifiants.

### 5.2 Créateurs

Standardisé par l'IETF dans la RFC 6749 (2012). Initialement conçu par une communauté incluant des ingénieurs de Google, Twitter et d'autres acteurs du web.

### 5.3 Rôles OAuth 2.0

- **Resource Owner** : propriétaire des données.
- **Client** : application demandant l'accès.
- **Authorization Server** : délivre les tokens.
- **Resource Server** : héberge les ressources protégées.

### 5.4 Flux OAuth 2.0

| Flux | Cas d'usage | Sécurité |
|------|-------------|----------|
| Authorization Code | Applications web et mobiles | Élevée, avec PKCE |
| Implicit | SPAs anciennes | Déconseillé (token exposé) |
| Resource Owner Password | Applications legacy de confiance | Déconseillé |
| Client Credentials | Machine-to-machine | Élevée |
| Device Code | Appareils sans clavier | Moyenne à élevée |

### 5.5 Architecture OAuth 2.0

```
┌──────────────┐          ┌─────────────────────┐          ┌──────────────┐
│   Client     │          │   Authorization     │          │   Resource   │
│  (App Web)   │ <──────> │      Server         │ <──────> │   Server     │
└──────────────┘          └─────────────────────┘          └──────────────┘
       ▲                                                         ▲
       │                                                         │
       └──────────────── Resource Owner ─────────────────────────┘
```

### 5.6 Flux Authorization Code avec PKCE

```
Client                                Authorization Server
  | ---------- Authorization Request + code_challenge ------> |
  | <--------- Authorization Code --------------------------- |
  | ---------- Token Request + code_verifier --------------> |
  | <--------- Access Token (+ Refresh Token) --------------- |
```

### 5.7 Configuration OAuth 2.0 - Keycloak

```bash
# Créer un realm
./kcadm.sh create realms -s realm=monrealm -s enabled=true

# Créer un client
./kcadm.sh create clients -r monrealm \
  -s clientId=monapp \
  -s 'redirectUries=["https://monapp.example.com/callback"]' \
  -s protocol=openid-connect \
  -s publicClient=false \
  -s clientAuthenticatorType=client-secret
```

### 5.8 Configuration OAuth 2.0 - Spring Boot

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          keycloak:
            client-id: monapp
            client-secret: ${CLIENT_SECRET}
            scope: openid,profile,email
            authorization-grant-type: authorization_code
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
        provider:
          keycloak:
            issuer-uri: https://auth.example.com/realms/monrealm
```

### 5.9 Configuration OAuth 2.0 - Node.js / Passport

```javascript
const passport = require('passport');
const OAuth2Strategy = require('passport-oauth2').Strategy;

passport.use('oauth2', new OAuth2Strategy({
  authorizationURL: 'https://auth.example.com/oauth/authorize',
  tokenURL: 'https://auth.example.com/oauth/token',
  clientID: 'monapp',
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: 'https://monapp.example.com/auth/callback'
}, (accessToken, refreshToken, profile, cb) => {
  return cb(null, { accessToken });
}));
```

### 5.10 Où utiliser OAuth 2.0

- Autorisation d'applications tierces (Google, Facebook, GitHub login).
- APIs protégées (REST, GraphQL).
- Applications mobiles et SPAs.
- Intégrations SaaS (Slack, Salesforce, Microsoft 365).
- Workflows machine-to-machine.

### 5.11 Commandes de vérification OAuth 2.0

```bash
# Obtenir un token client credentials
curl -X POST https://auth.example.com/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=monapp" \
  -d "client_secret=SECRET"

# Introspection du token
curl -X POST https://auth.example.com/oauth/introspect \
  -u monapp:SECRET \
  -d "token=ACCESS_TOKEN"

# Appel API avec token
curl -H "Authorization: Bearer ACCESS_TOKEN" https://api.example.com/resource
```

### 5.12 Bonnes pratiques OAuth 2.0

- Toujours utiliser PKCE pour les clients publics.
- Utiliser HTTPS partout.
- Stocker les secrets côté serveur.
- Limiter la durée de vie des access tokens.
- Utiliser des refresh tokens rotatifs.
- Valider les JWT (signature, exp, iss, aud).
- Enregistrer les redirect_uri de manière stricte.

---

## 6. OpenID Connect

### 6.1 Définition

**OpenID Connect (OIDC)** est une couche d'identité construite au-dessus d'OAuth 2.0. Il permet de vérifier l'identité d'un utilisateur et d'obtenir des informations de profil via un ID Token au format JWT.

### 6.2 Créateurs

Développé par la **OpenID Foundation**, basé sur OpenID 2.0 et OAuth 2.0. La spécification principale est OpenID Connect Core 1.0 (2014).

### 6.3 Rôles OIDC

- **OpenID Provider (OP)** : serveur d'identité (ex: Keycloak, Auth0, Okta).
- **Relying Party (RP)** : application cliente qui délègue l'authentification.
- **End-User** : utilisateur final.

### 6.4 Tokens OIDC

- **ID Token** : JWT signé contenant claims d'identité (sub, iss, aud, exp, etc.).
- **Access Token** : autorise l'accès aux ressources (OAuth 2.0).
- **Refresh Token** : permet de renouveler l'access token.

### 6.5 Flux OIDC

| Flux | Description |
|------|-------------|
| Authorization Code | Recommandé, avec PKCE pour les clients publics. |
| Implicit | Déconseillé, ID Token exposé dans l'URL. |
| Hybrid | Mélange authorization code + implicit. |

### 6.6 Architecture OIDC

```
┌─────────────┐         ┌─────────────────────┐         ┌─────────────┐
│  Relying    │  (1)    │   OpenID Provider   │  (2)    │  Resource   │
│   Party     │ <────-> │  (Keycloak/Auth0)   │ <────-> │   Server    │
└─────────────┘         └─────────────────────┘         └─────────────┘
       ▲                        ▲
       │                        │
       └────── End-User ────────┘
```

### 6.7 Exemple d'ID Token JWT

```json
{
  "iss": "https://auth.example.com",
  "sub": "user123",
  "aud": "monapp",
  "exp": 1735689600,
  "iat": 1735686000,
  "name": "Jean Dupont",
  "email": "jean.dupont@example.com",
  "email_verified": true
}
```

### 6.8 Configuration OIDC - Keycloak

```bash
# Activer OIDC sur un client existant
./kcadm.sh update clients/ID_CLIENT -r monrealm \
  -s "redirectUries=[\"https://monapp.example.com/*\"]" \
  -s standardFlowEnabled=true \
  -s implicitFlowEnabled=false \
  -s directAccessGrantsEnabled=false
```

### 6.9 Configuration OIDC - React

```javascript
import { AuthProvider } from 'react-oidc-context';

const oidcConfig = {
  authority: 'https://auth.example.com/realms/monrealm',
  client_id: 'monapp',
  redirect_uri: 'https://monapp.example.com/callback',
  response_type: 'code',
  scope: 'openid profile email',
};

<AuthProvider {...oidcConfig}>
  <App />
</AuthProvider>
```

### 6.10 Configuration OIDC - Angular

```typescript
import { AuthModule } from 'angular-auth-oidc-client';

AuthModule.forRoot({
  config: {
    authority: 'https://auth.example.com/realms/monrealm',
    redirectUrl: window.location.origin,
    postLogoutRedirectUri: window.location.origin,
    clientId: 'monapp',
    scope: 'openid profile email',
    responseType: 'code',
    silentRenew: true,
    useRefreshToken: true,
  },
})
```

### 6.11 Où utiliser OIDC

- Authentification fédérée (SSO d'entreprise).
- Login social (Google, Microsoft, Apple).
- Applications web, mobiles, desktop.
- Portails clients et partenaires.
- Intégration avec des Identity Providers cloud.

### 6.12 Commandes de vérification OIDC

```bash
# Récupérer la configuration du provider
curl https://auth.example.com/realms/monrealm/.well-known/openid-configuration

# Décoder un ID Token JWT
jwt decode ID_TOKEN

# Vérifier la signature avec les JWKS
jwkutil verify --token ID_TOKEN --jwks https://auth.example.com/realms/monrealm/protocol/openid-connect/certs

# Test avec oidcdebugger.com ou Postman
```

### 6.13 Bonnes pratiques OIDC

- Toujours valider la signature des ID Tokens.
- Vérifier `nonce` pour prévenir les replay attacks.
- Vérifier `state` contre les CSRF.
- Utiliser `response_type=code` avec PKCE.
- Configurer correctement les `redirect_uri`.
- Demander uniquement les scopes nécessaires.

---

## 7. Comparatif global

| Critère | TLS/SSL | IPsec | Kerberos | OAuth 2.0 | OIDC |
|---------|---------|-------|----------|-----------|------|
| Couche OSI | 4-7 | 3 | 5-7 | 7 | 7 |
| Objectif | Chiffrement transport | VPN / sécurisation IP | Authentification réseau | Délégation d'autorisation | Authentification fédérée |
| Chiffrement | Oui | Oui | Non directement | Non | Non |
| Authentification | Serveur (client optionnel) | Pair-à-pair / gateway | Oui, forte | Non (autorisation) | Oui |
| SSO | Non | Non | Oui | Non | Oui |
| Cas typique | HTTPS | VPN | AD / Hadoop | APIs | Login web/mobile |

---

## 8. Architectures et topologies

### 8.1 Architecture Zero Trust

Dans une architecture Zero Trust, aucune entité n'est implicitement de confiance. TLS, IPsec, OAuth 2.0 et OIDC sont combinés :

- **TLS** : chiffrement des flux applicatifs.
- **IPsec** : segmentation réseau sécurisée.
- **OIDC/OAuth 2.0** : authentification et autorisation continues.
- **Kerberos** : SSO interne et authentification des services.

### 8.2 Architecture hybride cloud

```
On-Premises                          Cloud (AWS/Azure/GCP)
┌─────────────┐                     ┌─────────────────────┐
│   AD +      │───── IPsec VPN ────▶│   Workloads         │
│  Kerberos   │                     │   OIDC / OAuth 2.0  │
└─────────────┘                     └─────────────────────┘
       │                                     │
       └───────────── TLS / mTLS ────────────┘
```

### 8.3 Architecture microservices

- **mTLS (mutual TLS)** : authentification service-à-service.
- **OAuth 2.0** : autorisation entre services.
- **OIDC** : authentification des utilisateurs finaux.
- **Service mesh** (Istio, Linkerd) : gestion centralisée du mTLS.

---

## 9. Commandes de vérification

### 9.1 TLS/SSL

```bash
# Test complet avec testssl.sh
testssl.sh --full https://example.com

# Vérification des certificats
openssl x509 -in cert.pem -text -noout

# Vérifier le chaînage
openssl verify -CAfile ca.pem cert.pem

# Scan nmap
nmap --script ssl-enum-ciphers -p 443 example.com
```

### 9.2 IPsec

```bash
ipsec statusall
ip xfrm state
ip xfrm policy
ping -I tunnel_endpoint peer_endpoint
```

### 9.3 Kerberos

```bash
kinit user@REALM
klist -e -k -t
kdestroy
setspn -L account
```

### 9.4 OAuth 2.0 / OIDC

```bash
curl https://auth.example.com/.well-known/openid-configuration
curl -X POST https://auth.example.com/oauth/token -d "grant_type=client_credentials&client_id=...&client_secret=..."
jwt decode ID_TOKEN
```

---

## 10. Applications et implémentations

### 10.1 Implémentations TLS

- OpenSSL
- GnuTLS
- BoringSSL (Google)
- NSS (Mozilla)
- wolfSSL
- mbed TLS (Arm)

### 10.2 Implémentations IPsec

- strongSwan
- libreswan
- Openswan
- Cisco ASA / IOS
- Juniper SRX
- Fortinet FortiGate
- pfSense
- MikroTik RouterOS

### 10.3 Implémentations Kerberos

- MIT Kerberos
- Heimdal
- Microsoft Active Directory
- FreeIPA / IPA

### 10.4 Implémentations OAuth 2.0 / OIDC

- Keycloak
- Auth0
- Okta
- Azure AD / Entra ID
- AWS Cognito
- Google Identity
- Spring Authorization Server
- Hydra (ORY)
- Dex

---

## 11. Ressources et bibliographie

### 11.1 RFCs essentielles

- RFC 8446 - TLS 1.3
- RFC 5246 - TLS 1.2
- RFC 4346 - TLS 1.1
- RFC 2246 - TLS 1.0
- RFC 6101 - SSL 3.0
- RFC 4301 à 4309 - IPsec
- RFC 7296 - IKEv2
- RFC 4120 - Kerberos V5
- RFC 6749 - OAuth 2.0
- RFC 7636 - PKCE
- RFC 8252 - OAuth 2.0 for Native Apps
- OpenID Connect Core 1.0

### 11.2 Livres recommandés

- *Cryptography Engineering* - Ferguson, Schneier, Kohno
- *Bulletproof TLS and PKI* - Ivan Ristić
- *Real-World Cryptography* - David Wong
- *OAuth 2 in Action* - Justin Richer et Antonio Sanso
- *OpenID Connect Authentication 2.0* - Nat Sakimura et al.
- *Network Security with OpenSSL* - Viega et al.

### 11.3 Liens utiles

- https://www.ssllabs.com/ssltest/
- https://testssl.sh/
- https://letsencrypt.org/
- https://www.keycloak.org/
- https://openid.net/connect/
- https://datatracker.ietf.org/
- https://www.strongswan.org/
- https://web.mit.edu/kerberos/

### 11.4 Auteur et crédits

**Auteur :** hackers_tchad  
**Date de publication :** 2026  
**Contact :** hackers_tchad (réseaux sociaux et communautés tech)  
**Remerciements :** IETF, OpenID Foundation, MIT Kerberos Consortium, communautés open source.

---

## 12. Fiches de synthèse

### Fiche TLS

- **Objectif :** chiffrer les communications transport.
- **Version recommandée :** TLS 1.3.
- **Clé :** certificats X.509, suites cryptographiques.
- **Outils :** OpenSSL, testssl.sh, SSL Labs.

### Fiche SSL

- **Statut :** obsolète.
- **Dernier version :** SSL 3.0 (1996).
- **Risques :** POODLE, BEAST, algorithmes faibles.
- **Action :** migrer vers TLS 1.2+.

### Fiche IPsec

- **Objectif :** VPN et sécurisation couche 3.
- **Composants :** AH, ESP, IKEv2.
- **Modes :** transport, tunnel.
- **Outils :** strongSwan, libreswan, routeurs entreprise.

### Fiche Kerberos

- **Objectif :** authentification centralisée par tickets.
- **Composants :** KDC, AS, TGS, TGT.
- **Risques :** Kerberoasting, Golden Ticket.
- **Outils :** MIT Kerberos, Active Directory, FreeIPA.

### Fiche OAuth 2.0

- **Objectif :** délégation d'autorisation.
- **Flux :** authorization code (avec PKCE), client credentials.
- **Tokens :** access token, refresh token.
- **Outils :** Keycloak, Auth0, Okta, Spring Authorization Server.

### Fiche OIDC

- **Objectif :** authentification fédérée.
- **Token clé :** ID Token JWT.
- **Flux :** authorization code + PKCE.
- **Outils :** Keycloak, Auth0, Azure AD, AWS Cognito.

---

**Fin du guide. Pour toute question ou contribution, contactez hackers_tchad.**
