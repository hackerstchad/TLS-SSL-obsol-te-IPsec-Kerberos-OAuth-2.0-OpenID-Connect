# Annexe 5 : Laboratoires Pratiques et Scénarios

**Auteur :** hackers_tchad  
**Date :** 2026

---

## Introduction

Cette annexe regroupe des scénarios de laboratoire concrets pour mettre en pratique les protocoles TLS, SSL, IPsec, Kerberos, OAuth 2.0 et OpenID Connect. Chaque lab comprend l'objectif, la topologie, les prérequis, les étapes de configuration et les commandes de vérification.

---

## Lab 1 : Déploiement d'un serveur HTTPS avec TLS 1.3

### Objectif
Configurer un serveur web Nginx avec un certificat TLS 1.3 valide, tester la configuration et obtenir un score A+ sur SSL Labs.

### Topologie
```
[Client] <---> [Internet] <---> [Nginx + Let's Encrypt] <---> [Backend]
```

### Prérequis
- Serveur Debian/Ubuntu avec Nginx installé.
- Nom de domaine pointant vers le serveur.
- Accès root.

### Étapes

#### 1. Installer Certbot et obtenir un certificat
```bash
sudo apt update
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d lab.example.com
```

#### 2. Configurer Nginx pour TLS 1.3
```nginx
server {
    listen 443 ssl http2;
    server_name lab.example.com;

    ssl_certificate     /etc/letsencrypt/live/lab.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/lab.example.com/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;
    ssl_stapling on;
    ssl_stapling_verify on;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    location / {
        root /var/www/html;
        index index.html;
    }
}
```

#### 3. Vérifier
```bash
sudo nginx -t
sudo systemctl reload nginx
openssl s_client -connect lab.example.com:443 -tls1_3 </dev/null
testssl.sh https://lab.example.com
```

### Résultat attendu
- Connexion en TLS 1.3.
- Score A+ sur SSL Labs.
- HSTS activé.

---

## Lab 2 : VPN site-à-site avec strongSwan et IKEv2

### Objectif
Établir un tunnel IPsec site-à-site entre deux passerelles Linux avec IKEv2 et certificats auto-signés.

### Topologie
```
Site A (192.168.1.0/24) <---> [Gateway A] ===== Internet ===== [Gateway B] <---> Site B (192.168.2.0/24)
```

### Prérequis
- Deux machines Linux avec strongSwan installé.
- Connectivité IP publique entre les deux gateways.

### Étapes

#### Gateway A
```bash
sudo apt install strongswan strongswan-pki

# Générer la CA
mkdir -p ~/pki/{cacerts,certs,private}
ipsec pki --gen --type ed25519 --outform pem > ~/pki/private/ca-key.pem
ipsec pki --self --ca --lifetime 3650 --in ~/pki/private/ca-key.pem \
  --dn "C=FR, O=Lab, CN=Lab CA" --outform pem > ~/pki/cacerts/ca-cert.pem

# Certificat Gateway A
ipsec pki --gen --type ed25519 --outform pem > ~/pki/private/gatewayA-key.pem
ipsec pki --pub --in ~/pki/private/gatewayA-key.pem --type ed25519 | \
  ipsec pki --issue --lifetime 1825 --cacert ~/pki/cacerts/ca-cert.pem \
  --cakey ~/pki/private/ca-key.pem --dn "C=FR, O=Lab, CN=gatewayA" \
  --san gatewayA --outform pem > ~/pki/certs/gatewayA-cert.pem

# Copier les certificats
sudo cp ~/pki/cacerts/ca-cert.pem /etc/ipsec.d/cacerts/
sudo cp ~/pki/certs/gatewayA-cert.pem /etc/ipsec.d/certs/
sudo cp ~/pki/private/gatewayA-key.pem /etc/ipsec.d/private/
```

```bash
# /etc/ipsec.conf sur Gateway A
conn siteA-siteB
    type=tunnel
    auto=start
    keyexchange=ikev2
    authby=rsasig
    left=203.0.113.1
    leftid="C=FR, O=Lab, CN=gatewayA"
    leftcert=gatewayA-cert.pem
    leftsubnet=192.168.1.0/24
    right=203.0.113.2
    rightid="C=FR, O=Lab, CN=gatewayB"
    rightsubnet=192.168.2.0/24
    ike=aes256gcm16-prfsha384-ecp384!
    esp=aes256gcm16-ecp384!
```

#### Gateway B
Procédure symétrique avec les adresses inversées.

#### Vérification
```bash
sudo ipsec restart
sudo ipsec statusall
ping 192.168.2.1
```

### Résultat attendu
- Tunnel `siteA-siteB` en `ESTABLISHED`.
- Ping entre les deux réseaux privés.

---

## Lab 3 : Authentification Kerberos avec MIT

### Objectif
Déployer un KDC MIT, créer des principaux et configurer SSH avec GSSAPI.

### Topologie
```
[Client Linux] <---> [KDC] <---> [Serveur SSH]
```

### Étapes

#### 1. Installer le KDC
```bash
sudo apt install krb5-kdc krb5-admin-server
sudo krb5_newrealm
```

#### 2. Configurer `/etc/krb5.conf`
```ini
[libdefaults]
    default_realm = LAB.LOCAL
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    forwardable = true

[realms]
    LAB.LOCAL = {
        kdc = kdc.lab.local
        admin_server = kdc.lab.local
    }

[domain_realm]
    .lab.local = LAB.LOCAL
```

#### 3. Créer des principaux
```bash
sudo kadmin.local -q "addprinc -pw password alice@LAB.LOCAL"
sudo kadmin.local -q "addprinc -randkey host/server.lab.local@LAB.LOCAL"
sudo kadmin.local -q "ktadd -k /etc/krb5.keytab host/server.lab.local@LAB.LOCAL"
```

#### 4. Configurer SSH
```bash
# /etc/ssh/sshd_config
GSSAPIAuthentication yes
GSSAPICleanupCredentials yes
```

#### 5. Tester
```bash
kinit alice@LAB.LOCAL
ssh alice@server.lab.local
```

### Résultat attendu
- Authentification SSH sans mot de passe via Kerberos.

---

## Lab 4 : Serveur OAuth 2.0 / OIDC avec Keycloak

### Objectif
Déployer Keycloak, configurer un realm, un client et tester le flux Authorization Code avec PKCE.

### Topologie
```
[Navigateur] <---> [Keycloak] <---> [Application Web]
```

### Étapes

#### 1. Démarrer Keycloak
```bash
docker run -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:latest start-dev
```

#### 2. Créer un realm et un client
```bash
./kcadm.sh config credentials --server http://localhost:8080 --realm master --user admin --password admin
./kcadm.sh create realms -s realm=lab -s enabled=true
./kcadm.sh create clients -r lab \
  -s clientId=webapp \
  -s 'redirectUris=["http://localhost:3000/callback"]' \
  -s publicClient=true \
  -s standardFlowEnabled=true \
  -s protocol=openid-connect
```

#### 3. Créer un utilisateur
```bash
./kcadm.sh create users -r lab -s username=alice -s enabled=true
./kcadm.sh set-password -r lab --username alice --new-password password
```

#### 4. Tester avec un client OAuth
Utiliser Postman ou oidcdebugger.com avec :
- Authorization endpoint : `http://localhost:8080/realms/lab/protocol/openid-connect/auth`
- Token endpoint : `http://localhost:8080/realms/lab/protocol/openid-connect/token`
- Client ID : `webapp`

### Résultat attendu
- Obtention d'un ID Token JWT après authentification d'Alice.

---

## Lab 5 : Audit d'une configuration TLS obsolète

### Objectif
Détecter les vulnérabilités SSL/TLS sur un serveur et proposer un plan de remédiation.

### Outils
- `testssl.sh`
- `nmap`
- `openssl`

### Étapes

#### 1. Scanner les protocoles
```bash
testssl.sh --protocols https://target.example.com
```

#### 2. Scanner les suites
```bash
nmap --script ssl-enum-ciphers -p 443 target.example.com
```

#### 3. Tester les vulnérabilités
```bash
testssl.sh --vulnerabilities https://target.example.com
```

#### 4. Vérifier les certificats
```bash
openssl s_client -connect target.example.com:443 2>/dev/null | openssl x509 -noout -text
```

### Résultat attendu
- Rapport listant les protocoles obsolètes, les suites faibles, les certificats expirés.

---

## Lab 6 : mTLS entre deux microservices

### Objectif
Sécuriser la communication entre deux services Spring Boot avec du mTLS.

### Étapes

#### 1. Générer une PKI
```bash
openssl req -x509 -newkey rsa:4096 -keyout ca.key -out ca.crt -days 365 -nodes
```

#### 2. Générer les certificats des services
```bash
# Service A
openssl req -newkey rsa:2048 -keyout serviceA.key -out serviceA.csr -nodes -subj "/CN=serviceA"
openssl x509 -req -in serviceA.csr -CA ca.crt -CAkey ca.key -out serviceA.crt -days 365

# Service B
openssl req -newkey rsa:2048 -keyout serviceB.key -out serviceB.csr -nodes -subj "/CN=serviceB"
openssl x509 -req -in serviceB.csr -CA ca.crt -CAkey ca.key -out serviceB.crt -days 365
```

#### 3. Configurer Spring Boot
```yaml
server:
  port: 8443
  ssl:
    enabled: true
    key-store: classpath:serviceA.p12
    key-store-password: changeit
    key-store-type: PKCS12
    trust-store: classpath:truststore.p12
    trust-store-password: changeit
    trust-store-type: PKCS12
    client-auth: need
```

### Résultat attendu
- Le service A refuse les connexions sans certificat client valide.

---

## Lab 7 : Détection de Kerberoasting

### Objectif
Comprendre et détecter une attaque Kerberoasting dans un environnement Active Directory.

### Étapes

#### 1. Créer un compte de service avec SPN
```powershell
New-ADUser -Name "svc_sql" -AccountPassword (ConvertTo-SecureString "P@ssw0rd123" -AsPlainText -Force) -Enabled $true
setspn -S MSSQLSvc/sql.lab.local:1433 LAB\svc_sql
```

#### 2. Simuler Kerberoasting avec Rubeus
```bash
Rubeus.exe kerberoast /outfile:hashes.kerberoast
```

#### 3. Détecter avec les logs Windows
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4769} | Where-Object { $_.Properties[8].Value -eq '0x1' }
```

### Résultat attendu
- Détection de demandes de TGS avec chiffrement RC4, signe d'une attaque Kerberoasting.

---

## Lab 8 : Fédération OIDC avec Google Identity

### Objectif
Permettre aux utilisateurs de se connecter à une application via leur compte Google.

### Étapes

#### 1. Créer des credentials dans Google Cloud Console
- Aller à `APIs & Services > Credentials`.
- Créer un OAuth 2.0 Client ID de type Web application.
- Définir les authorized redirect URIs.

#### 2. Configurer l'application
```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          google:
            client-id: YOUR_CLIENT_ID
            client-secret: YOUR_CLIENT_SECRET
            scope: openid,profile,email
```

#### 3. Tester
Lancer l'application, cliquer sur "Login with Google", vérifier l'ID Token retourné.

---

## Lab 9 : Hardening IPsec contre les attaques

### Objectif
Configurer strongSwan avec des paramètres sécurisés et vérifier l'absence de groupes faibles.

### Étapes

#### Configuration sécurisée
```bash
conn secure-tunnel
    type=tunnel
    auto=start
    keyexchange=ikev2
    authby=rsasig
    ike=aes256gcm16-prfsha384-ecp384!
    esp=aes256gcm16-ecp384!
    dpdaction=restart
    dpddelay=30s
    dpdtimeout=90s
    ikelifetime=8h
    lifetime=1h
```

#### Vérification
```bash
ipsec statusall
# Vérifier que les proposals n'incluent pas modp1024, modp1536, 3des, sha1
```

---

## Lab 10 : Analyse d'un flux OAuth 2.0 avec Wireshark

### Objectif
Capturer et analyser le flux Authorization Code avec PKCE.

### Étapes

#### 1. Lancer Wireshark
```bash
sudo tshark -i any -f "tcp port 8080 or tcp port 3000" -w oauth.pcap
```

#### 2. Effectuer une authentification via Keycloak.

#### 3. Ouvrir la capture dans Wireshark et filtrer :
```
http.request.uri contains "callback"
http.request.method == "POST"
```

### Résultat attendu
- Le code d'autorisation est échangé contre des tokens via POST.
- Aucun secret client en clair dans une URL.

---

## Checklist de sécurité globale

### TLS/SSL
- [ ] Désactiver SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1.
- [ ] Activer TLS 1.2 et TLS 1.3.
- [ ] Utiliser des suites AEAD (AES-GCM, ChaCha20-Poly1305).
- [ ] Activer HSTS.
- [ ] Activer OCSP Stapling.
- [ ] Renouveler automatiquement les certificats.

### IPsec
- [ ] Utiliser IKEv2.
- [ ] Désactiver les groupes DH faibles.
- [ ] Préférer AES-GCM.
- [ ] Activer PFS.
- [ ] Limiter les lifetimes.

### Kerberos
- [ ] Synchronisation NTP stricte.
- [ ] Désactiver RC4 et DES.
- [ ] Changer régulièrement le mot de passe KRBTGT.
- [ ] Limiter la délégation Kerberos.
- [ ] Surveiller les événements 4769.

### OAuth 2.0 / OIDC
- [ ] Utiliser HTTPS partout.
- [ ] PKCE obligatoire pour les clients publics.
- [ ] Durée de vie courte des access tokens.
- [ ] Refresh tokens rotatifs.
- [ ] Validation stricte des redirect_uri.
- [ ] Vérifier `state` et `nonce`.

---

## Templates de configuration

### Template Nginx sécurisé
```nginx
server {
    listen 443 ssl http2;
    server_name _;

    ssl_certificate /etc/ssl/certs/server.crt;
    ssl_certificate_key /etc/ssl/private/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    add_header Strict-Transport-Security "max-age=63072000" always;
}
```

### Template strongSwan IKEv2
```bash
conn ikev2-template
    type=tunnel
    auto=start
    keyexchange=ikev2
    authby=rsasig
    ike=aes256gcm16-prfsha384-ecp384!
    esp=aes256gcm16-ecp384!
```

### Template Keycloak client OIDC
```bash
./kcadm.sh create clients -r lab \
  -s clientId=template \
  -s 'redirectUris=["https://app.example.com/callback"]' \
  -s publicClient=false \
  -s standardFlowEnabled=true \
  -s directAccessGrantsEnabled=false \
  -s protocol=openid-connect
```

---

## Références complémentaires

- [README principal](README_securite_protocoles_avance.md)
- [Annexe TLS/SSL](annexe_tls_ssl_detaille.md)
- [Annexe IPsec](annexe_ipsec_detaille.md)
- [Annexe Kerberos](annexe_kerberos_detaille.md)
- [Annexe OAuth 2.0 / OIDC](annexe_oauth_oidc_detaille.md)

---

*Auteur : hackers_tchad - Date : 2026*
