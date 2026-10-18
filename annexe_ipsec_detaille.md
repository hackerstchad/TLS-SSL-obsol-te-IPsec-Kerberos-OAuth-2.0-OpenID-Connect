# Annexe IPsec - Guide Technique Avancé
**Auteur :** hackers_tchad | **Date :** 2026

---

## 1. Vue d'ensemble approfondie d'IPsec

IPsec (Internet Protocol Security) est un framework de sécurité développé par l'IETF pour protéger les communications IP. Contrairement à TLS qui opère au-dessus de TCP/IP, IPsec s'intègre directement dans la couche réseau (couche 3 du modèle OSI). Cela signifie qu'il peut protéger n'importe quel protocole transport (TCP, UDP, ICMP, SCTP) sans modification applicative.

IPsec a été standardisé dans une série de RFC entre 1998 et 2005, puis mis à jour régulièrement. Il est défini principalement par :
- RFC 4301 : Architecture de sécurité pour IP
- RFC 4302 : IP Authentication Header (AH)
- RFC 4303 : IP Encapsulating Security Payload (ESP)
- RFC 4306 : Internet Key Exchange (IKEv2)
- RFC 7296 : IKEv2 mis à jour
- RFC 4555 : Mobilité et multihoming (MOBIKE)

## 2. Objectifs de sécurité d'IPsec

IPsec fournit trois services fondamentaux :

### 2.1 Confidentialité
Le chiffrement ESP empêche l'interception et la lecture des données. Les algorithmes supportés incluent AES-CBC, AES-GCM, AES-CCM, ChaCha20-Poly1305, Camellia et 3DES (obsolète).

### 2.2 Intégrité
AH et ESP fournissent une intégrité des données via HMAC-SHA1, HMAC-SHA256, HMAC-SHA384, HMAC-SHA512 ou GMAC (mode authentifié).

### 2.3 Authentification
L'authentification des pairs est réalisée par certificats X.509, clés pré-partagées (PSK), authentification EAP ou par clés publiques RSA/ECDSA.

## 3. Architecture fonctionnelle

```
┌────────────────────────────────────────────────────────────┐
│                     Application                           │
├────────────────────────────────────────────────────────────┤
│                     Transport (TCP/UDP)                   │
├────────────────────────────────────────────────────────────┤
│  IPsec (SPD/SAD) ──> AH / ESP ──> IKEv2 (gestion clés)   │
├────────────────────────────────────────────────────────────┤
│                     IP (IPv4/IPv6)                        │
├────────────────────────────────────────────────────────────┤
│                     Liaison de données                    │
└────────────────────────────────────────────────────────────┘
```

## 4. Composants détaillés

### 4.1 SPD - Security Policy Database
La SPD définit quels paquets doivent être protégés, comment ils doivent l'être et où les envoyer. Chaque entrée contient :
- Adresses source et destination
- Protocoles et ports
- Action : BYPASS, PROTECT ou DISCARD
- Paramètres de protection si PROTECT

### 4.2 SAD - Security Association Database
La SAD contient les associations de sécurité actives, c'est-à-dire les paramètres négociés pour chaque tunnel actif : SPI, clés, algorithmes, modes, compteurs de séquence, fenêtre anti-replay.

### 4.3 SPI - Security Parameter Index
Le SPI est un identifiant 32 bits inclus dans l'en-tête AH/ESP. Il permet au récepteur de retrouver rapidement la SA correspondante dans sa SAD.

### 4.4 SA - Security Association
Une SA est une relation unidirectionnelle entre deux entités. Pour une communication bidirectionnelle, deux SA sont nécessaires (une dans chaque sens). Chaque SA est identifiée par le triplet (SPI, adresse destination, protocole de sécurité).

## 5. Modes de fonctionnement

### 5.1 Mode Transport
En mode transport, seule la charge utile IP est protégée. L'en-tête IP original reste intact, ce qui permet au routage de fonctionner normalement. Utilisé principalement pour les communications hôte-à-hôte.

```
[En-tête IP original] [En-tête AH/ESP] [Données chiffrées] [Authentification]
```

### 5.2 Mode Tunnel
En mode tunnel, le paquet IP entier est encapsulé dans un nouveau paquet IP. L'ancien paquet devient la charge utile. Utilisé pour les VPN car il permet de cacher les adresses internes.

```
[Nouvel en-tête IP] [En-tête AH/ESP] [Ancien en-tête IP] [Données] [Authentification]
```

## 6. Protocoles AH et ESP

### 6.1 AH (Authentication Header)
AH fournit :
- Authentification de l'origine
- Intégrité des données
- Anti-replay

AH n'assure pas la confidentialité. Il protège l'en-tête IP dans une certaine mesure, sauf les champs changeants (TTL, checksum, options).

Format AH :
- Next Header (8 bits)
- Payload Length (8 bits)
- Reserved (16 bits)
- SPI (32 bits)
- Sequence Number (32 bits)
- Authentication Data (variable)

### 6.2 ESP (Encapsulating Security Payload)
ESP fournit :
- Confidentialité (optionnel)
- Authentification de l'origine
- Intégrité des données
- Anti-replay

ESP est le protocole le plus utilisé car il offre le chiffrement. Le format ESP inclut :
- SPI (32 bits)
- Sequence Number (32 bits)
- Payload Data (chiffré)
- Padding
- Pad Length
- Next Header
- Authentication Data

## 7. IKE - Internet Key Exchange

### 7.1 IKEv1
IKEv1 combine ISAKMP, Oakley et SKEME. Il fonctionne en deux phases :
- Phase 1 : négociation d'une SA ISAKMP sécurisée (main mode 6 messages ou aggressive mode 3 messages).
- Phase 2 : négociation des SA IPsec (quick mode 3 messages).

IKEv1 est aujourd'hui déconseillé car il est complexe, lent et moins sécurisé.

### 7.2 IKEv2
IKEv2 simplifie considérablement l'échange avec 4 messages initiaux (IKE_SA_INIT et IKE_AUTH) et supporte :
- EAP pour l'authentification utilisateur
- MOBIKE pour la mobilité
- NAT Traversal natif
- Dead Peer Detection (DPD)
- Renégociation simplifiée

### 7.3 Diffie-Hellman et PFS
Le Perfect Forward Secrecy (PFS) est recommandé. IKEv2 supporte des groupes DH modernes comme ecp256, ecp384, ecp521, modp2048, modp3072, modp4096. Les groupes 1, 2 et 5 sont obsolètes (Logjam).

## 8. Configuration avancée strongSwan

### 8.1 Site-à-site avec certificats X.509

```bash
# /etc/ipsec.conf
conn siteA-siteB
    type=tunnel
    auto=start
    keyexchange=ikev2
    authby=rsasig
    left=203.0.113.1
    leftid="C=FR, O=Example, CN=gatewayA"
    leftcert=gatewayA.crt
    leftsubnet=192.168.1.0/24
    right=203.0.113.2
    rightid="C=FR, O=Example, CN=gatewayB"
    rightsubnet=192.168.2.0/24
    ike=aes256gcm16-prfsha384-ecp384!
    esp=aes256gcm16-ecp384!
    dpdaction=restart
    dpddelay=30s
    dpdtimeout=90s
```

### 8.2 Accès distant road warrior (EAP-MSCHAPv2)

```bash
conn rw-eap
    type=tunnel
    auto=add
    keyexchange=ikev2
    authby=rsaauth-eap
    eap_identity=%identity
    left=203.0.113.1
    leftid=@vpn.example.com
    leftcert=server.crt
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    right=%any
    rightauth=eap-mschapv2
    rightsourceip=10.10.10.0/24
    rightdns=8.8.8.8,8.8.4.4
    ike=aes256-sha256-modp2048!
    esp=aes256-sha256!
```

### 8.3 Connexion MOBIKE

```bash
conn mobile
    type=tunnel
    auto=add
    keyexchange=ikev2
    mobike=yes
    left=203.0.113.1
    leftid=@vpn.example.com
    leftsubnet=0.0.0.0/0
    right=%any
    rightsourceip=10.10.10.0/24
```

## 9. Configuration IPsec sur équipements réseau

### 9.1 Cisco IOS

```cisco
crypto isakmp policy 10
 encr aes 256
 hash sha256
 authentication rsa-sig
 group 14
crypto isakmp nat keepalive 20

crypto ipsec transform-set MY_SET esp-aes 256 esp-sha-hmac
 mode tunnel

crypto map MY_MAP 10 ipsec-isakmp
 set peer 203.0.113.2
 set transform-set MY_SET
 match address 100

interface GigabitEthernet0/0
 crypto map MY_MAP

access-list 100 permit ip 192.168.1.0 0.0.0.255 192.168.2.0 0.0.0.255
```

### 9.2 Juniper SRX

```junos
set security ike proposal IKE_PROP authentication-method rsa-signatures
set security ike proposal IKE_PROP dh-group group14
set security ike proposal IKE_PROP authentication-algorithm sha-256
set security ike proposal IKE_PROP encryption-algorithm aes-256-cbc
set security ike policy IKE_POL proposals IKE_PROP
set security ike policy IKE_POL certificate local-cert gatewayA

set security ipsec proposal IPSEC_PROP protocol esp
set security ipsec proposal IPSEC_PROP authentication-algorithm hmac-sha-256-128
set security ipsec proposal IPSEC_PROP encryption-algorithm aes-256-cbc
set security ipsec policy IPSEC_POL proposals IPSEC_PROP

set security ipsec vpn SITE_TO_SITE bind-interface st0.0
set security ipsec vpn SITE_TO_SITE ike gateway GW_B
set security ipsec vpn SITE_TO_SITE ike ipsec-policy IPSEC_POL
set security ipsec vpn SITE_TO_SITE establish-tunnels immediately
```

### 9.3 Fortinet FortiGate

```fortios
config vpn ipsec phase1-interface
    edit "SITE_B"
        set interface "wan1"
        set ike-version 2
        set peertype any
        set net-device disable
        set proposal aes256-sha256
        set dhgrp 14
        set remote-gw 203.0.113.2
        set psksecret ENC XXXX
    next
end

config vpn ipsec phase2-interface
    edit "SITE_B_P2"
        set phase1name "SITE_B"
        set proposal aes256-sha256
        set dhgrp 14
        set src-subnet 192.168.1.0 255.255.255.0
        set dst-subnet 192.168.2.0 255.255.255.0
    next
end
```

### 9.4 pfSense / OPNsense

Dans pfSense, IPsec se configure via l'interface web :
- VPN > IPsec > Tunnels
- Phase 1 : IKEv2, interface WAN, remote gateway, authentification par PSK ou certificat.
- Phase 2 : réseaux locaux et distants, proposals AES-256-GCM, SHA-256.
- Firewall > Rules > IPsec pour autoriser le trafic.

## 10. NAT Traversal (NAT-T)

Le NAT Traversal permet à IPsec de fonctionner lorsque l'un des pairs est derrière un NAT. Il encapsule IKE (UDP 500) et ESP (généralement UDP 4500) dans de l'UDP. La détection se fait via les payloads NAT-D et NAT-RAI.

```bash
# Ports à ouvrir
UDP 500  : IKE
UDP 4500 : NAT-T / IKEv2
ESP (IP 50) : si pas de NAT-T
AH (IP 51) : si pas de NAT-T
```

## 11. Dépannage IPsec

### 11.1 strongSwan

```bash
# Niveau de log
swanctl --log

# Vérifier la configuration
ipsec verify

# Détails des SAs
ipsec statusall

# Forcer une reconnexion
ipsec down siteA-siteB
ipsec up siteA-siteB

# Capturer les échanges IKE
tcpdump -i eth0 -n -s 0 -w ipsec.pcap udp port 500 or udp port 4500
```

### 11.2 Problèmes courants

- **PH1 ne s'établit pas** : vérifier les proposals, les clés PSK, les certificats, la connectivité UDP 500/4500.
- **PH1 OK mais pas PH2** : vérifier les subnets, les proposals ESP, les ACL/firewall.
- **Tunnel up mais pas de trafic** : vérifier les routes, les politiques de pare-feu, le NAT.
- **Performance faibles** : utiliser AES-GCM avec accélération matérielle, activer le offloading si disponible.

## 12. Sécurisation avancée d'IPsec

- Toujours utiliser IKEv2.
- Désactiver les groupes DH faibles (1, 2, 5, 22, 23, 24).
- Préférer AES-GCM avec authentification intégrée.
- Activer PFS avec ecp384 ou modp4096.
- Limiter les lifetimes (par exemple 8h pour IKE, 1h pour IPsec).
- Utiliser des certificats plutôt que des PSK.
- Surveiller les logs et configurer des alertes.

## 13. Cas d'usage avancés

### 13.1 VPN site-à-site redondant
Utiliser VRRP/HSRP sur les passerelles et configurer deux tunnels IPsec avec priorité/failover.

### 13.2 VPN d'accès distant avec MFA
Combiner IKEv2 + EAP-TLS ou EAP-PEAP avec un serveur RADIUS/NPS qui exige MFA.

### 13.3 Interconnexion cloud
AWS Site-to-Site VPN, Azure VPN Gateway, Google Cloud HA VPN utilisent tous IPsec/IKEv2.

### 13.4 Zero Trust Network Access (ZTNA)
IPsec peut servir de couche de transport sécurisée pour les architectures ZTNA, souvent combiné avec des agents et des policies dynamiques.

## 14. Commandes de vérification avancées

```bash
# Vérifier les politiques
ip xfrm policy

# Vérifier les états
ip xfrm state

# Statistiques
ip -s xfrm state

# Vérifier le parsing IKE
tcpdump -i any -n -s0 -vvv udp port 500 or udp port 4500

# Test de débit via le tunnel
iperf3 -c 192.168.2.10

# Vérifier MTU
ping -M do -s 1472 192.168.2.10
```

## 15. Références IPsec

- RFC 4301, 4302, 4303, 4306, 4308, 4309
- RFC 7296 - IKEv2
- RFC 4555 - MOBIKE
- RFC 7296bis
- strongSwan Documentation
- NIST SP 800-77 Rev 1 : Guide to IPsec VPNs

---
**Fin de l'annexe IPsec**
