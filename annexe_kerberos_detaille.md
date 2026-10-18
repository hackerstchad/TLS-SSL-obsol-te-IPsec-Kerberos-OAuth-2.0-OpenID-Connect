# Annexe 3 : Kerberos en profondeur

## A3.1 Génèse et philosophie de Kerberos

Kerberos tire son nom du chien à trois têtes de la mythologie grecque, gardien des enfers. Cette métaphore illustre les trois acteurs du protocole : le client, le service et le KDC. Le protocole a été conçu pour résoudre le problème de l'authentification dans des réseaux non sécurisés où les mots de passe ne doivent jamais transiter en clair.

### A3.2 Principes fondamentaux

1. **Single Sign-On (SSO)** : un seul ticket (TGT) permet d'accéder à de multiples services.
2. **Confiance centralisée** : tous les principals font confiance au KDC.
3. **Tickets horodatés** : limitent la durée de vie des preuves d'identité.
4. **Cryptographie symétrique** : chaque principal partage un secret avec le KDC.
5. **Mutual authentication** : le client et le service peuvent s'authentifier mutuellement.

### A3.3 Cycle de vie d'un ticket Kerberos

```
AS-REQ  -->  AS-REP (TGT)  -->  TGS-REQ  -->  TGS-REP (service ticket)  -->  AP-REQ  -->  accès
```

### A3.4 Format d'un principal Kerberos

```
primary/instance@REALM
```

Exemples :
- `jdoe@EXAMPLE.COM` (utilisateur)
- `HTTP/web.example.com@EXAMPLE.COM` (service web)
- `host/server.example.com@EXAMPLE.COM` (service hôte)

### A3.5 Types de tickets

| Type | Description |
|------|-------------|
| TGT | Ticket Granting Ticket, obtenu auprès de l'AS |
| Service ticket | Ticket pour un service spécifique, obtenu auprès du TGS |
| Renewable ticket | Peut être renouvelé sans réauthentification |
| Forwardable ticket | Peut être transféré à une autre machine |
| Proxiable ticket | Permet à un service d'obtenir des tickets au nom du client |

### A3.6 Configuration avancée MIT Kerberos

```ini
[libdefaults]
    default_realm = EXAMPLE.COM
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    proxiable = false
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    default_tkt_enctypes = aes256-cts-hmac-sha1-96
    default_tgs_enctypes = aes256-cts-hmac-sha1-96

[realms]
    EXAMPLE.COM = {
        kdc = kdc1.example.com:88
        kdc = kdc2.example.com:88
        admin_server = kdc1.example.com:749
        default_domain = example.com
    }

[domain_realm]
    .example.com = EXAMPLE.COM
    example.com = EXAMPLE.COM

[logging]
    kdc = FILE:/var/log/krb5kdc.log
    admin_server = FILE:/var/log/kadmin.log
    default = FILE:/var/log/krb5lib.log
```

### A3.7 Installation d'un KDC MIT sur Linux

```bash
# Debian/Ubuntu
sudo apt install krb5-kdc krb5-admin-server

# Créer le realm
sudo krb5_newrealm

# Démarrer les services
sudo systemctl enable --now krb5-kdc krb5-admin-server

# Créer un principal administrateur
sudo kadmin.local -q "addprinc admin/admin@EXAMPLE.COM"

# Créer un principal utilisateur
sudo kadmin.local -q "addprinc jdoe@EXAMPLE.COM"

# Créer un principal service
sudo kadmin.local -q "addprinc -randkey HTTP/web.example.com@EXAMPLE.COM"
sudo kadmin.local -q "ktadd -k /etc/apache2/web.keytab HTTP/web.example.com@EXAMPLE.COM"
```

### A3.8 Intégration Kerberos avec Apache

```apache
<Directory /var/www/html>
    AuthType GSSAPI
    AuthName "Kerberos Login"
    GssapiCredStore keytab:/etc/apache2/web.keytab
    GssapiLocalName On
    Require valid-user
</Directory>
```

### A3.9 Intégration Kerberos avec Nginx

```nginx
location / {
    auth_gss on;
    auth_gss_keytab /etc/nginx/web.keytab;
    auth_gss_realm EXAMPLE.COM;
}
```

### A3.10 Intégration Kerberos avec SSH (GSSAPI)

```bash
# /etc/ssh/sshd_config
GSSAPIAuthentication yes
GSSAPICleanupCredentials yes
UsePAM yes

# /etc/ssh/ssh_config
GSSAPIAuthentication yes
GSSAPIDelegateCredentials yes
```

### A3.11 Intégration Kerberos avec PostgreSQL

```bash
# postgresql.conf
krb_server_keyfile = '/etc/postgresql/pg.keytab'

# pg_hba.conf
hostgssenc  all  all  0.0.0.0/0  gss include_realm=0 krb_realm=EXAMPLE.COM
```

### A3.12 Intégration Kerberos avec Hadoop

Hadoop Security (Kerberos) requiert :
- Un KDC opérationnel.
- Des keytabs pour NameNode, DataNode, ResourceManager, NodeManager.
- La propriété `hadoop.security.authentication` définie à `kerberos`.
- Des principaux tels que `hdfs/_HOST@REALM`, `yarn/_HOST@REALM`, `mapred/_HOST@REALM`.

### A3.13 Attaques sur Kerberos et défenses

#### Kerberoasting
Un attaquant authentifié demande des TGS pour des services et tente de cracker offline leurs mots de passe.

**Défenses :**
- Utiliser des mots de passe forts pour les comptes de service.
- Activer AES256, désactiver RC4 et DES.
- Surveiller les demandes de TGS inhabituelles.
- Utiliser des comptes gMSA (Windows) ou des mots de passe aléatoires.

#### AS-REP Roasting
Exploite les comptes qui n'ont pas besoin de pré-authentification Kerberos.

**Défenses :**
- Ne jamais désactiver la pré-authentification.
- Identifier les comptes `DONT_REQ_PREAUTH`.

#### Golden Ticket
Un attaquant disposant du hash KRBTGT peut forger des TGT illimités.

**Défenses :**
- Changer régulièrement le mot de passe KRBTGT (deux fois pour invalidation).
- Surveiller les tickets anormaux (durée de vie, groupes SID).
- Segmenter les privilèges administratifs.

#### Silver Ticket
Un attaquant forge un ticket de service en connaissant le hash d'un compte de service.

**Défenses :**
- Rotation fréquente des mots de passe de service.
- Surveillance des accès aux ressources sensibles.

#### Pass-the-Ticket
Réutilisation de tickets volés.

**Défenses :**
- Limiter la délégation Kerberos.
- Activer Credential Guard (Windows).
- Surveiller les mouvements latéraux.

### A3.14 Commandes avancées Kerberos

```bash
# Lister les tickets avec détails
klist -ef

# Afficher le contenu d'un keytab
ktutil
ktutil:  read_kt /etc/keytab
ktutil:  list -e -t

# Renouveler un ticket
kinit -R jdoe@EXAMPLE.COM

# Initialiser avec un keytab
kinit -kt /etc/service.keytab service/web.example.com@EXAMPLE.COM

# Vérifier les SPN Windows
setspn -L domain\serviceaccount

# Rechercher des SPN pour Kerberoasting (PowerView)
Get-NetUser -SPN | Select samaccountname, serviceprincipalname

# Changer le mot de passe KRBTGT (deux fois)
net user krbtgt /domain
```

### A3.15 Haute disponibilité du KDC

- Déployer plusieurs KDC maîtres et esclaves.
- Utiliser `kprop` pour propager la base de données.
- Configurer les clients avec plusieurs entrées `kdc`.
- Windows : tous les DC sont des KDC par défaut.

### A3.16 PKINIT : Kerberos avec certificats

PKINIT permet d'utiliser des certificats X.509 pour l'authentification initiale au lieu d'un mot de passe. Requiert une infrastructure PKI.

```bash
# Activer PKINIT sur le KDC
kdcdefaults]
    pkinit_identity = FILE:/etc/krb5kdc/kdc.crt,/etc/krb5kdc/kdc.key
    pkinit_anchors = FILE:/etc/krb5kdc/ca.crt
```

### A3.17 Constrained Delegation vs Unconstrained Delegation

| Type | Risque | Utilisation |
|------|--------|-------------|
| Unconstrained Delegation | Très élevé | À éviter |
| Constrained Delegation | Moyen | Limitée à des SPN spécifiques |
| Resource-Based Constrained Delegation | Moyen | Géré côté ressource |

### A3.18 Outils pour Kerberos

- **kinit / klist / kdestroy / kadmin / ktutil** : outils MIT standard.
- **Rubeus** : outil d'interaction Kerberos pour Windows.
- **Impacket** : scripts Python pour les attaques Kerberos (GetUserSPNs.py).
- **BloodHound** : cartographie des relations de délégation Kerberos.
- **Mimikatz** : extraction de tickets.
- **PowerView / PowerUpSQL** : énumération Active Directory.

### A3.19 Table de dépannage Kerberos

| Symptôme | Cause probable | Solution |
|----------|---------------|----------|
| `kinit` échoue | Mauvais mot de passe / heure désynchronisée | Vérifier NTP, réinitialiser le mot de passe |
| `klist` vide | Ticket expiré ou jamais obtenu | Relancer `kinit` |
| Service refuse l'accès | Mauvais SPN / keytab incorrect | Vérifier `setspn -L`, régénérer le keytab |
| Erreur de realm | Mauvaise résolution DNS / krb5.conf | Vérifier `[domain_realm]` |
| Golden Ticket suspect | Compromission du KRBTGT | Changer deux fois le mot de passe KRBTGT |

### A3.20 Références Kerberos

- RFC 4120 - Kerberos Network Authentication Service V5
- RFC 4556 - PKINIT
- RFC 4121 - GSS-API Kerberos Mechanism
- RFC 5021 - Extended Kerberos Version 5 Key Distribution Center
- MIT Kerberos Documentation : https://web.mit.edu/kerberos/www/docs.html
- Microsoft Kerberos Authentication Overview

---

*Auteur : hackers_tchad - Date : 2026*
