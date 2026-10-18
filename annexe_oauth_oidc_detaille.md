# Annexe 4 : OAuth 2.0 et OpenID Connect en profondeur

## A4.1 Genèse d'OAuth 2.0

OAuth 2.0 est né du besoin de permettre aux utilisateurs d'autoriser des applications tierces à accéder à leurs ressources sans partager leurs mots de passe. Il a été standardisé par l'IETF en octobre 2012 (RFC 6749). OAuth 2.0 n'est pas un protocole d'authentification, mais un protocole d'autorisation.

### A4.2 Différence entre authentification et autorisation

| Concept | Définition | Exemple |
|---------|------------|---------|
| Authentification | Prouver qui vous êtes | Login avec mot de passe |
| Autorisation | Déterminer ce que vous pouvez faire | Accès à un agenda ou des contacts |

OAuth 2.0 fournit l'autorisation. OIDC ajoute l'authentification par-dessus OAuth 2.0.

### A4.3 Types de clients OAuth 2.0

| Type | Description | Exemples |
|------|-------------|----------|
| Confidential | Peut stocker un secret côté serveur | Application web traditionnelle |
| Public | Ne peut pas stocker de secret de manière sécurisée | SPA, mobile, desktop |

Les clients publics doivent obligatoirement utiliser PKCE.

### A4.4 Flux OAuth 2.0 en détail

#### A4.4.1 Authorization Code (RFC 6749)

```
1. Utilisateur clique sur "Se connecter avec..."
2. Redirection vers l'authorization server :
   GET /authorize?response_type=code&client_id=...&redirect_uri=...&scope=...&state=...
3. L'utilisateur s'authentifie et consent.
4. Redirection avec un authorization code.
5. Le client échange le code contre des tokens :
   POST /token
   grant_type=authorization_code&code=...&redirect_uri=...&client_id=...&client_secret=...
6. Réponse : access_token, refresh_token, id_token (OIDC), token_type, expires_in.
```

#### A4.4.2 Client Credentials (RFC 6749)

```bash
curl -X POST https://auth.example.com/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=API_CLIENT" \
  -d "client_secret=SECRET" \
  -d "scope=api:read"
```

Réponse :
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "api:read"
}
```

#### A4.4.3 Device Authorization Grant (RFC 8628)

Pour les appareils sans clavier (TV, IoT) :

```bash
# Étape 1 : demande de device code
POST /device_authorization
  client_id=TV_APP

Réponse :
{
  "device_code": "...",
  "user_code": "ABCD-EFGH",
  "verification_uri": "https://auth.example.com/device",
  "expires_in": 1800,
  "interval": 5
}

# Étape 2 : polling
POST /token
  grant_type=urn:ietf:params:oauth:grant-type:device_code
  device_code=...
  client_id=TV_APP
```

### A4.5 PKCE (RFC 7636)

PKCE (Proof Key for Code Exchange) protège le flux authorization code contre les attaques par interception du code.

```
Client génère :
  code_verifier  = random(128 octets)
  code_challenge = BASE64URL(SHA256(code_verifier))

Authorization Request :
  code_challenge=...&code_challenge_method=S256

Token Request :
  code_verifier=...
```

### A4.6 JWT, JWS, JWE, JWK, JWKS

| Acronyme | Signification | Rôle |
|----------|---------------|------|
| JWT | JSON Web Token | Format de token |
| JWS | JSON Web Signature | Signature des JWT |
| JWE | JSON Web Encryption | Chiffrement des JWT |
| JWK | JSON Web Key | Clé au format JSON |
| JWKS | JSON Web Key Set | Ensemble de JWK |

### A4.7 Structure d'un JWT

```
header.payload.signature
```

Exemple de header :
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "key-2026-01"
}
```

Exemple de payload (claims OIDC) :
```json
{
  "iss": "https://auth.example.com",
  "sub": "auth0|123456789",
  "aud": "monapp",
  "exp": 1735689600,
  "iat": 1735686000,
  "nonce": "n-0S6_WzA2Mj",
  "name": "Jean Dupont",
  "email": "jean.dupont@example.com",
  "email_verified": true,
  "groups": ["admins", "users"]
}
```

### A4.8 OpenID Connect Discovery

L'endpoint `.well-known/openid-configuration` fournit les métadonnées du provider :

```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/oauth/authorize",
  "token_endpoint": "https://auth.example.com/oauth/token",
  "userinfo_endpoint": "https://auth.example.com/oauth/userinfo",
  "jwks_uri": "https://auth.example.com/oauth/jwks",
  "response_types_supported": ["code", "token", "id_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256", "ES256"]
}
```

### A4.9 Scopes et claims OIDC

| Scope | Claims fournis |
|-------|----------------|
| openid | obligatoire, indique une requête OIDC |
| profile | name, family_name, given_name, middle_name, nickname, preferred_username, profile, picture, website, gender, birthdate, zoneinfo, locale, updated_at |
| email | email, email_verified |
| address | address |
| phone | phone_number, phone_number_verified |
| offline_access | refresh_token |

### A4.10 Configuration OAuth 2.0 / OIDC - Keycloak avancé

```bash
# Créer un realm
./kcadm.sh create realms -s realm=production -s enabled=true -s sslRequired=external

# Créer un client confidentiel
./kcadm.sh create clients -r production \
  -s clientId=webapp \
  -s 'redirectUris=["https://webapp.example.com/*"]' \
  -s 'webOrigins=["https://webapp.example.com"]' \
  -s publicClient=false \
  -s clientAuthenticatorType=client-secret \
  -s serviceAccountsEnabled=false \
  -s standardFlowEnabled=true \
  -s directAccessGrantsEnabled=false \
  -s protocol=openid-connect

# Activer PKCE pour un client public
./kcadm.sh update clients/CLIENT_ID -r production \
  -s attributes.pkceCodeChallengeMethod=S256

# Configurer un mapper de groupes
./kcadm.sh create clients/CLIENT_ID/protocol-mappers/models -r production \
  -s name=groups \
  -s protocol=openid-connect \
  -s protocolMapper=oidc-group-membership-mapper \
  -s 'config."full.path"=false' \
  -s 'config."id.token.claim"=true' \
  -s 'config."access.token.claim"=true' \
  -s 'config."claim.name"=groups'
```

### A4.11 Configuration OAuth 2.0 / OIDC - Spring Security

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .anyRequest().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2
                .userInfoEndpoint(userInfo -> userInfo
                    .oidcUserService(this.oidcUserService())
                )
            )
            .logout(logout -> logout
                .logoutSuccessUrl("/")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
            );
        return http.build();
    }

    private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        OidcUserService delegate = new OidcUserService();
        return (userRequest) -> {
            OidcUser oidcUser = delegate.loadUser(userRequest);
            Map<String, Object> claims = oidcUser.getClaims();
            // Mapper les groupes ou rôles personnalisés
            return oidcUser;
        };
    }
}
```

### A4.12 Configuration OAuth 2.0 / OIDC - Node.js (Passport + OpenID Client)

```javascript
const { Strategy } = require('openid-client');
const passport = require('passport');

const issuer = await Issuer.discover('https://auth.example.com/realms/production');
const client = new issuer.Client({
  client_id: 'webapp',
  client_secret: process.env.CLIENT_SECRET,
  redirect_uris: ['https://webapp.example.com/callback'],
  response_types: ['code'],
  token_endpoint_auth_method: 'client_secret_basic'
});

passport.use('oidc', new Strategy({ client }, (tokenset, userinfo, done) => {
  return done(null, { sub: tokenset.claims().sub, ...userinfo });
}));

app.get('/login', passport.authenticate('oidc', { scope: 'openid profile email' }));
app.get('/callback', passport.authenticate('oidc', {
  successRedirect: '/dashboard',
  failureRedirect: '/login'
}));
```

### A4.13 Configuration OAuth 2.0 / OIDC - Python (Authlib)

```python
from authlib.integrations.flask_client import OAuth

oauth = OAuth(app)
oauth.register(
    name='keycloak',
    client_id='webapp',
    client_secret='SECRET',
    server_metadata_url='https://auth.example.com/realms/production/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid profile email'}
)

@app.route('/login')
def login():
    redirect_uri = url_for('callback', _external=True)
    return oauth.keycloak.authorize_redirect(redirect_uri)

@app.route('/callback')
def callback():
    token = oauth.keycloak.authorize_access_token()
    user = token['userinfo']
    return f"Bonjour {user['name']}"
```

### A4.14 Sécurisation d'une API avec OAuth 2.0

```python
from functools import wraps
from jose import jwt
from jose.exceptions import JWTError

JWKS_URL = 'https://auth.example.com/realms/production/protocol/openid-connect/certs'

jwks = requests.get(JWKS_URL).json()

def require_scope(scope):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            try:
                payload = jwt.decode(token, jwks, algorithms=['RS256'], audience='webapp')
                token_scopes = payload.get('scope', '').split()
                if scope not in token_scopes:
                    abort(403)
            except JWTError:
                abort(401)
            return f(*args, **kwargs)
        return wrapper
    return decorator

@app.route('/api/data')
@require_scope('data:read')
def get_data():
    return jsonify({"message": "Accès autorisé"})
```

### A4.15 Refresh Token Rotation (RFC 6819, RFC 9700)

La rotation des refresh tokens limite l'impact d'une fuite. Chaque utilisation d'un refresh token génère un nouveau refresh token et invalide l'ancien.

### A4.16 Security Best Current Practices (OAuth 2.0 BCP, RFC 9700)

- Toujours utiliser HTTPS.
- Ne jamais utiliser le flux Implicit.
- Ne jamais utiliser le flux Resource Owner Password Credentials.
- Utiliser PKCE pour tous les clients, y compris confidentiels.
- Limiter la durée de vie des access tokens (courte).
- Utiliser des refresh tokens rotatifs.
- Valider `state`, `nonce`, `iss`, `aud`, `exp`.
- Enregistrer strictement les `redirect_uri`.
- Éviter les tokens dans les URLs.

### A4.17 Attaques OAuth 2.0 / OIDC et défenses

| Attaque | Mécanisme | Défense |
|---------|-----------|---------|
| Authorization code interception | Interception du code | PKCE |
| CSRF | Rejeu d'une URL de callback | Paramètre `state` |
| Replay d'ID Token | Rejeu d'un JWT | `nonce`, `iat`, `exp` |
| Token leakage | Fuite de token | HTTPS, scopes minimaux, durée courte |
| Redirect URI manipulation | Redirection vers un domaine attaquant | Liste blanche stricte |
| Consent phishing | Utilisateur trompé pour accorder des scopes | Éducation, scopes minimaux |

### A4.18 Fédération d'identités et SSO

OIDC permet le SSO entre plusieurs applications (Relying Parties) et un OpenID Provider commun. Les sessions peuvent être gérées via :
- Cookies de session côté OP.
- Front-channel logout.
- Back-channel logout.
- Session Management spec (iframe).

### A4.19 Commandes de test OAuth 2.0 / OIDC

```bash
# Découverte OIDC
curl https://auth.example.com/realms/production/.well-known/openid-configuration | jq

# Token client credentials
curl -X POST https://auth.example.com/realms/production/protocol/openid-connect/token \
  -d 'grant_type=client_credentials' \
  -d 'client_id=api-client' \
  -d 'client_secret=SECRET' \
  -d 'scope=api:read' | jq

# Décoder un JWT
jwt decode eyJhbGciOiJSUzI1NiIs...

# Introspection
curl -X POST https://auth.example.com/realms/production/protocol/openid-connect/token/introspect \
  -u api-client:SECRET \
  -d 'token=ACCESS_TOKEN' | jq

# Userinfo
curl -H 'Authorization: Bearer ACCESS_TOKEN' \
  https://auth.example.com/realms/production/protocol/openid-connect/userinfo | jq

# JWKS
curl https://auth.example.com/realms/production/protocol/openid-connect/certs | jq
```

### A4.20 Outils pour OAuth 2.0 / OIDC

- **Postman / Insomnia** : test manuel.
- **jwt.io / jwt.ms** : décodage JWT.
- **oidcdebugger.com** : débogage du flux authorization code.
- **Keycloak** : serveur d'identité open source.
- **ORY Hydra** : serveur OAuth 2.0 / OIDC.
- **Dex** : connecteur d'identité fédérée pour Kubernetes.
- **Auth0 / Okta** : Identity Providers cloud.
- **Spring Security / Authlib / Passport** : intégration applicative.

### A4.21 Références OAuth 2.0 / OIDC

- RFC 6749 - OAuth 2.0 Authorization Framework
- RFC 6750 - Bearer Token Usage
- RFC 6819 - OAuth 2.0 Threat Model and Security Considerations
- RFC 7636 - PKCE
- RFC 8252 - OAuth 2.0 for Native Apps
- RFC 8628 - OAuth 2.0 Device Authorization Grant
- RFC 9700 - OAuth 2.0 Security Best Current Practice
- OpenID Connect Core 1.0
- OpenID Connect Discovery 1.0
- OpenID Connect Session Management 1.0

---

*Auteur : hackers_tchad - Date : 2026*
