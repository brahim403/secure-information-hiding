# Tessera — Décisions & hypothèses (journal)

Une ligne par décision. `D-xx` = décision ; les hypothèses non tranchées sont
marquées **à confirmer**.

## Déploiement

**D-01 — Correctifs des scripts CLI WildFly fournis.** Les originaux sont
conservés tels quels dans `infra/wildfly/cli/original/` ; les copies corrigées
sont dans `infra/wildfly/cli/`. Deux changements :
- CORS : `Access-Control-Allow-Origin` `*` → `%{i,Origin}` dans `default-host.cli`
  (un `*` avec `Access-Control-Allow-Credentials: true` est rejeté par les
  navigateurs ; l'origine est déjà filtrée par la regex du `predicate`).
- Parenthèse fermante ajoutée sur la ligne `corsRegex` de `default-host.cli` et
  `add-host.cli` (alignée sur `add-api.cli`). **Vérifié** : jboss-cli de WildFly 42
  *tolère* son absence (l'original s'applique aussi) — correction par rigueur.
Les deux scripts corrigés ont été appliqués sur un WildFly 42 local
(« batch executed successfully ») ; `Access-Control-Allow-Origin=%{i,Origin}`,
HSTS et redirection http→https confirmés.

**D-02 — Interface de management non publiée.** Ports 9990 (natif) et 9993
(HTTPS/remoting) liés au réseau interne, non exposés. Le cahier mentionnait 9990 ;
on aligne sur **9990 + 9993**.

**D-03 — Domaines placeholder.** `your-domain.local` (dev) / `your-domain.tld`
(prod) dans les `.properties` jusqu'à obtention des domaines réels.

**D-04 — TLS.** mkcert en dev, Let's Encrypt en prod ; TLS 1.3 (1.2 min), HSTS,
CAA (DNS), CRL/OCSP. **Non exécuté** ici (pas de VPS/DNS).

## Question ouverte

**Q-01 — « Éviter l'interruption par des applications malveillantes ».**
Interprétation retenue : protéger l'écran de connexion / l'invite biométrique du
détournement (overlay, clickjacking). Mesures web appliquées/prévues : CSP
`frame-ancestors 'none'`, `X-Frame-Options`, pas de script tiers, SRI. **À
confirmer** : la consigne vise-t-elle autre chose (p. ex. attaques inter-apps au
niveau OS) ?
