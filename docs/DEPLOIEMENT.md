# Tessera — Runbook de déploiement (WildFly 42)

> État : **validé en local** (WildFly 42 / Java 25). Les parties VPS / TLS de
> production sont écrites mais **non exécutées** dans ce dépôt (pas de VPS ni de
> DNS ici) ; elles sont marquées « non exécuté ».

## 1. Pré-requis

- Java 25 (Temurin), WildFly 42, Maven 3.9+.
- `JBOSS_HOME` pointant sur l'installation WildFly.
- Dev : certificats **mkcert**. Prod : certificats **Let's Encrypt**.

## 2. Build

```
export JAVA_HOME=/chemin/vers/jdk-25
mvn -B verify                      # compile + tests (dont le test d'archi REST)
# produit backend/api/target/tessera-api.war
```

## 3. Configuration de l'hôte + déploiement

Les scripts CLI WildFly de base sont dans `infra/wildfly/cli/` (copies **corrigées**;
originaux dans `infra/wildfly/cli/original/`). Un fichier `.properties` par
environnement dans `infra/wildfly/cli/properties/` (domaines à remplacer).

```
export JBOSS_HOME=/opt/wildfly
export WILDFLY_CONTROLLER=remote+https://votre-hote:9993   # prod ; défaut local 127.0.0.1:9990
infra/wildfly/scripts/deploy.sh dev        # ou: prod
```

`deploy.sh` applique `default-host.cli` (front office, en-têtes de sécurité,
CORS), `add-api.cli` pour les hôtes `api` et `iam`, puis déploie le WAR. Les
scripts peuvent aussi être appelés directement :

```
$JBOSS_HOME/bin/jboss-cli.sh --connect --controller=remote+https://votre-hote:9993 \
  --file=infra/wildfly/cli/default-host.cli \
  --properties=infra/wildfly/cli/properties/default-host-prod.properties
```

## 4. Corrections apportées aux scripts CLI

Voir `docs/DECISIONS.md` (D-01). En résumé, par rapport aux originaux :

- **CORS** : `Access-Control-Allow-Origin` passe de `*` à `%{i,Origin}` (un `*`
  avec `Access-Control-Allow-Credentials: true` est rejeté par les navigateurs ;
  l'origine est déjà filtrée par la regex `predicate`).
- **Parenthèse** : ajout de la `)` fermante manquante sur la ligne `corsRegex`
  de `default-host.cli` et `add-host.cli` (alignée sur `add-api.cli`).
  Remarque : jboss-cli de WildFly 42 **tolère** l'absence de cette parenthèse
  (le script original s'applique quand même) ; la correction est faite par
  rigueur, pas pour débloquer une erreur.

Vérifié en local : le script corrigé s'applique (« batch executed successfully »)
et `Access-Control-Allow-Origin` vaut bien `%{i,Origin}` ; HSTS et la
redirection http→https sont posés.

## 5. TLS (non exécuté ici)

- **Dev** : `mkcert -install` puis générer les certificats des domaines
  `*.your-domain.local`, les importer dans un keystore Elytron.
- **Prod** : **Let's Encrypt** (certbot) ; TLS 1.3 (1.2 min), HSTS (posé par le
  CLI), **CAA** dans la zone DNS, **CRL/OCSP** activés. mTLS pour les liens
  internes (broker/IAM) le cas échéant.
- `<transport-guarantee>CONFIDENTIAL</transport-guarantee>` dans
  `WEB-INF/web.xml` (durcissement transport).

## 6. Durcissement de l'interface de management

- Ports **9990** (management natif) et **9993** (management HTTPS/remoting) liés
  au **réseau interne uniquement**, **non publiés**. Seul HTTPS applicatif est
  exposé.
- Conteneur non-root, image épinglée par condensat (voir `.github`).

## 7. VPS (non exécuté ici)

Déploiement via SSH depuis GitHub Actions, secrets dans GitHub Secrets. Job et
étapes à ajouter sous `.github/workflows/` ; exécuté sur le VPS cible, pas ici.

## 8. Smoke test

```
curl -s -X POST https://api.your-domain.tld/app-context/api/v1/tickets \
  -H 'Content-Type: application/json' \
  -d '{"ownerId":"u1","eventId":"evt","gate":"B","seat":"A1","slot":"s"}'
# puis POST .../api/v1/scan/<id>  -> ADMITTED, puis DENIED
```

## 9. Mise à jour de WildFly

```
infra/wildfly/scripts/update-wildfly.sh 42.0.1.Final   # garde l'ancien pour rollback
```
