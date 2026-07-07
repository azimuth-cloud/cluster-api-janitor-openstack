# Réécriture du projet en Go

## Contexte

Le projet actuel est écrit en Python (asyncio + kopf + easykube + httpx). C'est un opérateur Kubernetes qui nettoie les ressources OpenStack laissées par l'OCCM et le CSI Cinder lors de la suppression de clusters Cluster API.

La réécriture suit la méthode TDD : les tests Gherkin sont écrits en premier, puis les implémentations.

Outil de scaffolding : **kubebuilder** (skill disponible).

---

## Audit du code Python existant

### Modules principaux

| Fichier | Rôle |
|---|---|
| `capi_janitor/openstack/openstack.py` | Client OpenStack : authentification, catalogue de services, ressources REST paginées |
| `capi_janitor/openstack/operator.py` | Logique opérateur : handlers kopf, filtres de ressources, purge OpenStack |

### Fonctionnalités couvertes

**Authentification OpenStack**
- Uniquement `v3applicationcredential`
- Gestion du token X-Auth-Token (refresh avec mutex asyncio)
- Support certificat CA personnalisé (cacert depuis le secret K8s)
- Catalogue de services filtré par interface (public/internal/admin) et région

**Filtrage des ressources à nettoyer**
- Floating IPs : description `"Floating IP for Kubernetes external service … from cluster <name>"`
- Load Balancers Octavia : nom `kube_service_<cluster>_*`
- Security Groups : description `"Security Group for Service LoadBalancer in cluster <name>"`
- Volumes Cinder : métadonnée `cinder.csi.openstack.org/cluster == <name>`, sauf propriété `janitor.capi.azimuth-cloud.com/keep == true`
- Snapshots Cinder : même métadonnée cluster

**Politique de suppression**
- Volumes : configurable via env var `CAPI_JANITOR_DEFAULT_VOLUMES_POLICY` (défaut `delete`) et annotation `janitor.capi.stackhpc.com/volumes-policy` par cluster
- Application Credential : supprimé si annotation `janitor.capi.stackhpc.com/credential-policy: delete` sur le secret ET si c'est le dernier finalizer

**Lifecycle Kubernetes**
- Finalizer `janitor.capi.stackhpc.com` sur `OpenStackCluster`
- Nom du cluster : label `cluster.x-k8s.io/cluster-name` en priorité, sinon `metadata.name`
- Retry via annotation aléatoire `janitor.capi.stackhpc.com/retry` (déclenche un nouvel événement)
- Backoff configurable `CAPI_JANITOR_RETRY_DEFAULT_DELAY` (défaut 60s)

**Gestion des erreurs**
- HTTP 400/409 lors de la suppression : retry silencieux
- HTTP 404 lors de la récupération du catalogue : authentification considérée comme échouée (sans erreur fatale)
- HTTP 422 lors du patch des finalizers : `TemporaryError` kopf
- Erreur catalogue `volumev3` → fallback sur `block-storage`

### Tests existants

| Fichier | Ce qui est testé |
|---|---|
| `test_openstack.py` | Authentification réussie, 404, absence d'interface, absence de région, multiples services |
| `test_operator.py` | Filtrage FIPs, LBs, SGs, volumes, snapshots ; `empty()` ; `try_delete()` ; handler d'événement (ajout finalizer, skip, purge) ; erreur d'auth dans purge |

**Lacune notable** : `test_purge_openstack_resources_success` est commenté (complexité du mock).

### Chart Helm

- `ClusterRole` : namespaces (list/watch), events (create), secrets (get/delete), openstackclusters (list/get/watch/patch), CRDs (list/get/watch)
- Valeur `defaultVolumesPolicy: delete`
- Image : `ghcr.io/azimuth-cloud/cluster-api-janitor-openstack`

### PRs en attente à intégrer

| PR | Titre | Impact |
|---|---|---|
| #261 | Fix leaving Azimuth cluster loadbalancers behind | Ajoute la détection des LBs Azimuth (`kube_service_<cluster>_` + LBs nommés différemment par Azimuth) |

---

## Feuille de route agile

---

### Epic 1 — Authentification OpenStack

#### US1.1 — Authentification via Application Credential v3

```gherkin
Feature: Authentification OpenStack via Application Credential
  In order to accéder aux APIs OpenStack
  As an opérateur
  I want to m'authentifier avec un Application Credential v3

  Scenario: Authentification réussie
    Given un clouds.yaml avec auth_type "v3applicationcredential"
    And un application_credential_id et application_credential_secret valides
    When l'opérateur initialise la connexion OpenStack
    Then un token X-Auth-Token est obtenu depuis Keystone
    And le catalogue de services est chargé

  Scenario: Refresh du token lors d'une expiration
    Given un token X-Auth-Token expiré
    When l'opérateur effectue un appel API
    Then un nouveau token est demandé à Keystone
    And l'appel original est rejoué avec le nouveau token

  Scenario: Authentification avec un type non supporté
    Given un clouds.yaml avec auth_type "password"
    When l'opérateur tente de créer un client Cloud
    Then une erreur UnsupportedAuthenticationError est levée
```

#### US1.2 — Filtrage du catalogue de services par interface et région

```gherkin
Feature: Catalogue de services OpenStack
  Scenario: Endpoint sélectionné selon l'interface configurée
    Given un catalogue avec des endpoints "public" et "internal"
    And l'interface configurée est "public"
    When le catalogue est chargé
    Then seuls les endpoints "public" sont retenus

  Scenario: Endpoint sélectionné selon la région configurée
    Given un catalogue avec des endpoints pour "RegionOne" et "RegionTwo"
    And la région configurée est "RegionOne"
    When le catalogue est chargé
    Then seuls les endpoints de "RegionOne" sont retenus

  Scenario: Aucune région configurée
    Given un catalogue avec des endpoints dans plusieurs régions
    And aucune région n'est configurée
    When le catalogue est chargé
    Then le premier endpoint correspondant à l'interface est retenu pour chaque service
```

#### US1.3 — Gestion d'un credential révoqué ou invalide

```gherkin
Feature: Credential OpenStack invalide
  Scenario: Application credential supprimé avant la purge
    Given un cluster OpenStack en cours de suppression
    And l'application credential a déjà été supprimé
    When l'opérateur tente de s'authentifier
    Then is_authenticated retourne false
    And si include_appcred est true, un warning est émis et la purge s'arrête proprement
    And si include_appcred est false, une AuthenticationError est levée

  Scenario: Catalogue retourne 404
    Given une URL Keystone valide mais le catalogue retourne 404
    When l'opérateur charge le catalogue
    Then is_authenticated retourne false
    And aucune erreur fatale n'est levée
```

#### US1.4 — Support des certificats CA personnalisés

```gherkin
Feature: Certificat CA personnalisé
  Scenario: CA fourni dans le secret Kubernetes
    Given un secret Kubernetes contenant une entrée "cacert"
    When l'opérateur initialise le transport TLS
    Then le CA est chargé dans le contexte SSL
    And les appels HTTPS vers OpenStack utilisent ce CA pour la vérification

  Scenario: Pas de CA fourni
    Given un secret Kubernetes sans entrée "cacert"
    When l'opérateur initialise le transport TLS
    Then le CA système est utilisé pour la vérification TLS
```

---

### Epic 2 — Nettoyage des Floating IPs

#### US2.1 — Identifier les Floating IPs d'un cluster

```gherkin
Feature: Identification des Floating IPs d'un cluster
  Scenario: FIP appartenant au cluster
    Given une liste de Floating IPs OpenStack
    And une FIP avec la description "Floating IP for Kubernetes external service from cluster mycluster"
    When les FIPs du cluster "mycluster" sont listées
    Then cette FIP est incluse dans le résultat

  Scenario: FIP d'un autre cluster
    Given une FIP avec la description "Floating IP for Kubernetes external service from cluster othercluster"
    When les FIPs du cluster "mycluster" sont listées
    Then cette FIP est exclue du résultat

  Scenario: FIP sans description Kubernetes
    Given une FIP avec la description "Some other description"
    When les FIPs du cluster "mycluster" sont listées
    Then cette FIP est exclue du résultat
```

#### US2.2 — Supprimer les Floating IPs

```gherkin
Feature: Suppression des Floating IPs
  Scenario: Suppression réussie
    Given une FIP appartenant au cluster "mycluster"
    When la purge des FIPs est déclenchée
    Then la FIP est supprimée via l'API Neutron
    And un log INFO est émis

  Scenario: Erreur HTTP 400 lors de la suppression
    Given une suppression de FIP retourne HTTP 400
    When la purge tente de supprimer la FIP
    Then un warning est émis
    And la suppression continue pour les autres FIPs
    And check_fips est true pour déclencher une vérification

  Scenario: Erreur HTTP 500 lors de la suppression
    Given une suppression de FIP retourne HTTP 500
    When la purge tente de supprimer la FIP
    Then une exception est propagée
```

---

### Epic 3 — Nettoyage des Load Balancers Octavia

#### US3.1 — Identifier les Load Balancers Kubernetes d'un cluster

```gherkin
Feature: Identification des Load Balancers Kubernetes
  Scenario: LB appartenant au cluster
    Given un LB avec le nom "kube_service_mycluster_api"
    When les LBs du cluster "mycluster" sont listés
    Then ce LB est inclus dans le résultat

  Scenario: LB d'un autre cluster
    Given un LB avec le nom "kube_service_othercluster_api"
    When les LBs du cluster "mycluster" sont listés
    Then ce LB est exclu du résultat

  Scenario: LB sans préfixe kube_service
    Given un LB avec le nom "fake_service_mycluster_api"
    When les LBs du cluster "mycluster" sont listés
    Then ce LB est exclu du résultat
```

#### US3.2 — Identifier les Load Balancers Azimuth (PR #261)

```gherkin
Feature: Identification des Load Balancers Azimuth
  Scenario: LB Azimuth appartenant au cluster
    Given un LB Azimuth identifiable comme appartenant au cluster "mycluster"
    When les LBs du cluster "mycluster" sont listés
    Then ce LB Azimuth est inclus dans le résultat

  Scenario: Erreur HTTP lors du listing des LBs
    Given l'API Octavia retourne une erreur HTTP lors du listing
    When les LBs du cluster "mycluster" sont listés
    Then un log ERROR est émis avec le code HTTP
    And aucune exception n'est propagée
    And un warning indique que des LBs pourraient rester
```

#### US3.3 — Supprimer les Load Balancers en cascade

```gherkin
Feature: Suppression des Load Balancers en cascade
  Scenario: Suppression réussie avec cascade
    Given un LB appartenant au cluster "mycluster"
    When la purge des LBs est déclenchée
    Then le LB est supprimé avec le paramètre cascade=true
    And les ressources Octavia associées (listeners, pools, membres) sont supprimées
```

---

### Epic 4 — Nettoyage des Security Groups

#### US4.1 — Identifier les Security Groups d'un cluster

```gherkin
Feature: Identification des Security Groups d'un cluster
  Scenario: SG appartenant au cluster
    Given un SG avec la description "Security Group for Service LoadBalancer in cluster mycluster"
    When les SGs du cluster "mycluster" sont listés
    Then ce SG est inclus dans le résultat

  Scenario: SG d'un autre cluster
    Given un SG avec la description "Security Group for Service LoadBalancer in cluster othercluster"
    When les SGs du cluster "mycluster" sont listés
    Then ce SG est exclu du résultat
```

#### US4.2 — Supprimer les Security Groups

```gherkin
Feature: Suppression des Security Groups
  Scenario: Suppression réussie
    Given un SG appartenant au cluster "mycluster"
    When la purge des SGs est déclenchée
    Then le SG est supprimé via l'API Neutron

  Scenario: SG encore utilisé (HTTP 409)
    Given une suppression de SG retourne HTTP 409
    When la purge tente de supprimer le SG
    Then un warning est émis
    And check_secgroups est true pour une vérification ultérieure
```

---

### Epic 5 — Gestion des Volumes Cinder

#### US5.1 — Identifier les volumes d'un cluster

```gherkin
Feature: Identification des volumes Cinder d'un cluster
  Scenario: Volume appartenant au cluster sans marquage keep
    Given un volume avec la métadonnée "cinder.csi.openstack.org/cluster" = "mycluster"
    And la propriété "janitor.capi.azimuth-cloud.com/keep" est absente ou != "true"
    When les volumes du cluster "mycluster" sont listés
    Then ce volume est inclus dans le résultat

  Scenario: Volume marqué keep par l'utilisateur
    Given un volume avec la métadonnée "cinder.csi.openstack.org/cluster" = "mycluster"
    And la propriété "janitor.capi.azimuth-cloud.com/keep" = "true"
    When les volumes du cluster "mycluster" sont listés
    Then ce volume est exclu du résultat

  Scenario: Volume d'un autre cluster
    Given un volume avec la métadonnée "cinder.csi.openstack.org/cluster" = "othercluster"
    When les volumes du cluster "mycluster" sont listés
    Then ce volume est exclu du résultat

  Scenario: Volume sans métadonnée CSI
    Given un volume sans métadonnée "cinder.csi.openstack.org/cluster"
    When les volumes du cluster "mycluster" sont listés
    Then ce volume est exclu du résultat
```

#### US5.2 — Politique de suppression des volumes

```gherkin
Feature: Politique de suppression des volumes
  Scenario: Politique globale "delete" (défaut)
    Given la variable d'environnement CAPI_JANITOR_DEFAULT_VOLUMES_POLICY non définie
    When un cluster est supprimé sans annotation de volumes
    Then les volumes du cluster sont supprimés

  Scenario: Politique globale "keep"
    Given CAPI_JANITOR_DEFAULT_VOLUMES_POLICY = "keep"
    When un cluster est supprimé sans annotation de volumes
    Then les volumes du cluster sont conservés

  Scenario: Annotation "delete" sur le cluster (override keep global)
    Given CAPI_JANITOR_DEFAULT_VOLUMES_POLICY = "keep"
    And l'annotation "janitor.capi.stackhpc.com/volumes-policy" = "delete" sur l'OpenStackCluster
    When le cluster est supprimé
    Then les volumes du cluster sont supprimés

  Scenario: Annotation "keep" sur le cluster (override delete global)
    Given CAPI_JANITOR_DEFAULT_VOLUMES_POLICY = "delete"
    And l'annotation "janitor.capi.stackhpc.com/volumes-policy" = "keep" sur l'OpenStackCluster
    When le cluster est supprimé
    Then les volumes du cluster sont conservés
```

---

### Epic 6 — Gestion des Snapshots Cinder

#### US6.1 — Identifier et supprimer les snapshots d'un cluster

```gherkin
Feature: Snapshots Cinder d'un cluster
  Scenario: Snapshot appartenant au cluster
    Given un snapshot avec la métadonnée "cinder.csi.openstack.org/cluster" = "mycluster"
    When les snapshots du cluster "mycluster" sont listés
    Then ce snapshot est inclus dans le résultat

  Scenario: Snapshot d'un autre cluster
    Given un snapshot avec la métadonnée "cinder.csi.openstack.org/cluster" = "othercluster"
    When les snapshots du cluster "mycluster" sont listés
    Then ce snapshot est exclu du résultat

  Scenario: Snapshots supprimés avant les volumes
    Given des snapshots et des volumes appartenant au cluster "mycluster"
    When la purge est déclenchée avec include_volumes = true
    Then les snapshots sont supprimés en premier
    And les volumes sont supprimés ensuite
```

---

### Epic 7 — Gestion des Application Credentials

#### US7.1 — Supprimer l'Application Credential OpenStack

```gherkin
Feature: Suppression de l'Application Credential
  Scenario: Suppression autorisée (dernier finalizer)
    Given l'annotation "janitor.capi.stackhpc.com/credential-policy" = "delete" sur le secret
    And le finalizer de l'opérateur est le seul finalizer présent
    When la purge des ressources OpenStack est terminée
    Then l'Application Credential est supprimé via l'API Identity
    And le secret Kubernetes contenant clouds.yaml est supprimé

  Scenario: Autres finalizers encore présents
    Given l'annotation "credential-policy" = "delete" sur le secret
    And d'autres finalizers sont encore présents sur l'OpenStackCluster
    When la purge est terminée
    Then l'Application Credential n'est pas supprimé
    And une FinalizerStillPresentError est levée pour déclencher un retry

  Scenario: Application Credential non supprimable (403)
    Given l'Application Credential est restreint (pas d'unrestricted)
    When la suppression de l'appcred est tentée
    Then un warning est émis
    And la suppression du secret Kubernetes procède quand même
```

---

### Epic 8 — Lifecycle Kubernetes (pattern Finalizer)

#### US8.1 — Ajouter un finalizer à la création

```gherkin
Feature: Ajout du finalizer janitor sur OpenStackCluster
  Scenario: Cluster sans deletionTimestamp et sans finalizer janitor
    Given un OpenStackCluster sans deletionTimestamp
    And sans finalizer "janitor.capi.stackhpc.com"
    When un événement est reçu pour ce cluster
    Then le finalizer "janitor.capi.stackhpc.com" est ajouté via patch
    And un log INFO confirme l'ajout

  Scenario: Cluster avec finalizer déjà présent
    Given un OpenStackCluster sans deletionTimestamp
    And avec le finalizer "janitor.capi.stackhpc.com" déjà présent
    When un événement est reçu
    Then aucun patch n'est effectué
```

#### US8.2 — Nom du cluster depuis le label ou metadata.name

```gherkin
Feature: Résolution du nom du cluster
  Scenario: Label cluster.x-k8s.io/cluster-name présent
    Given un OpenStackCluster avec le label "cluster.x-k8s.io/cluster-name" = "myapp"
    And metadata.name = "myapp-openstack"
    When l'opérateur résout le nom du cluster pour le nettoyage
    Then le nom "myapp" est utilisé

  Scenario: Label absent
    Given un OpenStackCluster sans label "cluster.x-k8s.io/cluster-name"
    And metadata.name = "mycluster"
    When l'opérateur résout le nom du cluster
    Then le nom "mycluster" est utilisé
```

#### US8.3 — Supprimer le finalizer après nettoyage réussi

```gherkin
Feature: Suppression du finalizer après purge
  Scenario: Purge réussie
    Given un OpenStackCluster en cours de suppression
    And toutes les ressources OpenStack ont été supprimées
    When la purge est terminée sans erreur
    Then le finalizer "janitor.capi.stackhpc.com" est retiré via patch
    And un log INFO confirme la suppression du finalizer

  Scenario: Finalizer absent au moment de la suppression
    Given un OpenStackCluster avec deletionTimestamp
    And sans finalizer "janitor.capi.stackhpc.com"
    When un événement est reçu
    Then aucune purge n'est déclenchée
    And un log INFO indique que le finalizer est absent
```

#### US8.4 — Mécanisme de retry via annotation

```gherkin
Feature: Retry via annotation aléatoire
  Scenario: Erreur temporaire lors de la purge
    Given une purge qui échoue avec une ResourcesStillPresentError
    When l'opérateur gère l'erreur
    Then après un délai de backoff (5s pour ResourcesStillPresent)
    And une annotation aléatoire "janitor.capi.stackhpc.com/retry" est posée sur l'OpenStackCluster
    And un nouvel événement est déclenché pour rejouer la purge

  Scenario: Erreur inconnue lors de la purge
    Given une purge qui échoue avec une exception non classifiée
    When l'opérateur gère l'erreur
    Then le délai est CAPI_JANITOR_RETRY_DEFAULT_DELAY (défaut 60s)
    And l'exception est loguée avec stack trace

  Scenario: Ressource supprimée entre l'erreur et le retry
    Given l'OpenStackCluster est supprimé pendant le backoff
    When l'opérateur tente d'annoter la ressource
    Then l'ApiError 404 est ignorée
```

---

### Epic 9 — Configuration de l'opérateur

#### US9.1 — Configuration via variables d'environnement

```gherkin
Feature: Configuration via variables d'environnement
  Scenario: Politique volumes par défaut configurée
    Given CAPI_JANITOR_DEFAULT_VOLUMES_POLICY = "keep"
    When l'opérateur démarre
    Then la politique par défaut pour tous les clusters est "keep"

  Scenario: Délai de retry configurable
    Given CAPI_JANITOR_RETRY_DEFAULT_DELAY = "120"
    When une erreur non classifiée se produit
    Then le délai de retry est 120 secondes
```

---

### Epic 10 — Packaging et déploiement

#### US10.1 — Image Docker

```gherkin
Feature: Image Docker de l'opérateur
  Scenario: Build et push de l'image
    Given le code source de l'opérateur Go
    When le workflow GitHub Actions build-push-artifacts est déclenché
    Then une image est publiée sur ghcr.io/azimuth-cloud/cluster-api-janitor-openstack
    And l'image est taguée avec la version du chart

  Scenario: Sécurité de l'image
    Given l'image Docker
    Then le processus tourne en tant que non-root
    And le système de fichiers racine est en lecture seule
    And toutes les capabilities Linux sont droppées
```

#### US10.2 — Helm chart

```gherkin
Feature: Déploiement via Helm chart
  Scenario: Installation avec les valeurs par défaut
    Given le Helm chart cluster-api-janitor-openstack
    When helm install est exécuté
    Then un Deployment, ServiceAccount, ClusterRole et ClusterRoleBinding sont créés
    And la politique volumes par défaut est "delete"

  Scenario: Override de la politique volumes
    Given helm install avec --set defaultVolumesPolicy=keep
    When le chart est déployé
    Then la variable CAPI_JANITOR_DEFAULT_VOLUMES_POLICY = "keep" est injectée dans le pod
```

---

### Epic 11 — Observabilité (nouvelle fonctionnalité)

#### US11.1 — Métriques Prometheus

```gherkin
Feature: Métriques Prometheus
  Scenario: Comptage des purges réussies
    Given une purge de cluster réussie
    When les métriques sont exposées sur /metrics
    Then le compteur "janitor_purge_total{status=success}" est incrémenté

  Scenario: Comptage des ressources supprimées par type
    Given une purge ayant supprimé 3 FIPs, 2 LBs et 1 SG
    When les métriques sont exposées
    Then les jauges correspondantes reflètent les suppressions

  Scenario: Durée de purge
    Given une purge terminée
    When les métriques sont exposées
    Then un histogramme "janitor_purge_duration_seconds" contient la durée de la purge
```

#### US11.2 — Status conditions sur OpenStackCluster

```gherkin
Feature: Status conditions sur OpenStackCluster
  Scenario: Purge en cours
    Given une purge démarrée pour le cluster "mycluster"
    When la purge est en cours
    Then une condition "JanitorCleanupComplete" avec status "False" et reason "CleanupInProgress" est posée

  Scenario: Purge terminée avec succès
    Given une purge réussie
    When le finalizer est retiré
    Then la condition "JanitorCleanupComplete" passe à status "True"

  Scenario: Purge en erreur
    Given une purge échouant avec une erreur
    When l'erreur est gérée
    Then la condition "JanitorCleanupComplete" a status "False" et reason "CleanupFailed" avec un message d'erreur
```

---

### Epic 12 — Robustesse et extensibilité (nouvelles fonctionnalités)

#### US12.1 — Timeout configurable pour les appels OpenStack

```gherkin
Feature: Timeout HTTP configurable
  Scenario: Appel OpenStack qui dépasse le timeout
    Given CAPI_JANITOR_OPENSTACK_TIMEOUT = "30"
    When un appel API OpenStack dépasse 30 secondes
    Then le timeout est déclenché
    And une erreur temporaire est loguée pour retry
```

#### US12.2 — Support des services Cinder avec alias

```gherkin
Feature: Détection du service Cinder avec alias
  Scenario: Catalogue avec "volumev3"
    Given un catalogue OpenStack avec le service type "volumev3"
    When l'opérateur cherche le client Cinder
    Then le client "volumev3" est utilisé

  Scenario: Catalogue avec "block-storage" uniquement
    Given un catalogue OpenStack sans "volumev3" mais avec "block-storage"
    When l'opérateur cherche le client Cinder
    Then le client "block-storage" est utilisé

  Scenario: Catalogue sans service Cinder
    Given un catalogue sans "volumev3" ni "block-storage"
    When l'opérateur cherche le client Cinder
    Then une CatalogError est levée avec le message approprié
```

---

## Actions

1. [x] Réaliser un audit du code
2. [ ] Écrire la feuille de route agile (ce document)
3. [ ] Scaffolding du projet Go avec kubebuilder (`/kubebuilder`)
4. [ ] Écrire les tests Go (TDD) pour chaque user story
5. [ ] Implémenter les fonctionnalités en Go
6. [ ] Migrer le Helm chart pour l'image Go
7. [ ] Implémenter les epics 11 (observabilité) et 12 (robustesse)

## Ordre d'implémentation suggéré

```
Epic 1 (Auth) → Epic 2 (FIPs) → Epic 3 (LBs + PR #261)
→ Epic 4 (SGs) → Epic 5 (Volumes) → Epic 6 (Snapshots)
→ Epic 7 (AppCreds) → Epic 8 (Lifecycle K8s) → Epic 9 (Config)
→ Epic 10 (Packaging) → Epic 11 (Observabilité) → Epic 12 (Robustesse)
```
