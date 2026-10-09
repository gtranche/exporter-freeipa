# Exportateur FreeIPA

Expose l'état de FreeIPA à Prometheus, et le présente dans un tableau Grafana.

Rien n'écoute sur le réseau : le script écrit un fichier que le collecteur
textfile du `node_exporter` déjà présent sur la machine sert avec ses propres
métriques. Tout passe par le socket local de l'annuaire, qui authentifie root
sans mot de passe — aucun secret n'est stocké ni manipulé.

Aucune valeur propre à un site n'est inscrite dans le dépôt. Les deux
grandeurs que FreeIPA connaît lui-même — l'instance dirsrv et le suffixe du
domaine — sont déduites de la machine ; le reste tient dans un fichier de
configuration. Une suite de tests le vérifie à chaque passage.

## Ce qui est mesuré

23 familles de séries, sous le préfixe `freeipa_` :

| domaine | séries |
|---|---|
| services | `freeipa_service_actif`, `freeipa_services_actifs`, `freeipa_services_total` |
| annuaire | connexions, fils, opérations, octets, liens par mode, recherches par portée, erreurs |
| caches | taux, occupation, plafond, entrées, accès et succès, pour chaque base et chaque cache |
| Kerberos | `freeipa_kerberos_requetes_total` par type, `freeipa_kerberos_echecs_total` |
| temps de réponse | `freeipa_temps_reponse_secondes` par interface : `ldap`, `ldap_liaison`, `ldap_premiere`, `api`, `interface` |
| contenu | utilisateurs par état, groupes, machines, groupes de machines, services, règles HBAC et sudo, zones DNS |
| machines | `freeipa_machine`, une série par machine enrôlée |
| certificats | `freeipa_certificat_expiration_timestamp` |
| collecte | `freeipa_collecte_reussie`, `_timestamp`, `_duree_secondes` |

Deux mesures méritent un mot.

`freeipa_temps_reponse_secondes{interface="ldap_premiere"}` existe parce que la
**première** recherche d'une connexion neuve coûte parfois 250 ms, par fenêtres
de plusieurs minutes. Relevé : le serveur annonce `wtime` au plus 0,045 s sur
300 opérations et `etime` 0,0001 s, tandis que le client attend dans `poll()` en
consommant 0,12 ms de processeur. L'annuaire n'est donc pas lent : c'est un coût
d'établissement, que l'alerte prenait pour de la lenteur. La mesure est publiée
à part, et le filtre de `FreeipaLdapLent` est ancré pour ne pas la reprendre.

`freeipa_ldap_cache_occupation_octets` face à `_plafond_octets` : un taux de
succès bas ne signale rien tant que le cache n'est pas plein — il veut seulement
dire que la base est peu lue. Ce qui compte est la conjonction, cache rempli
**et** lectures qui le manquent.

## Configuration

    cp configuration.env.exemple configuration.env

Puis ajuster. Le fichier est ignoré par git : ses valeurs ne quittent pas la
machine. Les valeurs fournies en exemple appartiennent aux plages réservées à la
documentation (RFC 5737, RFC 2606) et ne joignent rien.

Il porte l'adresse de la machine FreeIPA, le namespace, le nom de job et
l'étiquette d'hôte, le Deployment de Grafana, les chemins système — qui varient
d'une distribution à l'autre — et, si `kubectl` n'est pas sur ce poste, l'hôte
par lequel y accéder. Chaque script le lit et refuse de tourner si une valeur
manque : un manifeste à moitié rendu s'appliquerait sans erreur et superviserait
la mauvaise machine.

Ce qui n'y figure pas, et n'a pas à y figurer : l'instance dirsrv, cherchée dans
`/run`, et le suffixe du domaine, lu dans le `rootDSE`. Pour les imposer malgré
tout, `INSTANCE_DIRSRV` et `BASE_LDAP` dans
`/etc/sysconfig/exporter-freeipa` sur la machine.

## Poser l'exportateur sur la machine FreeIPA

Il a besoin de `ldapsearch` (paquet `openldap-clients`), `openssl`, `curl` et
Python 3.6 ou plus. `python-ldap`, s'il est là, sert à décomposer liaison et
recherche ; sinon le script retombe sur une mesure grossière plutôt que de ne
rien publier. Il tourne en root : le lien EXTERNAL sur le socket de l'annuaire
et la lecture du journal du KDC l'exigent.

    sudo install -m 755 exporter-freeipa.py /usr/local/bin/exporter-freeipa.py
    sudo install -m 644 systemd/exporter-freeipa.service systemd/exporter-freeipa.timer \
        /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable --now exporter-freeipa.timer

Le minuteur n'est **pas** `Persistent=true` : au démarrage, le rattrapage des
collectes manquées entrerait en concurrence avec `dirsrv` au moment où il a
besoin de la machine.

## Poser la supervision et le tableau

    ./poser-supervision.sh
    ./grafana/installer-tableau.sh

`poser-supervision.sh` rend le modèle et l'applique : `Service`, `Endpoints`,
`ServiceMonitor` et neuf alertes. Pour n'obtenir que le manifeste — à verser
dans un dépôt GitOps, par exemple :

    ./rendre.sh kubernetes/supervision.yaml.modele

Les `Endpoints` sont écrits à la main et non en `EndpointSlice` :
prometheus-operator lit les `Endpoints`, un slice seul lui serait invisible.

L'installeur de tableau pose un ConfigMap, puis un volume et un montage dans le
Deployment de Grafana : il n'y a pas de découverte automatique ici, chaque
tableau est un montage explicite. Il ne redémarre Grafana que si le montage
manquait, et il vérifie son effet dans le conteneur plutôt que le code retour du
patch. 21 panneaux, dont la source de données est une variable : Grafana la
demande à l'ouverture, aucun nom d'installation n'est figé.

## Vérifier

    ./verifier-deploiement.sh [cible-ssh]

Confronte l'empreinte du script déployé, les directives des deux unités, l'état
du minuteur, la fraîcheur du fichier de métriques et le succès de la dernière
collecte. Ne modifie rien, et sort en 1 s'il y a le moindre écart.

## Tests

    ./tester.sh

Six suites. Les cinq premières ne demandent rien d'autre que Python 3 et un
shell ; `SANS_ALERTES=1` saute la sixième.

`tests/test-exporter-freeipa.py` — 64 cas, sans annuaire ni parc ni
identifiant : format exposé et échappement, lecture des attributs, détection du
suffixe du domaine, identités lisibles, agrégation des connexions ouvertes,
compteurs Kerberos y compris la rotation du journal, écriture atomique, état des
services, caches, inventaire, machines, chemins système, et le cas où la
collecte échoue entièrement.

`tests/test-tableau.py` — ce qui casse en silence dans un tableau : une source
de données figée, qui rend des panneaux vides chez qui ne nomme pas la sienne
comme l'auteur, une mise en page qui déborde des 24 colonnes, deux panneaux qui
se recouvrent.

`tests/test-depot-public.py` — aucune adresse, aucun nom de domaine, aucun
suffixe d'annuaire et aucun royaume Kerberos appartenant à une infrastructure
réelle. Le contrôle se fait par liste blanche : une liste de choses interdites
laisserait passer tout ce qu'on n'a pas imaginé.

`tests/test-commun.sh` et `tests/test-rendu.sh` — la citation des arguments qui
traversent un shell distant, et le rendu des modèles, qui doit échouer plutôt
que de laisser un trou.

`tests/test-alertes-freeipa.yaml.modele` — 11 cas joués par `promtool` sur les
règles **rendues**, celles qui seront appliquées. `promtool` ne se distribue pas
seul : il est emprunté à une image Prometheus dans un conteneur jetable —
l'image exacte du cluster par défaut, pour que l'outil soit la version qui
évaluera vraiment ces règles, ou celle de `IMAGE_PROMETHEUS` pour jouer les
tests sans cluster.

Neuf mutations des expressions ont été jouées contre ces tests, neuf sont vues :
filtre non ancré sur `FreeipaLdapLent`, conjonction retirée de
`FreeipaCacheSature`, appariement `on(base, cache)` ramené à `on()`, seuil
Kerberos abaissé, échéance de certificat élargie, nom de job décalé, et les
gardes `for` et seuils de `FreeipaAnnuaireInjoignable` et
`FreeipaConnexionsSaturees`.

Deux pièges de rédaction, pour qui ajoutera des cas. Une assertion
`exp_alerts: []` évaluée avant le `for` de l'alerte visée constate l'attente et
non la règle : elle passe même si l'expression est cassée. Et un appariement
`on(...)` ne se distingue d'un appariement vide que s'il y a **deux** séries du
côté droit — avec une seule, les deux formes rendent le même résultat.
