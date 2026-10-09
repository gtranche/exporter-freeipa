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

Documentation en anglais : [README.en.md](README.en.md).

## Ce qui est mesuré

55 séries, sous le préfixe `freeipa_` :

| domaine | séries |
|---|---|
| services | `freeipa_service_actif`, `freeipa_services_actifs`, `freeipa_services_total` |
| annuaire | connexions, fils, opérations, octets, liens par mode, recherches par portée, erreurs |
| caches | taux, occupation, plafond, entrées, accès et succès, pour chaque base et chaque cache |
| réplication | `freeipa_replication_accord_etat`, `_ruv_timestamp`, `_conflits`, `_accords`, `_suffixes`, `_changements`, et cinq autres |
| Kerberos | `freeipa_kerberos_requetes_total` par type, `freeipa_kerberos_echecs_total` |
| temps de réponse | `freeipa_temps_reponse_secondes` par interface : `ldap`, `ldap_liaison`, `ldap_premiere`, `api`, `interface` |
| contenu | utilisateurs par état, groupes, machines, groupes de machines, services, règles HBAC et sudo, zones DNS |
| machines | `freeipa_machine`, une série par machine enrôlée |
| certificats | `freeipa_certificat_expiration_timestamp` |
| collecte | `freeipa_collecte_reussie`, `_timestamp`, `_duree_secondes`, `_sonde_reussie` |

Trois mesures méritent un mot.

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

`freeipa_collecte_sonde_reussie{sonde="..."}` nomme la sonde qui est tombée. Les
dix collecteurs sont joués un à un : une panne de l'un ne prive plus des neuf
autres. Mesuré sur un banc où `ipactl` était absent : 9 lignes publiées avant,
75 après, et la sonde fautive désignée.

## Plusieurs serveurs IdM, en actif-actif

Un domaine FreeIPA porte souvent plusieurs serveurs IdM, tous inscriptibles.
L'exportateur se pose sur chacun, et tout — tableau comme alertes — est écrit
pour cela.

Trois détections indépendantes de la réplication, parce qu'aucune ne voit ce que
les autres voient :

- **l'état des accords**, `freeipa_replication_accord_etat`, côté émetteur.
  2 sain, 1 indéterminé, 0 en échec. Un état illisible vaut 1 et non 0 : une
  alerte fausse coûte plus cher qu'une alerte absente.
- **le retard de convergence**, entre serveurs. Un serveur ne connaît que ce
  qu'il a reçu : son RUV ne dit rien de son propre retard. L'écart ne se voit
  qu'en comparant la même série ailleurs, d'où le
  `max by (suffixe, replica) (...) - on(suffixe, replica) group_right() ...`
  du tableau et de `FreeipaReplicationEnRetard`.
- **la divergence du domaine**, `FreeipaDomaineDivergent` : le même compte
  d'utilisateurs lu sur chaque serveur ne devrait pas différer.

Mesuré sur deux 389-DS répliqués dont la liaison avait été cassée : les deux
serveurs restaient `Up`, 4 utilisateurs d'un côté, 3 de l'autre, 290 s de retard
réel. Une panne que `up` ne voit pas.

Les grandeurs du domaine — utilisateurs, groupes, machines, règles, zones — sont
publiées par chaque serveur et donc identiques. Le tableau les montre une fois,
par `max by (job)`, et se sert de l'écart entre serveurs comme signal.

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

    sudo ./installer.sh

Sur chaque serveur IdM du domaine. Le script refuse une machine qui n'est pas un
serveur FreeIPA, vérifie `python3` et `ldapsearch`, pose l'exportateur, ses deux
unités et le répertoire de métriques, arme le minuteur, joue une première
collecte et annonce combien de séries en sont sorties.

Surtout, il lit la ligne de commande de `node_exporter` pour savoir **s'il
tourne avec `--collector.textfile.directory`**, et dans quel répertoire : sans
ce drapeau le fichier serait écrit et personne ne le lirait. Le répertoire qu'il
y trouve est celui qu'il emploie, inscrit dans `/etc/sysconfig/exporter-freeipa`
s'il diffère du défaut — et ce fichier n'est jamais écrasé s'il existe déjà.

Seul un `node_exporter` lancé par root, `node_exporter` ou `prometheus` est
écouté : sans ce filtre, n'importe quel usager de la machine pourrait nommer un
processus `node_exporter` et désigner ainsi le répertoire où root va écrire.

Il sort en 0 si tout est en place, en 1 s'il refuse, et en **2** si la pose est
faite mais que `node_exporter` ne servira pas le fichier.

| option | effet |
|---|---|
| `--racine REP` | prépare l'arborescence sous `REP`, sans systemd ni collecte : pour une image, un paquet ou un essai |
| `--desinstaller` | retire l'exportateur, ses unités et le fichier de métriques — que personne ne saurait périmé — et laisse `/etc/sysconfig/exporter-freeipa` |
| `--repertoire-servi` | dit quel répertoire il retiendrait, et s'arrête là : rien n'est posé |

Rejouer `./installer.sh` est sans effet si rien n'a changé : il le dit et ne
réécrit rien.

Il a besoin de `ldapsearch` (paquet `openldap-clients`), `openssl`, `curl` et
Python 3.6 ou plus. `python-ldap`, s'il est là, sert à décomposer liaison et
recherche ; sinon le script retombe sur une mesure grossière plutôt que de ne
rien publier. Il tourne en root : le lien EXTERNAL sur le socket de l'annuaire
et la lecture du journal du KDC l'exigent.

Le minuteur n'est **pas** `Persistent=true` : au démarrage, le rattrapage des
collectes manquées entrerait en concurrence avec `dirsrv` au moment où il a
besoin de la machine.

## Poser la supervision et le tableau

    ./poser-supervision.sh
    ./grafana/installer-tableau.sh

`poser-supervision.sh` rend le modèle et l'applique : `Service`, `Endpoints`,
`ServiceMonitor` et quinze alertes, dont six sur la réplication. Pour n'obtenir
que le manifeste — à verser dans un dépôt GitOps, par exemple :

    ./rendre.sh kubernetes/supervision.yaml.modele

Les `Endpoints` sont écrits à la main et non en `EndpointSlice` :
prometheus-operator lit les `Endpoints`, un slice seul lui serait invisible. Pour
plusieurs serveurs IdM, ajouter une adresse par serveur dans le même `Endpoints`
suffit : les alertes et le tableau les distinguent par `instance`.

L'installeur de tableau pose un ConfigMap, puis un volume et un montage dans le
Deployment de Grafana : il n'y a pas de découverte automatique ici, chaque
tableau est un montage explicite. Il ne redémarre Grafana que si le montage
manquait, et il vérifie son effet dans le conteneur plutôt que le code retour du
patch. 28 panneaux, deux variables : la source de données, que Grafana demande à
l'ouverture, et le serveur — tous par défaut.

## Vérifier

    ./verifier-deploiement.sh [cible-ssh]

Confronte l'empreinte du script déployé, les directives des deux unités, l'état
du minuteur, la fraîcheur du fichier de métriques et le succès de la dernière
collecte. Ne modifie rien, et sort en 1 s'il y a le moindre écart.

## Tests

    ./tester.sh

Sept suites. Les six premières ne demandent rien d'autre que Python 3 et un
shell ; `SANS_ALERTES=1` saute la septième.

`tests/test-exporter-freeipa.py` — 93 cas, sans annuaire ni parc ni
identifiant : format exposé et échappement, lecture des attributs y compris en
base64, détection du suffixe du domaine, identités lisibles, agrégation des
connexions ouvertes, compteurs Kerberos y compris la rotation du journal, état
des accords de réplication et lecture des RUV, isolation des sondes, écriture
atomique, état des services, caches, inventaire, machines, chemins système, et
le cas où la collecte échoue entièrement.

`tests/test-tableau.py` — 16 cas : ce qui casse en silence dans un tableau. Une
source de données figée, qui rend des panneaux vides chez qui ne nomme pas la
sienne comme l'auteur ; une mise en page qui déborde des 24 colonnes ; deux
panneaux qui se recouvrent ; et tout ce qu'un second serveur IdM révèle — une
série agrégée qui fond trois serveurs en un, une légende qui ne dit pas lequel,
une table jointe sur une clé qui se répète d'un serveur à l'autre.

`tests/test-installer.sh` — 12 cas, joués dans une racine jetable : ce qui est
posé et avec quels droits, l'idempotence, le remplacement d'une version plus
ancienne, le retrait — fichier de métriques périmé compris — la survie du
fichier de surcharge de l'administrateur, et le refus d'une machine qui n'est
pas un serveur FreeIPA avant toute écriture.

`tests/test-depot-public.py` — aucune adresse, aucun nom de domaine, aucun
suffixe d'annuaire et aucun royaume Kerberos appartenant à une infrastructure
réelle. Le contrôle se fait par liste blanche : une liste de choses interdites
laisserait passer tout ce qu'on n'a pas imaginé.

`tests/test-commun.sh` et `tests/test-rendu.sh` — la citation des arguments qui
traversent un shell distant, et le rendu des modèles, qui doit échouer plutôt
que de laisser un trou.

`tests/test-alertes-freeipa.yaml.modele` — 24 cas joués par `promtool` sur les
règles **rendues**, celles qui seront appliquées. Les cas ajoutés pour la
réplication portent deux ou trois instances : c'est la seule façon de voir les
défauts d'appariement et d'agrégation d'un domaine actif-actif. `promtool` ne se
distribue pas seul : il est emprunté à une image Prometheus dans un conteneur
jetable — l'image exacte du cluster par défaut, pour que l'outil soit la version
qui évaluera vraiment ces règles, ou celle de `IMAGE_PROMETHEUS` pour jouer les
tests sans cluster.

Les expressions et le code ont été mutés pour vérifier que ces tests les
retiennent : 18 mutations de l'exportateur, 12 du tableau, 20 des alertes, 50
vues sur 50.

Deux pièges de rédaction, pour qui ajoutera des cas. Une assertion
`exp_alerts: []` évaluée avant le `for` de l'alerte visée constate l'attente et
non la règle : elle passe même si l'expression est cassée. Et un appariement
`on(...)` ne se distingue d'un appariement vide que s'il y a **deux** séries du
côté droit — avec une seule, les deux formes rendent le même résultat.

## Licence

GNU General Public License, version 3 ou ultérieure. Le texte est dans
[LICENSE](LICENSE).
