# FreeIPA exporter

Exposes the state of FreeIPA to Prometheus, and shows it in a Grafana dashboard.

Nothing listens on the network: the script writes a file that the textfile
collector of the `node_exporter` already running on the machine serves together
with its own metrics. So there is **only one port to open**, the one the
`node_exporter` already uses, and only one target to declare in Prometheus. Everything goes through the directory's local socket,
which authenticates root without a password — no secret is stored or handled.

No site-specific value is written in this repository. The two things FreeIPA
knows about itself — the dirsrv instance and the domain suffix — are read from
the machine; the rest lives in one configuration file. A test suite checks that
on every run.

A note on language: the code, the comments and the series names are French,
because these are the names actually exposed. Renaming them would break every
dashboard and alert already deployed, so this document explains them rather than
translating them. `freeipa_utilisateurs` is the user count,
`freeipa_replication_accords` the number of outbound replication agreements,
`freeipa_collecte_reussie` whether the last collection succeeded. The French
documentation is in [README.md](README.md).

## What is measured

55 series, all prefixed `freeipa_`:

| area | series |
|---|---|
| services | `freeipa_service_actif`, `freeipa_services_actifs`, `freeipa_services_total` — per-service and overall state, from `ipactl status` |
| directory | connections, threads, operations, bytes, binds by method, searches by scope, errors |
| caches | hit ratio, used bytes, maximum bytes, entries, tries and hits, for every backend and every cache |
| replication | `freeipa_replication_accord_etat`, `_ruv_timestamp`, `_conflits`, `_accords`, `_suffixes`, `_changements`, and five more |
| Kerberos | `freeipa_kerberos_requetes_total` by type, `freeipa_kerberos_echecs_total` |
| response time | `freeipa_temps_reponse_secondes` per interface: `ldap`, `ldap_liaison` (bind), `ldap_premiere` (first search on a fresh connection), `api`, `interface` (web UI) |
| contents | users by state, groups, hosts, host groups, services, HBAC and sudo rules, DNS zones |
| hosts | `freeipa_machine`, one series per enrolled host |
| certificates | `freeipa_certificat_expiration_timestamp` |
| collection | `freeipa_collecte_reussie`, `_timestamp`, `_duree_secondes`, `_sonde_reussie` |

Three measurements deserve a word.

`freeipa_temps_reponse_secondes{interface="ldap_premiere"}` exists because the
**first** search on a fresh connection sometimes costs 250 ms, in windows of
several minutes. Measured: the server reports `wtime` at most 0.045 s over 300
operations and `etime` 0.0001 s, while the client waits in `poll()` and burns
0.12 ms of CPU. The directory is not slow — this is a setup cost, which the
alert used to read as slowness. It is published on its own, and the filter in
`FreeipaLdapLent` is anchored so as not to pick it up again.

`freeipa_ldap_cache_occupation_octets` against `_plafond_octets`: a low hit
ratio means nothing while the cache is not full — it only says the backend is
rarely read. What matters is the conjunction: cache full **and** reads missing
it.

`freeipa_collecte_sonde_reussie{sonde="..."}` names the probe that failed. The
ten collectors run one by one, so one failure no longer costs the other nine.
Measured on a bench where `ipactl` was missing: 9 lines published before, 75
after, with the failing probe named.

## Several IdM servers, active-active

A FreeIPA domain often carries several IdM servers, all writable. The exporter
is installed on each of them, and everything — dashboard and alerts alike — is
written for that.

Replication is detected three independent ways, because none of them sees what
the others see:

- **agreement state**, `freeipa_replication_accord_etat`, on the sending side.
  2 healthy, 1 indeterminate, 0 failed. An unreadable state is reported as 1,
  not 0: a false alert costs more than a missing one. The reliable source is
  `nsds5replicaLastUpdateStatusJSON`, because the text form reads
  `Error (0) Replica acquired successfully` **when healthy** — matching on
  "Error" would flag every healthy agreement.
- **convergence lag**, across servers. A server only knows what it has
  received: its own RUV says nothing about its own lag. The gap only shows by
  comparing the same series elsewhere, hence the
  `max by (suffixe, replica) (...) - on(suffixe, replica) group_right() ...`
  in both the dashboard and `FreeipaReplicationEnRetard`.
- **domain divergence**, `FreeipaDomaineDivergent`: the same user count read on
  each server should not differ.

Measured on two replicated 389-DS instances whose link had been broken on
purpose: both servers stayed `up`, 4 users on one side, 3 on the other, 290 s of
real lag. A failure `up` cannot see.

Domain-wide quantities — users, groups, hosts, rules, zones — are published by
every server and are therefore identical. The dashboard shows them once, with
`max by (job)`, and uses the gap between servers as a signal instead.

Two alert rules were wrong as soon as there was more than one server, and are
fixed here: `FreeipaEchecsKerberos` summed across servers, which divides the
effective threshold by the number of servers and leaves `$labels` empty; and
`FreeipaCacheSature` matched `and on(base, cache)` without `instance`, pairing
one server's miss rate with another server's occupancy.

## Configuration

    cp configuration.env.exemple configuration.env

Then adjust it. The file is ignored by git: its values do not leave the machine.
The example values are in the ranges reserved for documentation (RFC 5737,
RFC 2606) and reach nothing.

Its blocks are grouped by **who needs them**, because that is not necessarily
the same person: the ssh target and the system paths of the FreeIPA host — which
differ from one distribution to the next — then the values for the file you hand
to whoever runs Prometheus, then the ones only needed to apply the manifest
yourself, then the ones only needed by the tests. Grafana does not appear at all:
the dashboard is imported by hand.

Every script demands only the values **it uses**, and names the one that is
missing. If all you manage is FreeIPA hosts, the first two blocks are enough:
`installer.sh` and `verifier-deploiement.sh` ask for nothing about the cluster.

What is not in it, and need not be: the dirsrv instance, looked up in `/run`,
and the domain suffix, read from the `rootDSE`. To force them anyway, set
`INSTANCE_DIRSRV` and `BASE_LDAP` in `/etc/sysconfig/exporter-freeipa` on the
machine.

## Installing the exporter on the FreeIPA machine

    sudo ./installer.sh

On every IdM server of the domain. The script refuses a machine that is not a
FreeIPA server, checks `python3` and `ldapsearch`, installs the exporter, its
two units and the metrics directory, arms the timer, runs a first collection and
reports how many series came out of it.

Above all, it reads `node_exporter`'s command line to find out **whether it runs
with `--collector.textfile.directory`**, and into which directory: without that
flag the file would be written and nobody would read it. The directory it finds
there is the one it uses, recorded in `/etc/sysconfig/exporter-freeipa` if it
differs from the default — and that file is never overwritten if it already
exists.

Only a `node_exporter` started by root, `node_exporter` or `prometheus` is
listened to: without that filter, any user of the machine could name a process
`node_exporter` and thereby choose the directory root writes into.

It exits 0 when everything is in place, 1 when it refuses, and **2** when the
install is done but `node_exporter` will not serve the file.

| option | effect |
|---|---|
| `--racine DIR` | stages the tree under `DIR`, with no systemd and no collection: for an image, a package or a trial |
| `--desinstaller` | removes the exporter, its units and the metrics file — which nobody would know is stale — and leaves `/etc/sysconfig/exporter-freeipa` alone |
| `--repertoire-servi` | says which directory it would pick, and stops there: nothing is installed |

Running `./installer.sh` again does nothing if nothing changed: it says so and
rewrites nothing.

It needs `ldapsearch` (package `openldap-clients`), `openssl`, `curl` and
Python 3.6 or later. `python-ldap`, when present, is used to separate bind from
search; otherwise the script falls back to a coarser measurement rather than
publishing nothing. It runs as root: the EXTERNAL bind on the directory socket
and reading the KDC log both require it.

The timer is **not** `Persistent=true`: at boot, catching up on missed
collections would compete with `dirsrv` exactly when it needs the machine.

Installing by hand, if you would rather:

    sudo install -m 755 exporter-freeipa.py /usr/local/bin/exporter-freeipa.py
    sudo install -m 644 systemd/exporter-freeipa.service systemd/exporter-freeipa.timer \
        /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable --now exporter-freeipa.timer

## The monitoring: a file to hand over

Prometheus and Grafana may well not be yours. So this repository produces a
**file**, and applies it only if you ask it to:

    ./rendre.sh kubernetes/supervision.yaml.modele > supervision-freeipa.yaml

The result is complete and self-contained: `Service`, `Endpoints`,
`ServiceMonitor` and fifteen alerts, six of them on replication. That is the file
you hand to whoever runs Prometheus — or commit into a GitOps repository. The
values it needs are grouped in `configuration.env` under "le fichier à remettre
à qui gère Prometheus"; no other block is read to produce it.

A marker left without a value makes the rendering **fail**: a half-substituted
manifest would apply without error and monitor the wrong machine.

If you do have `kubectl` access to the cluster yourself, the short way exists:

    ./poser-supervision.sh      # renders the template and applies it, idempotent

The `Endpoints` are written by hand rather than as an `EndpointSlice`:
prometheus-operator reads `Endpoints`, and a slice on its own would be invisible
to it. For several IdM servers, adding one address per server to the same
`Endpoints` is enough: alerts and dashboard tell them apart by `instance`.

## Installing the dashboard

Nothing to install, nothing to configure: `grafana/tableau-freeipa.json` imports
as it stands.

1. **Dashboards** → **New** → **Import**;
2. paste the contents of `grafana/tableau-freeipa.json`, or upload the file,
   then **Load**;
3. the form asks for three things only — **Name**, **Folder**, **UID** — and for
   no data source; **Import**.

The dashboard then opens on its own **Source de données** list, top left,
already set to your Grafana's default Prometheus. That is where the data source
is picked, not at import time. *(Measured on Grafana 12.4.0, with a data source
named `metriques-du-collegue` to prove no name is expected: the form asked
nothing, and the dashboard opened on it.)*

All 28 panels and both variables point at `${source}`, a `datasource`-typed
variable: no data source name is frozen into the file. The file carries **no**
`__inputs` to resolve — hence no question at import — and **no** numeric `id`,
an `id` inherited from the Grafana it was born on designating a *different*
dashboard on the target Grafana, which the import would overwrite. Its `uid` is
`freeipa`: re-importing a later version updates the same dashboard instead of
creating a second one (three imports in a row leave exactly one dashboard).

The second variable, `serveur`, fills itself from the data
(`label_values(freeipa_collecte_reussie, instance)`): it is multi-valued and
defaults to *All*, so a single-server domain has nothing to do with it.

Four tests guard this property, because it breaks silently: a frozen data source
name renders empty panels for anyone whose Prometheus is not called
"prometheus", and nobody sees a message.

## Checking a deployment

    ./verifier-deploiement.sh [ssh-target]

Compares the fingerprint of the deployed script, the directives of both units,
the state of the timer, the freshness of the metrics file and the success of the
last collection. Changes nothing, and exits 1 on the slightest discrepancy.

## Tests

    ./tester.sh

Seven suites. The first six need nothing beyond Python 3 and a shell;
`SANS_ALERTES=1` skips the seventh.

`tests/test-exporter-freeipa.py` — 93 cases, with no directory, no estate and no
credential: exposition format and escaping, attribute parsing including base64,
domain suffix detection, readable identities, aggregation of open connections,
Kerberos counters including log rotation, replication agreement state and RUV
parsing, probe isolation, atomic write, service state, caches, inventory, hosts,
system paths, and the case where collection fails entirely.

`tests/test-tableau.py` — 18 cases: what breaks silently in a dashboard. A
hardcoded data source, which renders empty panels for anyone who does not name
theirs as the author did; a layout that overflows the 24 columns; two
overlapping panels; and everything a second IdM server reveals — an aggregated
series melting three servers into one, a legend that does not say which, a table
joined on a key that repeats from one server to the next.

`tests/test-installer.sh` — 12 cases, played in a throwaway root: what gets
installed and with which permissions, idempotence, replacing an older version,
removal including the stale metrics file, survival of the administrator's
override file, and the refusal of a machine that is not a FreeIPA server before
anything is written.

`tests/test-depot-public.py` — no address, no domain name, no directory suffix
and no Kerberos realm belonging to a real infrastructure. The check is an
allowlist: a list of forbidden things lets through everything nobody thought of.

`tests/test-commun.sh` — 13 cases: quoting of arguments that cross a remote
shell, and the required values. Each script asks only for the ones it uses:
`verifier-deploiement.sh` has no use for a namespace, and demanding one would
stop anybody who does not run Prometheus.

`tests/test-rendu.sh` — 7 cases: template rendering, which must fail rather than
leave a hole.

`tests/test-alertes-freeipa.yaml.modele` — 24 cases played by `promtool` against
the **rendered** rules, the ones that will actually be applied. The cases added
for replication carry two or three instances: that is the only way to see the
matching and aggregation defects of an active-active domain. `promtool` is not
distributed on its own: it is borrowed from a Prometheus image in a throwaway
container — by default the cluster's exact image, so the tool is the version
that will really evaluate these rules, or the one in `IMAGE_PROMETHEUS` to run
the tests without a cluster.

The expressions and the code were mutated to check that these tests catch them:
18 mutations of the exporter, 12 of the dashboard, 20 of the alerts, 8 of
configuration loading and of the import properties, 58 caught out of 58.

Two writing traps, for whoever adds cases. An `exp_alerts: []` assertion
evaluated before the alert's `for` has elapsed observes the wait, not the rule:
it passes even with a broken expression. And an `on(...)` matcher is
indistinguishable from an empty one unless there are **two** series on the right
side — with a single one, both forms give the same result.

## Licence

GNU General Public License, version 3 or later. The text is in
[LICENSE](LICENSE).
