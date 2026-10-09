#!/usr/bin/env python3
# Copyright (C) 2026 gtranche
# SPDX-License-Identifier: GPL-3.0-or-later
"""Expose l'etat de FreeIPA au collecteur textfile de node_exporter.

Tout passe par le socket local de l'annuaire, qui authentifie root sans mot de
passe : aucun secret n'est stocke ni manipule.
"""

import base64
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.parse
from datetime import datetime, timezone

INSTANCE = os.environ.get("INSTANCE_DIRSRV", "")
BASE = os.environ.get("BASE_LDAP", "")
# Chemins systeme : ils varient d une distribution et d un paquet a l autre.
DESTINATION = os.environ.get("FICHIER_METRIQUES",
                             "/var/lib/node_exporter/textfile_collector/freeipa.prom")
ETAT = os.environ.get("FICHIER_ETAT", "/var/lib/node_exporter/etat-freeipa.json")
JOURNAL_KDC = os.environ.get("JOURNAL_KDC", "/var/log/krb5kdc.log")

# id:heure:ops_init:ops_fin:rw:dn:...:connid:ip=adresse
BASES_LDBM = {
    "userRoot": "userRoot",
    "ipaca": "cn=monitor,cn=ipaca,cn=ldbm database,cn=plugins,cn=config",
    "changelog": "cn=monitor,cn=changelog,cn=ldbm database,cn=plugins,cn=config",
}

CONNEXION = re.compile(r"^(\d+):(\d{14})Z:(\d+):(\d+):[^:]*:(.*):\d+:\d+:\d+:\d+:ip=(.*)$")


class Annuaire:
    """Interroge 389-DS par le socket local, et connait le suffixe du domaine."""

    def __init__(self, instance="", base=""):
        self._base = base
        self.url = "ldapi://" + urllib.parse.quote(self._socket(instance), safe="")

    @staticmethod
    def _socket(instance):
        chemin = f"/run/slapd-{instance}.socket"
        if os.path.exists(chemin):
            return chemin
        trouves = [f for f in os.listdir("/run") if f.startswith("slapd-") and f.endswith(".socket")]
        if not trouves:
            raise RuntimeError("aucun socket dirsrv dans /run")
        return "/run/" + trouves[0]

    @property
    def base(self):
        """Suffixe du domaine. Lu dans le rootDSE : il n a pas a etre configure."""
        if not self._base:
            self._base = self._suffixe()
        return self._base

    def _suffixe(self):
        # o=ipaca est aussi un contexte de nommage : on ne retient que dc=.
        trouves = self.entree("", ["defaultnamingcontext", "namingContexts"])
        for cle in ("defaultnamingcontext", "namingcontexts"):
            for valeur in trouves.get(cle, []):
                if valeur.lower().startswith("dc="):
                    return valeur
        raise RuntimeError("suffixe du domaine introuvable dans le rootDSE")

    def _appeler(self, base, filtre, attributs, portee="base"):
        r = subprocess.run(
            ["ldapsearch", "-LLL", "-o", "ldif-wrap=no", "-Y", "EXTERNAL",
             "-H", self.url, "-b", base, "-s", portee, filtre, *attributs],
            capture_output=True, text=True, timeout=60,
            env={**os.environ, "LANG": "C.UTF-8"},
        )
        return r.stdout if r.returncode == 0 else ""

    def entree(self, dn, demandes=()):
        """Rend les attributs d'une entree sous forme de dictionnaire de listes."""
        attributs = {}
        for ligne in self._appeler(dn, "(objectclass=*)", list(demandes)).splitlines():
            if ":" not in ligne or ligne.startswith("#"):
                continue
            cle, _, valeur = ligne.partition(":")
            attributs.setdefault(cle.strip().lower(), []).append(valeur.strip())
        return attributs

    def entrees(self, base, filtre, demandes=(), portee="sub"):
        """Rend une liste d entrees, chacune en dictionnaire de listes."""
        trouvees = []
        for ligne in self._appeler(base, filtre, list(demandes), portee).splitlines():
            if ligne.startswith("#") or ":" not in ligne:
                continue
            cle, _, valeur = ligne.partition(":")
            # « attribut:: valeur » : ldapsearch encode en base64 ce qui n est
            # pas du texte imprimable, et les compteurs de replication le sont.
            if valeur.startswith(":"):
                try:
                    valeur = base64.b64decode(valeur[1:].strip()).decode("utf-8", "replace")
                except ValueError:
                    valeur = ""
            if cle.strip().lower() == "dn":
                trouvees.append({})
            if trouvees:
                trouvees[-1].setdefault(cle.strip().lower(), []).append(str(valeur).strip())
        return trouvees

    def compter(self, base, filtre):
        sortie = self._appeler(base, filtre, ["dn"], portee="sub")
        return sum(1 for l in sortie.splitlines() if l.startswith("dn:"))


class Registre:
    """Accumule des series Prometheus et les rend au format texte."""

    def __init__(self):
        self.lignes = []

    def declarer(self, _nom, _aide, _genre="gauge"):
        self.lignes.append(f"# HELP {_nom} {_aide}")
        self.lignes.append(f"# TYPE {_nom} {_genre}")

    # Parametres prefixes : une etiquette nommee "nom" ou "valeur" entrerait
    # sinon en collision avec eux.
    def ajouter(self, _nom, _valeur, **etiquettes):
        if etiquettes:
            paires = ",".join(f'{c}="{self._echapper(v)}"' for c, v in sorted(etiquettes.items()))
            self.lignes.append(f"{_nom}{{{paires}}} {_valeur}")
        else:
            self.lignes.append(f"{_nom} {_valeur}")

    @staticmethod
    def _echapper(valeur):
        return str(valeur).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")

    def __str__(self):
        return "\n".join(self.lignes) + "\n"


def epoque(valeur, defaut=0):
    """Convertit une heure generalisee LDAP (20261009113622Z) en epoque Unix."""
    try:
        t = datetime.strptime(valeur.rstrip("Z"), "%Y%m%d%H%M%S")
        return int(t.replace(tzinfo=timezone.utc).timestamp())
    except ValueError:
        return defaut


def entier(attributs, cle, defaut=0):
    try:
        return int(attributs.get(cle, [defaut])[0])
    except (ValueError, IndexError):
        return defaut


def services(registre):
    r = subprocess.run(["ipactl", "status"], capture_output=True, text=True, timeout=120,
                       env={**os.environ, "LANG": "C.UTF-8"})
    registre.declarer("freeipa_service_actif", "1 si le service FreeIPA tourne.")
    actifs = total = 0
    for ligne in r.stdout.splitlines():
        if " Service: " in ligne or ligne.startswith("Directory Service:"):
            nom, _, etat = ligne.partition(":")
            nom = nom.replace(" Service", "").strip().lower().replace(" ", "-")
            vivant = 1 if etat.strip() == "RUNNING" else 0
            # Surtout pas "service" : prometheus-operator ajoute une etiquette
            # de ce nom valant le Service Kubernetes, qui ecrase la notre.
            registre.ajouter("freeipa_service_actif", vivant, composant=nom)
            total += 1
            actifs += vivant
    registre.declarer("freeipa_services_total", "Services declares par ipactl.")
    registre.ajouter("freeipa_services_total", total)
    registre.declarer("freeipa_services_actifs", "Services effectivement en marche.")
    registre.ajouter("freeipa_services_actifs", actifs)


def annuaire(a, registre):
    m = a.entree("cn=monitor")
    snmp = a.entree("cn=snmp,cn=monitor")
    cache = a.entree("cn=monitor,cn=userRoot,cn=ldbm database,cn=plugins,cn=config")

    simple = [
        ("freeipa_ldap_connexions_courantes", "currentconnections", "Connexions ouvertes."),
        ("freeipa_ldap_fils", "threads", "Fils de traitement."),
        ("freeipa_ldap_attente_lecture", "readwaiters", "Connexions en attente de lecture."),
        ("freeipa_ldap_connexions_au_max_de_fils", "currentconnectionsatmaxthreads",
         "Connexions ayant atteint le plafond de fils."),
    ]
    for nom, cle, aide in simple:
        registre.declarer(nom, aide)
        registre.ajouter(nom, entier(m, cle))

    compteurs = [
        ("freeipa_ldap_connexions_total", "totalconnections", m, "Connexions depuis le demarrage."),
        ("freeipa_ldap_operations_initiees_total", "opsinitiated", m, "Operations initiees."),
        ("freeipa_ldap_operations_terminees_total", "opscompleted", m, "Operations terminees."),
        ("freeipa_ldap_entrees_envoyees_total", "entriessent", m, "Entrees renvoyees aux clients."),
        ("freeipa_ldap_octets_envoyes_total", "bytessent", m, "Octets renvoyes aux clients."),
        ("freeipa_ldap_erreurs_total", "errors", snmp, "Operations en erreur."),
        ("freeipa_ldap_erreurs_securite_liens_total", "bindsecurityerrors", snmp,
         "Echecs d authentification sur un lien."),
    ]
    for nom, cle, source, aide in compteurs:
        registre.declarer(nom, aide, "counter")
        registre.ajouter(nom, entier(source, cle))

    registre.declarer("freeipa_ldap_liens_total", "Liens etablis, par mode d authentification.", "counter")
    for mode, cle in (("anonyme", "anonymousbinds"), ("non_authentifie", "unauthbinds"),
                      ("simple", "simpleauthbinds"), ("fort", "strongauthbinds")):
        registre.ajouter("freeipa_ldap_liens_total", entier(snmp, cle), mode=mode)

    registre.declarer("freeipa_ldap_recherches_total", "Recherches, par portee.", "counter")
    for portee, cle in (("base", "searchops"), ("un_niveau", "onelevelsearchops"),
                        ("sous_arbre", "wholesubtreesearchops")):
        registre.ajouter("freeipa_ldap_recherches_total", entier(snmp, cle), portee=portee)

    # Un cache d entrees qui s effondre est le premier signe d un annuaire trop
    # petit pour sa charge. Le taux seul ne suffit pas a le voir venir : il
    # faut l occupation face au plafond.
    registre.declarer("freeipa_ldap_cache_taux", "Taux de succes des caches, en pourcentage.")
    registre.declarer("freeipa_ldap_cache_occupation_octets", "Occupation actuelle des caches.")
    registre.declarer("freeipa_ldap_cache_plafond_octets", "Taille maximale allouee aux caches.")
    registre.declarer("freeipa_ldap_cache_entrees", "Nombre d entrees actuellement en cache.")
    registre.declarer("freeipa_ldap_cache_acces_total", "Acces au cache.", "counter")
    registre.declarer("freeipa_ldap_cache_succes_total", "Acces au cache ayant abouti.", "counter")

    for base, dn in BASES_LDBM.items():
        c = a.entree(dn) if dn != "userRoot" else cache
        if not c:
            continue
        for nom_cache, prefixe in (("entrees", "entrycache"), ("dn", "dncache")):
            e = {"base": base, "cache": nom_cache}
            registre.ajouter("freeipa_ldap_cache_taux", entier(c, prefixe + "hitratio"), **e)
            registre.ajouter("freeipa_ldap_cache_occupation_octets",
                             entier(c, "current" + prefixe + "size"), **e)
            plafond = entier(c, "max" + prefixe + "size")
            if plafond > 0:
                registre.ajouter("freeipa_ldap_cache_plafond_octets", plafond, **e)
            registre.ajouter("freeipa_ldap_cache_entrees", entier(c, "current" + prefixe + "count"), **e)
            registre.ajouter("freeipa_ldap_cache_acces_total", entier(c, prefixe + "tries"), **e)
            registre.ajouter("freeipa_ldap_cache_succes_total", entier(c, prefixe + "hits"), **e)

    debut = m.get("starttime", [""])[0]
    if debut:
        registre.declarer("freeipa_ldap_demarrage_timestamp", "Date de demarrage de l annuaire.")
        registre.ajouter("freeipa_ldap_demarrage_timestamp", epoque(debut))

    return m


def connexions(m, registre):
    """Agrege les connexions ouvertes par identite : une serie par connexion
    ferait exploser la cardinalite a chaque reconnexion."""
    maintenant = time.time()
    par_identite = {}
    for brut in m.get("connection", []):
        trouve = CONNEXION.match(brut)
        if not trouve:
            continue
        _, ouverture, ops_init, _, dn, ip = trouve.groups()
        duree = maxima = maintenant - epoque(ouverture)
        identite = lisible(dn)
        cle = (identite, ip)
        etat = par_identite.setdefault(cle, {"nombre": 0, "duree_max": 0.0, "ops": 0})
        etat["nombre"] += 1
        etat["duree_max"] = max(etat["duree_max"], maxima)
        etat["ops"] += int(ops_init)

    registre.declarer("freeipa_connexions_ouvertes", "Connexions LDAP ouvertes, par identite.")
    registre.declarer("freeipa_connexion_duree_max_secondes",
                      "Age de la plus ancienne connexion ouverte par cette identite.")
    registre.declarer("freeipa_connexion_operations", "Operations initiees sur les connexions ouvertes.")
    for (identite, ip), etat in sorted(par_identite.items()):
        registre.ajouter("freeipa_connexions_ouvertes", etat["nombre"], identite=identite, ip=ip)
        registre.ajouter("freeipa_connexion_duree_max_secondes", round(etat["duree_max"], 1),
                         identite=identite, ip=ip)
        registre.ajouter("freeipa_connexion_operations", etat["ops"], identite=identite, ip=ip)


def lisible(dn):
    """Rend une identite courte a partir d un DN d annuaire."""
    if dn.startswith("fqdn="):
        return dn.split(",")[0][5:]
    if dn.startswith("krbprincipalname="):
        return dn.split(",")[0][17:]
    if dn.startswith("uid="):
        return dn.split(",")[0][4:]
    if dn.startswith("cn="):
        return dn.split(",")[0][3:]
    return dn[:60] or "(anonyme)"


def inventaire(a, registre):
    base = a.base
    mesures = [
        ("freeipa_utilisateurs", f"cn=users,cn=accounts,{base}",
         "(&(objectclass=posixaccount)(!(nsaccountlock=TRUE)))", {"etat": "actif"}),
        ("freeipa_utilisateurs", f"cn=users,cn=accounts,{base}",
         "(&(objectclass=posixaccount)(nsaccountlock=TRUE))", {"etat": "desactive"}),
        ("freeipa_groupes", f"cn=groups,cn=accounts,{base}", "(objectclass=ipausergroup)", {}),
        ("freeipa_machines", f"cn=computers,cn=accounts,{base}", "(objectclass=ipahost)", {}),
        ("freeipa_groupes_machines", f"cn=hostgroups,cn=accounts,{base}", "(objectclass=ipahostgroup)", {}),
        ("freeipa_services_enregistres", f"cn=services,cn=accounts,{base}", "(objectclass=ipaservice)", {}),
        ("freeipa_regles_hbac", f"cn=hbac,{base}", "(objectclass=ipahbacrule)", {}),
        ("freeipa_regles_sudo", f"cn=sudorules,cn=sudo,{base}", "(objectclass=ipasudorule)", {}),
        ("freeipa_zones_dns", f"cn=dns,{base}", "(objectclass=idnszone)", {}),
    ]
    declares = set()
    aides = {
        "freeipa_utilisateurs": "Comptes utilisateurs.",
        "freeipa_groupes": "Groupes d utilisateurs.",
        "freeipa_machines": "Machines enrolees dans le domaine.",
        "freeipa_groupes_machines": "Groupes de machines.",
        "freeipa_services_enregistres": "Principaux de service.",
        "freeipa_regles_hbac": "Regles de controle d acces.",
        "freeipa_regles_sudo": "Regles sudo.",
        "freeipa_zones_dns": "Zones DNS servies.",
    }
    for nom, base, filtre, etiquettes in mesures:
        if nom not in declares:
            registre.declarer(nom, aides[nom])
            declares.add(nom)
        registre.ajouter(nom, a.compter(base, filtre), **etiquettes)


def machines(a, registre):
    """Une serie par machine enrolee.

    Soustraire deux totaux ne dit pas lesquelles manquent, et se trompe des
    qu un ensemble n est pas inclus dans l autre.
    """
    sortie = a._appeler(f"cn=computers,cn=accounts,{a.base}", "(objectclass=ipahost)", ["fqdn"], portee="sub")
    noms = [l.split(":", 1)[1].strip() for l in sortie.splitlines() if l.lower().startswith("fqdn:")]
    registre.declarer("freeipa_machine", "1 pour chaque machine presente dans le domaine.")
    for nom in sorted(set(noms)):
        registre.ajouter("freeipa_machine", 1, machine=nom)


def kerberos(registre):
    """Compte les requetes du KDC en ne relisant que les lignes nouvelles."""
    etat = {"inode": 0, "offset": 0, "as": 0, "tgs": 0, "echecs": 0}
    if os.path.exists(ETAT):
        try:
            etat.update(json.load(open(ETAT)))
        except (ValueError, OSError):
            pass

    if os.path.exists(JOURNAL_KDC):
        st = os.stat(JOURNAL_KDC)
        # Rotation : l inode change, ou le fichier a rapetisse.
        if st.st_ino != etat["inode"] or st.st_size < etat["offset"]:
            etat.update({"inode": st.st_ino, "offset": 0})
        with open(JOURNAL_KDC, "r", errors="replace") as f:
            f.seek(etat["offset"])
            for ligne in f:
                if "AS_REQ" in ligne:
                    etat["as"] += 1
                elif "TGS_REQ" in ligne:
                    etat["tgs"] += 1
                if "FAILED" in ligne or "CLIENT_NOT_FOUND" in ligne or "PREAUTH_FAILED" in ligne:
                    etat["echecs"] += 1
            etat["offset"] = f.tell()
        try:
            with open(ETAT, "w") as f:
                json.dump(etat, f)
        except OSError:
            pass

    registre.declarer("freeipa_kerberos_requetes_total", "Requetes traitees par le KDC.", "counter")
    registre.ajouter("freeipa_kerberos_requetes_total", etat["as"], type="AS")
    registre.ajouter("freeipa_kerberos_requetes_total", etat["tgs"], type="TGS")
    registre.declarer("freeipa_kerberos_echecs_total", "Requetes Kerberos refusees.", "counter")
    registre.ajouter("freeipa_kerberos_echecs_total", etat["echecs"])


def temps_de_reponse(a, registre):
    """Mesure separement la liaison et la recherche.

    Les confondre donnerait un chiffre qui bouge pour deux raisons sans jamais
    dire laquelle : une authentification lente et un annuaire lent n appellent
    pas la meme correction.
    """
    registre.declarer("freeipa_temps_reponse_secondes", "Temps de reponse mesure, par interface.")

    try:
        import ldap
        import ldap.sasl

        debut = time.time()
        conn = ldap.initialize(a.url)
        conn.set_option(ldap.OPT_TIMEOUT, 10)
        conn.sasl_interactive_bind_s("", ldap.sasl.external())
        liaison = time.time() - debut

        # Portee "base" : mesure l aller-retour, pas la taille de l annuaire.
        #
        # La PREMIERE recherche d une connexion neuve coute parfois 250 ms,
        # par fenetres de plusieurs minutes. Mesure le 2026-10-01 : le serveur
        # annonce wtime au plus 0,045 s sur 300 operations et etime 0,0001 s,
        # tandis que le client attend dans poll() en consommant 0,12 ms de CPU.
        # L annuaire n est donc pas lent : c est un cout d etablissement, que
        # l alerte prenait pour de la lenteur d annuaire.
        #
        # On mesure donc la SECONDE recherche, qui repond a la question posee
        # — « une recherche de portee base tient sous la milliseconde » — et on
        # publie la premiere sous une etiquette distincte pour ne pas perdre le
        # signal. L alerte filtre sur interface=~"ldap|ldap_liaison", ancre :
        # ldap_premiere n y entre pas.
        debut = time.time()
        conn.search_s(a.base, ldap.SCOPE_BASE, "(objectclass=*)", ["dn"])
        premiere = time.time() - debut

        debut = time.time()
        conn.search_s(a.base, ldap.SCOPE_BASE, "(objectclass=*)", ["dn"])
        recherche = time.time() - debut
        conn.unbind_s()

        registre.ajouter("freeipa_temps_reponse_secondes", round(liaison, 5), interface="ldap_liaison")
        registre.ajouter("freeipa_temps_reponse_secondes", round(recherche, 5), interface="ldap")
        registre.ajouter("freeipa_temps_reponse_secondes", round(premiere, 5), interface="ldap_premiere")
    except Exception:                      # noqa: BLE001
        # python-ldap absent ou liaison refusee : on retombe sur une mesure
        # grossiere plutot que de ne rien publier.
        debut = time.time()
        a.entree(a.base)
        registre.ajouter("freeipa_temps_reponse_secondes", round(time.time() - debut, 4), interface="ldap")

    for nom, cible in (("api", "https://localhost/ipa/session/json"),
                       ("interface", "https://localhost/ipa/ui/")):
        debut = time.time()
        r = subprocess.run(["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
                            "--max-time", "10", cible],
                           capture_output=True, text=True, timeout=20)
        ecoule = time.time() - debut
        if r.stdout.strip() not in ("", "000"):
            registre.ajouter("freeipa_temps_reponse_secondes", round(ecoule, 4), interface=nom)


def certificats(registre):
    registre.declarer("freeipa_certificat_expiration_timestamp", "Fin de validite des certificats.")
    chemins = {
        "httpd": "/var/lib/ipa/certs/httpd.crt",
        "autorite": "/etc/ipa/ca.crt",
    }
    for nom, chemin in chemins.items():
        if not os.path.exists(chemin):
            continue
        r = subprocess.run(["openssl", "x509", "-in", chemin, "-noout", "-enddate"],
                           capture_output=True, text=True, timeout=20)
        if "notAfter=" not in r.stdout:
            continue
        brut = r.stdout.strip().split("=", 1)[1]
        try:
            t = datetime.strptime(brut, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        registre.ajouter("freeipa_certificat_expiration_timestamp", int(t.timestamp()), certificat=nom)


# Liste blanche d attributs : l entree de l accord porte aussi le mot de passe
# du compte de replication, et rien ne doit pouvoir le faire entrer en metrique.
ACCORD_ATTRIBUTS = ["cn", "nsDS5ReplicaRoot", "nsDS5ReplicaHost", "nsDS5ReplicaPort",
                    "nsds5replicaLastUpdateStatus", "nsds5replicaLastUpdateStatusJSON",
                    "nsds5replicaUpdateInProgress", "nsds5replicaLastUpdateEnd",
                    "nsds5replicaChangesSentSinceStartup"]
REPLICA_ATTRIBUTS = ["nsDS5ReplicaRoot", "nsDS5ReplicaId", "nsDS5ReplicaType",
                     "nsds5ReplicaChangeCount", "nsds50ruv"]

ETATS = {"green": 2, "amber": 1, "red": 0}
# « 1:8/0 » : identifiant du fournisseur, changements envoyes, changements omis.
ENVOIS = re.compile(r"(\d+):(\d+)/(\d+)")
# « {replica 2 ldap://hote:389} <csn mini> <csn maxi> », les CSN pouvant manquer.
RUV = re.compile(r"\{replica (\d+) ([^}]*)\}((?:\s+[0-9a-fA-F]+)*)")
CODE_STATUT = re.compile(r"Error \((-?\d+)\)")


def sante_accord(attributs):
    """Sante d un accord : 2 sain, 1 indetermine ou degrade, 0 en echec.

    Le champ JSON tranche. A defaut, le texte : il commence par « Error (0) »
    meme quand tout va bien, donc seul le code entre parentheses se lit.
    """
    brut = attributs.get("nsds5replicalastupdatestatusjson", [])
    if brut:
        try:
            return ETATS.get(json.loads(brut[0]).get("state", ""), 1)
        except (ValueError, TypeError, AttributeError):
            pass
    trouve = CODE_STATUT.search(attributs.get("nsds5replicalastupdatestatus", [""])[0])
    if trouve:
        return 2 if trouve.group(1) == "0" else 0
    return 1


def replication(a, registre):
    """Etat de la replication, du point de vue de ce serveur seul.

    Chaque serveur ne connait que ce qu il a recu : le retard reel se calcule
    en comparant la meme serie entre serveurs, pas sur un serveur isole.
    """
    replicas = a.entrees("cn=config", "(objectclass=nsds5replica)", REPLICA_ATTRIBUTS)
    registre.declarer("freeipa_replication_suffixes", "Nombre de suffixes repliques.")
    registre.ajouter("freeipa_replication_suffixes", len(replicas))
    if not replicas:
        return

    registre.declarer("freeipa_replication_identifiant", "Identifiant de ce replica.")
    registre.declarer("freeipa_replication_type", "Role 389-DS : 3 fournisseur, 2 concentrateur.")
    registre.declarer("freeipa_replication_changements", "Changements enregistres par ce replica.")
    registre.declarer("freeipa_replication_ruv_timestamp",
                      "Date du dernier changement connu de ce serveur pour chaque fournisseur.")
    registre.declarer("freeipa_replication_conflits", "Entrees en conflit de replication.")
    for r in replicas:
        suffixe = r.get("nsds5replicaroot", [""])[0]
        if not suffixe:
            continue
        e = {"suffixe": suffixe}
        registre.ajouter("freeipa_replication_identifiant", entier(r, "nsds5replicaid"), **e)
        registre.ajouter("freeipa_replication_type", entier(r, "nsds5replicatype"), **e)
        registre.ajouter("freeipa_replication_changements", entier(r, "nsds5replicachangecount"), **e)
        for brut in r.get("nsds50ruv", []):
            trouve = RUV.search(brut)
            if not trouve:
                continue
            identifiant, fournisseur, csn = trouve.groups()
            dernier = csn.split()
            if not dernier:
                continue
            registre.ajouter("freeipa_replication_ruv_timestamp", int(dernier[-1][:8], 16),
                             replica=identifiant, fournisseur=fournisseur, **e)
        registre.ajouter("freeipa_replication_conflits",
                         a.compter(suffixe, "(nsds5ReplConflict=*)"), **e)

    accords = a.entrees("cn=config", "(objectclass=nsds5replicationagreement)", ACCORD_ATTRIBUTS)
    registre.declarer("freeipa_replication_accords", "Nombre d accords de replication sortants.")
    registre.ajouter("freeipa_replication_accords", len(accords))
    registre.declarer("freeipa_replication_accord_etat",
                      "Sante d un accord : 2 sain, 1 indetermine, 0 en echec.")
    registre.declarer("freeipa_replication_accord_en_cours", "1 si une mise a jour est en cours.")
    registre.declarer("freeipa_replication_accord_derniere_maj_timestamp",
                      "Fin de la derniere mise a jour reussie de cet accord.")
    registre.declarer("freeipa_replication_accord_changements_envoyes_total",
                      "Changements envoyes par cet accord depuis le demarrage.", "counter")
    registre.declarer("freeipa_replication_accord_changements_omis_total",
                      "Changements omis par cet accord depuis le demarrage.", "counter")
    for c in accords:
        e = {"accord": c.get("cn", [""])[0],
             "suffixe": c.get("nsds5replicaroot", [""])[0],
             "pair": c.get("nsds5replicahost", [""])[0]}
        registre.ajouter("freeipa_replication_accord_etat", sante_accord(c), **e)
        registre.ajouter("freeipa_replication_accord_en_cours",
                         1 if c.get("nsds5replicaupdateinprogress", [""])[0].upper() == "TRUE" else 0,
                         **e)
        fin = epoque(c.get("nsds5replicalastupdateend", [""])[0])
        if fin:
            registre.ajouter("freeipa_replication_accord_derniere_maj_timestamp", fin, **e)
        envoyes = omis = 0
        for identifiant, envoi, saut in ENVOIS.findall(
                c.get("nsds5replicachangessentsincestartup", [""])[0]):
            envoyes += int(envoi)
            omis += int(saut)
        registre.ajouter("freeipa_replication_accord_changements_envoyes_total", envoyes, **e)
        registre.ajouter("freeipa_replication_accord_changements_omis_total", omis, **e)

def ecrire(chemin, contenu):
    """Ecriture atomique : node_exporter ne doit jamais lire un fichier partiel."""
    descripteur, provisoire = tempfile.mkstemp(dir=os.path.dirname(chemin), suffix=".tmp")
    try:
        with os.fdopen(descripteur, "w") as f:
            f.write(contenu)
        os.chmod(provisoire, 0o644)
        os.replace(provisoire, chemin)
    except BaseException:
        os.unlink(provisoire)
        raise


SONDES = ("services", "annuaire", "etat_annuaire", "connexions", "replication",
          "inventaire", "machines", "kerberos", "temps_de_reponse", "certificats")


class Sondes:
    """Joue les collecteurs un a un, sans qu un seul puisse emporter les autres.

    Une sonde qui n a pas pu etre jouee compte comme en echec : sinon un
    annuaire injoignable laisserait croire que tout ce qu il porte va bien.
    """

    def __init__(self, registre, attendues):
        self._registre = registre
        self._etats = {nom: 0 for nom in attendues}

    def jouer(self, nom, action, *args):
        try:
            resultat = action(*args)
        except Exception as erreur:            # noqa: BLE001
            print(f"sonde {nom} : {erreur}")
            return None
        self._etats[nom] = 1
        return resultat

    def publier(self):
        """Publie l etat de chaque sonde et rend 1 si toutes ont abouti."""
        for nom, etat in sorted(self._etats.items()):
            self._registre.ajouter("freeipa_collecte_sonde_reussie", etat, sonde=nom)
        return int(all(self._etats.values()))


def main():
    debut = time.time()
    registre = Registre()
    registre.declarer("freeipa_collecte_sonde_reussie",
                      "1 si cette sonde s est achevee sans erreur.")
    sondes = Sondes(registre, SONDES)

    sondes.jouer("services", services, registre)
    a = sondes.jouer("annuaire", Annuaire, INSTANCE, BASE)
    if a is not None:
        m = sondes.jouer("etat_annuaire", annuaire, a, registre)
        if m is not None:
            sondes.jouer("connexions", connexions, m, registre)
        sondes.jouer("replication", replication, a, registre)
        sondes.jouer("inventaire", inventaire, a, registre)
        sondes.jouer("machines", machines, a, registre)
    sondes.jouer("kerberos", kerberos, registre)
    if a is not None:
        sondes.jouer("temps_de_reponse", temps_de_reponse, a, registre)
    sondes.jouer("certificats", certificats, registre)
    reussie = sondes.publier()

    registre.declarer("freeipa_collecte_reussie", "1 si la collecte s est achevee sans erreur.")
    registre.ajouter("freeipa_collecte_reussie", reussie)
    registre.declarer("freeipa_collecte_timestamp", "Date de fin de la derniere collecte.")
    registre.ajouter("freeipa_collecte_timestamp", int(time.time()))
    registre.declarer("freeipa_collecte_duree_secondes", "Duree de la derniere collecte.")
    registre.ajouter("freeipa_collecte_duree_secondes", round(time.time() - debut, 3))

    ecrire(DESTINATION, str(registre))
    return 0 if reussie else 1


if __name__ == "__main__":
    raise SystemExit(main())
