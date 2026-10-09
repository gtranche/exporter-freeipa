#!/usr/bin/env python3
# Tests de l exportateur FreeIPA. Ils n ont besoin ni d un annuaire, ni du
# parc, ni d un identifiant : tout ce qui touche a 389-DS passe par un double
# qui rend les attributs deja decoupes, comme le fait ldapsearch.
#
# Non couvert, et volontairement : temps_de_reponse(), qui importe python-ldap
# et lance curl sur localhost. Le mesurer hors de la machine ne prouverait rien.

import contextlib
import importlib.util
import io
import os
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone

CHEMIN = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "..", "exporter-freeipa.py")
_spec = importlib.util.spec_from_file_location("exporteur_freeipa", CHEMIN)
ef = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ef)


class Sortie:
    """Relit ce qu un Registre a produit, comme Prometheus le lira."""

    def __init__(self, registre):
        self.texte = str(registre)
        self.series = {}
        self.aides = {}
        self.genres = {}
        for ligne in self.texte.splitlines():
            if ligne.startswith("# HELP "):
                nom, _, aide = ligne[7:].partition(" ")
                self.aides.setdefault(nom, []).append(aide)
            elif ligne.startswith("# TYPE "):
                nom, _, genre = ligne[7:].partition(" ")
                self.genres[nom] = genre
            elif ligne:
                cle, _, valeur = ligne.rpartition(" ")
                self.series[cle] = float(valeur)

    def valeur(self, cle):
        return self.series[cle]

    def noms(self, prefixe):
        return sorted(c for c in self.series if c.startswith(prefixe))


class Doublure:
    """Tient la place de l annuaire : des attributs deja decoupes."""

    def __init__(self, entrees=None, comptes=None, fqdn=(), base="dc=exemple,dc=test"):
        self.entrees = entrees or {}
        self.comptes = comptes or {}
        self.fqdn = fqdn
        self.base = base
        self.url = "ldapi://doublure"

    def entree(self, dn, demandes=()):
        return self.entrees.get(dn, {})

    def compter(self, base, filtre):
        return self.comptes.get((base, filtre), 0)

    def _appeler(self, base, filtre, attributs, portee="base"):
        return "".join(f"fqdn: {n}\n" for n in self.fqdn)


class Commande:
    """Remplace subprocess.run : rend une sortie preparee, sans rien executer."""

    def __init__(self, *sorties):
        self.sorties = list(sorties)
        self.appels = []

    def __call__(self, argv, **_):
        self.appels.append(argv)
        sortie = self.sorties.pop(0) if self.sorties else ""
        return type("R", (), {"stdout": sortie, "stderr": "", "returncode": 0})()


class FormatExpose(unittest.TestCase):
    def test_un_guillemet_dans_une_etiquette_ne_coupe_pas_la_ligne_en_deux(self):
        r = ef.Registre()
        r.ajouter("m", 1, identite='il a dit "non"')
        self.assertIn(r'identite="il a dit \"non\""', str(r))
        self.assertEqual(len(str(r).strip().splitlines()), 1)

    def test_une_antislash_est_doublee_avant_les_guillemets_et_non_apres(self):
        r = ef.Registre()
        r.ajouter("m", 1, chemin="c:\\dir")
        self.assertIn(r'chemin="c:\\dir"', str(r))

    def test_un_retour_a_la_ligne_dans_une_valeur_devient_une_espace(self):
        r = ef.Registre()
        r.ajouter("m", 1, texte="deux\nlignes")
        self.assertEqual(len(str(r).strip().splitlines()), 1)
        self.assertIn('texte="deux lignes"', str(r))

    def test_les_etiquettes_sortent_dans_un_ordre_stable_quel_que_soit_l_appel(self):
        a, b = ef.Registre(), ef.Registre()
        a.ajouter("m", 1, zebre="z", alpha="a")
        b.ajouter("m", 1, alpha="a", zebre="z")
        self.assertEqual(str(a), str(b))

    def test_une_serie_sans_etiquette_s_ecrit_sans_accolades(self):
        r = ef.Registre()
        r.ajouter("m", 2)
        self.assertEqual(str(r), "m 2\n")

    def test_le_genre_annonce_est_celui_demande(self):
        r = ef.Registre()
        r.declarer("m_total", "aide", "counter")
        self.assertEqual(Sortie(r).genres["m_total"], "counter")

    def test_la_sortie_se_termine_par_un_retour_a_la_ligne(self):
        r = ef.Registre()
        r.ajouter("m", 1)
        self.assertTrue(str(r).endswith("\n"))


class LectureDesAttributs(unittest.TestCase):
    def test_un_attribut_absent_rend_le_defaut_plutot_qu_une_erreur(self):
        self.assertEqual(ef.entier({}, "absent", 5), 5)

    def test_un_attribut_non_numerique_rend_le_defaut(self):
        self.assertEqual(ef.entier({"k": ["vide"]}, "k", 2), 2)

    def test_une_liste_vide_rend_le_defaut(self):
        self.assertEqual(ef.entier({"k": []}, "k", 4), 4)

    def test_la_premiere_valeur_est_retenue_quand_l_attribut_est_multiple(self):
        self.assertEqual(ef.entier({"k": ["7", "9"]}, "k"), 7)


class IdentiteLisible(unittest.TestCase):
    def test_une_machine_est_nommee_par_son_fqdn_et_non_par_son_dn(self):
        self.assertEqual(ef.lisible("fqdn=serveur1.exemple.test,cn=computers,dc=x"),
                         "serveur1.exemple.test")

    def test_un_principal_kerberos_perd_son_dn_et_garde_son_nom(self):
        self.assertEqual(ef.lisible("krbprincipalname=HTTP/ipa@LOCAL,cn=services,dc=x"),
                         "HTTP/ipa@LOCAL")

    def test_un_compte_utilisateur_est_reduit_a_son_identifiant(self):
        self.assertEqual(ef.lisible("uid=alice,cn=users,cn=accounts,dc=x"), "alice")

    def test_une_liaison_anonyme_porte_un_nom_plutot_qu_une_chaine_vide(self):
        self.assertEqual(ef.lisible(""), "(anonyme)")

    def test_un_dn_inattendu_est_tronque_pour_ne_pas_faire_exploser_l_etiquette(self):
        self.assertEqual(len(ef.lisible("x" * 200)), 60)


class ConnexionsOuvertes(unittest.TestCase):
    @staticmethod
    def ligne(identifiant, dn, ip, age_secondes, ops):
        ouverture = datetime.now(timezone.utc) - timedelta(seconds=age_secondes)
        horodatage = ouverture.strftime("%Y%m%d%H%M%S")
        return f"{identifiant}:{horodatage}Z:{ops}:0:rw:{dn}:0:0:0:0:ip={ip}"

    def mesurer(self, lignes):
        r = ef.Registre()
        ef.connexions({"connection": lignes}, r)
        return Sortie(r)

    def test_une_identite_qui_ouvre_trois_connexions_ne_fait_qu_une_serie(self):
        s = self.mesurer([self.ligne(i, "uid=alice,dc=x", "192.0.2.5", 10, 1)
                          for i in range(3)])
        self.assertEqual(s.noms("freeipa_connexions_ouvertes"),
                         ['freeipa_connexions_ouvertes{identite="alice",ip="192.0.2.5"}'])
        self.assertEqual(s.valeur('freeipa_connexions_ouvertes{identite="alice",ip="192.0.2.5"}'), 3)

    def test_la_meme_identite_vue_de_deux_adresses_reste_deux_series(self):
        s = self.mesurer([self.ligne(1, "uid=alice,dc=x", "192.0.2.5", 10, 1),
                          self.ligne(2, "uid=alice,dc=x", "192.0.2.6", 10, 1)])
        self.assertEqual(len(s.noms("freeipa_connexions_ouvertes")), 2)

    def test_la_duree_retenue_est_celle_de_la_plus_ancienne_connexion(self):
        s = self.mesurer([self.ligne(1, "uid=alice,dc=x", "198.51.100.1", 10, 1),
                          self.ligne(2, "uid=alice,dc=x", "198.51.100.1", 600, 1)])
        duree = s.valeur('freeipa_connexion_duree_max_secondes{identite="alice",ip="198.51.100.1"}')
        self.assertGreaterEqual(duree, 599)
        self.assertLess(duree, 620)

    def test_les_operations_des_connexions_d_une_identite_s_additionnent(self):
        s = self.mesurer([self.ligne(1, "uid=alice,dc=x", "198.51.100.1", 10, 7),
                          self.ligne(2, "uid=alice,dc=x", "198.51.100.1", 10, 5)])
        self.assertEqual(s.valeur('freeipa_connexion_operations{identite="alice",ip="198.51.100.1"}'), 12)

    def test_une_ligne_au_format_inattendu_est_ignoree_sans_interrompre_les_autres(self):
        s = self.mesurer(["ceci n est pas une connexion",
                          self.ligne(1, "uid=alice,dc=x", "198.51.100.1", 10, 1)])
        self.assertEqual(len(s.noms("freeipa_connexions_ouvertes")), 1)

    def test_aucune_connexion_declare_quand_meme_les_series(self):
        s = self.mesurer([])
        self.assertIn("freeipa_connexions_ouvertes", s.aides)
        self.assertEqual(s.noms("freeipa_connexions_ouvertes"), [])


class CompteurKerberos(unittest.TestCase):
    def setUp(self):
        self.repertoire = tempfile.TemporaryDirectory()
        self.addCleanup(self.repertoire.cleanup)
        self.journal = os.path.join(self.repertoire.name, "krb5kdc.log")
        self.etat = os.path.join(self.repertoire.name, "etat.json")
        for nom, valeur in (("JOURNAL_KDC", self.journal), ("ETAT", self.etat)):
            ancien = getattr(ef, nom)
            setattr(ef, nom, valeur)
            self.addCleanup(setattr, ef, nom, ancien)

    def ecrire(self, texte, mode="a"):
        with open(self.journal, mode) as f:
            f.write(texte)

    def collecter(self):
        r = ef.Registre()
        ef.kerberos(r)
        return Sortie(r)

    def test_les_requetes_sont_comptees_par_type(self):
        self.ecrire("AS_REQ ok\nTGS_REQ ok\nTGS_REQ ok\n")
        s = self.collecter()
        self.assertEqual(s.valeur('freeipa_kerberos_requetes_total{type="AS"}'), 1)
        self.assertEqual(s.valeur('freeipa_kerberos_requetes_total{type="TGS"}'), 2)

    def test_une_seconde_collecte_ne_recompte_pas_les_lignes_deja_lues(self):
        self.ecrire("AS_REQ ok\n")
        self.collecter()
        self.ecrire("AS_REQ ok\n")
        s = self.collecter()
        self.assertEqual(s.valeur('freeipa_kerberos_requetes_total{type="AS"}'), 2)

    def test_un_compteur_ne_redescend_pas_quand_le_journal_tourne(self):
        self.ecrire("AS_REQ ok\nAS_REQ ok\n")
        self.collecter()
        os.remove(self.journal)
        self.ecrire("AS_REQ ok\n", mode="w")
        s = self.collecter()
        self.assertEqual(s.valeur('freeipa_kerberos_requetes_total{type="AS"}'), 3)

    def test_un_journal_tronque_sur_place_est_relu_depuis_le_debut(self):
        self.ecrire("AS_REQ ok\nAS_REQ ok\nAS_REQ ok\n")
        self.collecter()
        self.ecrire("AS_REQ ok\n", mode="w")
        s = self.collecter()
        self.assertEqual(s.valeur('freeipa_kerberos_requetes_total{type="AS"}'), 4)

    def test_les_refus_sont_comptes_quel_que_soit_leur_libelle(self):
        self.ecrire("AS_REQ FAILED\nAS_REQ CLIENT_NOT_FOUND\nAS_REQ PREAUTH_FAILED\n")
        self.assertEqual(self.collecter().valeur("freeipa_kerberos_echecs_total"), 3)

    def test_un_etat_illisible_ne_fait_pas_echouer_la_collecte(self):
        with open(self.etat, "w") as f:
            f.write("{ceci n est pas du json")
        self.ecrire("AS_REQ ok\n")
        self.assertEqual(self.collecter().valeur('freeipa_kerberos_requetes_total{type="AS"}'), 1)

    def test_un_journal_absent_expose_des_compteurs_a_zero_plutot_que_rien(self):
        s = self.collecter()
        self.assertEqual(s.valeur('freeipa_kerberos_requetes_total{type="AS"}'), 0)
        self.assertEqual(s.valeur("freeipa_kerberos_echecs_total"), 0)


class EcritureAtomique(unittest.TestCase):
    def setUp(self):
        self.repertoire = tempfile.TemporaryDirectory()
        self.addCleanup(self.repertoire.cleanup)
        self.cible = os.path.join(self.repertoire.name, "freeipa.prom")

    def test_le_contenu_ecrit_est_celui_relu(self):
        ef.ecrire(self.cible, "m 1\n")
        self.assertEqual(open(self.cible).read(), "m 1\n")

    def test_le_fichier_est_lisible_par_node_exporter_qui_n_est_pas_root(self):
        ef.ecrire(self.cible, "m 1\n")
        self.assertEqual(oct(os.stat(self.cible).st_mode & 0o777), "0o644")

    def test_une_seconde_ecriture_remplace_sans_laisser_de_fichier_provisoire(self):
        ef.ecrire(self.cible, "m 1\n")
        ef.ecrire(self.cible, "m 2\n")
        self.assertEqual(open(self.cible).read(), "m 2\n")
        self.assertEqual(os.listdir(self.repertoire.name), ["freeipa.prom"])

    def test_une_ecriture_interrompue_ne_laisse_ni_fichier_partiel_ni_provisoire(self):
        # node_exporter lit ce fichier toutes les 15 secondes : un .tmp oublie
        # ou une version tronquee se verraient en series manquantes.
        ef.ecrire(self.cible, "m 1\n")
        with self.assertRaises(TypeError):
            ef.ecrire(self.cible, 42)
        self.assertEqual(open(self.cible).read(), "m 1\n")
        self.assertEqual(os.listdir(self.repertoire.name), ["freeipa.prom"])


class EtatDesServices(unittest.TestCase):
    STATUT = (
        "Directory Service: RUNNING\n"
        "krb5kdc Service: RUNNING\n"
        "named Service: STOPPED\n"
        "ipa-dnskeysyncd Service: RUNNING\n"
        "ipa: INFO: The ipactl command was successful\n"
    )

    def mesurer(self, statut):
        ancien = ef.subprocess.run
        ef.subprocess.run = Commande(statut)
        self.addCleanup(setattr, ef.subprocess, "run", ancien)
        r = ef.Registre()
        ef.services(r)
        return Sortie(r)

    def test_l_etiquette_est_composant_car_prometheus_operator_ecrase_service(self):
        s = self.mesurer(self.STATUT)
        self.assertTrue(all("composant=" in c for c in s.noms("freeipa_service_actif")))
        self.assertFalse(any('service="' in c for c in s.noms("freeipa_service_actif")))

    def test_l_annuaire_est_nomme_directory_comme_sur_la_machine(self):
        s = self.mesurer(self.STATUT)
        self.assertEqual(s.valeur('freeipa_service_actif{composant="directory"}'), 1)

    def test_un_service_arrete_vaut_zero_et_non_une_serie_absente(self):
        s = self.mesurer(self.STATUT)
        self.assertEqual(s.valeur('freeipa_service_actif{composant="named"}'), 0)

    def test_le_total_compte_les_services_declares_et_non_ceux_qui_marchent(self):
        s = self.mesurer(self.STATUT)
        self.assertEqual(s.valeur("freeipa_services_total"), 4)
        self.assertEqual(s.valeur("freeipa_services_actifs"), 3)

    def test_la_ligne_de_conclusion_d_ipactl_n_est_pas_prise_pour_un_service(self):
        s = self.mesurer(self.STATUT)
        self.assertNotIn('freeipa_service_actif{composant="ipa"}', s.series)


class CachesDeLAnnuaire(unittest.TestCase):
    def mesurer(self, attributs_user_root):
        doublure = Doublure(entrees={
            "cn=monitor": {"currentconnections": ["3"], "threads": ["16"],
                           "readwaiters": ["0"], "currentconnectionsatmaxthreads": ["0"],
                           "starttime": ["20261001120000Z"]},
            "cn=snmp,cn=monitor": {},
            "cn=monitor,cn=userRoot,cn=ldbm database,cn=plugins,cn=config": attributs_user_root,
        })
        r = ef.Registre()
        ef.annuaire(doublure, r)
        return Sortie(r)

    def test_le_taux_et_l_occupation_sont_exposes_pour_chaque_cache_de_la_base(self):
        s = self.mesurer({"entrycachehitratio": ["99"], "currententrycachesize": ["1000"],
                          "maxentrycachesize": ["2000"], "currententrycachecount": ["42"],
                          "entrycachetries": ["100"], "entrycachehits": ["99"],
                          "dncachehitratio": ["50"], "currentdncachesize": ["10"],
                          "maxdncachesize": ["20"], "currentdncachecount": ["2"]})
        self.assertEqual(s.valeur('freeipa_ldap_cache_taux{base="userRoot",cache="entrees"}'), 99)
        self.assertEqual(s.valeur('freeipa_ldap_cache_taux{base="userRoot",cache="dn"}'), 50)
        self.assertEqual(s.valeur('freeipa_ldap_cache_occupation_octets{base="userRoot",cache="entrees"}'), 1000)
        self.assertEqual(s.valeur('freeipa_ldap_cache_plafond_octets{base="userRoot",cache="entrees"}'), 2000)

    def test_un_plafond_nul_n_est_pas_expose_car_il_ferait_une_division_par_zero(self):
        # L alerte divise l occupation par le plafond : publier un zero y
        # produirait +Inf, et un cache sans plafond n a rien a signaler.
        s = self.mesurer({"entrycachehitratio": ["99"], "maxentrycachesize": ["0"],
                          "dncachehitratio": ["0"], "maxdncachesize": ["0"]})
        self.assertEqual(s.noms("freeipa_ldap_cache_plafond_octets"), [])
        self.assertIn('freeipa_ldap_cache_taux{base="userRoot",cache="entrees"}', s.series)

    def test_une_base_sans_entree_de_monitoring_est_passee_sans_series_vides(self):
        s = self.mesurer({})
        self.assertEqual(s.noms("freeipa_ldap_cache_taux"), [])

    def test_la_date_de_demarrage_de_l_annuaire_est_rendue_en_secondes_epoch(self):
        s = self.mesurer({})
        attendu = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc).timestamp()
        self.assertEqual(s.valeur("freeipa_ldap_demarrage_timestamp"), attendu)

    def test_les_compteurs_sont_annonces_en_counter_et_les_jauges_en_gauge(self):
        s = self.mesurer({})
        self.assertEqual(s.genres["freeipa_ldap_operations_initiees_total"], "counter")
        self.assertEqual(s.genres["freeipa_ldap_connexions_courantes"], "gauge")


class InventaireDuDomaine(unittest.TestCase):
    def test_les_comptes_actifs_et_desactives_sont_deux_etats_d_une_meme_mesure(self):
        base = "cn=users,cn=accounts,dc=exemple,dc=test"
        doublure = Doublure(comptes={
            (base, "(&(objectclass=posixaccount)(!(nsaccountlock=TRUE)))"): 12,
            (base, "(&(objectclass=posixaccount)(nsaccountlock=TRUE))"): 3,
        })
        r = ef.Registre()
        ef.inventaire(doublure, r)
        s = Sortie(r)
        self.assertEqual(s.valeur('freeipa_utilisateurs{etat="actif"}'), 12)
        self.assertEqual(s.valeur('freeipa_utilisateurs{etat="desactive"}'), 3)

    def test_une_mesure_a_deux_etats_n_est_declaree_qu_une_fois(self):
        # Un deuxieme bloc HELP pour le meme nom fait rejeter tout le fichier
        # par le collecteur textfile.
        r = ef.Registre()
        ef.inventaire(Doublure(), r)
        s = Sortie(r)
        self.assertEqual(s.aides["freeipa_utilisateurs"], ["Comptes utilisateurs."])

    def test_chaque_mesure_declaree_porte_une_aide(self):
        r = ef.Registre()
        ef.inventaire(Doublure(), r)
        s = Sortie(r)
        for cle in s.series:
            self.assertIn(cle.split("{")[0], s.aides)


class MachinesEnrolees(unittest.TestCase):
    def mesurer(self, fqdn):
        r = ef.Registre()
        ef.machines(Doublure(fqdn=fqdn), r)
        return Sortie(r)

    def test_une_serie_par_machine_plutot_qu_un_total_qui_ne_dit_pas_laquelle_manque(self):
        s = self.mesurer(["b.test", "a.test"])
        self.assertEqual(s.noms("freeipa_machine{"),
                         ['freeipa_machine{machine="a.test"}', 'freeipa_machine{machine="b.test"}'])

    def test_une_machine_listee_deux_fois_ne_produit_qu_une_serie(self):
        s = self.mesurer(["a.test", "a.test"])
        self.assertEqual(len(s.noms("freeipa_machine{")), 1)

    def test_un_domaine_vide_declare_la_mesure_sans_aucune_serie(self):
        s = self.mesurer([])
        self.assertIn("freeipa_machine", s.aides)
        self.assertEqual(s.noms("freeipa_machine{"), [])


class Certificats(unittest.TestCase):
    def test_une_date_openssl_est_rendue_en_secondes_epoch(self):
        # certificats() lit des chemins fixes : on verifie la conversion sur la
        # fonction de bibliotheque qu il emploie, pas sur le systeme de fichiers.
        t = datetime.strptime("Oct  9 10:00:00 2027 GMT", "%b %d %H:%M:%S %Y %Z")
        self.assertEqual(t.replace(tzinfo=timezone.utc).timestamp(),
                         datetime(2027, 10, 9, 10, 0, tzinfo=timezone.utc).timestamp())

    def test_un_certificat_absent_ne_fait_pas_echouer_la_collecte(self):
        ancien = ef.subprocess.run
        ef.subprocess.run = Commande("")
        self.addCleanup(setattr, ef.subprocess, "run", ancien)
        r = ef.Registre()
        ef.certificats(r)
        self.assertIn("freeipa_certificat_expiration_timestamp", Sortie(r).aides)


class CollecteComplete(unittest.TestCase):
    def test_une_collecte_qui_echoue_le_dit_au_lieu_de_laisser_des_series_figees(self):
        # Sans freeipa_collecte_reussie, un annuaire muet se lirait comme un
        # annuaire calme : les compteurs ne bougent plus, aucun seuil n est
        # franchi, et aucune alerte ne part.
        repertoire = tempfile.TemporaryDirectory()
        self.addCleanup(repertoire.cleanup)
        cible = os.path.join(repertoire.name, "freeipa.prom")
        for nom, valeur in (("DESTINATION", cible), ("JOURNAL_KDC", "/inexistant"),
                            ("ETAT", os.path.join(repertoire.name, "etat.json"))):
            ancien = getattr(ef, nom)
            setattr(ef, nom, valeur)
            self.addCleanup(setattr, ef, nom, ancien)

        class Injoignable:
            def __init__(self, _):
                raise RuntimeError("aucun socket dirsrv dans /run")

        ancien = ef.Annuaire
        ef.Annuaire = Injoignable
        self.addCleanup(setattr, ef, "Annuaire", ancien)

        with contextlib.redirect_stdout(io.StringIO()) as bruit:
            self.assertEqual(ef.main(), 1)
        self.assertIn("collecte incomplete", bruit.getvalue())
        s = Sortie(type("R", (), {"__str__": lambda _: open(cible).read()})())
        self.assertEqual(s.valeur("freeipa_collecte_reussie"), 0)
        self.assertGreater(s.valeur("freeipa_collecte_timestamp"), time.time() - 60)


class CheminsSysteme(unittest.TestCase):
    """Ils varient selon la distribution : aucun ne doit etre fige dans le code."""

    def recharger(self, **variables):
        anciennes = {c: os.environ.get(c) for c in variables}
        for cle, valeur in variables.items():
            if valeur is None:
                os.environ.pop(cle, None)
            else:
                os.environ[cle] = valeur

        def rendre():
            for cle, valeur in anciennes.items():
                if valeur is None:
                    os.environ.pop(cle, None)
                else:
                    os.environ[cle] = valeur
        self.addCleanup(rendre)
        # Le module lit son environnement a l execution : il faut le rejouer, et
        # non reutiliser celui qui a ete charge en tete de fichier.
        spec = importlib.util.spec_from_file_location("exporteur_rejoue", CHEMIN)
        rejoue = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(rejoue)
        return rejoue

    def test_le_fichier_de_metriques_suit_le_repertoire_du_collecteur_textfile(self):
        self.assertEqual(self.recharger(FICHIER_METRIQUES="/ailleurs/ipa.prom").DESTINATION,
                         "/ailleurs/ipa.prom")

    def test_le_fichier_d_etat_se_place_ou_l_exportateur_peut_ecrire(self):
        self.assertEqual(self.recharger(FICHIER_ETAT="/ailleurs/etat.json").ETAT,
                         "/ailleurs/etat.json")

    def test_le_journal_du_kdc_n_est_pas_au_meme_endroit_partout(self):
        self.assertEqual(self.recharger(JOURNAL_KDC="/ailleurs/kdc.log").JOURNAL_KDC,
                         "/ailleurs/kdc.log")

    def test_sans_configuration_les_chemins_sont_ceux_du_paquet_node_exporter(self):
        # Explicitement vides : l environnement du poste ne doit pas decider.
        rejoue = self.recharger(FICHIER_METRIQUES=None, FICHIER_ETAT=None,
                                JOURNAL_KDC=None)
        self.assertEqual(rejoue.DESTINATION,
                         "/var/lib/node_exporter/textfile_collector/freeipa.prom")
        self.assertEqual(rejoue.ETAT, "/var/lib/node_exporter/etat-freeipa.json")
        self.assertEqual(rejoue.JOURNAL_KDC, "/var/log/krb5kdc.log")


class SuffixeDuDomaine(unittest.TestCase):
    """Le suffixe se deduit de l annuaire : aucune valeur de site dans le depot."""

    class SansSocket(ef.Annuaire):
        """Seule la recherche du socket est remplacee : elle n existe qu en production."""

        @staticmethod
        def _socket(_instance):
            return "/run/slapd-doublure.socket"

    def annuaire(self, rootdse, base=""):
        """Un vrai Annuaire : ldapsearch est remplace, le reste est le code teste."""
        self.commande = Commande(rootdse)
        ancien = ef.subprocess.run
        ef.subprocess.run = self.commande
        self.addCleanup(setattr, ef.subprocess, "run", ancien)
        return self.SansSocket(base=base)

    def test_le_suffixe_est_lu_dans_le_rootdse_faute_de_configuration(self):
        a = self.annuaire("dn:\ndefaultnamingcontext: dc=exemple,dc=test\n")
        self.assertEqual(a.base, "dc=exemple,dc=test")

    def test_les_attributs_du_rootdse_sont_demandes_car_ils_sont_operationnels(self):
        # Sans les nommer, 389-DS ne les renvoie pas : la detection rendrait vide.
        a = self.annuaire("dn:\ndefaultnamingcontext: dc=exemple,dc=test\n")
        a.base
        argv = self.commande.appels[0]
        self.assertIn("defaultnamingcontext", argv)
        self.assertIn("namingContexts", argv)

    def test_le_rootdse_est_interroge_a_la_racine_et_non_dans_le_domaine(self):
        a = self.annuaire("dn:\ndefaultnamingcontext: dc=exemple,dc=test\n")
        a.base
        argv = self.commande.appels[0]
        self.assertEqual(argv[argv.index("-b") + 1], "")
        self.assertEqual(argv[argv.index("-s") + 1], "base")

    def test_un_suffixe_fourni_par_la_configuration_n_interroge_pas_l_annuaire(self):
        a = self.annuaire("", base="dc=impose,dc=test")
        self.assertEqual(a.base, "dc=impose,dc=test")
        self.assertEqual(self.commande.appels, [])

    def test_le_contexte_de_l_autorite_de_certification_n_est_pas_le_domaine(self):
        # o=ipaca est un contexte de nommage a part entiere, et vient parfois en
        # tete : le retenir ferait chercher les comptes dans la mauvaise base.
        a = self.annuaire("dn:\nnamingContexts: o=ipaca\nnamingContexts: dc=exemple,dc=test\n")
        self.assertEqual(a.base, "dc=exemple,dc=test")

    def test_le_suffixe_par_defaut_prime_sur_la_liste_des_contextes(self):
        a = self.annuaire("dn:\nnamingContexts: dc=autre,dc=test\n"
                          "defaultnamingcontext: dc=bon,dc=test\n")
        self.assertEqual(a.base, "dc=bon,dc=test")

    def test_le_suffixe_n_est_lu_qu_une_fois_pour_toute_la_collecte(self):
        # inventaire, machines et temps_de_reponse le demandent chacun : une
        # lecture par appel ajouterait trois allers-retours a chaque passage.
        a = self.annuaire("dn:\ndefaultnamingcontext: dc=exemple,dc=test\n")
        a.base, a.base, a.base
        self.assertEqual(len(self.commande.appels), 1)

    def test_un_rootdse_muet_fait_echouer_la_collecte_plutot_que_deviner(self):
        a = self.annuaire("dn:\n")
        with self.assertRaises(RuntimeError):
            a.base


if __name__ == "__main__":
    unittest.main(verbosity=2)
