#!/usr/bin/env python3
# Copyright (C) 2026 gtranche
# SPDX-License-Identifier: GPL-3.0-or-later
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

    def __init__(self, par_dn=None, comptes=None, fqdn=(), base="dc=exemple,dc=test"):
        self.par_dn = par_dn or {}
        self.comptes = comptes or {}
        self.fqdn = fqdn
        self.base = base
        self.url = "ldapi://doublure"

    def entree(self, dn, demandes=()):
        return self.par_dn.get(dn, {})

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
        doublure = Doublure(par_dn={
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
            def __init__(self, *_):
                raise RuntimeError("aucun socket dirsrv dans /run")

        ancien = ef.Annuaire
        ef.Annuaire = Injoignable
        self.addCleanup(setattr, ef, "Annuaire", ancien)

        with contextlib.redirect_stdout(io.StringIO()) as bruit:
            self.assertEqual(ef.main(), 1)
        self.assertIn("sonde annuaire : aucun socket dirsrv", bruit.getvalue())
        s = Sortie(type("R", (), {"__str__": lambda _: open(cible).read()})())
        self.assertEqual(s.valeur("freeipa_collecte_reussie"), 0)
        self.assertGreater(s.valeur("freeipa_collecte_timestamp"), time.time() - 60)

    def test_chaque_sonde_dit_son_propre_etat_pour_qu_on_sache_laquelle_est_tombee(self):
        # « collecte en echec » n indique pas quoi reparer, et une sonde qui n a
        # pas pu etre jouee doit compter comme en echec, pas disparaitre.
        registre = ef.Registre()
        sondes = ef.Sondes(registre, ef.SONDES)
        self.assertEqual(sondes.publier(), 0)
        s = Sortie(registre)
        for nom in ef.SONDES:
            self.assertEqual(s.valeur(f'freeipa_collecte_sonde_reussie{{sonde="{nom}"}}'), 0, nom)


class SondesIndependantes(unittest.TestCase):
    """Une sonde en panne ne doit pas emporter la collecte entiere.

    ipactl absent ne dit rien des certificats, et un annuaire injoignable ne
    dit rien de Kerberos : tout perdre sur une panne, c est perdre la mesure
    qui aurait nomme la cause.
    """

    def test_une_sonde_en_panne_ne_prive_pas_des_autres(self):
        registre = ef.Registre()
        sondes = ef.Sondes(registre, ("qui_tombe", "qui_marche"))

        def tombe():
            raise RuntimeError("ipactl introuvable")

        with contextlib.redirect_stdout(io.StringIO()) as bruit:
            self.assertIsNone(sondes.jouer("qui_tombe", tombe))
        self.assertIn("sonde qui_tombe : ipactl introuvable", bruit.getvalue())
        sondes.jouer("qui_marche", lambda: None)
        sondes.publier()
        s = Sortie(registre)
        self.assertEqual(s.valeur('freeipa_collecte_sonde_reussie{sonde="qui_tombe"}'), 0)
        self.assertEqual(s.valeur('freeipa_collecte_sonde_reussie{sonde="qui_marche"}'), 1)

    def test_la_collecte_n_est_reussie_que_si_toutes_les_sondes_aboutissent(self):
        registre = ef.Registre()
        sondes = ef.Sondes(registre, ("a", "b"))
        sondes.jouer("a", lambda: None)
        self.assertEqual(sondes.publier(), 0)
        sondes.jouer("b", lambda: None)
        self.assertEqual(sondes.publier(), 1)

    def test_une_sonde_rend_ce_que_le_collecteur_a_produit(self):
        # annuaire() rend les compteurs que connexions() lit ensuite : les
        # perdre reviendrait a enchainer sur du vide.
        sondes = ef.Sondes(ef.Registre(), ("a",))
        self.assertEqual(sondes.jouer("a", lambda x: {"vu": x}, 3), {"vu": 3})


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


# LDIF releve tel quel sur deux replicas 389-DS 2.4.6 en multi-maitre.
REPLICAS = """dn: cn=replica,cn=dc\\3Dexemple\\2Cdc\\3Dtest,cn=mapping tree,cn=config
nsDS5ReplicaRoot: dc=exemple,dc=test
nsDS5ReplicaId: 1
nsDS5ReplicaType: 3
nsds5ReplicaChangeCount: 10
nsds50ruv: {replicageneration} 6ac8d195000000010000
nsds50ruv: {replica 1 ldap://ds1.exemple.test:3389} 6ac8d19b000100010000 6ac8d1fa000000010000
nsds50ruv: {replica 2 ldap://ds2.exemple.test:3389} 6ac8d19e000100020000 6ac8d26c000000020000
"""

SAIN = ('nsds5replicaLastUpdateStatus: Error (0) Replica acquired successfully:'
        ' Incremental update succeeded\n'
        'nsds5replicaLastUpdateStatusJSON: {"state": "green", "ldap_rc": "0",'
        ' "ldap_rc_text": "Success", "repl_rc": "0", "repl_rc_text": "replica acquired"}\n')
ECHEC = ('nsds5replicaLastUpdateStatus: Error (-1) Problem connecting to replica'
         ' - LDAP error: Can\'t contact LDAP server (connection error)\n'
         'nsds5replicaLastUpdateStatusJSON: {"state": "red", "ldap_rc": "-1",'
         ' "ldap_rc_text": "Can\'t contact LDAP server", "repl_rc": "16"}\n')


def accord(statut=SAIN, extra=""):
    return ("dn: cn=vers-ds2,cn=replica,cn=dc\\3Dexemple\\2Cdc\\3Dtest,cn=mapping tree,cn=config\n"
            "cn: vers-ds2\n"
            "nsDS5ReplicaRoot: dc=exemple,dc=test\n"
            "nsDS5ReplicaHost: ds2.exemple.test\n"
            "nsDS5ReplicaPort: 3389\n"
            "nsds5replicaUpdateInProgress: FALSE\n"
            "nsds5replicaLastUpdateEnd: 20261009113622Z\n"
            "nsds5replicaChangesSentSinceStartup:: MTo4LzAg\n" + statut + extra)


class HeureGeneralisee(unittest.TestCase):
    """Un seul analyseur de date, employe par l annuaire et par la replication."""

    def test_une_heure_generalisee_ldap_devient_une_epoque_unix(self):
        self.assertEqual(ef.epoque("20261009113622Z"), 1791545782)

    def test_le_fuseau_est_utc_et_non_celui_de_la_machine(self):
        # Sans tzinfo explicite, Python lirait l heure locale et decalerait tout.
        self.assertEqual(ef.epoque("19700101000000Z"), 0)

    def test_une_date_illisible_rend_le_defaut_au_lieu_de_lever(self):
        self.assertEqual(ef.epoque("pas une date", defaut=-1), -1)


class LectureDePlusieursEntrees(unittest.TestCase):
    """Les accords de replication sont plusieurs : les fusionner les perdrait."""

    def annuaire(self, *sorties):
        self.commande = Commande(*sorties)
        ancien = ef.subprocess.run
        ef.subprocess.run = self.commande
        self.addCleanup(setattr, ef.subprocess, "run", ancien)

        class SansSocket(ef.Annuaire):
            @staticmethod
            def _socket(_instance):
                return "/run/slapd-doublure.socket"

        return SansSocket(base="dc=exemple,dc=test")

    def test_deux_entrees_sont_rendues_separement_et_non_fusionnees(self):
        a = self.annuaire("dn: cn=a\ncn: a\ndn: cn=b\ncn: b\n")
        trouvees = a.entrees("cn=config", "(objectclass=*)", ["cn"])
        self.assertEqual([e["cn"] for e in trouvees], [["a"], ["b"]])

    def test_une_valeur_encodee_en_base64_est_decodee(self):
        # ldapsearch ecrit « attribut:: » pour ce qui n est pas imprimable, et
        # les compteurs de replication en font partie.
        a = self.annuaire("dn: cn=a\nnsds5replicaChangesSentSinceStartup:: MTo4LzAg\n")
        trouvees = a.entrees("cn=config", "(objectclass=*)", [])
        self.assertEqual(trouvees[0]["nsds5replicachangessentsincestartup"], ["1:8/0"])

    def test_un_attribut_avant_tout_dn_est_ignore_plutot_que_de_lever(self):
        a = self.annuaire("cn: orphelin\ndn: cn=a\ncn: a\n")
        self.assertEqual(a.entrees("cn=config", "(objectclass=*)", []), [{"dn": ["cn=a"], "cn": ["a"]}])


class SanteDesAccords(unittest.TestCase):
    """L etat d un accord se lit sans se faire piéger par le texte du statut."""

    def test_un_accord_sain_est_reconnu_malgre_un_texte_qui_commence_par_error(self):
        # 389-DS ecrit « Error (0) ... succeeded » quand tout va bien : chercher
        # le mot Error rendrait tout accord sain en panne.
        self.assertEqual(ef.sante_accord({
            "nsds5replicalastupdatestatusjson": ['{"state": "green"}']}), 2)

    def test_un_accord_en_echec_est_distingue_d_un_accord_sain(self):
        self.assertEqual(ef.sante_accord({
            "nsds5replicalastupdatestatusjson": ['{"state": "red"}']}), 0)

    def test_un_accord_degrade_n_est_ni_sain_ni_en_echec(self):
        self.assertEqual(ef.sante_accord({
            "nsds5replicalastupdatestatusjson": ['{"state": "amber"}']}), 1)

    def test_sans_le_champ_json_le_code_entre_parentheses_du_texte_fait_foi(self):
        # Les 389-DS anterieurs a 1.4 n ont pas le champ JSON.
        self.assertEqual(ef.sante_accord({
            "nsds5replicalastupdatestatus": ["Error (0) Incremental update succeeded"]}), 2)
        self.assertEqual(ef.sante_accord({
            "nsds5replicalastupdatestatus": ["Error (-1) Problem connecting to replica"]}), 0)

    def test_un_json_illisible_vaut_indetermine_et_non_une_panne(self):
        # Une alerte fausse coute plus cher qu une alerte absente.
        self.assertEqual(ef.sante_accord({
            "nsds5replicalastupdatestatusjson": ["{ceci n est pas du json"]}), 1)

    def test_un_etat_json_inconnu_vaut_indetermine_plutot_qu_une_panne(self):
        # Une version a venir de 389-DS peut nommer un etat que nous ignorons.
        self.assertEqual(ef.sante_accord({
            "nsds5replicalastupdatestatusjson": ['{"state": "mauve"}']}), 1)

    def test_un_statut_absent_vaut_indetermine(self):
        self.assertEqual(ef.sante_accord({}), 1)


class EtatDeLaReplication(unittest.TestCase):
    """Chaque serveur ne publie que sa propre vue : la comparaison est en PromQL."""

    def collecter(self, *sorties):
        self.commande = Commande(*sorties)
        ancien = ef.subprocess.run
        ef.subprocess.run = self.commande
        self.addCleanup(setattr, ef.subprocess, "run", ancien)

        class SansSocket(ef.Annuaire):
            @staticmethod
            def _socket(_instance):
                return "/run/slapd-doublure.socket"

        registre = ef.Registre()
        ef.replication(SansSocket(base="dc=exemple,dc=test"), registre)
        return Sortie(registre)

    def test_un_serveur_seul_sans_replication_ne_fait_pas_echouer_la_collecte(self):
        s = self.collecter("")
        self.assertEqual(s.valeur("freeipa_replication_suffixes"), 0)
        self.assertNotIn("freeipa_replication_accords", s.series)

    def test_le_ruv_donne_une_date_par_fournisseur_ce_qui_permet_de_les_comparer(self):
        s = self.collecter(REPLICAS, "", accord())
        self.assertEqual(s.valeur('freeipa_replication_ruv_timestamp{fournisseur='
                                  '"ldap://ds1.exemple.test:3389",replica="1",'
                                  'suffixe="dc=exemple,dc=test"}'), 1791545850)
        self.assertEqual(s.valeur('freeipa_replication_ruv_timestamp{fournisseur='
                                  '"ldap://ds2.exemple.test:3389",replica="2",'
                                  'suffixe="dc=exemple,dc=test"}'), 1791545964)

    def test_la_generation_du_replica_n_est_pas_prise_pour_un_fournisseur(self):
        # « {replicageneration} » n a pas d identifiant : il ne doit pas entrer.
        s = self.collecter(REPLICAS, "", accord())
        self.assertEqual(len([l for l in s.series if l.startswith(
            "freeipa_replication_ruv_timestamp{")]), 2)

    def test_un_fournisseur_encore_sans_changement_ne_produit_pas_de_serie(self):
        neuf = ("dn: cn=replica,cn=mapping tree,cn=config\n"
                "nsDS5ReplicaRoot: dc=exemple,dc=test\n"
                "nsds50ruv: {replica 3 ldap://ds3.exemple.test:3389}\n")
        s = self.collecter(neuf, "", "")
        self.assertEqual([l for l in s.series if l.startswith(
            "freeipa_replication_ruv_timestamp{")], [])

    def test_les_compteurs_d_envoi_encodes_en_base64_sont_decodes(self):
        s = self.collecter(REPLICAS, "", accord())
        e = ('{accord="vers-ds2",pair="ds2.exemple.test",suffixe="dc=exemple,dc=test"}')
        self.assertEqual(s.valeur("freeipa_replication_accord_changements_envoyes_total" + e), 8)
        self.assertEqual(s.valeur("freeipa_replication_accord_changements_omis_total" + e), 0)

    def test_un_accord_en_panne_est_signale_alors_que_le_serveur_repond(self):
        # Le cas que up ne voit pas : les deux serveurs debout, la replication muette.
        s = self.collecter(REPLICAS, "", accord(ECHEC))
        self.assertEqual(s.valeur('freeipa_replication_accord_etat{accord="vers-ds2",'
                                  'pair="ds2.exemple.test",suffixe="dc=exemple,dc=test"}'), 0)

    def test_les_deux_suffixes_repliques_d_un_serveur_freeipa_sont_distingues(self):
        # Un serveur FreeIPA avec autorite replique aussi o=ipaca.
        deux = REPLICAS + ("dn: cn=replica,cn=o\\3Dipaca,cn=mapping tree,cn=config\n"
                           "nsDS5ReplicaRoot: o=ipaca\n"
                           "nsDS5ReplicaId: 1181\n")
        s = self.collecter(deux, "", "", accord())
        self.assertEqual(s.valeur("freeipa_replication_suffixes"), 2)
        self.assertEqual(s.valeur('freeipa_replication_identifiant{suffixe="o=ipaca"}'), 1181)

    def test_les_entrees_en_conflit_sont_comptees_dans_le_suffixe_concerne(self):
        s = self.collecter(REPLICAS, "dn: nsuniqueid=1+uid=alice\ndn: nsuniqueid=2+uid=bob\n", accord())
        self.assertEqual(s.valeur('freeipa_replication_conflits{suffixe="dc=exemple,dc=test"}'), 2)

    def test_les_conflits_sont_cherches_dans_le_suffixe_et_non_dans_la_configuration(self):
        self.collecter(REPLICAS, "", accord())
        bases = [argv[argv.index("-b") + 1] for argv in self.commande.appels]
        self.assertIn("dc=exemple,dc=test", bases)

    def test_le_mot_de_passe_du_compte_de_replication_n_est_jamais_demande(self):
        # Liste blanche d attributs : il vit dans la meme entree que le statut.
        self.collecter(REPLICAS, "", accord())
        demandes = " ".join(" ".join(argv) for argv in self.commande.appels).lower()
        for interdit in ("credential", "passwd", "password", "nsds5replicabinddn"):
            self.assertNotIn(interdit, demandes)

    def test_une_date_de_derniere_mise_a_jour_absente_ne_devient_pas_zero(self):
        # Une epoque a zero s afficherait comme 1970 et declencherait l alerte de retard.
        sans_date = accord().replace("nsds5replicaLastUpdateEnd: 20261009113622Z\n", "")
        s = self.collecter(REPLICAS, "", sans_date)
        self.assertEqual([l for l in s.series if l.startswith(
            "freeipa_replication_accord_derniere_maj_timestamp{")], [])

    def test_une_mise_a_jour_en_cours_est_rapportee_telle_quelle(self):
        en_cours = accord().replace("nsds5replicaUpdateInProgress: FALSE",
                                    "nsds5replicaUpdateInProgress: TRUE")
        s = self.collecter(REPLICAS, "", en_cours)
        self.assertEqual(s.valeur('freeipa_replication_accord_en_cours{accord="vers-ds2",'
                                  'pair="ds2.exemple.test",suffixe="dc=exemple,dc=test"}'), 1)

class GenreDeLAuteur(unittest.TestCase):
    """« Qui » commence par : est-ce quelqu un, ou un automate ?"""

    def test_un_compte_utilisateur_est_reconnu_comme_une_personne(self):
        self.assertEqual(ef.genre_auteur("uid=marie,cn=users,cn=accounts,dc=exemple,dc=test"), "compte")

    def test_un_principal_de_service_n_est_pas_pris_pour_une_personne(self):
        self.assertEqual(ef.genre_auteur("krbprincipalname=DNS/ds1.exemple.test@EXEMPLE.TEST,cn=services,dc=exemple,dc=test"), "service")

    def test_un_principal_de_machine_est_distingue_d_un_service(self):
        self.assertEqual(ef.genre_auteur("fqdn=poste.exemple.test,cn=computers,dc=exemple,dc=test"), "machine")

    def test_un_greffon_de_l_annuaire_n_est_pas_un_administrateur(self):
        self.assertEqual(ef.genre_auteur("cn=memberOf Plugin,cn=plugins,cn=config"), "greffon")

    def test_le_directory_manager_est_nomme_administrateur(self):
        self.assertEqual(ef.genre_auteur("cn=Directory Manager"), "administrateur")

    def test_le_compte_de_l_autorite_de_certification_n_est_pas_une_personne(self):
        # Mesure du 2026-11-01 : c est lui qui reecrit la CRL toutes les quinze
        # minutes. Compte comme personne, il noie la derniere main humaine.
        self.assertEqual(ef.genre_auteur("uid=pkidbuser,ou=People,o=ipaca"), "autorite")

    def test_un_auteur_vide_rend_un_genre_plutot_que_de_lever(self):
        self.assertEqual(ef.genre_auteur(""), "autre")
        self.assertEqual(ef.genre_auteur(None), "autre")


class BrancheDeLEntree(unittest.TestCase):
    """Le RDN seul ne dit pas si « wazuh » est une machine ou une zone DNS."""

    BASE = "dc=exemple,dc=test"

    def test_une_zone_dns_et_un_compte_de_meme_nom_sont_distingues(self):
        self.assertEqual(ef.branche(f"idnsname=wazuh.t.,cn=dns,{self.BASE}", self.BASE), "cn=dns")
        self.assertEqual(ef.branche(f"uid=wazuh,cn=users,cn=accounts,{self.BASE}", self.BASE),
                         "cn=accounts")

    def test_une_virgule_echappee_ne_coupe_pas_le_composant_en_deux(self):
        # « dc\\=exemple\\,dc\\=test » est un seul composant : 389-DS en sert.
        self.assertEqual(ef.branche("cn=x,dc\\=exemple\\,dc\\=test," + self.BASE, self.BASE),
                         "dc\\=exemple\\,dc\\=test")

    def test_une_entree_posee_a_meme_le_suffixe_a_le_suffixe_pour_branche(self):
        self.assertEqual(ef.branche(f"uid=seul,{self.BASE}", self.BASE), self.BASE)

    def test_un_contexte_de_nommage_etranger_est_sa_propre_branche(self):
        self.assertEqual(ef.branche("o=ipaca", self.BASE), "o=ipaca")

    def test_le_suffixe_lui_meme_rend_le_suffixe_et_non_une_chaine_vide(self):
        self.assertEqual(ef.branche(self.BASE, self.BASE), self.BASE)

    def test_une_entree_hors_du_suffixe_garde_sa_propre_branche(self):
        self.assertEqual(ef.branche("cn=MasterCRL,ou=crlIssuingPoints,o=ipaca", self.BASE),
                         "o=ipaca")


class GenreDObjetTouche(unittest.TestCase):
    """La branche ne distingue pas ce que l administrateur distingue.

    Mesure du 2026-11-01 sur l annuaire reel : utilisateurs, groupes, machines
    et services rendaient tous « cn=accounts ». Les conteneurs de ces tests
    sont ceux lus dans api.env de l installation.
    """

    BASE = "dc=exemple,dc=test"

    def objet(self, dn):
        return ef.objet(dn + "," + self.BASE, self.BASE)

    def test_un_groupe_ne_se_confond_plus_avec_un_utilisateur(self):
        self.assertEqual(self.objet("uid=jdoe,cn=users,cn=accounts"), "utilisateur")
        self.assertEqual(self.objet("cn=admins,cn=groups,cn=accounts"), "groupe")

    def test_un_groupe_de_machines_se_distingue_d_une_machine(self):
        self.assertEqual(self.objet("fqdn=w1.exemple.test,cn=computers,cn=accounts"),
                         "machine")
        self.assertEqual(self.objet("cn=serveurs,cn=hostgroups,cn=accounts"),
                         "groupe de machines")

    def test_une_regle_hbac_se_distingue_d_un_service_hbac(self):
        self.assertEqual(self.objet("ipauniqueid=abc,cn=hbac"), "regle hbac")
        self.assertEqual(self.objet("cn=sshd,cn=hbacservices,cn=hbac"), "service hbac")
        self.assertEqual(self.objet("cn=admin,cn=hbacservicegroups,cn=hbac"),
                         "groupe de services hbac")

    def test_une_regle_sudo_se_distingue_d_une_commande_sudo(self):
        self.assertEqual(self.objet("ipauniqueid=abc,cn=sudorules,cn=sudo"), "regle sudo")
        self.assertEqual(self.objet("sudocmd=/bin/ls,cn=sudocmds,cn=sudo"), "commande sudo")
        self.assertEqual(self.objet("cn=lecture,cn=sudocmdgroups,cn=sudo"),
                         "groupe de commandes sudo")

    def test_un_enregistrement_dns_se_distingue_de_sa_zone(self):
        # cn=dns est le seul conteneur a profondeur libre de FreeIPA.
        self.assertEqual(self.objet("idnsname=exemple.test.,cn=dns"), "zone dns")
        self.assertEqual(self.objet("idnsname=www,idnsname=exemple.test.,cn=dns"),
                         "enregistrement dns")

    def test_la_configuration_du_serveur_est_nommee_hors_du_suffixe(self):
        # Le premier enregistrement reel du journal portait sur cn=config :
        # c est l allumage du journal lui-meme.
        self.assertEqual(ef.objet("cn=config", self.BASE), "configuration du serveur")
        self.assertEqual(ef.objet("cn=encryption,cn=config", self.BASE),
                         "configuration du serveur")

    def test_l_autorite_de_certification_n_est_pas_une_entree_du_domaine(self):
        self.assertEqual(ef.objet("cn=MasterCRL,ou=crlIssuingPoints,ou=ca,o=ipaca",
                                  self.BASE), "autorite de certification")

    def test_un_conteneur_inconnu_retombe_sur_sa_branche_plutot_que_d_etre_tu(self):
        # Un genre inconnu doit rester visible : « autre » cacherait ou l
        # ecriture a eu lieu.
        self.assertEqual(self.objet("cn=x,cn=inconnu"), "cn=inconnu")


class HeureDUnEnregistrementDAudit(unittest.TestCase):
    """389-DS date son journal d audit en heure locale, l annuaire en UTC."""

    def fuseau(self, nom):
        ancien = os.environ.get("TZ")
        os.environ["TZ"] = nom
        time.tzset()
        def rendre():
            if ancien is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = ancien
            time.tzset()
        self.addCleanup(rendre)

    def test_l_heure_du_journal_d_audit_est_lue_en_heure_locale(self):
        # Mesure du 2026-11-01 : le meme enregistrement porte « time:
        # 20261101225437 » et « modifytimestamp: 20261101215437Z ». Lue comme
        # une heure generalisee, chaque trace serait datee d une heure trop tot.
        self.fuseau("Europe/Paris")
        self.assertEqual(ef.epoque_locale("20261101225437"),
                         ef.epoque("20261101215437Z"))

    def test_le_decalage_suit_le_fuseau_du_serveur_et_non_celui_du_lecteur(self):
        self.fuseau("Asia/Tokyo")
        self.assertEqual(ef.epoque_locale("20261101225437"),
                         ef.epoque("20261101135437Z"))

    def test_une_heure_illisible_ne_fait_pas_tomber_la_collecte(self):
        self.assertEqual(ef.epoque_locale("pas une heure"), 0)


class EtatPartage(unittest.TestCase):
    """L etat est relu par chaque sonde : s il est illisible, toutes tombent."""

    def setUp(self):
        self.repertoire = tempfile.TemporaryDirectory()
        self.addCleanup(self.repertoire.cleanup)
        ancien = ef.ETAT
        ef.ETAT = os.path.join(self.repertoire.name, "etat.json")
        self.addCleanup(setattr, ef, "ETAT", ancien)

    def ecrire(self, contenu):
        with open(ef.ETAT, "w") as f:
            f.write(contenu)

    def test_un_etat_absent_est_un_etat_vide(self):
        self.assertEqual(ef.lire_etat(), {})

    def test_un_etat_tronque_est_un_etat_vide(self):
        self.ecrire('{"as": 12')
        self.assertEqual(ef.lire_etat(), {})

    def test_un_etat_qui_n_est_pas_un_objet_est_un_etat_vide(self):
        # « null » et « [] » sont du JSON valide : sans garde, la premiere sonde
        # qui y cherche une cle tombe, et toutes les suivantes avec elle.
        for contenu in ("null", "[]", '"douze"', "12"):
            self.ecrire(contenu)
            self.assertEqual(ef.lire_etat(), {}, contenu)

    def test_ce_qui_est_ecrit_est_relu(self):
        ef.ecrire_etat({"as": 12, "modifications": {"quand": 1, "mesure": {"suivies": 3}}})
        self.assertEqual(ef.lire_etat()["modifications"]["mesure"]["suivies"], 3)


class QuiAModifieQuoi(unittest.TestCase):
    """Les attributs operationnels repondent deja, sans rien allumer."""

    def setUp(self):
        # Sans etat propre, le releve ecrirait dans le fichier de production et
        # ces tests seraient verts parce que son cache ne marche pas ici.
        self.repertoire = tempfile.TemporaryDirectory()
        self.addCleanup(self.repertoire.cleanup)
        ancien = ef.ETAT
        ef.ETAT = os.path.join(self.repertoire.name, "etat.json")
        self.addCleanup(setattr, ef, "ETAT", ancien)
        self.recherches = 0

    def collecter(self, ldif, limite=20, periode=0):
        for nom, valeur in (("LIMITE_MODIFICATIONS", limite),
                            ("PERIODE_MODIFICATIONS", periode)):
            ancienne = getattr(ef, nom)
            setattr(ef, nom, valeur)
            self.addCleanup(setattr, ef, nom, ancienne)
        commande = Commande(ldif)

        def compter(*args, **kwargs):
            self.recherches += 1
            return commande(*args, **kwargs)

        ancien = ef.subprocess.run
        ef.subprocess.run = compter
        self.addCleanup(setattr, ef.subprocess, "run", ancien)

        class SansSocket(ef.Annuaire):
            @staticmethod
            def _socket(_instance):
                return "/run/doublure.socket"

        registre = ef.Registre()
        ef.modifications(SansSocket(base="dc=exemple,dc=test"), registre)
        return Sortie(registre)

    @staticmethod
    def entree(dn, auteur, quand, createur=None):
        return (f"dn: {dn}\nmodifiersName: {auteur}\nmodifyTimestamp: {quand}\n"
                f"creatorsName: {createur or auteur}\n")

    def test_deux_entrees_du_meme_auteur_ne_font_qu_une_serie(self):
        s = self.collecter(
            self.entree("uid=a,cn=users,cn=accounts,dc=exemple,dc=test",
                        "uid=gtranche,cn=users,cn=accounts,dc=exemple,dc=test", "20261001120000Z")
            + self.entree("uid=b,cn=users,cn=accounts,dc=exemple,dc=test",
                          "uid=gtranche,cn=users,cn=accounts,dc=exemple,dc=test", "20261002120000Z"))
        self.assertEqual(s.valeur('freeipa_entrees_modifiees{auteur="gtranche",genre="compte"}'), 2)

    def test_la_date_retenue_par_auteur_est_la_plus_recente_et_non_la_derniere_lue(self):
        s = self.collecter(
            self.entree("uid=a,dc=exemple,dc=test", "uid=g,dc=exemple,dc=test", "20261009120000Z")
            + self.entree("uid=b,dc=exemple,dc=test", "uid=g,dc=exemple,dc=test", "20260101120000Z"))
        self.assertEqual(
            s.valeur('freeipa_derniere_modification_timestamp{auteur="g",genre="compte"}'),
            ef.epoque("20261009120000Z"))

    def test_le_createur_et_le_modificateur_sont_comptes_separement(self):
        s = self.collecter(self.entree("uid=a,dc=exemple,dc=test",
                                       "cn=Directory Manager", "20261001120000Z",
                                       createur="uid=g,dc=exemple,dc=test"))
        self.assertEqual(
            s.valeur('freeipa_entrees_modifiees{auteur="Directory Manager",'
                     'genre="administrateur"}'), 1)
        self.assertEqual(s.valeur('freeipa_entrees_creees{auteur="g",genre="compte"}'), 1)

    def test_le_total_des_entrees_suivies_est_publie_pour_que_rien_ne_soit_cache(self):
        s = self.collecter(self.entree("uid=a,dc=exemple,dc=test", "uid=g,dc=exemple,dc=test",
                                       "20261001120000Z") * 1
                           + self.entree("uid=b,dc=exemple,dc=test", "uid=g,dc=exemple,dc=test",
                                         "20261002120000Z"))
        self.assertEqual(s.valeur("freeipa_entrees_suivies"), 2)

    def test_la_liste_des_modifications_recentes_est_bornee(self):
        ldif = "".join(self.entree(f"uid=u{i},cn=users,cn=accounts,dc=exemple,dc=test",
                                   f"uid=a{i},dc=exemple,dc=test", f"2026100{i}120000Z")
                       for i in range(1, 6))
        s = self.collecter(ldif, limite=2)
        self.assertEqual(len(s.noms("freeipa_modification_recente_timestamp")), 2)

    def test_la_borne_retient_les_plus_recentes_et_non_les_premieres_venues(self):
        ldif = (self.entree("uid=vieille,dc=exemple,dc=test", "uid=a,dc=exemple,dc=test",
                            "20260101120000Z")
                + self.entree("uid=recente,dc=exemple,dc=test", "uid=b,dc=exemple,dc=test",
                              "20261009120000Z"))
        s = self.collecter(ldif, limite=1)
        self.assertEqual(s.noms("freeipa_modification_recente_timestamp"),
                         ['freeipa_modification_recente_timestamp{auteur="b",branche='
                          '"dc=exemple,dc=test",entree="recente",genre="compte"}'])

    def test_une_entree_sans_date_lisible_n_entre_pas_dans_les_recentes(self):
        s = self.collecter("dn: uid=a,dc=exemple,dc=test\nmodifiersName: uid=g,dc=exemple,dc=test\n"
                           "modifyTimestamp: pas-une-date\ncreatorsName: uid=g,dc=exemple,dc=test\n")
        self.assertEqual(s.noms("freeipa_modification_recente_timestamp"), [])
        self.assertEqual(s.valeur('freeipa_entrees_modifiees{auteur="g",genre="compte"}'), 1)

    def test_un_annuaire_sans_trace_declare_les_mesures_sans_aucune_serie(self):
        s = self.collecter("")
        self.assertEqual(s.valeur("freeipa_entrees_suivies"), 0)
        self.assertEqual(s.noms("freeipa_entrees_modifiees"), [])
        self.assertIn("freeipa_entrees_modifiees", s.aides)

    def test_la_branche_est_exposee_pour_situer_l_entree_modifiee(self):
        s = self.collecter(self.entree("idnsname=zone.exemple.test.,cn=dns,dc=exemple,dc=test",
                                       "uid=g,dc=exemple,dc=test", "20261001120000Z"))
        self.assertEqual(s.valeur('freeipa_modification_recente_timestamp{auteur="g",'
                                  'branche="cn=dns",entree="zone.exemple.test.",genre="compte"}'),
                         ef.epoque("20261001120000Z"))


    def test_la_recherche_n_est_pas_rejouee_avant_la_fin_de_la_periode(self):
        # Elle n est pas indexee : 389-DS parcourt tout le suffixe a chaque fois.
        premiere = self.entree("uid=a,dc=exemple,dc=test",
                               "uid=g,dc=exemple,dc=test", "20261001120000Z")
        self.collecter(premiere, periode=3600)
        seconde = self.collecter(
            premiere + self.entree("uid=b,dc=exemple,dc=test",
                                   "uid=g,dc=exemple,dc=test", "20261002120000Z"),
            periode=3600)
        self.assertEqual(self.recherches, 1)
        self.assertEqual(seconde.valeur("freeipa_entrees_suivies"), 1)

    def test_les_series_sont_republiees_entre_deux_releves(self):
        # Une serie qui disparaitrait entre deux releves ferait battre les
        # alertes posees sur elle.
        ldif = self.entree("uid=a,cn=users,dc=exemple,dc=test",
                           "uid=g,dc=exemple,dc=test", "20261001120000Z")
        self.collecter(ldif, periode=3600)
        s = self.collecter(ldif, periode=3600)
        self.assertEqual(s.valeur("freeipa_entrees_suivies"), 1)
        self.assertEqual(s.valeur('freeipa_entrees_modifiees{auteur="g",genre="compte"}'), 1)
        self.assertEqual(s.valeur('freeipa_entrees_creees{auteur="g",genre="compte"}'), 1)
        self.assertEqual(
            s.valeur('freeipa_derniere_modification_timestamp{auteur="g",genre="compte"}'),
            ef.epoque("20261001120000Z"))
        self.assertEqual(s.noms("freeipa_modification_recente_timestamp"),
                         ['freeipa_modification_recente_timestamp{auteur="g",'
                          'branche="cn=users",entree="a",genre="compte"}'])

    def test_la_periode_ecoulee_fait_rejouer_la_recherche(self):
        self.collecter(self.entree("uid=a,dc=exemple,dc=test",
                                   "uid=g,dc=exemple,dc=test", "20261001120000Z"), periode=0)
        s = self.collecter(
            self.entree("uid=a,dc=exemple,dc=test",
                        "uid=g,dc=exemple,dc=test", "20261001120000Z")
            + self.entree("uid=b,dc=exemple,dc=test",
                          "uid=g,dc=exemple,dc=test", "20261002120000Z"), periode=0)
        self.assertEqual(self.recherches, 2)
        self.assertEqual(s.valeur("freeipa_entrees_suivies"), 2)


MODIFY = """time: 20261027102743
dn: uid=73747737483,ou=people,dc=exemple,dc=test
#cn: Frank Lee
result: 0
changetype: modify
replace: description
description: ce qui ne doit pas sortir
-
replace: modifiersname
modifiersname: uid=gtranche,cn=users,cn=accounts,dc=exemple,dc=test
-

"""


class LectureDuJournalDAudit(unittest.TestCase):
    """Le format est celui de la note de conception amont, verifie mot pour mot."""

    def lire(self, texte):
        lecture = ef.LectureAudit()
        for ligne in texte.splitlines(True):
            lecture.ligne(ligne)
        lecture.clore()
        return lecture

    def test_un_enregistrement_modify_donne_son_auteur_et_son_type(self):
        lecture = self.lire(MODIFY)
        self.assertEqual(lecture.operations,
                         [("uid=gtranche,cn=users,cn=accounts,dc=exemple,dc=test", "modify", True)])

    def test_les_noms_des_attributs_modifies_sont_retenus(self):
        self.assertEqual(sorted(n for n, _ in self.lire(MODIFY).attributs),
                         ["description", "modifiersname"])

    def test_un_mot_de_passe_journalise_ne_sort_que_par_son_nom_d_attribut(self):
        # La propriete que l exportateur doit garder : il ne manipule aucun
        # secret. Un mot de passe journalise ne doit pas pouvoir en ressortir.
        texte = MODIFY.replace("replace: description\ndescription: ce qui ne doit pas sortir",
                               "replace: userpassword\nuserpassword: tres-secret")
        lecture = self.lire(texte)
        self.assertEqual(sorted(n for n, _ in lecture.attributs),
                         ["modifiersname", "userpassword"])
        self.assertNotIn("tres-secret", repr(lecture.attributs) + repr(lecture.operations))

    def test_une_creation_compte_les_attributs_qu_elle_pose(self):
        lecture = self.lire("time: 20261027102743\ndn: uid=neuf,dc=exemple,dc=test\n"
                            "result: 0\nchangetype: add\nobjectClass: top\nuid: neuf\n"
                            "creatorsname: cn=Directory Manager\n\n")
        self.assertEqual(lecture.operations, [("cn=Directory Manager", "add", True)])
        self.assertEqual(sorted(n for n, _ in lecture.attributs),
                         ["creatorsname", "objectclass", "uid"])

    def test_une_suppression_est_comptee_bien_qu_elle_ne_touche_aucun_attribut(self):
        lecture = self.lire("time: 20261027102743\ndn: uid=parti,dc=exemple,dc=test\n"
                            "result: 0\nchangetype: delete\n\n")
        self.assertEqual(lecture.operations, [("", "delete", True)])
        self.assertEqual(lecture.attributs, [])

    def test_un_fragment_sans_en_tete_est_jete_plutot_que_compte_de_travers(self):
        # Une lecture incrementielle peut reprendre au milieu d un
        # enregistrement : le fragment porte alors son changetype mais pas son
        # en-tete, et serait compte comme une ecriture d auteur inconnu.
        tronque = "result: 0\nchangetype: modify\nreplace: description\ndescription: x\n-\n\n"
        lecture = self.lire(tronque + MODIFY)
        self.assertEqual(len(lecture.operations), 1)
        self.assertEqual(lecture.operations[0][0],
                         "uid=gtranche,cn=users,cn=accounts,dc=exemple,dc=test")

    def test_un_resultat_non_nul_est_compte_comme_n_ayant_pas_abouti(self):
        lecture = self.lire(MODIFY.replace("result: 0", "result: 50"))
        self.assertEqual([aboutie for _, _, aboutie in lecture.operations], [False])

    def test_les_lignes_de_commentaire_ne_sont_pas_prises_pour_des_attributs(self):
        # « #cn: Frank Lee » vient de nsslapd-auditlog-display-attrs.
        self.assertNotIn("cn", [n for n, _ in self.lire(MODIFY).attributs])

    def test_la_ligne_tiret_separe_les_blocs_sans_clore_l_enregistrement(self):
        self.assertEqual(len(self.lire(MODIFY).operations), 1)

    def test_deux_enregistrements_colles_sont_separes_par_leur_en_tete(self):
        self.assertEqual(len(self.lire(MODIFY.replace("\n\n", "\n") * 2).operations), 2)

    def test_une_ligne_repliee_ne_devient_jamais_un_nom_d_attribut(self):
        # 389-DS replie ses lignes a 78 colonnes, ce que mes temoins ecrits a la
        # main ne faisaient pas : la suite d une valeur commence par une espace
        # et peut porter un deux-points, donc ressembler a un attribut.
        texte = ("time: 20261101225437\n"
                 "dn: cn=essai,dc=exemple,dc=test\n"
                 "result: 0\n"
                 "changetype: add\n"
                 "description: une valeur assez longue pour etre repliee par le\n"
                 " serveur, dont la suite porte motdepasse: tres-secret\n"
                 "\n")
        noms = [n for n, _ in self.lire(texte).attributs]
        self.assertEqual(noms, ["description"])
        self.assertNotIn("tres-secret", str(self.lire(texte).attributs))

    def test_le_vrai_enregistrement_de_crl_est_lu_sans_sa_valeur(self):
        # Le premier enregistrement reel qu ait vu cet analyseur, releve le
        # 2026-11-01 : valeurs repliees et encodees en base64.
        lecture = self.lire(CRL_REELLE)
        self.assertEqual(lecture.operations,
                         [("uid=pkidbuser,ou=People,o=ipaca", "modify", True)])
        self.assertEqual(sorted(n for n, _ in lecture.attributs),
                         ["crlsize", "entryusn", "expiredcerts", "firstunsaved",
                          "modifiersname", "modifytimestamp", "revokedcerts",
                          "unrevokedcerts"])
        self.assertNotIn("rO0ABXNy", str(lecture.attributs))

    def test_l_en_tete_du_journal_n_est_pas_pris_pour_un_enregistrement(self):
        # 389-DS ecrit son nom et son adresse en tete, indentes par une
        # tabulation, a chaque demarrage comme a chaque rotation.
        entete = ("\t389-Directory/2.8.0 B2026.243.0000\n"
                  "\tds1.exemple.test:636 (/etc/dirsrv/slapd-EXEMPLE-TEST)\n"
                  "\n")
        self.assertEqual(self.lire(entete + CRL_REELLE).operations,
                         [("uid=pkidbuser,ou=People,o=ipaca", "modify", True)])

    def test_un_auteur_encode_en_base64_est_decode(self):
        texte = MODIFY.replace("modifiersname: uid=gtranche,cn=users,cn=accounts,dc=exemple,dc=test",
                               "modifiersname:: dWlkPWfDqXJhcmQ=")
        self.assertEqual(self.lire(texte).operations[0][0], "uid=gérard")


CRL_REELLE = """time: 20261101225437
dn: cn=MasterCRL,ou=crlIssuingPoints,ou=ca,o=ipaca
result: 0
changetype: modify
replace: crlSize
crlSize: 010
-
replace: revokedCerts
revokedCerts:: rO0ABXNyABNqYXZhLnV0aWwuSGFzaHRhYmxlE7sPJSFK5LgDAAJGAApsb2FkRmF
 jdG9ySQAJdGhyZXNob2xkeHA/QAAAAAAAAncIAAAAAwAAAAB4
-
replace: unrevokedCerts
unrevokedCerts:: rO0ABXNyABNqYXZhLnV0aWwuSGFzaHRhYmxlE7sPJSFK5LgDAAJGAApsb2FkR
 mFjdG9ySQAJdGhyZXNob2xkeHA/QAAAAAAAAncIAAAAAwAAAAB4
-
replace: expiredCerts
expiredCerts:: rO0ABXNyABNqYXZhLnV0aWwuSGFzaHRhYmxlE7sPJSFK5LgDAAJGAApsb2FkRmF
 jdG9ySQAJdGhyZXNob2xkeHA/QAAAAAAAAncIAAAAAwAAAAB4
-
replace: firstUnsaved
firstUnsaved: -1
-
replace: modifiersname
modifiersname: uid=pkidbuser,ou=People,o=ipaca
-
replace: modifytimestamp
modifytimestamp: 20261101215437Z
-
replace: entryusn
entryusn: 112153

"""


# Le geste que l administrateur veut retrouver : qui a mis qui dans un groupe.
# Les trois derniers blocs sont ceux que 389-DS ajoute de lui-meme.
AJOUT_DANS_GROUPE = """time: 20261101230512
dn: cn=wazuh-admins,cn=groups,cn=accounts,dc=exemple,dc=test
result: 0
changetype: modify
add: member
member: uid=jdoe,cn=users,cn=accounts,dc=exemple,dc=test
-
replace: modifiersname
modifiersname: uid=gtranche,cn=users,cn=accounts,dc=exemple,dc=test
-
replace: modifytimestamp
modifytimestamp: 20261101220512Z
-
replace: entryusn
entryusn: 112200
-

"""


class SondeDuJournalDAudit(unittest.TestCase):
    """Eteint, le journal ne doit pas pouvoir passer pour « rien ne bouge »."""

    def setUp(self):
        self.repertoire = tempfile.TemporaryDirectory()
        self.addCleanup(self.repertoire.cleanup)
        self.journal = os.path.join(self.repertoire.name, "audit")
        for nom, valeur in (("ETAT", os.path.join(self.repertoire.name, "etat.json")),
                            ("JOURNAL_AUDIT", "")):
            ancien = getattr(ef, nom)
            setattr(ef, nom, valeur)
            self.addCleanup(setattr, ef, nom, ancien)

    def ecrire(self, texte, mode="a"):
        with open(self.journal, mode) as f:
            f.write(texte)

    def collecter(self, allume="on", chemin=None):
        chemin = self.journal if chemin is None else chemin
        commande = Commande(f"dn: cn=config\nnsslapd-auditlog: {chemin}\n"
                            f"nsslapd-auditlog-logging-enabled: {allume}\n")
        ancien = ef.subprocess.run
        ef.subprocess.run = commande
        self.addCleanup(setattr, ef.subprocess, "run", ancien)
        self.commande = commande

        class SansSocket(ef.Annuaire):
            @staticmethod
            def _socket(_instance):
                return "/run/doublure.socket"

        registre = ef.Registre()
        ef.audit(SansSocket(base="dc=exemple,dc=test"), registre)
        return Sortie(registre)

    def test_un_journal_eteint_est_dit_eteint_plutot_que_compte_a_zero(self):
        s = self.collecter(allume="off")
        self.assertEqual(s.valeur("freeipa_audit_journal_actif"), 0)

    def test_un_journal_allume_est_annonce_comme_tel(self):
        self.ecrire(MODIFY)
        self.assertEqual(self.collecter().valeur("freeipa_audit_journal_actif"), 1)

    def test_le_chemin_du_journal_est_lu_dans_la_configuration_de_l_annuaire(self):
        self.ecrire(MODIFY)
        s = self.collecter()
        self.assertEqual(s.valeur('freeipa_audit_ecritures_total{auteur="gtranche",'
                                  'genre="compte",objet="ou=people",operation="modify"}'), 1)
        self.assertIn("nsslapd-auditlog", self.commande.appels[0])

    def test_un_journal_allume_et_non_vide_dont_rien_ne_sort_signale_un_format_inconnu(self):
        self.ecrire('{"time": "2026", "dn": "uid=x"}\n')
        s = self.collecter()
        self.assertEqual(s.valeur("freeipa_audit_format_reconnu"), 0)

    def test_un_journal_eteint_et_vide_n_est_pas_signale_comme_illisible(self):
        self.ecrire("")
        self.assertEqual(self.collecter(allume="off").valeur("freeipa_audit_format_reconnu"), 1)

    def test_un_journal_allume_encore_vide_n_est_pas_signale_comme_illisible(self):
        self.ecrire("")
        self.assertEqual(self.collecter().valeur("freeipa_audit_format_reconnu"), 1)

    def test_un_journal_lisible_est_reconnu(self):
        self.ecrire(MODIFY)
        self.assertEqual(self.collecter().valeur("freeipa_audit_format_reconnu"), 1)

    def test_la_taille_du_journal_est_exposee_pour_voir_venir_le_plafond(self):
        self.ecrire(MODIFY)
        self.assertEqual(self.collecter().valeur("freeipa_audit_journal_octets"),
                         len(MODIFY))

    def test_une_seconde_collecte_ne_recompte_pas_les_enregistrements_deja_lus(self):
        self.ecrire(MODIFY)
        self.collecter()
        self.ecrire(MODIFY)
        s = self.collecter()
        self.assertEqual(s.valeur('freeipa_audit_ecritures_total{auteur="gtranche",'
                                  'genre="compte",objet="ou=people",operation="modify"}'), 2)

    def test_un_compteur_ne_redescend_pas_quand_le_journal_tourne(self):
        self.ecrire(MODIFY)
        self.collecter()
        os.remove(self.journal)
        self.ecrire(MODIFY, mode="w")
        s = self.collecter()
        self.assertEqual(s.valeur('freeipa_audit_ecritures_total{auteur="gtranche",'
                                  'genre="compte",objet="ou=people",operation="modify"}'), 2)

    def test_les_attributs_touches_sont_comptes_par_nom_et_par_operation(self):
        self.ecrire(MODIFY)
        s = self.collecter()
        self.assertEqual(s.valeur('freeipa_audit_attributs_total{attribut="description",'
                                  'operation="modify"}'), 1)

    def test_une_ecriture_qui_n_a_pas_abouti_est_comptee_a_part(self):
        self.ecrire(MODIFY.replace("result: 0", "result: 50"))
        s = self.collecter()
        self.assertEqual(s.valeur('freeipa_audit_echecs_total{auteur="gtranche",'
                                  'genre="compte",operation="modify"}'), 1)

    def test_un_journal_absent_declare_les_mesures_sans_faire_echouer_la_collecte(self):
        s = self.collecter(allume="off", chemin="/n-existe-pas/audit")
        self.assertEqual(s.valeur("freeipa_audit_journal_octets"), 0)
        self.assertIn("freeipa_audit_ecritures_total", s.aides)

    def traces(self, s):
        return [c for c in s.series
                if c.startswith("freeipa_audit_ecriture_recente_timestamp")]

    def test_une_ecriture_nomme_le_genre_d_objet_touche_et_pas_que_son_auteur(self):
        # Sans cette etiquette, « gtranche a fait trois modifications » ne dit
        # pas s il a touche un utilisateur, un groupe ou une regle.
        self.ecrire(AJOUT_DANS_GROUPE)
        s = self.collecter()
        self.assertEqual(s.valeur('freeipa_audit_ecritures_total{auteur="gtranche",'
                                  'genre="compte",objet="groupe",operation="modify"}'), 1)

    def test_un_geste_recent_nomme_l_entree_touchee_son_attribut_et_le_membre(self):
        self.ecrire(AJOUT_DANS_GROUPE)
        s = self.collecter()
        self.assertEqual(
            s.valeur('freeipa_audit_ecriture_recente_timestamp{attributs="member",'
                     'auteur="gtranche",entree="wazuh-admins",genre="compte",'
                     'membres="jdoe",objet="groupe",operation="modify"}'),
            ef.epoque_locale("20261101230512"))

    def test_les_attributs_que_le_serveur_reecrit_seul_ne_noient_pas_le_geste(self):
        # Chaque modify porte modifiersname, modifytimestamp et entryusn : les
        # montrer rendrait tous les gestes identiques a la lecture.
        self.ecrire(AJOUT_DANS_GROUPE)
        traces = self.traces(self.collecter())
        self.assertEqual(len(traces), 1)
        self.assertIn('attributs="member"', traces[0])
        for ecrit_par_le_serveur in ("entryusn", "modifytimestamp", "modifiersname"):
            self.assertNotIn(ecrit_par_le_serveur, traces[0])

    def test_un_geste_recent_survit_a_un_passage_qui_n_apporte_rien(self):
        # Le journal n est lu qu une fois : sans l etat, la trace disparaitrait
        # au passage suivant et le tableau se viderait tout seul.
        self.ecrire(AJOUT_DANS_GROUPE)
        self.collecter()
        traces = self.traces(self.collecter())
        self.assertEqual(len(traces), 1)
        self.assertIn('entree="wazuh-admins"', traces[0])

    def test_seules_les_identites_d_appartenance_voient_leur_valeur_publiee(self):
        # La liste blanche est la seule raison pour laquelle « member » sort :
        # tout autre attribut garde sa valeur pour lui.
        self.ecrire(AJOUT_DANS_GROUPE.replace(
            "add: member\nmember: uid=jdoe,cn=users,cn=accounts,dc=exemple,dc=test",
            "replace: userpassword\nuserpassword: tres-secret"))
        s = self.collecter()
        self.assertNotIn("tres-secret", s.texte)
        traces = self.traces(s)
        self.assertIn('attributs="userpassword"', traces[0])
        self.assertIn('membres=""', traces[0])

    def test_un_ajout_de_nombreux_membres_est_borne_en_disant_ce_qui_manque(self):
        # Une etiquette qui porterait les cinq cents membres d un groupe dirait
        # l annuaire, pas le geste.
        self.ecrire(AJOUT_DANS_GROUPE.replace(
            "member: uid=jdoe,cn=users,cn=accounts,dc=exemple,dc=test\n",
            "".join(f"member: uid=u{i},cn=users,cn=accounts,dc=exemple,dc=test\n"
                    for i in range(8))))
        self.assertIn('membres="u0 u1 u2 u3 u4 +3"', self.traces(self.collecter())[0])

    def test_une_regle_hbac_et_une_regle_sudo_sont_nommees_chacune(self):
        for dn, attendu in (("ipauniqueid=a1,cn=hbac", "regle hbac"),
                            ("ipauniqueid=a2,cn=sudorules,cn=sudo", "regle sudo")):
            self.ecrire(AJOUT_DANS_GROUPE.replace(
                "cn=wazuh-admins,cn=groups,cn=accounts", dn))
        s = self.collecter()
        for attendu in ("regle hbac", "regle sudo"):
            self.assertEqual(s.valeur('freeipa_audit_ecritures_total{auteur="gtranche",'
                                      f'genre="compte",objet="{attendu}",'
                                      'operation="modify"}'), 1)

    def test_la_trace_garde_les_gestes_les_plus_recents_et_non_les_premiers_lus(self):
        ancien = ef.LIMITE_MODIFICATIONS
        ef.LIMITE_MODIFICATIONS = 2
        self.addCleanup(setattr, ef, "LIMITE_MODIFICATIONS", ancien)
        for minute in ("01", "02", "03"):
            self.ecrire(AJOUT_DANS_GROUPE
                        .replace("time: 20261101230512", f"time: 202611012305{minute}")
                        .replace("cn=wazuh-admins", f"cn=groupe{minute}"))
        traces = self.traces(self.collecter())
        self.assertEqual(len(traces), 2)
        self.assertEqual(sorted("groupe" + m for m in ("02", "03")),
                         sorted(t.split('entree="')[1].split('"')[0] for t in traces))

    def test_le_plafond_replie_les_auteurs_au_dela_de_la_limite(self):
        ancien = ef.PLAFOND_ETIQUETTES
        ef.PLAFOND_ETIQUETTES = 2
        self.addCleanup(setattr, ef, "PLAFOND_ETIQUETTES", ancien)
        for nom in ("un", "deux", "trois"):
            self.ecrire(MODIFY.replace("uid=gtranche,cn=users,cn=accounts,dc=exemple,dc=test",
                                       f"uid={nom},dc=exemple,dc=test"))
        s = self.collecter()
        self.assertEqual(s.valeur('freeipa_audit_ecritures_total{auteur="autres",'
                                  'genre="autre",objet="ou=people",operation="modify"}'), 1)

    def test_un_mot_de_passe_journalise_ne_ressort_pas_dans_les_metriques(self):
        self.ecrire(MODIFY.replace("replace: description\ndescription: ce qui ne doit pas sortir",
                                   "replace: userpassword\nuserpassword: tres-secret"))
        s = self.collecter()
        self.assertNotIn("tres-secret", s.texte)
        self.assertEqual(s.valeur('freeipa_audit_attributs_total{attribut="userpassword",'
                                  'operation="modify"}'), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
