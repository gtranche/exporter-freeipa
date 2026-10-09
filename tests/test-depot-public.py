#!/usr/bin/env python3
# Ce depot est public : il ne doit porter aucune adresse, aucun nom de domaine
# et aucun royaume Kerberos appartenant a une infrastructure reelle.
#
# Le controle se fait par liste blanche, jamais par motif de rejet : une liste
# de choses interdites laisse passer tout ce qu on n a pas imagine, alors qu une
# liste de choses permises oblige a declarer chaque ajout. Un faux positif se
# corrige en ajoutant une ligne ci-dessous, en connaissance de cause.

import ipaddress
import os
import re
import subprocess
import unittest

RACINE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")

# RFC 5737 : plages reservees a la documentation. Elles ne joignent rien.
RESEAUX_PERMIS = [ipaddress.ip_network(r) for r in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
    "127.0.0.0/8", "0.0.0.0/32", "255.255.255.255/32",
)]

# RFC 2606 et RFC 6761 : suffixes reserves, plus les domaines publics que ce
# depot cite legitimement.
SUFFIXES_PERMIS = (".test", ".example", ".invalid", ".localhost")
DOMAINES_PERMIS = {
    "example.com", "example.net", "example.org", "localhost",
    "kubernetes.io", "coreos.com", "quay.io", "prometheus.io",
    "docker.io", "grafana.com", "github.com",
}
TLD_SURVEILLES = ("com", "net", "org", "io", "fr", "eu", "local", "lan", "home", "internal")

ROYAUMES_PERMIS = {"EXEMPLE.TEST", "EXEMPLE-TEST"}
COMPOSANTS_DC_PERMIS = {"exemple", "test", "impose", "bon", "autre", "devine", "x"}

ADRESSE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAINE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(" + "|".join(TLD_SURVEILLES) + r")\b")
DC = re.compile(r"\bdc=([A-Za-z0-9_-]+)")
# Deux caracteres au moins par composant, et rien d alphanumerique apres : un
# royaume Kerberos ressemble a EXEMPLE.TEST, pas a un fragment de nom de locale
# ni a une borne d intervalle lue dans une expression reguliere.
ROYAUME = re.compile(r"\b[A-Z][A-Z0-9]+(?:[.-][A-Z][A-Z0-9]+)+(?![-\w])")


def fichiers_suivis():
    sortie = subprocess.run(["git", "-C", RACINE, "ls-files"],
                            capture_output=True, text=True, check=True).stdout
    for nom in sortie.split():
        chemin = os.path.join(RACINE, nom)
        if not os.path.isfile(chemin):
            continue
        try:
            with open(chemin, encoding="utf-8") as f:
                yield nom, f.read()
        except UnicodeDecodeError:
            continue


class DepotPublic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fichiers = list(fichiers_suivis())
        if not cls.fichiers:
            raise unittest.SkipTest("aucun fichier suivi par git")

    def parcourir(self, motif):
        for nom, contenu in self.fichiers:
            for ligne_no, ligne in enumerate(contenu.splitlines(), 1):
                for m in motif.finditer(ligne):
                    yield f"{nom}:{ligne_no}", m

    def test_aucune_adresse_hors_des_plages_reservees_a_la_documentation(self):
        for ou, m in self.parcourir(ADRESSE):
            try:
                adresse = ipaddress.ip_address(m.group(0))
            except ValueError:
                continue                      # un numero de version, pas une adresse
            self.assertTrue(any(adresse in r for r in RESEAUX_PERMIS),
                            f"{ou} : adresse non reservee {adresse}")

    def test_aucun_nom_de_domaine_hors_des_suffixes_reserves(self):
        for ou, m in self.parcourir(DOMAINE):
            nom = m.group(0)
            if nom.endswith(SUFFIXES_PERMIS) or nom in DOMAINES_PERMIS:
                continue
            self.assertTrue(any(nom.endswith("." + d) for d in DOMAINES_PERMIS),
                            f"{ou} : domaine non declare {nom}")

    def test_aucun_suffixe_d_annuaire_autre_que_ceux_des_exemples(self):
        for ou, m in self.parcourir(DC):
            self.assertIn(m.group(1).lower(), COMPOSANTS_DC_PERMIS,
                          f"{ou} : composant de domaine non declare dc={m.group(1)}")

    def test_aucun_royaume_kerberos_reel(self):
        for ou, m in self.parcourir(ROYAUME):
            self.assertIn(m.group(0), ROYAUMES_PERMIS,
                          f"{ou} : royaume ou identifiant majuscule non declare {m.group(0)}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
