#!/usr/bin/env python3
# Tests du tableau Grafana. Ils ne demandent pas de Grafana : ils protegent ce
# qui casse en silence — une source de donnees figee, qui rend des panneaux
# vides chez qui ne nomme pas sa source « prometheus », et une mise en page qui
# deborde des 24 colonnes, que l interface rogne sans rien dire.

import json
import os
import unittest

CHEMIN = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "..", "grafana", "tableau-freeipa.json")


def sources(objet, chemin="tableau"):
    """Rend chaque reference a une source de donnees, avec son emplacement."""
    if isinstance(objet, dict):
        for cle, valeur in objet.items():
            if cle == "datasource":
                yield f"{chemin}.datasource", valeur
            else:
                yield from sources(valeur, f"{chemin}.{cle}")
    elif isinstance(objet, list):
        for i, valeur in enumerate(objet):
            yield from sources(valeur, f"{chemin}[{i}]")


class Tableau(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(CHEMIN, encoding="utf-8") as f:
            cls.d = json.load(f)

    def test_le_tableau_est_un_json_que_grafana_peut_lire(self):
        # Un JSON invalide donne un tableau vide dans l interface, sans message.
        self.assertIn("panels", self.d)
        self.assertEqual(self.d["uid"], "freeipa")

    def test_la_source_de_donnees_est_une_variable_et_non_un_nom_fige(self):
        # Figee, elle ne vaut que pour l installation ou le tableau est ne.
        references = list(sources(self.d))
        self.assertTrue(references)
        for ou, valeur in references:
            self.assertEqual(valeur, {"type": "prometheus", "uid": "${source}"}, ou)

    def test_la_variable_de_source_est_declaree_sinon_rien_ne_resout(self):
        variables = self.d["templating"]["list"]
        source = next(v for v in variables if v["name"] == "source")
        self.assertEqual(source["type"], "datasource")
        self.assertEqual(source["query"], "prometheus")

    def test_chaque_panneau_tient_dans_les_vingt_quatre_colonnes(self):
        for p in self.d["panels"]:
            g = p["gridPos"]
            self.assertLessEqual(g["x"] + g["w"], 24, p["title"])
            self.assertGreaterEqual(g["x"], 0, p["title"])

    def test_aucun_panneau_ne_recouvre_un_autre(self):
        # Grafana les empile alors au chargement, et la mise en page bouge.
        occupe = {}
        for p in self.d["panels"]:
            g = p["gridPos"]
            for y in range(g["y"], g["y"] + g["h"]):
                for x in range(g["x"], g["x"] + g["w"]):
                    autre = occupe.get((x, y))
                    self.assertIsNone(autre, f"{p['title']} recouvre {autre} en ({x},{y})")
                    occupe[(x, y)] = p["title"]

    def test_chaque_panneau_porte_un_titre_et_au_moins_une_requete(self):
        for p in self.d["panels"]:
            self.assertTrue(p.get("title"), json.dumps(p.get("gridPos")))
            self.assertTrue(p.get("targets"), p["title"])
            for t in p["targets"]:
                self.assertTrue(t.get("expr"), p["title"])

    def test_toutes_les_requetes_portent_sur_les_series_de_cet_exportateur(self):
        # Une requete sur une serie d un autre exportateur rendrait un panneau
        # vide chez qui n a que celui-ci.
        for p in self.d["panels"]:
            for t in p["targets"]:
                self.assertRegex(t["expr"], r"freeipa_|\bup\b", p["title"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
