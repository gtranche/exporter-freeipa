#!/usr/bin/env python3
# Copyright (C) 2026 gtranche
# SPDX-License-Identifier: GPL-3.0-or-later
# Tests du tableau Grafana. Ils ne demandent pas de Grafana : ils protegent ce
# qui casse en silence — une source de donnees figee, qui rend des panneaux
# vides chez qui ne nomme pas sa source « prometheus », et une mise en page qui
# deborde des 24 colonnes, que l interface rogne sans rien dire.

import json
import os
import re
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

    def test_le_tableau_s_importe_tel_quel_sans_rien_a_resoudre(self):
        # L export « for sharing externally » de Grafana remplace les sources
        # par des entrees ${DS_...} a resoudre via __inputs. Celui-la n en a
        # pas : colle dans la boite d import, il s ouvre sur la source choisie.
        self.assertNotIn("__inputs", self.d)
        self.assertNotIn("__requires", self.d)
        self.assertNotIn("${DS_", json.dumps(self.d))

    def test_le_tableau_ne_porte_pas_d_identifiant_numerique(self):
        # Un « id » herite du Grafana ou le tableau est ne designe un AUTRE
        # tableau sur le Grafana d arrivee : a l import, il l ecraserait.
        self.assertIsNone(self.d.get("id"))

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

# Les huit grandeurs du domaine sont les memes sur tous les serveurs d un
# domaine actif-actif : chaque exportateur les publie, il faut n en montrer
# qu une.
REPLIQUEES = {"freeipa_utilisateurs", "freeipa_groupes", "freeipa_machines",
              "freeipa_groupes_machines", "freeipa_services_enregistres",
              "freeipa_regles_hbac", "freeipa_regles_sudo", "freeipa_zones_dns"}

SELECTEUR = re.compile(r"\b(freeipa_[a-z_]+)(\{([^}]*)\})?")
AGREGATION = re.compile(r"\b(?:sum|avg|count|min|max)\s*(?:by \(([^)]*)\))?\s*\(")
FILTRE = 'instance=~"$serveur"'


def requetes(tableau):
    """Rend chaque requete du tableau avec le titre de son panneau."""
    for p in tableau["panels"]:
        for t in p["targets"]:
            yield p["title"], " ".join(t["expr"].split())


class PlusieursServeurs(unittest.TestCase):
    """Un domaine FreeIPA peut porter plusieurs serveurs IdM en actif-actif.

    Les defauts que ces tests retiennent sont tous silencieux : un panneau qui
    additionne trois serveurs, une legende qui ne dit pas lequel, une table qui
    fond deux serveurs sur une meme ligne.
    """

    @classmethod
    def setUpClass(cls):
        with open(CHEMIN, encoding="utf-8") as f:
            cls.d = json.load(f)

    def test_la_variable_de_serveur_est_declaree_et_lit_les_instances_presentes(self):
        serveur = next(v for v in self.d["templating"]["list"] if v["name"] == "serveur")
        self.assertEqual(serveur["type"], "query")
        self.assertIn("label_values(", serveur["query"])
        self.assertIn("instance", serveur["query"])
        # Sans « tous » par defaut, le tableau s ouvre sur un seul serveur et
        # cache les autres a qui ne touche pas la liste.
        self.assertTrue(serveur["includeAll"])
        self.assertTrue(serveur["multi"])
        self.assertEqual(serveur["current"]["value"], ["$__all"])

    def test_chaque_selecteur_se_restreint_aux_serveurs_choisis(self):
        for titre, expr in requetes(self.d):
            for nom, accolades, _ in SELECTEUR.findall(expr):
                self.assertIn(FILTRE, accolades, f"{titre} : {nom}")

    def test_les_grandeurs_du_domaine_ne_sont_comptees_qu_une_fois(self):
        for titre, expr in requetes(self.d):
            noms = {nom for nom, _, _ in SELECTEUR.findall(expr)}
            if noms & REPLIQUEES:
                self.assertIn("by (job)", expr, titre)

    def test_une_serie_qui_nomme_le_serveur_ne_l_agrege_pas(self):
        # Sans « by (instance) », trois serveurs a huit refus deviennent un
        # seul a vingt-quatre, et la legende ne nomme plus personne.
        for p in self.d["panels"]:
            for t in p["targets"]:
                expr = " ".join(t["expr"].split())
                if "{{instance}}" not in t.get("legendFormat", ""):
                    continue
                # group_right() rend les etiquettes de l operande de droite :
                # une agregation a gauche n enleve rien au resultat.
                if "group_right()" in expr:
                    continue
                for etiquettes in AGREGATION.findall(expr):
                    self.assertIsNotNone(etiquettes, f"{p['title']} : agregation sans « by »")
                    self.assertIn("instance", etiquettes, f"{p['title']} : by ({etiquettes})")

    def test_une_legende_nommee_nomme_le_serveur(self):
        for p in self.d["panels"]:
            for t in p["targets"]:
                legende = t.get("legendFormat", "")
                if "{{" in legende:
                    self.assertIn("{{instance}}", legende, p["title"])

    def test_une_table_joint_sur_une_cle_qui_distingue_les_serveurs(self):
        # « identite » ou « base » se repetent d un serveur a l autre : joindre
        # dessus fusionne deux lignes de deux serveurs en une seule.
        for p in self.d["panels"]:
            jointures = [tr for tr in p.get("transformations", [])
                         if tr["id"] == "joinByField"]
            if not jointures:
                continue
            for tr in jointures:
                self.assertEqual(tr["options"]["byField"], "cle", p["title"])
            for t in p["targets"]:
                self.assertIn("label_join(", t["expr"], p["title"])
                self.assertRegex(t["expr"], r'"cle", "[^"]*", "instance"', p["title"])

    def test_aucune_table_ne_masque_la_colonne_du_serveur(self):
        for p in self.d["panels"]:
            for tr in p.get("transformations", []):
                if tr["id"] != "organize":
                    continue
                exclues = tr["options"].get("excludeByName", {})
                self.assertFalse(exclues.get("instance"), p["title"])

    def test_la_replication_est_presentee_avec_le_reste(self):
        exprs = " ".join(expr for _, expr in requetes(self.d))
        for nom in ("freeipa_replication_accords", "freeipa_replication_accord_etat",
                    "freeipa_replication_ruv_timestamp", "freeipa_replication_conflits"):
            self.assertIn(nom, exprs)

    def test_le_retard_de_convergence_se_mesure_entre_serveurs_et_non_sur_un_seul(self):
        # Un serveur ne connait que ce qu il a recu : son RUV ne dit rien de son
        # retard. L ecart ne se voit qu en comparant la meme serie ailleurs.
        retards = [expr for _, expr in requetes(self.d)
                   if "freeipa_replication_ruv_timestamp" in expr]
        self.assertTrue(retards)
        for expr in retards:
            self.assertIn("group_right()", expr)
            apparie = re.search(r"on\(([^)]*)\) group_right", expr)
            self.assertIsNotNone(apparie, expr)
            self.assertNotIn("instance", apparie.group(1), expr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
