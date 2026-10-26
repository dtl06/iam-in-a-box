#!/usr/bin/env python3
"""jml.py : cycle de vie des comptes de Nordivia (Joiners, Movers, Leavers).

Compare l'export RH (état voulu) à l'annuaire LDAP (état actuel), puis crée,
modifie ou désactive les comptes pour que LDAP corresponde à l'export.
Idempotent : relancé sur le même export, il ne fait rien.

    python jml.py hr/export_j1.csv --dry-run   # affiche le plan sans rien écrire
    python jml.py hr/export_j1.csv             # applique le plan
"""
import argparse
import csv
import os
import secrets
import string
import sys
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import requests
import yaml
from dotenv import load_dotenv
from ldap3 import (HASHED_SALTED_SHA, LEVEL, MODIFY_ADD, MODIFY_DELETE,
                   MODIFY_REPLACE, SUBTREE, Connection, Server)
from ldap3.utils.hashed import hashed

ICI = Path(__file__).resolve().parent
load_dotenv(ICI.parent / ".env")

BASE_DN = "dc=nordivia,dc=local"
PEOPLE_DN = f"ou=people,{BASE_DN}"
DISABLED_DN = f"ou=disabled,{BASE_DN}"
GROUPS_DN = f"ou=groups,{BASE_DN}"
ROLES_DN = f"ou=roles,{BASE_DN}"

LDAP_URL = os.environ.get("LDAP_URL", "ldap://localhost:389")
KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://localhost:8080")
REALM = "nordivia"
FEDERATION = "openldap"  # nom du keycloak_ldap_user_federation dans ldap.tf
JOURNAL = ICI / "logs" / "jml.csv"


# ─── Modèle ──────────────────────────────────────────────────────────────────

@dataclass
class Compte:
    """Un compte, tel qu'il est dans LDAP ou tel que l'export RH le veut."""
    matricule: str
    uid: str
    prenom: str
    nom: str
    email: str
    service: str
    poste: str
    groupes: frozenset  # services (ou=groups) dont il est membre
    roles: frozenset    # rôles applicatifs (ou=roles) dont il est membre

    @property
    def dn(self):
        return f"uid={self.uid},{PEOPLE_DN}"

    def etat(self):
        """Résumé d'une ligne, pour l'affichage et le journal d'audit."""
        return (f"service={self.service};poste={self.poste};"
                f"groupes={'|'.join(sorted(self.groupes))};roles={'|'.join(sorted(self.roles))}")


@dataclass
class Action:
    type: str            # "creation", "modification" ou "desactivation"
    matricule: str
    voulu: Compte = None  # absent pour une désactivation
    actuel: Compte = None  # absent pour une création


# ─── Lecture de l'état voulu (export RH) et de l'état actuel (LDAP) ──────────

def lire_export(chemin, roles_par_poste):
    """Renvoie ({matricule: Compte voulu} pour les actifs, {matricules partis})."""
    voulus, partis = {}, set()
    with open(chemin, newline="", encoding="utf-8") as f:
        for ligne in csv.DictReader(f):
            ligne = {k: v.strip() for k, v in ligne.items()}
            if ligne["statut"] == "parti":
                partis.add(ligne["matricule"])
                continue
            if ligne["poste"] not in roles_par_poste:
                # Refus plutôt que droits par défaut : un poste inconnu est une erreur RH
                sys.exit(f"Erreur : poste « {ligne['poste']} » (matricule {ligne['matricule']}) "
                         f"absent de roles_par_poste.yaml. Rien n'a été modifié.")
            voulus[ligne["matricule"]] = Compte(
                matricule=ligne["matricule"],
                uid="",  # connu après comparaison avec LDAP (existant) ou généré (arrivée)
                prenom=ligne["prenom"],
                nom=ligne["nom"],
                email=ligne["email"],
                service=ligne["service"],
                poste=ligne["poste"],
                groupes=frozenset([ligne["service"]]),
                roles=frozenset(roles_par_poste[ligne["poste"]]),
            )
    return voulus, partis


def premier(attributs, nom):
    valeurs = attributs.get(nom) or [""]
    return str(valeurs[0])


def lire_annuaire(conn):
    """Lit LDAP. Renvoie (comptes actifs par matricule, matricules désactivés,
    uid déjà pris, groupes existants, rôles existants)."""
    # 1. Appartenances : qui est member de quel groupe / rôle
    appartenances = {}  # dn utilisateur (minuscules) -> {"groupes": set, "roles": set}
    existants = {"groupes": set(), "roles": set()}
    for base, cle in ((GROUPS_DN, "groupes"), (ROLES_DN, "roles")):
        conn.search(base, "(objectClass=groupOfNames)", LEVEL, attributes=["cn", "member"])
        for entree in conn.entries:
            nom = entree.cn.value
            existants[cle].add(nom)
            for membre in entree.member.values:
                appartenances.setdefault(membre.lower(), {"groupes": set(), "roles": set()})[cle].add(nom)

    # 2. Comptes actifs (ou=people)
    comptes = {}
    conn.search(PEOPLE_DN, "(objectClass=inetOrgPerson)", LEVEL,
                attributes=["uid", "givenName", "sn", "mail", "employeeNumber", "departmentNumber", "title"])
    for entree in conn.entries:
        a = entree.entry_attributes_as_dict
        app = appartenances.get(entree.entry_dn.lower(), {"groupes": set(), "roles": set()})
        compte = Compte(
            matricule=premier(a, "employeeNumber"),
            uid=premier(a, "uid"),
            prenom=premier(a, "givenName"),
            nom=premier(a, "sn"),
            email=premier(a, "mail"),
            service=premier(a, "departmentNumber"),
            poste=premier(a, "title"),
            groupes=frozenset(app["groupes"]),
            roles=frozenset(app["roles"]),
        )
        comptes[compte.matricule] = compte

    # 3. Comptes désactivés et uid déjà pris (y compris désactivés : un uid n'est jamais réattribué)
    conn.search(DISABLED_DN, "(objectClass=inetOrgPerson)", LEVEL, attributes=["employeeNumber"])
    desactives = {premier(e.entry_attributes_as_dict, "employeeNumber") for e in conn.entries}
    conn.search(BASE_DN, "(uid=*)", SUBTREE, attributes=["uid"])
    uids_pris = {premier(e.entry_attributes_as_dict, "uid") for e in conn.entries}

    return comptes, desactives, uids_pris, existants["groupes"], existants["roles"]


# ─── Calcul du plan : comparer l'état voulu à l'état actuel ──────────────────

def nouvel_uid(prenom, nom, uids_pris):
    """prenom.nom en ASCII minuscule (Chloé → chloe), suffixé en cas d'homonyme."""
    base = unicodedata.normalize("NFKD", f"{prenom}.{nom}").encode("ascii", "ignore").decode()
    base = base.lower().replace(" ", "-")
    uid, n = base, 2
    while uid in uids_pris:
        uid, n = f"{base}{n}", n + 1
    return uid


def calculer_plan(voulus, partis, actuels, desactives, uids_pris, groupes_ldap, roles_ldap):
    plan, avertissements = [], []

    for matricule, voulu in sorted(voulus.items()):
        inconnus = (voulu.groupes - groupes_ldap) | (voulu.roles - roles_ldap)
        if inconnus:
            sys.exit(f"Erreur : {', '.join(sorted(inconnus))} (matricule {matricule}) "
                     f"n'existe pas dans l'annuaire. Rien n'a été modifié.")

        actuel = actuels.get(matricule)
        if actuel is None:
            if matricule in desactives:
                avertissements.append(f"{matricule} est actif dans l'export mais désactivé dans LDAP : "
                                      f"réintégration à traiter manuellement.")
                continue
            voulu.uid = nouvel_uid(voulu.prenom, voulu.nom, uids_pris)
            uids_pris.add(voulu.uid)
            plan.append(Action("creation", matricule, voulu=voulu))
        else:
            voulu.uid = actuel.uid
            # On compare aussi les appartenances : un rôle ajouté à la main hors modèle
            # est une dérive, corrigée comme une mobilité.
            if (actuel.service, actuel.poste, actuel.groupes, actuel.roles) != \
               (voulu.service, voulu.poste, voulu.groupes, voulu.roles):
                plan.append(Action("modification", matricule, voulu=voulu, actuel=actuel))

    for matricule in sorted(partis):
        if matricule in actuels:  # déjà désactivé ou inconnu : rien à faire
            plan.append(Action("desactivation", matricule, actuel=actuels[matricule]))

    return plan, avertissements


def afficher_plan(plan, avertissements):
    symboles = {"creation": "+ création     ", "modification": "~ modification ", "desactivation": "− désactivation"}
    for action in plan:
        v, a = action.voulu, action.actuel
        if action.type == "creation":
            detail = f"{v.uid:<16} {v.service} / {v.poste} ; rôles : {', '.join(sorted(v.roles))}"
        elif action.type == "modification":
            changements = []
            if a.service != v.service:
                changements.append(f"service {a.service} → {v.service}")
            if a.poste != v.poste:
                changements.append(f"poste {a.poste} → {v.poste}")
            changements += [f"-groupe {g}" for g in sorted(a.groupes - v.groupes)]
            changements += [f"+groupe {g}" for g in sorted(v.groupes - a.groupes)]
            changements += [f"-rôle {r}" for r in sorted(a.roles - v.roles)]
            changements += [f"+rôle {r}" for r in sorted(v.roles - a.roles)]
            detail = f"{a.uid:<16} " + " ; ".join(changements)
        else:
            retraits = ", ".join(sorted(a.groupes | a.roles)) or "aucun"
            detail = f"{a.uid:<16} retrait de : {retraits} ; déplacé vers ou=disabled ; sessions fermées"
        print(f"  {symboles[action.type]}  {action.matricule}  {detail}")

    for message in avertissements:
        print(f"  ! {message}")

    compte = {t: sum(1 for x in plan if x.type == t) for t in symboles}
    print(f"\nPlan : {compte['creation']} création(s), {compte['modification']} modification(s), "
          f"{compte['desactivation']} désactivation(s).")


# ─── Application dans LDAP ───────────────────────────────────────────────────

def dn_groupe(nom):
    return f"cn={nom},{GROUPS_DN}"


def dn_role(nom):
    return f"cn={nom},{ROLES_DN}"


def ajouter_membre(conn, dn_cible, dn_utilisateur):
    conn.modify(dn_cible, {"member": [(MODIFY_ADD, [dn_utilisateur])]})


def retirer_membre(conn, dn_cible, dn_utilisateur):
    # On ne retire que l'utilisateur : le member placeholder reste, le groupOfNames
    # n'est donc jamais vide (sinon OpenLDAP refuse la modification).
    conn.modify(dn_cible, {"member": [(MODIFY_DELETE, [dn_utilisateur])]})


def generer_mot_de_passe(longueur=16):
    """Aléatoire cryptographique (secrets, pas random), conforme à la politique du realm."""
    speciaux = "!@#$%&*?-_"
    alphabet = string.ascii_letters + string.digits + speciaux
    while True:
        mdp = "".join(secrets.choice(alphabet) for _ in range(longueur))
        if (any(c.isupper() for c in mdp) and any(c.islower() for c in mdp)
                and any(c.isdigit() for c in mdp) and any(c in speciaux for c in mdp)):
            return mdp


def creer(conn, v):
    mot_de_passe = generer_mot_de_passe()
    conn.add(v.dn, ["inetOrgPerson"], {
        "uid": v.uid,
        "cn": f"{v.prenom} {v.nom}",
        "givenName": v.prenom,
        "sn": v.nom,
        "mail": v.email,
        "employeeNumber": v.matricule,
        "departmentNumber": v.service,
        "title": v.poste,
        "userPassword": hashed(HASHED_SALTED_SHA, mot_de_passe),  # stocké haché {SSHA}
    })
    for g in v.groupes:
        ajouter_membre(conn, dn_groupe(g), v.dn)
    for r in v.roles:
        ajouter_membre(conn, dn_role(r), v.dn)
    # Affiché une seule fois, jamais journalisé
    print(f"    mot de passe initial de {v.uid} : {mot_de_passe}")


def modifier(conn, v, a):
    # Les attributs d'abord : la modification du compte met à jour son modifyTimestamp,
    # ce qui le fait remonter dans la synchronisation « changed users » de Keycloak.
    conn.modify(a.dn, {"departmentNumber": [(MODIFY_REPLACE, [v.service])],
                       "title": [(MODIFY_REPLACE, [v.poste])]})
    # Retraits avant ajouts : à aucun moment la personne ne cumule ancien et nouveau poste
    for g in a.groupes - v.groupes:
        retirer_membre(conn, dn_groupe(g), a.dn)
    for r in a.roles - v.roles:
        retirer_membre(conn, dn_role(r), a.dn)
    for g in v.groupes - a.groupes:
        ajouter_membre(conn, dn_groupe(g), a.dn)
    for r in v.roles - a.roles:
        ajouter_membre(conn, dn_role(r), a.dn)


def desactiver(conn, keycloak, a):
    # 1. Fermer les sessions tant que Keycloak voit encore le compte dans ou=people
    sessions = keycloak.fermer_sessions(a.uid)
    # 2. Retirer tous les droits
    for g in a.groupes:
        retirer_membre(conn, dn_groupe(g), a.dn)
    for r in a.roles:
        retirer_membre(conn, dn_role(r), a.dn)
    # 3. Déplacer sans supprimer : l'entrée reste pour l'audit, mais sort du périmètre
    #    de la fédération (search_scope ONE_LEVEL sur ou=people)
    conn.modify_dn(a.dn, f"uid={a.uid}", new_superior=DISABLED_DN)
    print(f"    {a.uid} : {sessions} compte(s) Keycloak déconnecté(s)")


def journaliser(action, avant, apres):
    JOURNAL.parent.mkdir(exist_ok=True)
    nouveau = not JOURNAL.exists()
    with open(JOURNAL, "a", newline="", encoding="utf-8") as f:
        ecrivain = csv.writer(f)
        if nouveau:
            ecrivain.writerow(["horodatage", "matricule", "action", "avant", "apres"])
        ecrivain.writerow([datetime.now(timezone.utc).isoformat(timespec="seconds"),
                           action.matricule, action.type, avant, apres])


# ─── API d'administration Keycloak ───────────────────────────────────────────

class Keycloak:
    def __init__(self):
        reponse = requests.post(
            f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token",
            data={"grant_type": "password", "client_id": "admin-cli",
                  "username": os.environ["KC_BOOTSTRAP_ADMIN_USERNAME"],
                  "password": os.environ["KC_BOOTSTRAP_ADMIN_PASSWORD"]},
            timeout=10,
        )
        reponse.raise_for_status()
        self.http = requests.Session()
        self.http.headers["Authorization"] = f"Bearer {reponse.json()['access_token']}"
        self.api = f"{KEYCLOAK_URL}/admin/realms/{REALM}"

    def appel(self, methode, chemin, **kwargs):
        reponse = self.http.request(methode, f"{self.api}{chemin}", timeout=30, **kwargs)
        reponse.raise_for_status()
        return reponse.json() if reponse.content else None

    def fermer_sessions(self, uid):
        utilisateurs = self.appel("GET", "/users", params={"username": uid, "exact": "true"})
        for u in utilisateurs:
            self.appel("POST", f"/users/{u['id']}/logout")
        return len(utilisateurs)

    def synchroniser(self):
        federations = self.appel("GET", "/components",
                                 params={"type": "org.keycloak.storage.UserStorageProvider", "name": FEDERATION})
        if not federations:
            raise RuntimeError(f"Fédération « {FEDERATION} » introuvable dans le realm {REALM}")
        resultat = self.appel("POST", f"/user-storage/{federations[0]['id']}/sync",
                              params={"action": "triggerChangedUsersSync"})
        # Les rôles viennent des groupOfNames, dont la modification ne touche pas l'entrée
        # utilisateur : on vide le cache pour que Keycloak relise les appartenances.
        self.appel("POST", "/clear-user-cache")
        return resultat


# ─── Programme principal ─────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Cycle de vie des comptes à partir de l'export RH.")
    parser.add_argument("export", help="export RH au format CSV")
    parser.add_argument("--dry-run", action="store_true", help="affiche le plan sans rien écrire")
    parser.add_argument("--roles", default=ICI / "config" / "roles_par_poste.yaml", type=Path,
                        help="modèle de rôles par poste")
    args = parser.parse_args()

    roles_par_poste = yaml.safe_load(args.roles.read_text(encoding="utf-8"))
    voulus, partis = lire_export(args.export, roles_par_poste)

    conn = Connection(Server(LDAP_URL), user=f"cn=admin,{BASE_DN}",
                      password=os.environ["LDAP_ADMIN_PASSWORD"], auto_bind=True, raise_exceptions=True)
    actuels, desactives, uids_pris, groupes_ldap, roles_ldap = lire_annuaire(conn)
    plan, avertissements = calculer_plan(voulus, partis, actuels, desactives, uids_pris, groupes_ldap, roles_ldap)

    print(f"Export : {args.export}  ({len(voulus)} actifs, {len(partis)} partis)\n")
    if not plan:
        print("Annuaire déjà conforme à l'export : aucun changement.")
        for message in avertissements:
            print(f"  ! {message}")
        return
    afficher_plan(plan, avertissements)
    if args.dry_run:
        print("Mode --dry-run : rien n'a été écrit.")
        return

    # Connexion à Keycloak AVANT toute écriture : s'il est injoignable, on s'arrête
    # sans avoir modifié LDAP (sinon un départ serait traité sans fermeture de session).
    keycloak = Keycloak()

    print("\nApplication :")
    for action in plan:
        if action.type == "creation":
            creer(conn, action.voulu)
            journaliser(action, "", action.voulu.etat())
        elif action.type == "modification":
            modifier(conn, action.voulu, action.actuel)
            journaliser(action, action.actuel.etat(), action.voulu.etat())
        else:
            desactiver(conn, keycloak, action.actuel)
            journaliser(action, action.actuel.etat(), "ou=disabled;groupes=;roles=")
        print(f"  ✓ {action.type} {action.matricule}")

    resultat = keycloak.synchroniser()
    print(f"\nSynchronisation Keycloak : {resultat.get('status', resultat)}")
    print(f"Journal d'audit : {JOURNAL.relative_to(ICI)}")


if __name__ == "__main__":
    main()
