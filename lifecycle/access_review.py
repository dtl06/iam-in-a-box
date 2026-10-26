#!/usr/bin/env python3
"""access_review.py : revue des accès du realm Nordivia.

Interroge l'API d'administration de Keycloak (utilisateurs, rôles effectifs,
événements de connexion) et la confronte au dernier export RH et au modèle de rôles.
Détecte : conflits de séparation des tâches, comptes orphelins, écarts au modèle,
comptes inactifs ou jamais connectés.

    python access_review.py hr/export_j1.csv --jours 30
"""
import argparse
import csv
import html
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path

import yaml

from jml import ICI, Keycloak  # même connexion admin que jml.py

RAPPORTS = ICI / "reports"
GRAVITES = ["critique", "élevée", "moyenne", "faible"]  # ordre de tri


@dataclass
class Constat:
    gravite: str
    type: str
    utilisateur: str
    matricule: str
    detail: str
    recommandation: str


# ─── Collecte ────────────────────────────────────────────────────────────────

def lire_export(chemin):
    """{matricule: statut} du dernier export RH."""
    with open(chemin, newline="", encoding="utf-8") as f:
        return {l["matricule"].strip(): l["statut"].strip() for l in csv.DictReader(f)}


def attribut(utilisateur, nom):
    return (utilisateur.get("attributes", {}).get(nom) or [""])[0]


def collecter(keycloak, roles_applicatifs):
    """Utilisateurs du realm avec leurs rôles effectifs et leur dernière connexion."""
    utilisateurs = keycloak.appel("GET", "/users", params={"briefRepresentation": "false", "max": 1000})

    # Dernière connexion par utilisateur, à partir des événements LOGIN (paginés)
    derniere_connexion, debut = {}, 0
    while True:
        lot = keycloak.appel("GET", "/events", params={"type": "LOGIN", "first": debut, "max": 500})
        for evt in lot:
            derniere_connexion[evt["userId"]] = max(evt["time"], derniere_connexion.get(evt["userId"], 0))
        if len(lot) < 500:
            break
        debut += 500

    comptes = []
    for u in utilisateurs:
        # Rôles *effectifs* (composite) : inclut ceux hérités d'un groupe ou d'un rôle composite.
        # On ne garde que les rôles applicatifs (pas default-roles-nordivia, offline_access…).
        effectifs = keycloak.appel("GET", f"/users/{u['id']}/role-mappings/realm/composite")
        roles = {r["name"] for r in effectifs} & roles_applicatifs
        login_ms = derniere_connexion.get(u["id"])
        comptes.append({
            "uid": u["username"],
            "matricule": attribut(u, "matricule"),
            "poste": attribut(u, "poste"),
            "service": attribut(u, "service"),
            "actif": u.get("enabled", True),
            "roles": roles,
            "cree_le": datetime.fromtimestamp(u.get("createdTimestamp", 0) / 1000, timezone.utc),
            "derniere_connexion": datetime.fromtimestamp(login_ms / 1000, timezone.utc) if login_ms else None,
        })
    return sorted(comptes, key=lambda c: c["uid"])


# ─── Contrôles ───────────────────────────────────────────────────────────────

def controler_sod(comptes, regles):
    for c in comptes:
        for regle in regles:
            if set(regle["roles"]) <= c["roles"]:
                yield Constat("critique", "Conflit SoD", c["uid"], c["matricule"],
                              f"cumule {' + '.join(regle['roles'])} : {regle['raison']}",
                              "Retirer l'un des deux rôles, ou scinder le poste")


def controler_modele_sod(roles_par_poste, regles):
    """Un poste du modèle qui viole lui-même une règle SoD : le problème est en amont."""
    for poste, roles in roles_par_poste.items():
        for regle in regles:
            if set(regle["roles"]) <= set(roles):
                yield Constat("critique", "Modèle toxique", f"poste « {poste} »", "",
                              f"le modèle de rôles attribue {' + '.join(regle['roles'])} à ce poste",
                              "Revoir roles_par_poste.yaml avec la DRH et le contrôle interne")


def controler_orphelins(comptes, export):
    for c in comptes:
        statut = export.get(c["matricule"])
        if statut is None:
            yield Constat("élevée", "Compte orphelin", c["uid"], c["matricule"] or "—",
                          "présent dans l'annuaire, absent du dernier export RH",
                          "Identifier un responsable ou désactiver le compte")
        elif statut == "parti" and c["actif"]:
            yield Constat("élevée", "Départ non traité", c["uid"], c["matricule"],
                          "marqué « parti » dans l'export RH, mais le compte est toujours actif",
                          "Lancer jml.py sur le dernier export")


def controler_ecarts_modele(comptes, roles_par_poste):
    for c in comptes:
        if c["poste"] not in roles_par_poste:
            yield Constat("moyenne", "Poste hors modèle", c["uid"], c["matricule"],
                          f"poste « {c['poste'] or 'vide'} » absent de roles_par_poste.yaml",
                          "Compléter le modèle de rôles ou corriger le poste")
            continue
        en_trop = c["roles"] - set(roles_par_poste[c["poste"]])
        if en_trop:
            yield Constat("moyenne", "Écart au modèle", c["uid"], c["matricule"],
                          f"{', '.join(sorted(en_trop))} non justifié(s) par le poste « {c['poste']} »",
                          "Retirer le rôle, ou documenter une exception approuvée")


def controler_inactifs(comptes, jours, maintenant):
    for c in comptes:
        if c["derniere_connexion"] is None:
            anciennete = (maintenant - c["cree_le"]).days
            gravite = "moyenne" if anciennete >= jours else "faible"
            yield Constat(gravite, "Jamais connecté", c["uid"], c["matricule"],
                          f"aucune connexion enregistrée (compte créé il y a {anciennete} j)",
                          "Vérifier que le compte est toujours nécessaire")
        else:
            inactivite = (maintenant - c["derniere_connexion"]).days
            if inactivite >= jours:
                yield Constat("moyenne", "Compte inactif", c["uid"], c["matricule"],
                              f"dernière connexion il y a {inactivite} j (seuil : {jours} j)",
                              "Confirmer le besoin auprès du manager, sinon désactiver")


# ─── Sorties ─────────────────────────────────────────────────────────────────

def ecrire_csv(constats, chemin):
    with open(chemin, "w", newline="", encoding="utf-8") as f:
        ecrivain = csv.writer(f)
        ecrivain.writerow(["gravite", "type", "utilisateur", "matricule", "detail", "recommandation"])
        for c in constats:
            ecrivain.writerow([c.gravite, c.type, c.utilisateur, c.matricule, c.detail, c.recommandation])


def ecrire_html(constats, comptes, export, jours, chemin):
    e = html.escape
    resume = " ".join(
        f'<span class="badge {g}">{sum(1 for c in constats if c.gravite == g)} {g}</span>' for g in GRAVITES)
    lignes = "\n".join(
        f'<tr><td><span class="badge {c.gravite}">{c.gravite}</span></td><td>{e(c.type)}</td>'
        f'<td>{e(c.utilisateur)}</td><td>{e(c.matricule)}</td><td>{e(c.detail)}</td>'
        f'<td>{e(c.recommandation)}</td></tr>' for c in constats)
    matrice = "\n".join(
        f'<tr><td>{e(c["uid"])}</td><td>{e(c["matricule"])}</td><td>{e(c["service"])}</td>'
        f'<td>{e(c["poste"])}</td><td>{e(", ".join(sorted(c["roles"])))}</td>'
        f'<td>{c["derniere_connexion"].strftime("%Y-%m-%d %H:%M") if c["derniere_connexion"] else "jamais"}</td></tr>'
        for c in comptes)
    chemin.write_text(f"""<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><title>Revue des accès · Nordivia · {date.today()}</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #1f2937; }}
  table {{ border-collapse: collapse; width: 100%; margin-bottom: 2rem; font-size: .9rem; }}
  th, td {{ border-bottom: 1px solid #e5e7eb; padding: .45rem .6rem; text-align: left; vertical-align: top; }}
  th {{ background: #f9fafb; }}
  .badge {{ display: inline-block; padding: .1rem .5rem; border-radius: 999px; font-size: .8rem; font-weight: 600; }}
  .critique {{ background: #fee2e2; color: #991b1b; }} .élevée {{ background: #ffedd5; color: #9a3412; }}
  .moyenne {{ background: #fef9c3; color: #854d0e; }} .faible {{ background: #e0f2fe; color: #075985; }}
  .meta {{ color: #6b7280; }}
</style></head><body>
<h1>Revue des accès · Nordivia</h1>
<p class="meta">Générée le {datetime.now().strftime("%Y-%m-%d %H:%M")} · export RH : {e(export)} ·
seuil d'inactivité : {jours} jours · {len(comptes)} comptes analysés</p>
<p>{resume}</p>
<h2>Constats, par gravité</h2>
<table><tr><th>Gravité</th><th>Type</th><th>Compte</th><th>Matricule</th><th>Détail</th><th>Recommandation</th></tr>
{lignes or '<tr><td colspan="6">Aucun constat.</td></tr>'}
</table>
<h2>Qui a accès à quoi</h2>
<table><tr><th>Compte</th><th>Matricule</th><th>Service</th><th>Poste</th><th>Rôles effectifs</th><th>Dernière connexion</th></tr>
{matrice}
</table>
</body></html>
""", encoding="utf-8")


# ─── Programme principal ─────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Revue des accès du realm Nordivia.")
    parser.add_argument("export", help="dernier export RH (CSV), référence pour les comptes orphelins")
    parser.add_argument("--jours", type=int, default=30, help="seuil d'inactivité en jours (défaut : 30)")
    args = parser.parse_args()

    roles_par_poste = yaml.safe_load((ICI / "config" / "roles_par_poste.yaml").read_text(encoding="utf-8"))
    regles = yaml.safe_load((ICI / "config" / "sod_rules.yaml").read_text(encoding="utf-8"))
    roles_applicatifs = {r for roles in roles_par_poste.values() for r in roles} \
        | {r for regle in regles for r in regle["roles"]}

    export = lire_export(args.export)
    comptes = collecter(Keycloak(), roles_applicatifs)
    maintenant = datetime.now(timezone.utc)

    constats = [
        *controler_modele_sod(roles_par_poste, regles),
        *controler_sod(comptes, regles),
        *controler_orphelins(comptes, export),
        *controler_ecarts_modele(comptes, roles_par_poste),
        *controler_inactifs(comptes, args.jours, maintenant),
    ]
    constats.sort(key=lambda c: (GRAVITES.index(c.gravite), c.type, c.utilisateur))

    RAPPORTS.mkdir(exist_ok=True)
    base = RAPPORTS / f"revue_{date.today().isoformat()}"
    ecrire_csv(constats, base.with_suffix(".csv"))
    ecrire_html(constats, comptes, args.export, args.jours, base.with_suffix(".html"))

    print(f"{len(comptes)} comptes analysés, {len(constats)} constat(s) :")
    for c in constats:
        print(f"  [{c.gravite:^8}] {c.type:<18} {c.utilisateur:<26} {c.detail}")
    print(f"\nRapports : {base.with_suffix('.csv').relative_to(ICI)}  et  {base.with_suffix('.html').relative_to(ICI)}")


if __name__ == "__main__":
    main()
