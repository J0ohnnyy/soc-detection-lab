# Investigation — Scénario 01 : intrusion chaînée sur poste Windows

**Date :** 2026/08/23 · **Analyste :** Karim EL HAOURATI · **Sévérité :** Haute

## Résumé

Rejeu du [scénario 01](../emulation/scenario-01-chained-intrusion.md) (exécution → découverte →
ingress tool transfer → vol d'identifiants → persistance → compte backdoor → effacement des logs)
sur la victime Windows (`win-victim`, 10.10.10.20 dans l'archi cible / 192.168.157.152 dans le lab
réel) à l'aide d'Atomic Red Team. **6 des 7 étapes ont été détectées par le SIEM Wazuh**, avec
3 corrections de règles apportées en cours d'investigation suite à des faux négatifs constatés.
La 7ᵉ étape (ingress tool transfer via `certutil`) n'a pas pu être observée : Windows Defender
bloque l'exécution de la technique au niveau comportemental avant même que Sysmon ne génère de
télémétrie — ce n'est pas un défaut de règle mais une limite de l'environnement de test.

## Scénario émulé

- Chaîne ATT&CK : `T1059.001` → `T1105` → `T1003.001` → `T1547.001` + `T1053.005` → `T1136.001` → `T1070.001`
- Outil d'émulation : Atomic Red Team (`Invoke-AtomicTest`, module local `C:\AtomicRedTeam`)
- Complément : déclenchement organique de `T1003.001` observé hors scénario (scan LSASS par
  Windows Defender), utilisé pour valider la règle 100101 sans exécuter de code offensif.

## Détection

| Étape | Technique | Source (EID) | Règle déclenchée | Résultat |
|---|---|---|---|---|
| Exécution obfusquée | T1059.001 | Sysmon EID 1 | **100100** | ✅ détecté (test ART T1059.001-15) |
| Ingress tool transfer (certutil) | T1105 | Sysmon EID 1 | 100104 | ❌ non observable — Defender bloque `certutil.exe` (urlcache et verifyctl) avant création du process |
| Vol d'identifiants (LSASS) | T1003.001 | Sysmon EID 10 | **100101** | ✅ détecté (télémétrie organique : `MsMpEng.exe` → `lsass.exe`, GrantedAccess `0x1410`) |
| Persistance (Run key) | T1547.001 | Sysmon EID 13 | **100102** | ✅ détecté après correctif (`if_sid 92302`) |
| Persistance (tâche planifiée) | T1053.005 | Sysmon EID 1 | **100103** | ✅ détecté directement |
| Compte backdoor | T1136.001 | Sysmon EID 1 | **100106** | ✅ détecté directement |
| Effacement des logs | T1070.001 | Sysmon EID 1 | **100105** | ✅ détecté après correctif (regex image+commandLine) |

## Analyse (timeline)

1. **Préparation du lab** : SIEM Wazuh single-node déployé (manager+indexer+dashboard), agent Wazuh
   installé sur la victime Windows avec collecte du canal `Microsoft-Windows-Sysmon/Operational`.
2. **1ʳᵉ passe de scenario-01** : `T1059.001` (100100) détecté immédiatement. `T1105` (certutil)
   silencieux — investigation a montré `Access is denied` côté Windows et 0 événement Sysmon EID1
   pour `certutil.exe`, confirmé par `Get-MpThreatDetection` (Defender a bien la commande en
   historique de détection).
3. Étapes 4 à 7 rejouées en synchrone (script unique) : `T1547.001` (Run key) et `T1070.001`
   (clear log) **silencieux** malgré une télémétrie Sysmon confirmée présente (EID13 et EID1
   respectivement) → **faux négatifs de règle**, pas de télémétrie manquante.
4. **Root cause 100102** : l'EID13 `CurrentVersion\Run` est en réalité capté par la règle native
   Wazuh **92302** avant que le groupe custom `sysmon_event_13` ne soit évalué pour la règle locale
   → la règle 100102 ne se déclenchait jamais. Corrigée en la rebasant sur `<if_sid>92302</if_sid>`.
5. **Root cause 100105** : la commande réelle générée par `wevtutil` est
   `"C:\Windows\system32\wevtutil.exe" cl "Windows PowerShell"` — la regex `wevtutil\s+cl` ne
   matche pas à cause du `.exe"` intercalé. Corrigée en séparant le match sur `image` (`wevtutil.exe`)
   et `commandLine` (`\bcl\b`).
6. Après redéploiement, rejeu de scenario-01 : **100102 et 100105 se déclenchent correctement.**
7. **Investigation LSASS (100101)** : la validation directe via dump `comsvcs.dll MiniDump` a été
   bloquée par l'AMSI (script marqué "malicious content"). Une méthode bénigne équivalente
   (`(Get-Process lsass).Handle` en PowerShell/.NET, ouverture `PROCESS_ALL_ACCESS`) n'a généré
   aucun événement — **découverte d'un gap de configuration majeur** : la config Sysmon
   (SwiftOnSecurity) livre `<ProcessAccess onmatch="include">` **vide** par défaut, donc l'EID10
   n'est jamais collecté quelle que soit la technique. Corrigé en ajoutant `lsass.exe` comme cible
   explicite dans `sysmonconfig.xml`, puis rechargement de Sysmon.
8. Après correction de la télémétrie, **une alerte 100101 authentique est apparue sans action de
   l'analyste** : `MsMpEng.exe` (Windows Defender) accédant à `lsass.exe` avec `GrantedAccess: 0x1410`
   — signal identique à celui utilisé par les outils de dumping de credentials. Ceci confirme que la
   règle fonctionne, mais révèle aussi un **faux positif structurel** déjà anticipé côté Sigma
   (`filter_legit` sur `wininit.exe`/`services.exe`/`MsMpEng.exe`) mais absent côté Wazuh. Corrigé en
   ajoutant `<field name="win.eventdata.sourceImage" negate="yes">` sur la règle 100101.
9. `T1105` (certutil) reste non détectable dans cet environnement : deux variantes testées
   (`-urlcache`, `-verifyctl`) sont bloquées par la protection temps réel/comportementale de
   Defender avant la création du process. Tamper Protection empêche la désactivation scriptée de
   Defender ; une désactivation manuelle via l'interface aurait été nécessaire pour aller plus loin.

## Indicateurs de compromission

- **Hôtes / comptes** : `win-victim` (DESKTOP-CFL100L) ; compte local backdoor `atomicbackdoor`
  (créé puis supprimé, test T1136.001).
- **Processus / fichiers** : `powershell.exe -EncodedCommand ...` ; `reg.exe` (clé
  `HKCU\...\CurrentVersion\Run\AtomicRun` → `calc.exe`) ; `schtasks.exe /create /tn AtomicSchTask` ;
  `net.exe user atomicbackdoor /add` ; `wevtutil.exe cl "Windows PowerShell"` ;
  `MsMpEng.exe` → accès `lsass.exe` (GrantedAccess `0x1410`, bénin — scan Defender).
- **Réseau (IP/domaines)** : aucun C2 externe dans ce scénario (émulation locale ART, pas de
  Kali/redirecteur impliqué à ce stade).

## Réponse

Scénario d'émulation en environnement isolé — aucune réponse d'endiguement réelle nécessaire.
Chaque test atomique a été nettoyé (`Invoke-AtomicTest <T####> -Cleanup`) après validation.
Voir [`playbooks/ir-playbook-template.md`](../playbooks/ir-playbook-template.md) pour la procédure
qui s'appliquerait en conditions réelles sur une détection T1003.001/T1070.001.

## Enseignements

- **Angles morts identifiés :**
  - La config Sysmon par défaut (SwiftOnSecurity) désactive silencieusement l'EID10
    (`ProcessAccess`) — tout un pan de détection (credential access, injection de processus) était
    inopérant sans que rien ne le signale. À vérifier systématiquement lors du déploiement d'un
    nouveau collecteur.
  - Une règle peut sembler correcte à la lecture mais être invalidée par une **règle parente
    Wazuh qui absorbe l'événement en amont** (cas 100102/règle native 92302) — la validation par
    émulation réelle reste indispensable, la revue de code seule ne suffit pas.
  - `wazuh-logtest` **ne peut pas simuler les événements Windows eventchannel** : le décodeur
    interne `windows_eventchannel` (`rule id="60000"`) est assigné selon l'origine réseau du
    message (agent → remoted), pas selon sa structure JSON — un event synthétique injecté via
    stdin tombe systématiquement dans le décodeur `json` générique et n'atteint jamais l'arbre de
    règles Sysmon. Limite de l'outil à documenter pour les prochaines validations.
  - Un antivirus moderne (Defender comportemental + Tamper Protection) peut rendre certaines
    techniques ATT&CK **non rejouables sans désactivation manuelle** — la couverture de détection
    doit alors être argumentée par cohérence de schéma plutôt que par démonstration live.

- **Règles créées / tunées :**
  - `100102` (T1547.001) : rebasée sur `if_sid 92302` au lieu de `if_group sysmon_event_13`.
  - `100105` (T1070.001) : regex élargie, split en match `image` + `commandLine`.
  - `100101` (T1003.001) : ajout d'un filtre anti-FP (`negate="yes"` sur `sourceImage`) pour
    `wininit.exe`/`services.exe`/`MsMpEng.exe`, aligné sur la version Sigma existante.
  - `sysmonconfig.xml` (victime) : ajout de `lsass.exe` en cible `ProcessAccess` (EID10).
