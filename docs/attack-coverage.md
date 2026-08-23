# MITRE ATT&CK — Detection Coverage

Suivi de la couverture : chaque technique émulée → règle → statut de validation.
La couche [`navigator-layer.json`](navigator-layer.json) génère la **heatmap** correspondante.

Légende statut : ✅ détecté & validé · 🟡 règle écrite, à valider · ⬜ à faire

| Tactique | Technique | ID | Règle Sigma | Wazuh | Statut |
|---|---|---|---|---|---|
| Execution | PowerShell encoded command | T1059.001 | `win_powershell_encoded_command.yml` | 100100 | ✅ |
| Discovery | System/Account/Network discovery | T1082/T1033/T1016 | `win_system_discovery.yml` | — | 🟡 |
| Command & Control | Ingress tool transfer (certutil) | T1105 | `win_ingress_tool_transfer_certutil.yml` | 100104 | 🟡¹ |
| Credential Access | LSASS memory access | T1003.001 | `win_lsass_access_credential_dumping.yml` | 100101 | ✅ |
| Persistence | Registry Run keys | T1547.001 | `win_registry_run_key_persistence.yml` | 100102 | ✅ |
| Persistence | Scheduled Task | T1053.005 | `win_scheduled_task_creation.yml` | 100103 | ✅ |
| Persistence | Local account creation | T1136.001 | `win_local_account_creation.yml` | 100106 | ✅ |
| Lateral Movement | Remote Services (SMB/RDP/WinRM) | T1021 | `win_lateral_movement_connection.yml` | — | 🟡 |
| Defense Evasion | Clear Windows event logs | T1070.001 | `win_clear_eventlog.yml` | 100105 | ✅ |
| Defense Evasion | Process Injection | T1055 | — | — | ⬜ |

> ¹ T1105 : règle cohérente par construction (même schéma décodeur/champs que les 6 règles validées
> ci-dessus), mais l'exécution de `certutil -urlcache`/`-verifyctl` est bloquée au niveau comportemental
> par Windows Defender dans ce lab avant même que Sysmon ne puisse logger le process — donc non
> observable en conditions réelles sans désactiver la protection temps réel (bloqué par Tamper Protection
> en script). Voir [scenario-01](../emulation/scenario-01-chained-intrusion.md) pour le détail.
>
> Après avoir rejoué [`scenario-01`](../emulation/scenario-01-chained-intrusion.md) et validé une
> détection, passe son statut à ✅ ici et son `score` à `90` dans `navigator-layer.json`.

## Corrections apportées lors de la validation (2026-08-23)

Rejouer `scenario-01` sur le lab a révélé 3 défauts de règles, corrigés dans
[`local_rules.xml`](../detections/wazuh/local_rules.xml) :

| Règle | Problème | Correction |
|---|---|---|
| **100102** (Run key) | `if_group sysmon_event_13` n'est jamais peuplé pour cet event précis — l'EID13 est en réalité capté par la règle native **92302** avant que le groupe custom ne s'applique. | Rebasée sur `<if_sid>92302</if_sid>`. |
| **100105** (clear log) | Regex `wevtutil\s+cl` ne matchait pas la commande réelle `"wevtutil.exe" cl "..."` (le `.exe"` casse l'adjacence espace). | Split en deux champs : `image` = `wevtutil.exe` + `commandLine` contient `\bcl\b`. |
| **100101** (LSASS) | Aucun filtre anti-FP alors que la version **Sigma** en a un (`filter_legit` sur wininit/services/MsMpEng) — confirmé par une vraie alerte générée par le scan LSASS de Windows Defender lui-même. | Ajout de `<field name="win.eventdata.sourceImage" negate="yes">` excluant wininit.exe/services.exe/MsMpEng.exe. |

Également identifié : la config Sysmon (SwiftOnSecurity) livre `<ProcessAccess onmatch="include">` **vide**
par défaut → l'EID10 (nécessaire à 100101) n'est jamais généré tant qu'on n'ajoute pas explicitement
`lsass.exe` en cible. Corrigé dans `sysmonconfig.xml` sur la victime.

## Générer la heatmap Navigator

1. Ouvre [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
2. *Open Existing Layer → Upload from local* → [`navigator-layer.json`](navigator-layer.json)
3. Couleur = statut de couverture → capture d'écran dans le README

> La heatmap est le visuel le plus parlant en entretien : ce que le SOC voit… et ses angles morts.
