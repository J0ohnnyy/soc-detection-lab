# MITRE ATT&CK — Detection Coverage

Suivi de la couverture : chaque technique émulée → règle → statut de validation.
La couche [`navigator-layer.json`](navigator-layer.json) génère la **heatmap** correspondante.

Légende statut : ✅ détecté & validé · 🟡 règle écrite, à valider · ⬜ à faire

| Tactique | Technique | ID | Règle Sigma | Wazuh | Statut |
|---|---|---|---|---|---|
| Execution | PowerShell encoded command | T1059.001 | `win_powershell_encoded_command.yml` | 100100 | 🟡 |
| Discovery | System/Account/Network discovery | T1082/T1033/T1016 | `win_system_discovery.yml` | — | 🟡 |
| Command & Control | Ingress tool transfer (certutil) | T1105 | `win_ingress_tool_transfer_certutil.yml` | 100104 | 🟡 |
| Credential Access | LSASS memory access | T1003.001 | `win_lsass_access_credential_dumping.yml` | 100101 | 🟡 |
| Persistence | Registry Run keys | T1547.001 | `win_registry_run_key_persistence.yml` | 100102 | 🟡 |
| Persistence | Scheduled Task | T1053.005 | `win_scheduled_task_creation.yml` | 100103 | 🟡 |
| Persistence | Local account creation | T1136.001 | `win_local_account_creation.yml` | 100106 | 🟡 |
| Lateral Movement | Remote Services (SMB/RDP/WinRM) | T1021 | `win_lateral_movement_connection.yml` | — | 🟡 |
| Defense Evasion | Clear Windows event logs | T1070.001 | `win_clear_eventlog.yml` | 100105 | 🟡 |
| Defense Evasion | Process Injection | T1055 | — | — | ⬜ |

> Après avoir rejoué [`scenario-01`](../emulation/scenario-01-chained-intrusion.md) et validé une
> détection, passe son statut à ✅ ici et son `score` à `90` dans `navigator-layer.json`.

## Générer la heatmap Navigator

1. Ouvre [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
2. *Open Existing Layer → Upload from local* → [`navigator-layer.json`](navigator-layer.json)
3. Couleur = statut de couverture → capture d'écran dans le README

> La heatmap est le visuel le plus parlant en entretien : ce que le SOC voit… et ses angles morts.
