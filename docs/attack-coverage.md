# MITRE ATT&CK — Detection Coverage

Suivi de la couverture : chaque technique émulée → règle → statut de validation.
Objectif : générer une **heatmap ATT&CK Navigator** à partir de ce tableau.

Légende statut : ✅ détecté & validé · 🟡 règle écrite, à valider · ⬜ à faire

| Tactique | Technique | ID | Règle | Statut |
|---|---|---|---|---|
| Execution | PowerShell encoded command | T1059.001 | `win_powershell_encoded_command.yml` | 🟡 |
| Credential Access | LSASS memory access | T1003.001 | `win_lsass_access_credential_dumping.yml` | 🟡 |
| Persistence | Registry Run keys | T1547.001 | `win_registry_run_key_persistence.yml` | 🟡 |
| Execution | Scheduled Task | T1053.005 | — | ⬜ |
| Defense Evasion | Process Injection | T1055 | — | ⬜ |
| Discovery | System Information Discovery | T1082 | — | ⬜ |
| Lateral Movement | Remote Services (RDP/SMB) | T1021 | — | ⬜ |
| Command & Control | Application Layer Protocol | T1071 | — | ⬜ |

## Générer la heatmap Navigator

1. Exporter ce tableau en couche JSON (script à venir dans `docs/`)
2. Charger dans [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
3. Couleur = statut de couverture → capture d'écran dans le README

> La heatmap est le visuel le plus parlant en entretien : elle montre d'un coup d'œil
> ce que le SOC voit… et ses angles morts.
