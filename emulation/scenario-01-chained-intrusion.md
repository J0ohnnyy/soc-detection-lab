# Scénario 01 — Intrusion chaînée sur poste Windows

Chaîne d'attaque réaliste rejouée avec **Atomic Red Team**, de l'exécution initiale
jusqu'à l'effacement des traces. À la fin, tu dois retrouver **chaque étape** dans Wazuh
et remplir une [investigation](../investigations/TEMPLATE-investigation.md).

## Rôles des machines

| Machine | Rôle dans le scénario |
|---|---|
| **Wazuh SIEM** (10.10.10.10) | Reçoit la télémétrie, déclenche les détections — c'est ton poste d'analyste |
| **Windows victime** (10.10.10.20) | Cible : on y exécute les tests atomiques (Sysmon actif) |
| **Kali attaquant** (10.10.10.30) | Sert de serveur pour l'étape *ingress* (héberge le fichier téléchargé) |

> Prérequis : lab monté ([`../lab/README.md`](../lab/README.md)), Sysmon qui remonte les EID 1/3/10/13, agent Windows *Active*.

## La chaîne (MITRE ATT&CK)

```
T1059.001  Execution        →  T1082/T1033  Discovery
   → T1105  Ingress transfer →  T1003.001   Credential access
      → T1547.001 + T1053.005 Persistence
         → T1021 Lateral movement → T1070.001 Defense evasion (log clear)
```

## Déroulé (sur la victime Windows, PowerShell admin)

| # | Étape | ATT&CK | Commande Atomic Red Team | Sysmon EID | Détection attendue |
|---|---|---|---|---|---|
| 1 | Exécution obfusquée | T1059.001 | `Invoke-AtomicTest T1059.001 -TestNumbers 1` | 1 | `win_powershell_encoded_command` / Wazuh 100100 |
| 2 | Reconnaissance | T1082/T1033 | `Invoke-AtomicTest T1082` ; `Invoke-AtomicTest T1033` | 1 | `win_system_discovery` |
| 3 | Téléchargement d'outil | T1105 | `Invoke-AtomicTest T1105 -TestNumbers 1` | 1 | `win_ingress_tool_transfer_certutil` / Wazuh 100104 |
| 4 | Vol d'identifiants | T1003.001 | `Invoke-AtomicTest T1003.001 -TestNumbers 1` | 10 | `win_lsass_access_credential_dumping` / Wazuh 100101 |
| 5a | Persistance (Run key) | T1547.001 | `Invoke-AtomicTest T1547.001 -TestNumbers 1` | 13 | `win_registry_run_key_persistence` / Wazuh 100102 |
| 5b | Persistance (tâche) | T1053.005 | `Invoke-AtomicTest T1053.005 -TestNumbers 1` | 1 | `win_scheduled_task_creation` / Wazuh 100103 |
| 6 | Compte backdoor | T1136.001 | `Invoke-AtomicTest T1136.001 -TestNumbers 1` | 1 | `win_local_account_creation` / Wazuh 100106 |
| 7 | Effacement des logs | T1070.001 | `Invoke-AtomicTest T1070.001 -TestNumbers 1` | 1 | `win_clear_eventlog` / Wazuh 100105 |

> **Nettoyage** après la session : `Invoke-AtomicTest <T####> -Cleanup` pour chaque test.

## Ce que tu produis (les livrables du scénario)

1. **Validation** : pour chaque étape, confirme que la règle se déclenche → passe le
   statut à ✅ dans [`../docs/attack-coverage.md`](../docs/attack-coverage.md) et monte le
   score à `90` dans [`../docs/navigator-layer.json`](../docs/navigator-layer.json).
2. **Captures** : screenshot du dashboard Wazuh pour 2–3 alertes clés (à mettre dans le README).
3. **Investigation** : remplis un writeup à partir du template — timeline corrélée des 7 étapes,
   IoC, et ce qui a été détecté vs manqué.
4. **Heatmap** : recharge `navigator-layer.json` dans ATT&CK Navigator → capture de la couverture.

## Critère de réussite

> Tu dois pouvoir **raconter l'histoire** de l'intrusion uniquement à partir des alertes
> Wazuh, dans l'ordre, avec les timestamps — c'est exactement l'exercice d'un analyste SOC.
