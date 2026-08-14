# Adversary Emulation Plan — Atomic Red Team

Chaque technique est rejouée sur la victime Windows, puis on vérifie que la **détection**
correspondante se déclenche dans Wazuh. Les résultats alimentent
[`../docs/attack-coverage.md`](../docs/attack-coverage.md).

## Installation (victime Windows, environnement isolé)

```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
```

## Techniques ciblées (phase 1)

| # | Technique | ATT&CK | Test atomique | Détection attendue |
|---|---|---|---|---|
| 1 | PowerShell encoded command | T1059.001 | `Invoke-AtomicTest T1059.001 -TestNumbers 1` | [rule](../detections/sigma/win_powershell_encoded_command.yml) |
| 2 | LSASS credential dumping | T1003.001 | `Invoke-AtomicTest T1003.001 -TestNumbers 1` | [rule](../detections/sigma/win_lsass_access_credential_dumping.yml) |
| 3 | Registry Run key persistence | T1547.001 | `Invoke-AtomicTest T1547.001 -TestNumbers 1` | [rule](../detections/sigma/win_registry_run_key_persistence.yml) |
| 4 | Scheduled task | T1053.005 | `Invoke-AtomicTest T1053.005` | *à écrire* |
| 5 | Process injection | T1055 | `Invoke-AtomicTest T1055` | *à écrire* |

> Nettoyage après chaque test : `Invoke-AtomicTest <T####> -Cleanup`

## Boucle de validation (par technique)

1. Lancer le test atomique
2. Confirmer la télémétrie (Sysmon EID attendu)
3. La règle se déclenche ? → sinon, ajuster/écrire la règle
4. Faux positifs ? → tuner (`filter_*`)
5. Journaliser le résultat dans la matrice de couverture
