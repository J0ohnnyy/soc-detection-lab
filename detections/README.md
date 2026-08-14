# Detections

Règles de détection portables au format **Sigma**, taguées **MITRE ATT&CK**.
Sigma = format neutre → convertible vers Wazuh, Elastic, Splunk, etc.

## Convention

- 1 fichier = 1 règle, nommé `win_<intitulé>.yml` / `lin_<intitulé>.yml`
- Champs obligatoires : `title`, `id`, `description`, `references`, `tags` (attack.*), `logsource`, `detection`, `falsepositives`, `level`
- Chaque règle est **validée** par un test atomique (voir [`../emulation/`](../emulation/))

## Convertir Sigma → SIEM

```bash
pip install sigma-cli
# Elastic (Lucene/EQL)
sigma convert -t lucene detections/sigma/win_powershell_encoded_command.yml
# Splunk
sigma convert -t splunk detections/sigma/*.yml
```

Pour Wazuh, transposer la logique Sigma en règle XML `<rule>` (decoders Sysmon) — un
mapping d'exemple sera ajouté au fil des détections.

## Cycle de vie d'une règle

`hypothèse → écriture → émulation → validation → tuning FP → statut ✅ dans la matrice`
