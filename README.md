# SOC Detection Lab — Purple-Team Detection Engineering

> Home SOC where I **emulate adversary techniques**, **engineer & validate detections** mapped to **MITRE ATT&CK**, and **document coverage** — the full detection-engineering lifecycle of a SOC analyst.

**Author:** Karim EL HAOURATI · M.Sc. Cybersecurity
**Stack:** Wazuh (SIEM) · Sysmon · auditd · Sigma · Atomic Red Team · MITRE ATT&CK Navigator

![status](https://img.shields.io/badge/status-in%20progress-orange) ![focus](https://img.shields.io/badge/focus-detection%20engineering-blue) ![mapped](https://img.shields.io/badge/mapped%20to-MITRE%20ATT%26CK-red)

---

## 🎯 Goal

Build a working SOC, run realistic attacks, and answer the question that matters in an interview:
**"Can you actually detect this — and prove it?"**

Every technique I emulate produces: a **detection rule**, a **validation result**, an **ATT&CK mapping**, and (for chained scenarios) an **investigation writeup**.

## 🧩 Architecture

```
Attacker  (Kali + Atomic Red Team / Caldera)
    │  runs ATT&CK techniques
    ▼
Victims ── Windows (Sysmon) · Linux (auditd) ── Wazuh agents
    │  telemetry (EDR-like)
    ▼
SIEM  Wazuh single-node (indexer + dashboards)
    │  ├─ detection rules (Sigma → Wazuh/Elastic)
    │  ├─ dashboards & alerts
    │  └─ threat hunting queries
    ▼
Outputs ── investigations · IR playbooks · ATT&CK coverage heatmap
```

See [`docs/lab-architecture.md`](docs/lab-architecture.md) for the full topology and [`lab/README.md`](lab/README.md) to build it.

## 🗺️ Roadmap

| Phase | Objectif | Livrable |
|---|---|---|
| **1. Lab & télémétrie** | Wazuh + agents + Sysmon/auditd, logs qui remontent | `lab/` setup validé |
| **2. Baseline & dashboards** | Vue d'ensemble, tuning du bruit | dashboards exportés |
| **3. Émulation d'adversaire** | Rejouer des techniques ATT&CK | `emulation/` test plan + résultats |
| **4. Detection engineering** | Écrire/valider des règles Sigma | `detections/sigma/` |
| **5. Threat hunting** | Chasses hypothèse-driven (beaconing, LOLBins) | `investigations/` hunts |
| **6. Investigation & IR** | Scénario chaîné → détection → réponse | rapport + `playbooks/` |

## 📁 Structure

```
soc-detection-lab/
├── lab/                 # Comment monter le lab (Wazuh, agents, Sysmon)
├── detections/
│   └── sigma/           # Règles de détection (portables, taguées ATT&CK)
├── emulation/           # Plans d'émulation (Atomic Red Team) + résultats
├── playbooks/           # Playbooks de réponse à incident
├── investigations/      # Writeups d'investigation (chaînes d'attaque)
└── docs/                # Architecture, guide de setup, matrice de couverture ATT&CK
```

## 🛡️ Détections déjà écrites

| Règle | Technique ATT&CK | Source |
|---|---|---|
| [PowerShell encoded command](detections/sigma/win_powershell_encoded_command.yml) | T1059.001 | Sysmon EID 1 |
| [LSASS access (credential dumping)](detections/sigma/win_lsass_access_credential_dumping.yml) | T1003.001 | Sysmon EID 10 |
| [Registry Run key persistence](detections/sigma/win_registry_run_key_persistence.yml) | T1547.001 | Sysmon EID 13 |

➡️ Couverture suivie dans [`docs/attack-coverage.md`](docs/attack-coverage.md).

## 🧠 Compétences démontrées

`Detection engineering` · `SIEM (Wazuh / ELK)` · `Sysmon & log analysis` · `Sigma` · `MITRE ATT&CK` · `Adversary emulation (Atomic Red Team)` · `Threat hunting` · `Incident response` · `Documentation`

---

> ⚠️ Lab de recherche/formation. Toutes les techniques offensives sont exécutées **dans un environnement isolé**, sur des machines dont je suis propriétaire, à des fins **défensives** (écriture de détections).
