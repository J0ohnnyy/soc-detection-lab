# Lab Architecture

## Topologie

```
                    Réseau isolé (host-only) 10.10.10.0/24
  ┌──────────────┐      ┌──────────────────┐      ┌──────────────┐
  │  Kali        │      │  Windows 10/11   │      │  Ubuntu      │
  │  (attaquant) │─────▶│  Sysmon + agent  │      │  auditd+agent│
  │  ART/Caldera │      │  10.10.10.20     │      │  10.10.10.21 │
  └──────────────┘      └────────┬─────────┘      └──────┬───────┘
                                 │  télémétrie           │
                                 ▼                       ▼
                        ┌───────────────────────────────────┐
                        │        Wazuh SIEM (single-node)    │
                        │  indexer + dashboards · 10.10.10.10│
                        │  règles de détection · alerting    │
                        └───────────────────────────────────┘
```

## Sources de données

| Source | Plateforme | Événements clés |
|---|---|---|
| **Sysmon** | Windows | EID 1 (process), 3 (network), 10 (process access), 11 (file), 13 (registry) |
| **Windows Security** | Windows | 4624/4625 (logon), 4688, 4720 (user created) |
| **auditd** | Linux | execve, connexions, modifications de fichiers sensibles |
| **(option) Zeek/Suricata** | Réseau | flux, DNS, TLS, alertes IDS |

## Flux de détection

```
télémétrie → Wazuh decoders → règles (Wazuh + Sigma converties) → alertes → dashboard → investigation
```

## Principes

- **Isolement total** : le réseau du lab ne route pas vers Internet côté victimes.
- **Reproductible** : tout est documenté (`lab/README.md`) pour rejouer le lab.
- **Défensif** : l'offensif (Atomic Red Team) sert uniquement à **générer de la donnée** pour écrire des détections.
