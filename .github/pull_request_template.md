## What changed

<!-- Short description of the checkpoint: what works now that didn't before. -->

## Component

- [ ] Wazuh
- [ ] n8n (SOAR)
- [ ] Grafana
- [ ] TheHive
- [ ] Cortex + MISP
- [ ] Integrator (shared files)

## Checklist (CONTRIBUTING.md, light rules)

- [ ] I merged the latest `main` into my branch (`git pull origin main`) before opening this PR.
- [ ] I only changed my own folders (or this is an integrator change).
- [ ] UI changes are exported to files (`n8n-export.sh`, `grafana-export.sh`, component export scripts).
- [ ] No secrets, `.env` files, certificates, API keys or data in the diff; exported n8n workflows reference credentials by name only.
- [ ] `scripts/healthcheck.sh` is green for my run mode.
- [ ] `scripts/ci-checks.sh all` passes locally.

## Contracts (PROJECT.md section 5)

- [ ] No contract is affected.
- [ ] A contract changes: which one (C1–C9)? Agreed with the other owner: <!-- name --> — `contracts-check.sh --only <Cx>` passes in `full` mode.

## Playbooks (n8n only)

- [ ] New playbooks follow the conventions in `nodes/core/n8n/README.md` (naming, header note, traceability, idempotent).
- [ ] Any playbook marked `auto_approve` is listed here with its justification:
