# Boundaries enforced by this stack (read before changing anything)
- Relay infra lives ONLY in `relay/infra/` (own package + tsconfig,
  Effect 4 / Alchemy peers, shared pnpm workspace lockfile at `relay/`
  root). The runtime (`relay/src`, `relay/package.json`
  deps incl. Effect 3) is untouched by infra changes.
- No imports from Core, no shared DB/R2/Hyperdrive/Queues. The only cross-repo
  coupling is two PUBLIC origins passed at deploy time (see `.env.example`).
- Core infra lives in the Core repo. Do not add Core
  resources here, do not read Core state, do not set Core's
  `runWorkerFirst:true` (Core concern, not Relay — Relay serves API only and
  declares no `assets`, so `runWorkerFirst` does not apply).
- Push policy: commit locally, never push. No real deployments from this task.
