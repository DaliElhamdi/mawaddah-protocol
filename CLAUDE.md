# mawaddah-protocol (public)
Public companion of the private **Mawaddah** app: the blind relay (`relay/`) and the pure-Dart protocol package (`packages/mawaddah_protocol/`). The project is run from the **primary private repository** `DaliElhamdi/mawaddah` (checked out next to this folder as `../mawaddah`): its `docs/SPEC.md`, `docs/WORKFLOW.md`, `docs/ROUTING.md`, ADRs, milestones and phase issues apply here too. Read spec sections via `../mawaddah/docs/spec/INDEX.md` (4.3–4.6, 5, 13).

## Always
- This repository is PUBLIC: never commit secrets, owner data, app code or content. Never run workflows with secrets on fork PRs.
- Never invent cryptography; protocol changes need an ADR (in the primary repo) and the owner's approval.
- Work only through issues → branches → PRs into `main`; never push to `main` or force-push.
- Conventional Commits `type(scope): subject` (list: .github/commit-types.txt); enable hooks: `git config core.hooksPath .githooks`.
- Tests, docs (`PROTOCOL.md`, `PRIVACY.md`, `SECURITY.md`) and test vectors change in the same PR as the code.
- Privacy wording must stay accurate: never say "no server" or "100% anonymous".
- Commands: `scripts/check.sh [--quick]`, `scripts/test.sh`. Issues for protocol work are opened here and linked from the primary repo's milestone issue.
