# AGENTS Policy

These rules apply to all coding agents working in this repository.

## Vendor code protection

- Treat all content under third-party/ as vendor code.
- Do not create, edit, move, rename, or delete files under third-party/.
- Do not run refactors, formatters, or bulk replacements that touch third-party/.
- Do not stage or commit changes under third-party/.

## Exception handling

- Only modify third-party/ when the user gives an explicit, file-specific request.
- Before any allowed third-party change, ask for confirmation and restate the exact files that will be touched.
- Keep third-party edits minimal and isolated.

## Safety checks before edits

- Before applying changes, run a status check and review changed paths.
- If any unexpected changes appear under third-party/, stop and ask the user how to proceed.
- Scope searches and replacements to first-party paths only (for example src/, install/, service/, man/, tests/, CMakeLists.txt, README.md).

## PR hygiene

- Keep third-party/ out of the final diff unless explicitly approved by the user.
- If third-party changes are present but not approved, revert or unstage them before finalizing.
