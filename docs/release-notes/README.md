# Patch notes

Every release has hand-written patch notes in this folder, one file per version: `v1.5.0.md` for the release tagged
`v1.5.0`. They are written by a person for the people who use the app, not generated from commit messages.

To release a version:

1. Copy `TEMPLATE.md` to `vX.Y.Z.md` and write the notes. Say what changed for the user, what was fixed, and anything
   that behaves differently or is not tested yet. Keep it plain and honest.
2. Commit and push the notes to `main`.
3. Tag and push `vX.Y.Z`. The release workflow (`.github/workflows/release.yml`) first runs
   `scripts/check-release-notes.ps1`, which stops the release if the file is missing, very short, or still contains a
   `TODO`, then publishes the notes as the body of the GitHub release.

Releases up to v1.4.0 were published with automatically generated notes.
