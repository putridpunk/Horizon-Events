## What changed for the user

<!-- In plain words. This usually becomes a line in docs/release-notes/. -->

## How it was tested

- [ ] Backend tests (`cd backend && python -m pytest`)
- [ ] Frontend tests and build (`cd frontend && npm test -- --run && npm run build`)
- [ ] Tried it by hand: <!-- what you did -->

## Checklist

- [ ] New behaviour has tests; anything touching the network or the OS goes through an injected fake
- [ ] Nothing leaves the computer unless the user sets it up
- [ ] Docs updated (README, docs/api.md, docs/detection-rules.md, docs/security.md as needed)
- [ ] Patch notes added for the next version in docs/release-notes/
- [ ] New detection rules are translated into every language file
