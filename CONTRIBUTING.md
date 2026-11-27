# Contributing to Horizon Events

Thank you for wanting to help. This is a small project, so a short conversation before a big change saves everyone time.

## Before you start

- Read the [LICENSE](LICENSE). It is not a standard open-source licence: it limits redistribution, resale and earning income from the software without the owner's permission. If you plan anything beyond sending patches to this repository (for example a fork you publish or a product built on it), ask the owner first.
- For a bug, open an issue with the *Bug report* template. For an idea, use *Feature request*. For a security problem, **do not open a public issue**: follow [docs/security.md](docs/security.md#reporting-a-problem).
- For anything larger than a small fix, open an issue to talk about it before writing the code.

## Setting up

You need Python 3.11 or newer and Node 20 or newer.

```bash
python -m venv .venv
.venv/Scripts/activate            # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
cd backend && python -m pytest    # backend tests
cd ../frontend && npm install && npm test -- --run && npm run build
```

The backend tests use an in-memory SQLite database. CI also runs them on PostgreSQL (set `HORIZON_TEST_DATABASE_URL`, see the README).

## How the code is organised

Read [docs/architecture.md](docs/architecture.md) first. In short: parsers turn logs into events, the detection engine (pure Python, no web or database imports) turns events into detections, the alert manager turns detections into alerts, and the API is a thin layer over services. Only `database/` issues SQL.

## What a good change looks like

- **It has tests.** New behaviour gets a test that would fail without it; a bug fix gets a test that reproduces the bug. Anything that talks to the network, the operating system or a mail server is tested through an injected fake, never the real thing.
- **It keeps the privacy promise.** Nothing leaves the computer unless the user set it up and the screen says so. Do not add telemetry or background network calls.
- **It explains problems in plain words.** Errors say what is wrong and what to do about it, and they are checked on the server, not only in the page.
- **It handles untrusted input.** Log lines, uploaded files and anything from the network are data, never code or SQL. Values go into queries as parameters.
- **User-facing text is translatable.** New screen text is written in English; if you add a detection rule, its name, description and advice must be translated into every language file (a test checks this). Say in the pull request if you used a machine translation.
- **Patch notes are written by hand.** Anything a user would notice goes into `docs/release-notes/` for the next version (see the README in that folder). Do not paste generated notes.
- **Docs move with the code.** Update the README, `docs/api.md`, `docs/detection-rules.md` or `docs/security.md` where your change touches them.

## Pull requests

Keep them focused: one change, with a description of what changed for the user and how you tested it. CI must pass (backend on SQLite and PostgreSQL, frontend tests and build). Be ready for questions: a review is a conversation.
