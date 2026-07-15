# Contributing

Hedge is intentionally narrow during Build Week. Changes should improve evidence quality, safety, reliability, evaluation, or the core GitHub-native experience.

Before opening a change:

```bash
npm install
npm run check
npm run eval
npm run build
```

Security-sensitive changes must include a fixture or test. Product or security tradeoffs must be recorded in `docs/DECISIONS.md`. New limitations must be recorded in `docs/LIMITATIONS.md`.
