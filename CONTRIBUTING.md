# Contributing

Thanks for helping make AI agents safer to extend.

## Setup

```bash
npm ci
npm test
```

Node 22 or newer is needed for the test tooling. The published CLI runs on Node 20+.

## Adding or changing a rule

1. Pick the rule file for its category in `src/rules/`. Rule ids are permanent: never renumber or reuse one.
2. Write the test first in the matching `test/rules-*.test.ts`: at least two realistic true positives and at least three benign near-misses.
3. Keep regexes linear. Rules run on attacker-controlled text, and `test/rules-contract.test.ts` fails any rule that is slow on adversarial input.
4. Prefer precision. High and critical findings should almost never fire on popular, benign skills and configs. Use a lower severity for weaker signals.
5. Keep fixtures inert: `attacker.example` hosts, documentation IP ranges and fake keys built at runtime in tests.

Run `node dist/cli.js scan test/fixtures/corpus/benign` after `npm run build` to check that the benign corpus stays clean.

## Pull requests

- One topic per pull request, with tests.
- `npm run typecheck`, `npm test` and `npm run build` must pass.
- No new runtime dependencies.
