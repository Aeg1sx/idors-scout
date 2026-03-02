# Contributing

English | [한국어](CONTRIBUTING.ko.md)

Thanks for contributing to IDOR Scout.

## Development Setup

1. Install dependencies:
```bash
npm ci
```

2. Build:
```bash
npm run build
```

3. Run tests:
```bash
npm test
```

## Contribution Workflow

1. Create a feature branch.
2. Keep changes focused and small.
3. Add or update tests for behavior changes.
4. Run `npm run build` and `npm test` before opening PR.
5. Open a pull request with:
- problem statement
- approach summary
- risk notes
- test evidence

## Coding Guidelines

- Use TypeScript strict mode conventions.
- Avoid breaking CLI/config compatibility without clear migration notes.
- Prefer explicit behavior over magic defaults for security-sensitive logic.
- Redact secrets/tokens from examples, logs, and reports.

## Pull Request Checklist

- [ ] Code builds successfully
- [ ] Tests pass locally
- [ ] Docs/config examples updated (if needed)
- [ ] No credentials/tokens committed
- [ ] Backward compatibility impact described

## Reporting Security Issues

If your contribution contains or discovers a security issue, follow `SECURITY.md` and use private disclosure.
