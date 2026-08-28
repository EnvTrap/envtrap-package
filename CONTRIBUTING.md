# Contributing to envtrap

Thank you for your interest in contributing to the envtrap package! We welcome community contributions, bug reports, and suggestions.

As a security-focused project, we maintain strict architectural rules to keep the package clean, secure, and maintainable.

---

## Setup & Development

This package is built with TypeScript and managed with `pnpm`. You will need Node.js (v18+) and `pnpm` installed.

1. **Clone the repository:**
   ```bash
   git clone https://github.com/EnvTrap/envtrap-package.git
   cd envtrap-package
   ```

2. **Install dependencies:**
   ```bash
   pnpm install
   ```

3. **Build the TypeScript files:**
   ```bash
   pnpm build
   ```

4. **Run integration tests:**
   ```bash
   pnpm test
   ```

---

## Repository Structure

- `src/ports/` — Interfaces and abstractions for Dependency Inversion.
- `src/domain/` — Pure logic models and helper objects (matcher, redactor, dedup).
- `src/config/` — Configuration schemas, mergers, and validator classes.
- `src/secrets/` — Environment and file secret loaders.
- `src/reporting/` — Emojiless, plain-text printers and structured file loggers.
- `src/mitm/` — HTTPS CA generator and loopback proxy servers.
- `src/cli/` — CLI subcommands and child process orchestrators.
- `src/hooks/` — ESM custom customization loaders and CJS require wrappers.

---

## Coding Standards (SOLID)

We enforce strict coding principles to ensure the codebase remains clean, extensible, and free of bloat:
1. **Single Responsibility (SRP)**: Every class must have one reason to change. Keep files small and focused.
2. **Open/Closed (OCP)**: Add new channels or secret sources by extending interfaces, not editing existing code.
3. **Liskov Substitution (LSP)**: All implementations must be completely swappable with their interface.
4. **Interface Segregation (ISP)**: Keep interfaces small and specific.
5. **Dependency Inversion (DIP)**: Always depend on abstractions (ports), never on concrete classes.
6. **Minimalist CLI Output**: Avoid emojis, redundant horizontal rule separators, and custom block shapes. Follow the standard bracket-prefixed plaintext tags for consistency.

---

## Pull Request Guidelines

1. **Keep PRs focused**: Submit separate PRs for unrelated bug fixes or features.
2. **Conventional Commits**: Use clean conventional prefix formats (e.g. `fix(mitm): ...`, `refactor(secrets): ...`).
3. **No Code Without Tests**: Add integration tests in `test/` verifying the runtime boundaries behave properly.
4. **Verify Build**: Always run `pnpm build` and `pnpm test` before pushing.
