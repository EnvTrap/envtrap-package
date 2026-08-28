# SOLID Coding Principles & Standards

We enforce strict coding principles to ensure the codebase remains maintainable, testable, and robust. This document outlines the standards developers must follow.

---

## 1. SOLID Application in envtrap

### Single Responsibility Principle (SRP)
Every class must have exactly **one reason to change**.
- **Violation**: The old `Scanner` used to contain secrets arrays, configure settings, deduplicate leaks, format strings, print alerts, and check subprocesses.
- **Enforcement**: We broke `Scanner` into single-concern classes:
  - `DedupCache`: Deduplicates (name, channel) pairs using a TTL.
  - `ContentClamp`: Limits scanned data sizes.
  - `SecretMatcher`: Matches substrings.
  - `FileEventLogger` & `LeakAlertPrinter`: Separate logging destinations.

### Open/Closed Principle (OCP)
The system should be **open for extension, but closed for modification**.
- **Enforcement**: To add a new source of secrets, you do not modify the CLI execution or the loaders. Instead, you implement `ISecretSource` (e.g. `VaultSecretSource`) and add it to the constructor array of `SecretSourceComposer`. The core engine remains untouched.

### Liskov Substitution Principle (LSP)
Subtypes must be completely **substitutable for their base types**.
- **Enforcement**: The `CompositeReporter` uses the `ILeakReporter` interface. Any class implementing `ILeakReporter` (e.g. `LeakAlertPrinter`, `FileEventLogger`) can be added to the composite without breaking the runtime behavior or requiring conditional logic.

### Interface Segregation Principle (ISP)
Clients should **not be forced to depend on interfaces they do not use**.
- **Enforcement**: Rather than having a large `IReporter` interface that forces every listener to implement `.summary()`, `.banner()`, and `.warn()`, we split it:
  - `ILeakReporter`: Used for logging a single event (`.report()`).
  - `IRunSummaryPrinter`: Used only at process shutdown to display the summary.
  - `BannerPrinter`: Prints CLI startup messages.

### Dependency Inversion Principle (DIP)
Depend upon **abstractions (interfaces), not concretions (classes)**.
- **Enforcement**: The `Scanner` does not instantiate or import `LeakAlertPrinter`. Instead, its constructor accepts `IReporter`. This means we can instantiate `Scanner` with a mock reporter during unit testing, isolating it from standard output streams.

---

## 2. Code Rules & Limits

To keep the codebase from decomposing into large files, we enforce strict limits:

### Class Size
- A class must **not exceed 100 lines of code** (including comments). If a class starts growing, extract private sub-methods into a new collaborator class.
- A class must have **no more than 2 instance variables** (meaningful collaborator fields). This ensures that classes remain highly cohesive.

### Method Length
- No method should **exceed 10 lines of executable code**.
- Break complex methods down into private helpers, or extract the logic into a new pure domain class.

### Parameter Limitations
- Constructors and methods should accept **no more than 3 parameters**.
- If a method requires more, pass a structured parameter object or refactor the method into smaller sub-responsibilities.

### State Isolation
- **No global states or module-level mutable variables**.
- Every service (like `CertificateAuthority` or the scanner engine) must keep its state contained inside class instances. This allows independent tests to run concurrently without side-effects or state leaks.

---

## 3. Print Formatting Standards

To maintain a professional, minimalist, and standardized CLI output, follow these print formatting rules:

- **No Emojis**: Never use icons or emojis (such as `📤`, `🔴`, `🚨`, `✅`, `⚠`) in console logs. Use clean prefix labels instead: `[envtrap]`, `[envtrap] warning:`, `[envtrap] info:`.
- **No Horizontal Rule Dividers**: Never print horizontal rule dividing lines (e.g. `───────` or `═══════`). These clutter the console and make text parsing difficult. Use native standard output formatting and standard list structures instead.
- **Simple Lists**: Group summaries using standard ASCII markers: `->` for bullet points.
- **ANSI Colors**: Use colors (via `chalk`) selectively. Use `chalk.red.bold` for secret leaks, `chalk.gray` for timestamps/secondary metadata, and standard colored labels for different channels to help developers quickly spot leaks.
