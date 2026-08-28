# Software Design & Architecture Principles

To ensure `envtrap` remains highly testable, modular, and maintainable as an open-source project, all contributions must adhere to clean-code architectural patterns.

---

## 1. Clean Architecture & Layering

The codebase is split into three core layers with distinct boundaries and strict dependency rules:

1. **Domain Layer (`src/domain/`)**: 
   - Contains pure business logic and rule sets (such as `SecretMatcher`, `DedupCache`, and `OutputRedactor`).
   - Must remain entirely stateless and free of side-effects. It does not access the network, file system, or operating system interfaces.
   
2. **Ports Layer (`src/ports/`)**:
   - Outlines the core abstractions and interfaces (`IScanner`, `IReporter`, `ISecretSource`).
   - Acts as the contract between the domain logic and the external runtime adapters.

3. **Adapters Layer (`src/mitm/`, `src/secrets/`, `src/reporting/`, `src/cli/`)**:
   - Implements the interfaces defined in the Ports layer.
   - Interacts with Node.js runtime APIs, handles network sockets, executes operating system commands, and parses system configurations.

### The Dependency Rule
Dependencies must point inward. Adapters depend on Ports and Domain. The Domain layer must never import or depend on anything in the Adapters layer. This ensures that the core scanning logic is completely isolated from Node.js environment changes.

---

## 2. SOLID Architectural Design

### Single Responsibility (SRP)
Every class must represent a single, focused responsibility. Large components must be broken down into cohesive collaborators. For example, instead of the core engine coordinating caching, redaction, and stream parsing in one place, these concerns are delegated:
- `DedupCache` handles temporary duplicate suppression.
- `ContentClamp` manages memory buffers.
- `OutputRedactor` executes fingerprinting and string replacements.

### Open/Closed (OCP)
The framework is designed to allow extensions without modifying existing code. For instance:
- **Secret Sources**: To load credentials from a new API key manager, implement the `ISecretSource` interface. The `SecretSourceComposer` accepts any list of sources, keeping the loader process closed to modification.
- **Reporting**: Custom alert handlers are integrated by implementing the `ILeakReporter` interface and registering them with `CompositeReporter`.

### Liskov Substitution (LSP)
All interface implementations must be fully substitutable. Callers interacting with `ILeakReporter` or `IScanner` must be able to use any subtype interchangeably without checking constructors or handling unexpected exceptions.

### Interface Segregation (ISP)
Interfaces must remain highly cohesive and minimal. Instead of a monolithic reporter contract, interfaces are segregated by operational context:
- `ILeakReporter` maps to immediate event alerts.
- `RunSummaryPrinter` maps to exit summary output.
- `BannerPrinter` maps to initialization output.

### Dependency Inversion (DIP)
High-level controllers (such as the CLI runner and MITM proxy server) do not depend on concrete implementations of the scanner or logger. They interact solely through interfaces (`IScanner`, `IReporter`). Concretions are bound during bootstrap inside the `RunCommandBuilder` composition root.

---

## 3. Concurrency, State Isolation, and Testability

### Eliminating Global Mutability
To ensure thread safety and support parallel test execution:
- **No Global Singleton Instances**: Class instances must be instantiated explicitly. Do not export mutable module-level variables.
- **Encapsulated State**: Operational state (such as certificate pools or event caches) must be encapsulated entirely within class instances.

### Designing for Testability
Every external side-effect (I/O, network requests, time calculations) must be abstractable. If a component interacts with the file system or standard streams, those boundaries must be injected via constructors to allow standard unit tests to inject mocks and run in isolation.
