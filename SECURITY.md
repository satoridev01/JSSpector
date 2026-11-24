# Security Policy

## Reporting a vulnerability in JSSpector

Please **do not open a public issue**. Instead, use GitHub's **private vulnerability reporting** for this repository: open the *Security* tab and choose *Report a vulnerability*.

JSSpector parses untrusted source code, so crashes, hangs, excessive resource use and path or symlink escapes caused by crafted input files are all in scope.

## Findings JSSpector produces on third-party projects

JSSpector is developed against real-world open-source repositories.

- **Replays of already published advisories** (CVE replay: scanning the commit before and after a known fix) use public information. Their data may live in this repository.
- **Findings on the current code (HEAD) of third-party projects** may be undisclosed vulnerabilities. They:
  - are **never committed to this repository** and never posted in issues, PRs or public reports;
  - are triaged in a private companion repository;
  - are reported to the affected maintainers through their published security policy or GitHub private vulnerability reporting (coordinated disclosure), with time given to release a fix before any details are made public.
- **Public reports** from this repository contain only aggregate metrics (counts, precision and recall).

If you use JSSpector to scan software you don't own, follow the same coordinated-disclosure practice.
