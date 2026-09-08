# Security Policy

## Intended use

DomainScan is a **defensive reconnaissance tool**. It is meant to help people
who own or administer a domain understand its public attack surface: DNS,
TLS, mail authentication, exposed files and so on.

Only scan domains you own or are explicitly authorized to test. Unauthorized
scanning of infrastructure you do not control may violate terms of service or
the law in your jurisdiction.

## Reporting a vulnerability

If you find a vulnerability in **DomainScan itself** (for example, the app
crashes on crafted input, leaks data it should not, or a check behaves
intrusively), please report it responsibly:

- Open a **private security advisory** on GitHub:
  **Security → Report a vulnerability**, or
- Email the maintainers with `[DomainScan security]` in the subject.

Please include:

1. The affected version.
2. A short description of the issue.
3. Steps to reproduce (ideally with a harmless test target).
4. Any suggested fix.

We will acknowledge reports within 72 hours and aim to resolve confirmed issues
promptly.

## What is out of scope

- Findings about *scanned third-party websites* (DomainScan reports what is
  publicly visible; report those to the site owner).
- Denial-of-service or aggressive scanning behaviour of the tool against
  targets you are not authorized to test.

## Reporting bugs in a scanned target

If a scan surfaces something sensitive (an exposed `.git`, a database left
open, a subdomain takeover), contact the owner of that system directly. Do not
access, modify or exploit it.
