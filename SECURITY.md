# Security policy

## Reporting a vulnerability in Rastro

Please report it privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue for it.

Say what you found, how to reproduce it and what an attacker could do with it. Rastro is a one-person project, so an answer may take a few days.

Rastro reads names chosen by attackers and writes them into HTML case files, so these matter most:

- anything that lets a domain name, a registry answer or a DNS answer run script or load content in a case file;
- anything that makes Rastro connect to an investigated domain;
- anything that puts the path of an investigated link, or personal data, into a case file.

## Using Rastro responsibly

- Rastro investigates infrastructure, never people. Do not use it, or extend it, to identify the people behind a domain.
- The abuse reports are drafts. Check them, complete them and send them only to the registrar's published abuse contact.
- Keep the names you see live, and the case files about them, out of public repositories until a registrar, a certificate authority or a blocklist has acted on them.
