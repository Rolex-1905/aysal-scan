# Security policy

## Reporting a vulnerability
Please report vulnerabilities **privately** through GitHub's "Report a vulnerability" (Security tab)
or by contacting the maintainer via the LinkedIn link in the README. Do not open a public issue for
an unpatched vulnerability. You will get an acknowledgement within a few days.

## Threat model
Aysal-Scan reads untrusted input (repositories, file names, JWT claims, provider API responses) and
makes network requests with credentials it finds. Its design rules:

1. **Untrusted text is never interpreted.** Anything originating outside the tool is escaped before
   it reaches the terminal (Rich markup), HTML or Markdown output.
2. **Raw secrets are never stored in findings or reports.** Only masked values (at most ~25% of the
   value) and an id (SHA-256, or HMAC-SHA256 when `AYSAL_SCAN_ID_SALT` is set) are emitted.
3. **Verification is read-only, time-limited and rate-limited per provider**, and a credential is only
   sent to the provider its format identifies. Non-200 responses are never treated as "active".
4. **A scan that cannot run exits 2** instead of reporting a clean result.
5. **Repository-provided ignore files can be disabled** (`--no-ignore-file`) for hostile repositories.
6. **Symlinks are not followed;** binary and oversized files are skipped.

## Responsible use
Verification uses the credential it found. Only run it against credentials you are authorised to
test. Use `--no-blast-radius` otherwise.
