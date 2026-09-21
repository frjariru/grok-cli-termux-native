# Security Penetration Test Report

**Generated:** 2026-09-20 21:22:32 UTC

# Executive Summary

# Executive Summary

A black-box security assessment of **https://testphp.vulnweb.com** could not be completed because the target was **unreachable for the entire engagement window**.

**Overall posture: Not assessed.**

Every request to the host failed at the network level. The DNS name resolves consistently to a single address in AWS `us-west-2`, but TCP `80`/`443` never completed a connection and no HTTP response from the target was ever received. This was confirmed to be **host-specific and not an artifact of the assessment environment**: control hosts and cloud endpoints connected normally from the same environment, while the target timed out; independent external vantage points and third-party fetch services also failed on this host while succeeding on controls.

**Key points**
- **No vulnerability was confirmed, and none was ruled out.** There are no positive or negative security conclusions about the application itself — the absence of findings here does not indicate the application is secure.
- The application's live behavior, configuration, and currently deployed version could not be observed.
- Historical (archived) material indicates the application is a deliberately vulnerable PHP demo with classic weaknesses (SQL injection, cross-site scripting, path traversal, verbose error and source disclosure). These are recorded strictly as **unverified leads** for a future re-test and are **not** findings.

**Business impact**
- Cannot be determined until the service is reachable and testing can be performed. If the outage is unintended, it is itself an availability concern for the asset owner. If the host has been decommissioned, it should be removed from scope; if it is expected to be online, connectivity to the origin should be investigated.

# Methodology

# Methodology

**Engagement type:** External black-box assessment.
**Scope:** `https://testphp.vulnweb.com` only (no other assets were tested).
**Standards:** Organized around the **OWASP Web Security Testing Guide (WSTG)** categories, in a PTES-style flow.

**Test categories planned and attempted** (each blocked at the first live request):
- Reconnaissance, technology fingerprinting, and attack-surface mapping
- Endpoint, parameter, and form enumeration (augmented with an historical surface map recovered from public web archives)
- SQL injection
- Cross-site scripting (reflected, stored, DOM-based)
- Authentication, session management, and access control (IDOR / broken function-level authorization)
- Path traversal / local file inclusion, unrestricted file upload, and information disclosure
- A dedicated, multi-vantage reachability verification to distinguish a target outage from an environment problem

**Constraint:** The live target was globally unreachable for the whole run. Consequently **every test category remains untested rather than clean**, and all candidate surfaces are carried as open (proof-gap) items rather than resolved. The engagement should be treated as *incomplete*, not as a passed assessment.

# Technical Analysis

# Technical Analysis

## Root cause of the blocker: target globally unreachable

The target could not be reached at any point during the assessment. The failure was verified from multiple independent directions to rule out an environment-side cause:

- **DNS was healthy and consistent:** the host resolved, via the local resolver and public resolvers (`8.8.8.8`, `1.1.1.1`), to a single IPv4 address in AWS `us-west-2` (no IPv6 record).
- **TCP `80` and `443` never connected:** direct (proxy-bypassed) connections timed out at the TCP connect stage with no TLS handshake; a port scan found no responsive ports across `1-1024` and common alternates; a sweep of `80`, `443`, `8080`, `8443`, `8000`, `8001`, `8888`, `3000`, and `22` all timed out.
- **Proxy behavior:** the egress proxy returned its own gateway timeout for every request to this host; no target response was ever captured.
- **Environment egress was healthy:** control hosts (`example.com`, `google.com`) and AWS `us-west-2` endpoints connected in well under a second, proving the failure is specific to this host, not the network path or region.
- **External corroboration:** external HTTP reader/proxy services failed on this origin while succeeding on controls, and independent global probing nodes reported connection timeouts on both TCP `80` and `443`. The most recent public archive capture of the host predates this assessment by roughly six months.

Conclusion: the origin server appears to be offline or filtering all inbound traffic. No HTTP-level testing was possible.

## Coverage summary

A total of **31 surfaces** were enumerated for testing and recorded. **30 remain open** (blocked by the outage — no live request could be sent), and **1** (host reachability) was conclusively characterized as an external outage. Open surfaces include: the SQL injection sinks (`listproducts.php?cat=`, `artists.php?artist=`, `product.php?pic=`, `AJAX/infoartist.php?id=`, `login.php`, `search.php`, `cart.php`, category/artist lookups); the cross-site-scripting sinks (`search.php`, `guestbook.php`, `comment.php`, `artists.php`, `signup.php`/`userinfo.php`/`login.php` fields, the AJAX `innerHTML` sinks, `hpp/*`, `Mod_Rewrite_Shop/*`); the file/path sinks (`showimage.php?file=`, `product.php?pic=`, `index.php?cmd=`); the authentication and access-control surfaces (`login.php`, `userinfo.php`, `cart.php`, `signup.php` → `/secured/newuser.php`, session management); file-upload surfaces; and the information-disclosure artifact checklist.

Because no request reached the target, none of these can be stated as confirmed **or** ruled out.

## Unverified leads (explicitly NOT findings)

The application's historical surface was recoverable from public archives, and the historical responses indicate classic weaknesses consistent with this being a purpose-built vulnerable test application. **These are prioritization leads only** — they come from archived, potentially stale captures of unknown current fidelity, and could not be reproduced against the live service:

- **SQL injection (highest-priority lead):** archived responses to `listproducts.php?cat=` and `artists.php?artist=` reportedly show raw MySQL syntax errors on an unescaped single quote, an `ORDER BY` column-count boundary, and UNION-based extraction of a schema value reflected back into the page. Related DB-warning evidence was also observed for the AJAX ID lookups.
- **Cross-site scripting:** archived DOM sinks in the AJAX page build `innerHTML` from XML/AJAX-derived values; historical scanner URLs against the search, guestbook, comment, `hpp/*`, and shop-detail pages contain script payloads, but the server-side reflection/encoding context could not be retrieved.
- **Path traversal / LFI and information disclosure:** candidate file/path parameters (`showimage.php?file=`, `product.php?pic=`) and a set of exposed project/source artifacts (IDE metadata, CVS, connection/config files, backups) are indicated by the archived surface but were never fetched live.
- A verbose PHP error mode leaking filesystem paths is indicated by archived responses.

None of the above was validated live and none is filed as a vulnerability.

## Attack chaining

No attack chains could be constructed or validated: chaining requires at least one confirmed finding, and none exists because no live request succeeded. This is a direct consequence of the outage, not a judgment that chaining is not possible on this application.

# Recommendations

# Recommendations

## Immediate
1. **Establish whether the target should be live.** Confirm with the asset owner whether `testphp.vulnweb.com` is intended to be in service. If it has been decommissioned, remove it from scope; if it is expected to be online, investigate the origin outage/filtering (the host resolves but accepts no TCP connections on `80`/`443`).
2. **Do not treat this run as a passed assessment.** The absence of findings reflects an inability to test, not a clean result. Record the engagement as incomplete pending re-test.

## Short-term
3. **Re-run the assessment once the host is reachable.** A quick pre-flight reachability gate (a 3–5 second TCP connect or an HTTP request expecting a `200`) should be used before dispatching any testing, so effort is not spent against a dead origin.
4. **On re-test, prioritize in this order** (based on the unverified leads above):
   - SQL injection on `listproducts.php?cat=`, `artists.php?artist=`, `product.php?pic=`, `AJAX/infoartist.php?id=` (and the login form), using differential/boolean and error-based probes followed by controlled extraction.
   - Reflected and stored cross-site scripting on the search, guestbook, and comment pages, and the search/listing parameters.
   - Path traversal / LFI on `showimage.php?file=` and `product.php?pic=`.
   - Authenticated testing of `userinfo.php`/`cart.php` (forced browsing, IDOR) and session/CSRF controls.
   - Information-disclosure checks for the exposed project/source artifacts.

## Retest & validation
5. **Re-verify reachability before and after remedial work**, and re-confirm each remediated item with a targeted proof-of-concept once the service is available. Because none of the surfaces above were tested, all remain open and must be revisited rather than assumed safe.

