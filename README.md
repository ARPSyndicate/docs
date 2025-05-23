# API Documentation

## Osprey Vision
[Osprey Vision](https://www.osprey.vision) is an Artificial Intelligence API for Information Discovery.

### Endpoints without authentication (aggressive ratelimits, limited access)
- Returns a streaming response for a prompt<br>
`POST` https://api.osprey.vision/
    - `prompt` (json dict string | mandatory): ask any query

### Endpoints with authentication (no ratelimits, full access)
- Returns a streaming response for a prompt<br>
`POST` https://api.osprey.vision/beta/
    - `prompt` (json dict string | mandatory): ask any query
    - `auth` (json dict string | mandatory): [authentication code](https://www.arpsyndicate.io/pricing.html)

- Returns a streaming response containing a summary for a list of webpages<br>
`POST` https://api.osprey.vision/summarize/
    - `links` (json dict string | mandatory): HTTP/HTTPS links separated by space/newline
    - `auth` (json dict string | mandatory): [authentication code](https://www.arpsyndicate.io/pricing.html)

- Returns a streaming response containing a vulnerability advisory<br>
`POST` https://api.osprey.vision/advisory/
    - `vulnid` (json dict string | mandatory): generates for a [supported vulnerability identifier](#supported-vulnerability-identifiers)
    - `lang` (json dict string | mandatory): choose from English, Mandarin, Spanish, Russian, French, German, Finnish, Estonian, Japanese, Korean, Italian & Hindi
    - `auth` (json dict string | mandatory): [authentication code](https://www.arpsyndicate.io/pricing.html)

## Subdomain Center
[Subdomain Center](https://www.subdomain.center) is a Shadow IT / Subdomain Intelligence API.

### Endpoints without authentication (aggressive ratelimits, limited access)
- Returns a list of subdomains for a domain<br>
`GET` https://api.subdomain.center/?domain={DOMAIN}&engine={ENGINE}
    - `domain` (string | mandatory): searches by any domain/subdomain
    - `engine` (string | optional): choose a clustering engine
        - `cuttlefish` (default): clusters by domain
        - `octopus`: clusters by visual identity

### Endpoints with authentication (no ratelimits, full access)
- Returns a list of subdomains for a domain<br>
`GET` https://api.subdomain.center/beta/?domain={DOMAIN}&engine={ENGINE}&auth={AUTH}
    - `domain` (string | mandatory): searches by any domain/subdomain
    - `engine` (string | optional): choose a clustering engine
        - `cuttlefish` (default): clusters by domain
        - `octopus`: clusters by visual identity
    - `auth` (string | mandatory): [authentication code](https://www.arpsyndicate.io/pricing.html)


## Exploit Observer
[Exploit Observer](https://www.exploit.observer) is a Vulnerability / Exploit Intelligence API.

### Endpoints without authentication (no ratelimits)
- Returns a watchlist of vulnerability & exploit identifiers<br>
`GET` https://api.exploit.observer/watchlist/identifiers

- Returns a detailed watchlist of vulnerability & exploit identifiers<br>
`GET` https://api.exploit.observer/watchlist/describers

- Returns a watchlist of vulnerable technologies<br>
`GET` https://api.exploit.observer/watchlist/technologies

- Returns statistics around all vulnerabilities & exploits<br>
`GET` https://api.exploit.observer/stats

### Endpoints without authentication (aggressive ratelimits)
- Returns information related to a VID<br>
`GET` https://api.exploit.observer/?keyword={VID}&enrich={TRUE/FALSE}
    - `keyword` (string | mandatory): searches by any of the [supported vulnerability identifiers](#supported-vulnerability-identifiers)
    - `enrich` (boolean | optional): enables enrichment with additional data points for CVE/GHSA IDs (Includes EPSS, Aliases, Affected Products & Additional References)

- Returns a list of VEDAS identifiers associated with a Russian VID but not a CVE<br>
`GET` https://api.exploit.observer/russia/noncve

- Returns a list of VEDAS identifiers associated with a Chinese VID but not a CVE<br>
`GET` https://api.exploit.observer/china/noncve

### Endpoints with authentication (no ratelimits)
- Returns information related to a VID<br>
`GET` https://api.exploit.observer/beta/?keyword={VID}&enrich={TRUE/FALSE}&auth={AUTH}
    - `keyword` (string | mandatory): searches by any of the [supported vulnerability identifiers](#supported-vulnerability-identifiers)
    - `enrich` (boolean | optional): enables enrichment with additional data points for CVE/GHSA IDs (Includes EPSS, Aliases, Affected Products & Additional References)
    - `auth` (string | mandatory): [authentication code](https://www.arpsyndicate.io/pricing.html)

### Supported Vulnerability Identifiers
- A.R.P. Syndicate Vulnerability & Exploit Data Aggregation System (VEDAS) - `VEDAS:OBLIVIONHAWK`
- China National Vulnerability Database (CNVD) - `CNVD-2024-02713`
- China National Vulnerability Database of Information Security (CNNVD) - `CNNVD-202312-2255`
- Cisco Talos (TALOS) - `TALOS-2023-1896`
- Common Vulnerabilities and Exposures (CVE) - `CVE-2021-3450`
- CXSecurity World Laboratory of Bugtraq (WLB) - `WLB-2024010058`
- Defiant Wordfence (WORDFENCE) - `WORDFENCE-00086b84-c1ec-447a-a536-1c73eac1cc85`
- European Union Vulnerability Database (EUVD) - `EUVD-2025-14498`
- GitHub Commits (GHCOMMIT) - `GHCOMMIT-102448040d5132460e3b0013e03ebedec0677e00`
- GitHub Repositories (GITHUB) - `GITHUB/aio-libs/aiohttp`
- GitHub Security Advisories (GHSA) - `GHSA-wfh5-x68w-hvw2`
- Google Bug Hunters VRP (GBHVRP) - `GBHVRP-F8GFYGv4g`
- Google Chromium Issues (CHROMIUM) - `CHROMIUM-40057791`
- Google Project Zero (PROJECTZERO) - `PROJECTZERO-42450487`
- Hackerone Hacktivity (H1) - `H1-2230915`
- Japan Vulnerability Notes iPedia (JVNDB) - `JVNDB-2023-006199`
- Knownsec Seebug (SSVID) - `SSVID-99817`
- Linux Open Source Security Foundation (OSSF) - `OSSF-OSV-2024-1427`
- Microsoft Common Vulnerabilities and Exposures (MSCVE) - `MSCVE-2025-21415`
- Mozilla Foundation Issues (MOZILLA) - `MOZILLA-290162`
- Mozilla Foundation Security Advisories (MFSA) - `MFSA2024-51`
- OffSec Exploit Database (EDB) - `EDB-10102`
- openSUSE Common Vulnerabilities and Exposures (SUCVE) - `SUCVE-2023-40547`
- openSUSE Issues (SUSE) - `SUSE-1183851`
- Packet Storm Security (PSS) - `PSS-170615`
- Patchstack (PATCHSTACK) - `PATCHSTACK/spectrum/wordpress-spectrum-theme-remote-code-execution`
- ProjectDiscovery Nuclei (PD) - `PD/http/cves/2020/CVE-2020-12720`
- ProtectAI Huntr (HUNTR) - `HUNTR-001d1c29-805a-4035-93bb-71a0e81da3e5`
- Rapid7 Metasploit Framework (MSF) - `MSF/auxiliary_admin/2wire/xslt_password_reset`
- RedHat Common Vulnerabilities and Exposures (RHCVE) - `RHCVE-2025-27098`
- RedHat Issues (REDHAT) - `REDHAT-290162`
- RedHat Security Advisories (RHSA) - `RHSA-2025:1730`
- Russian Data Bank of Information Security Threats (BDU) - `BDU:2024-00390`
- Snyk Vulnerability Database (SNYK) - `SNYK-JAVA-ORGCLOJURE-5740378`
- Source Incite (SRC) - `SRC-2021-0019`
- Tenable Common Vulnerabilities and Exposures (TNCVE) - `TNCVE-2025-25763`
- Tenable Security Advisories (TNS) - `TNS-2021-05`
- Trend Micro Zero Day Initiative (ZDI) - `ZDI-23-1714`
- VARIoT Exploits (VAR-E) - `VAR-E-201704-0525`
- VARIoT Vulnerabilities (VAR) - `VAR-202404-0085`
- Veracode SourceClear Vulnerability Database (SRCCLR-SID) - `SRCCLR-SID-3173`
- WP Engine WPScan (WPSCAN) - `WPSCAN-52568abd-c509-411e-8391-c75e7613eb42`
- YouTube (YT) - `YT/ccqjhUmwLCk`
- Zero Science Lab (ZSL) - `ZSL-2022-5743`
- 0Day Today (0DAY-ID) - `0DAY-ID-24705`
- Vendor/Product ({vendor}__{product}) - `grafana`
- Vendor/Product + Version ({vendor}__{product}@{version}) - `felixwelberg@1.0.45`
- Multiple Non-VID Keywords ({keywordA}__{keywordB}) - `pci__util`