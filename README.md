# API Documentation

## Subdomain Center
[Subdomain Center](https://www.subdomain.center) is a Shadow IT / Subdomain Intelligence API.

### Endpoints without authentication (aggressive ratelimits)
- Returns a list of subdomains for a domain<br>
`GET` https://api.subdomain.center/?domain={DOMAIN}
    - `domain` (string | mandatory): searches by any domain

### Endpoints with authentication (no ratelimits)
- Returns a list of subdomains for a domain<br>
`GET` https://api.subdomain.center/beta/?domain={DOMAIN}&auth={AUTH}
    - `domain` (string | mandatory): searches by any domain
    - `auth` (string | mandatory): [authentication code](https://www.arpsyndicate.io/pricing.html)


## Exploit Observer
[Exploit Observer](https://www.exploit.observer) is a Vulnerability / Exploit Intelligence API.

### Endpoints without authentication (no ratelimits)
- Returns a watchlist of vulnerability & exploit identifiers<br>
`GET` https://api.exploit.observer/watchlist/identifiers

- Returns a watchlist of vulnerable technologies<br>
`GET` https://api.exploit.observer/watchlist/technologies

- Returns statistics around all vulnerabilities & exploits<br>
`GET` https://api.exploit.observer/stats

### Endpoints without authentication (aggressive ratelimits)
- Returns information related to a VID<br>
`GET` https://api.exploit.observer/?keyword={VID}&enrich={TRUE/FALSE}
    - `keyword` (string | mandatory): searches by any of the [supported vulnerability identifiers](#supported-vulnerability-identifiers)
    - `enrich` (boolean | optional): enables enrichment with additional data points for CVE/GHSA IDs (Includes EPSS, Aliases & Additional References)

- Returns a list of VEDAS identifiers associated with a Russian VID but not a CVE<br>
`GET` https://api.exploit.observer/russia/noncve

- Returns a list of VEDAS identifiers associated with a Chinese VID but not a CVE<br>
`GET` https://api.exploit.observer/china/noncve

### Endpoints with authentication (no ratelimits)
- Returns information related to a VID<br>
`GET` https://api.exploit.observer/beta/?keyword={VID}&enrich={TRUE/FALSE}&auth={AUTH}
    - `keyword` (string | mandatory): searches by any of the [supported vulnerability identifiers](#supported-vulnerability-identifiers)
    - `enrich` (boolean | optional): enables enrichment with additional data points for CVE/GHSA IDs (Includes EPSS, Aliases & Additional References)
    - `auth` (string | mandatory): [authentication code](https://www.arpsyndicate.io/pricing.html)

### Supported Vulnerability Identifiers
- A.R.P. Syndicate Vulnerability & Exploit Data Aggregation System (VEDAS) - `VEDAS:OBLIVIONHAWK`
- Common Vulnerabilities and Exposures (CVE) - `CVE-2021-3450`
- Russian Data Bank of Information Security Threats (BDU) - `BDU:2024-00390`
- China National Vulnerability Database (CNVD) - `CNVD-2024-02713`
- China National Vulnerability Database of Information Security (CNNVD) - `CNNVD-202312-2255`
- Japan Vulnerability Notes iPedia (JVNDB) - `JVNDB-2023-006199`
- GitHub Security Advisories (GHSA) - `GHSA-wfh5-x68w-hvw2`
- GitHub Commits (GHCOMMIT) - `GHCOMMIT-102448040d5132460e3b0013e03ebedec0677e00`
- Veracode SourceClear Vulnerability Database (SRCCLR-SID) - `SRCCLR-SID-3173`
- Snyk Vulnerability Database (SNYK) - `SNYK-JAVA-ORGCLOJURE-5740378`
- OffSec Exploit Database (EDB) - `EDB-10102`
- 0Day Today (0DAY-ID) - `0DAY-ID-24705`
- Knownsec Seebug (SSVID) - `SSVID-99817`
- Trend Micro Zero Day Initiative (ZDI) - `ZDI-23-1714`
- Packet Storm Security (PSS) - `PSS-170615`
- CXSecurity World Laboratory of Bugtraq (WLB) - `WLB-2024010058`
- Rapid7 Metasploit Framework (MSF) - `MSF/auxiliary_admin/2wire/xslt_password_reset`
- ProjectDiscovery Nuclei (PD) - `PD/http/cves/2020/CVE-2020-12720`
- Hackerone Hacktivity (H1) - `H1-2230915`
- Cisco Talos (TALOS) - `TALOS-2023-1896`
- ProtectAI Huntr (HUNTR) - `HUNTR-001d1c29-805a-4035-93bb-71a0e81da3e5`
- WP Engine WPScan (WPSCAN) - `WPSCAN-52568abd-c509-411e-8391-c75e7613eb42`
- Defiant Wordfence (WORDFENCE) - `WORDFENCE-00086b84-c1ec-447a-a536-1c73eac1cc85`
- YouTube (YT) - `YT/ccqjhUmwLCk`
- Zero Science Lab (ZSL) - `ZSL-2022-5743`
- VARIoT Exploits (VAR-E) - `VAR-E-201704-0525`
- VARIoT Vulnerabilities (VAR) - `VAR-202404-0085`
- Vendor/Product (No Prefix) - `grafana`
- Vendor/Product + Version (No Prefix) - `felixwelberg@1.0.45`