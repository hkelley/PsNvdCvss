# PsNvdCvss
Powershell module to calculate aggregate (riskiest) CVSS vector scores from a list of CVE IDs.


In short, `Get-NvdCvssAggregateVector` takes an array of CVEs (such as you might get from a Nessus plugin finding) and it calculates the riskiest value from each score in the CVSS (3.1) vector (as reported by the NVD).

Without an NVD API key, it sleeps 10 seconds between requests (to avoid rate limits).    Specifying an API key reduces the sleep to one second.

Quick Example:
```
Import-Module PsNvdCvss
Initialize-NvdCvssResources -NVDApiKey $apikey
$cveIds = "CVE-2019-17571,CVE-2020-9488,CVE-2022-23302,CVE-2022-23305,CVE-2022-23307,CVE-2023-26464" -split ','
$cveIds.Count
Get-NvdCvssAggregateVector -CVEIDs $cveIds
```

returns
```
attackVector          : NETWORK
attackComplexity      : LOW
privilegesRequired    : NONE
userInteraction       : NONE
scope                 : UNCHANGED
confidentialityImpact : HIGH
integrityImpact       : HIGH
availabilityImpact    : HIGH
```

and if you run with verbosity,  the CVSS vectors are printed so that you can verify the calculations
```
VERBOSE: CVE-2019-17571 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
VERBOSE: CVE-2020-9488  CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N
VERBOSE: CVE-2022-23302 CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
VERBOSE: CVE-2022-23305 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
VERBOSE: CVE-2022-23307 CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
VERBOSE: CVE-2023-26464 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
```