function Initialize-NvdCvssResources {
    param (
        [string] $NVDApiKey
    )

    $Script:HttpHeaders = @{}
    $Script:HttpSleepSecs = 10
    if(-not [string]::IsNullOrWhiteSpace($NVDApiKey)){
        $Script:HttpHeaders["apiKey"] = $NVDApiKey
        $Script:HttpSleepSecs = 1
    }

    $Script:cveBlanks = @{}
    $Script:cveMetrics = @{}
    $Script:cveListCache = @{}
    $Script:RANK_ATTACKVECTOR = @{
        NETWORK = 4
        ADJACENT_NETWORK = 3
        LOCAL = 2
        PHYSICAL = 1
    }
    $Script:RANK_SCOPE = @{
        CHANGED = 2
        UNCHANGED = 1
    }
    $Script:RANK_DEFAULT_HL = @{
        HIGH = 3
        LOW = 2
        NONE = 1
    }
    $Script:RANK_DEFAULT_LH = @{
        NONE = 3
        LOW = 2
        HIGH = 1
    }
}

function Get-NvdCvssWorseVector {
    param(
          [string] $VectorName
        , [string[]] $VectorValues
    )

    if($VectorValues.Count -ne 2) {
        throw "Must provide two VectorValues to compare"
    }
    if($VectorValues[0].ToString() -eq $VectorValues[1].ToString()){
        return $VectorValues[0]
    }

    # Check for a named rank for this vector
    if(-not( $rank = Get-Variable -Name ("RANK_" + $VectorName) -Scope "Script" -ErrorAction SilentlyContinue)) {  
        if($VectorName -like "*Impact") {
            $rank = $Script:RANK_DEFAULT_HL
        } else {
            # Complexity vectors, lower the barrier, higher the risk
            $rank = $Script:RANK_DEFAULT_LH
        }
    } 

    if(!($rank)) {
        throw "Could not find vector score rank for $VectorName"
    }

    # Compare the numeric equivalents
    if($rank[$VectorValues[0]] -gt $rank[$VectorValues[1]]){
        return $VectorValues[0]
    } else {
        return $VectorValues[1]
    }
}

function Get-NvdCvssAggregateVector {
    param(
        [string[]] $CVEIDs
    )

    $sortedCveIds = $CVEIDs | Select-Object -Unique | Sort-Object
    $key = $sortedCveIds -join "_"

    # Initialize-NvdCvssResources variable or fetch from cache?
    if($null -eq $Script:cveListCache) {
        Initialize-NvdCvssResources
    } elseif($agg = $Script:cveListCache[$key]) {
        return $agg
    }

    $agg = $null
    foreach($cveid in $CVEIDs) {
        if($metric = Get-NvdCvssMetric -CVEID $cveid) {
            if($null -eq $agg) {
                # initialize-NvdCvssResourcesialize the CVE agg with this first result
                $agg = $metric.psobject.Copy()
            } else {
                foreach($propName in $agg.psobject.Properties.Name) {
                    $agg."$propName" = Get-NvdCvssWorseVector -VectorName $propName -VectorValues ($agg."$propName",$metric."$propName")
                }
            }
        } else {

        }
        Start-Sleep -Seconds $Script:HttpSleepSecs
    }
    
    # Cache it
    $Script:cveListCache[$key] = $agg
    return $agg
}

function Get-NvdCvssMetric {
    param(
        $CVEID
    )

    # Initialize-NvdCvssResources variable or fetch from cache?
    if($null -eq $Script:cveMetrics) {
        Initialize-NvdCvssResources
    } elseif($cveMetric = $Script:cveMetrics[$CVEID]){
        return $cveMetric
    }

    if(     $CVEID -notlike "CVE-*" `
        -or $null -ne $Script:cveBlanks[$CVEID] ) {
        Write-Warning "Skipping $CVEID"
        return $null
    }

    $uri = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$CVEID"
    try {
        if($cvedata = Invoke-RestMethod -Headers $Script:HttpHeaders -Uri $uri -RetryIntervalSec 5 -MaximumRetryCount 2) {

            # Try for a primary report
            if($cveReport = $cvedata.vulnerabilities.cve.metrics.cvssMetricV31 | ?{$_.type -eq "Primary"} ) {
                # matched on primary
            } else {
                $cveReport = $cvedata.vulnerabilities.cve.metrics.cvssMetricV31 | Select-Object -First 1
            }

            if ($null -eq $cveReport) {
                throw "Could not find CVSS vector data for $CVEID in NVD"
            }
            Write-Verbose "$cveid`t$($cveReport.cvssData.vectorString)"

            $cvssMetric = $cveReport | Select-Object -ExpandProperty cvssData | Select-Object -ExcludeProperty version,vectorString,baseScore,baseSeverity 
            $Script:cveMetrics[$CVEID] = $cvssMetric
            return $cvssMetric
        }
    }  catch {
        $Script:cveBlanks[$CVEID] = $_.Exception.Message
        Write-Warning "No CVSS data found for $CVEID at $uri"
        return $null
    }
}