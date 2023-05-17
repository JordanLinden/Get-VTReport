# Get-VTReport
# Version 1.1
# Generate file signatures and submit to VirusTotal for detection reports

# Jordan Linden @https://github.com/JordanLinden
# 15 May 2023

# Disclaimer: This script is not production-ready. Use at your own risk.


Param(
    [string]$hash = $null,
    [string]$samplesPath = ".\samples",
    [string]$sigcheck = ".\sigcheck.exe",
    [switch]$noConsole = $false,
    [switch]$help = $false
)

$Banner = "`nGet-VTReport v1.1 - Generate file signatures and submit to VirusTotal for detection reports"
$Banner += "`nCreated by Jordan Linden"
$Banner += "`nhttps://github.com/JordanLinden"

Write-Host $Banner -f White
Write-Host ("`n" + "* "*64 + "`n") -f White

function showHelp {
    Write-Host "`nDESCRIPTION:"
    Write-Host "    Get-VTReport v1.1"
    Write-Host "    Author: Jordan Linden"
    
    $desc = "`nHash sample files with sysinternals sigcheck tool and get VirusTotal detection scores"
    $desc += " or provide hashes to submit to VirusTotal Public API."
    $desc += "`nReports are timestamped and outputted to the script`'s directory under the Reports folder."
    Write-Host $desc
    
    Write-Host "`nRemember to adhere to the VirusTotal API constraints:"
    Write-Host "https://developers.virustotal.com/reference/public-vs-premium-api"
    
    Write-Host "`nDEPENDENCIES:"
    Write-Host "    Sysinternals sigcheck: https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck"
    
    Write-Host "`nOPTIONS:"
    Write-Host "           hash - a single hash string"
    Write-Host "    samplesPath - directory location of sample files to be hashed"
    Write-Host "                - [default: .\samples]"
    Write-Host "       sigcheck - file location of sigcheck executable"
    Write-Host "                - [default: .\sigcheck.exe]"
    Write-Host "      noConsole - disable outputting results to console"
    Write-Host "                - type switch"
    Write-Host "                - [default: false]"
    Write-Host "           help - display this help menu"
    Write-Host "                - type switch"
    Write-Host "                - [default: false]"
    Write-Host "`nEXAMPLE USAGE:"
    Write-Host "    # submit a single file hash to VirusTotal"
    Write-Host '    Get-VTReport.ps1 -hash 7c9d5724064693dfeef76fd4da8d6f159ef0e6707e67c4a692a03e94f4a6e27a'
    Write-Host "`n" -NoNewline
    Write-Host "    # specify path to sigcheck and hash files within the samples folder for submission to VirusTotal"
    Write-Host '    Get-VTReport.ps1 -sigcheck ".\sigcheck.exe" -samplesPath ".\samples"'
    Write-Host "`n`n"
}

if ($help) {
    showHelp
    return
}

# Prevent output text wrap based on console width
$PSDefaultParameterValues['out-file:width'] = 2000

# Create Reports folder if not present
if (-not (Test-Path -Path ".\Reports")) {
    New-Item -ItemType Directory -Path ".\Reports" > $null
}

# Create timestamped report file
$reportFile = "report-" + (Get-Date).tostring("yyyyMMddhhmmss") + ".txt"
$reportFilePath = ".\Reports\$reportFile"

$headerPadding = "="*16

function GenerateHashes {
    
    # Fetch files from samples directory
    $samples = Get-ChildItem -Path $samplesPath | Select -Expand FullName
    
    # Set sigcheck exe
    $cmd = $sigcheck
    
    # List desired sigcheck fields
    $fields = @(
        "MD5",
        "SHA1",
        "PESHA1",
        "PESHA256",
        "SHA256",
        "VT detection",
        "VT link"
    )
    
    # Run sigcheck on each file in samples
    Foreach($samplePath in $samples) {
        try {
            
            # Insert output separator for current sample
            $header = $headerPadding + " Report for " + $samplePath.Split("\")[-1] + " " + $headerPadding
            echo $header >> $reportFilePath
            
            # Execute sigcheck with VirusTotal report enabled, output in csv format
            # Select applicable fields from csv and clean up output
            $params = "-accepteula -nobanner -c -vt -v -h `"$samplePath`""
            $result = Invoke-Expression "$cmd $params" | ConvertFrom-Csv -Delim ',' | Select $fields |
            % {$_."VT detection" = $_."VT detection".Replace("|", "/"); $_}
            
            # Print results to console if enabled
            if ($noConsole) {
                Write-Host ("Signatures for " + $samplePath.Split("\")[-1] + " generated and successfully submitted to VirusTotal") -f White
            } else {
                Write-Host ("Signatures and report for " + $samplePath.Split("\")[-1]) -f White
                Write-Output $result
            }
            
            # Populate report file
            echo $result >> $reportFilePath
            
        } catch {
            $error = "Failed to process " + ($samplePath.Split("\")[-1]) + "`n"
            Write-Host $error -ForegroundColor Red -BackgroundColor Black
            Throw
        }
    }
}

function submitHash($secureKey) {
    try {
        
        # Set TLS 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        
        # Insert hash into VirusTotal URI
        $hash = $hash.ToUpper()
        $uri = "https://www.virustotal.com/api/v3/files/$hash"
        
        # Convert API key from SecureString to String
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
        $apiKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        
        # Build request headers
        $headers = @{}
        $headers.Add("accept", "application/json")
        $headers.Add("x-apikey", "$apiKey")
        
        # Submit the hash
        $response = Invoke-RestMethod -Uri $uri -Method GET -Headers $headers
        
        Write-Host ("Hash ${hash} successfully submitted to VirusTotal") -f White
    } catch {
        # When hash is unknown, VirusTotal API returns a 404 and exception occurs on Invoke-RestMethod 
        if (($_.Exception.Response.StatusCode.value__) -and ($_.Exception.Response.StatusCode.value__ -eq "404")) {
            Write-Host ("`nHash ${hash} is unknown to VirusTotal") -f Yellow
            return
        } else {
            Write-Host "VirusTotal request failed`n" -ForegroundColor Red -BackgroundColor Black
            Throw
        }
    }
    
    return $response
}

if ($hash) {
    
    # Clear report file if exists
    if (Test-Path -Path $reportFilePath) {Clear-Content -Force -Path $reportFilePath}
    
    # Disable later functions
    $hashes = $null
    $samplesPath = $null
    
    # Prompt user for VirusTotal API key
    $secureKey = Read-Host -AsSecureString -Prompt "VirusTotal API key"
    
    # Submit hash to VirusTotal
    Write-Host ("`nSubmitting hash to VirusTotal ...") -f Green
    $VTresult = submitHash($secureKey)
    
    # Parse JSON response
    $VTmalicious = [int]$VTresult.data.attributes.last_analysis_stats.malicious
    $VTundetected = [int]$VTresult.data.attributes.last_analysis_stats.undetected
    $VTtotal = ($VTmalicious) + ($VTundetected)
    
    $VTbaseURI = "https://www.virustotal.com/gui/file/ID/detection"
    
    # Print stylized output to console if enabled
    if (-Not $noConsole) {
        if ($VTmalicious -gt 0) {$fColor = "Red"}
        else {$fColor = "Gray"}
        
        Write-Host "`n" -NoNewline
        Write-Host "VT detection : " -NoNewline; Write-Host ([string]$VTmalicious + "/" + [string]$VTtotal) -f $fColor
        Write-Host "VT link      : " -NoNewline; Write-Host ($VTbaseURI.Replace('ID',$hash))
    }
    
    # Generate report
    $header = $headerPadding + " Report for " + $hash.ToUpper() + " " + $headerPadding
    echo $header >> $reportFilePath
    
    $report =  ("`nVT detection : " + [string]$VTmalicious + "/" + [string]$VTtotal)
    $report += ("`nVT link      : " + $VTbaseURI.Replace('ID',$hash))
    echo $report >> $reportFilePath
}

# Check if samples is enabled and that the provided path is valid and not empty
if ($samplesPath) {
    if (Test-Path -Path ${samplesPath}\*) {
        
        # Check if sigcheck path is valid
        if ((Test-Path -Path $sigcheck) -and ($sigcheck -like "*.exe")) {
            
            # Clear report file if exists
            if (Test-Path -Path $reportFilePath) {Clear-Content -Force -Path $reportFilePath}
            
            # Invoke sigcheck and generate report
            Write-Host ("Generating signatures for files under " + $samplesPath.Split("\")[-1] + " directory ...") -f Green
            GenerateHashes
        } else {
            Throw "Sysinternals sigcheck executable not found"
        }
    } else {
        Throw "You must provide a valid path to a directory that is not empty"
    }
}

Write-Host "`nDone! Results can be found in $reportFile under the Reports folder`n" -f Green
