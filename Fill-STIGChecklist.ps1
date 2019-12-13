<#
.SYNOPSIS
    Add data to STIGViewer Checklist.

.DESCRIPTION
    Import STIGViewer Checklist, populate comment/finding details field with comments, and current user signature with timestamp.

.Parameter ChecklistDirectory
    Location of .CKL files that need to be updated with comments and finding details.

.Parameter Files
    Retrieves all .CKL from the $ChecklistDirectory value. This will accept multiple .CKL files.
    
    Example: [String[]]$Files = $((Get-ChildItem -Path $ChecklistDirectory -Filter *.ckl).Fullname)
    Example: [String[]]$Files = "\\Server01\ORG\STIG_Checklists\Whatever.ckl"

.Parameter SaveDirectory
    Location to save output after checklist parsing is completed. Current default: User's My Documents directory.

.Parameter Signature
    Signature to place in comments section. Current default: Username

.EXAMPLE
    .\Fill-STIGChecklist.ps1 -Files "C:\Temp\Other\Checklists\Server2012.ckl", "C:\Temp\Other\Checklists\Server2016.ckl" -Signature "wb"
    Fill both .CKL files entered directly. Changed signature to "wb".

.EXAMPLE
    .\Fill-STIGChecklist.ps1 -SaveDirectory "$env:UserProfile\Desktop" -Signature "DMD"
    Fill all .CKL files in $ChecklistDirectory. Saves completed files to user's desktop. Changed signature to "DMD".

.EXAMPLE
    .\Fill-STIGChecklist.ps1 -ChecklistDirectory "\\Server01\Some\Directory\CKLs" -SaveDirectory "$env:UserProfile\Desktop" -Signature "BC"
    Fill all .CKL files in $ChecklistDirectory. Saves completed files to user's desktop. Changed signature to "BC".

.NOTES
    Author: JBear
    Date: 12/11/2019

    Modify default values within [Hashtable]$VData.
    Add specific vulnerability values to [Hashtable]$VData; use ONLY number for the name (i.e. 3080, 71582, etc.)
#>
[CmdletBinding(SupportsShouldProcess)]
param(

    #Directory where your checklists are located
    [Parameter(ValueFromPipeline=$True,HelpMessage="Enter directory to retrieve checklist(s) that need to be updated")]
    [String]$ChecklistDirectory = "C:\Temp\",

    #See below lines for examples
    [Parameter(Mandatory=$false,HelpMessage="Enter full path to .ckl file")]
    [ValidateScript({Test-Path -Path $_})]
    [String[]]$Files = $((Get-ChildItem -Path $ChecklistDirectory -Filter *.ckl).Fullname),

    #Directory to save updated checklist information; default value is $env:USERPROFILE\Documents which will be executing user's My Documents location
    [Parameter(ValueFromPipeline=$True,HelpMessage="Enter desired directory for updated checklist to be saved; Default is user's My Documents")]
    [String]$SaveDirectory = "$env:USERPROFILE\Documents",

    #Sign comment section; use $env:USERNAME or "JND" for initials
    [Parameter(ValueFromPipeline=$True,HelpMessage="Enter initials or desired signature")]
    [String]$Signature = $env:USERNAME
)

#Add specific vulnerability comments here - follow examples below
[HashTable]$VData = @{
    
    #Default values
    Default = @{

        #Set Default comments based on finding status
        NotAFinding = @{ 
        
            Details = "Not a finding - This check has been..."
            Comment = "Verified NAF"
        }

        Open = @{
        
            Details = "Verifiying open status result"
            Comment = "Verified Open"
        }

        Not_Applicable = @{
        
            Details = "Verified N/A result"
            Comment = "Verified Open"
        }

        Not_Reviewed = @{
        
            Details = "This check has not been reviewed"
            Comment = "Requires manual review"
        }
    }

    #Values for V-3080; when adding new items to the hashtable - ONLY use the number of the ID for the name as seen below (i.e. 3080, 41657, etc.)
    <#3080 = @{
        
        NotAFinding = @{ 
        
            Details = "Details specific to 3080 being NAF"
            Comment = "Comment specific to 3080 being NAF"
        }

        Open = @{
        
            Details = "ETP submitted and approved for open finding"
            Comment = "Comment specific to 3080 being open"
        }

        Not_Applicable = @{
        
            Details = "Details specific to 3080 being N/A"
            Comment = "Comment specific to 3080 being N/A"
        }

        Not_Reviewed = @{
        
            Details = "Details specific to 3080 being Not Reviewed"
            Comment = "Comment specific to 3080 being Not Reviewed"
        }    
    }#>
}

function Import-StigCKL {
<#
.SYNOPSIS
    Load a CKL file as an [XML] element.

.PARAMETER Path
    Full path to the CKL file
  
.EXAMPLE
    Import-StigCKL -Path "C:\CKLs\MyCKL.ckl"
#>
[CmdletBinding(SupportsShouldProcess)]
param()
    Try {

        #Checklist file data
        #$script: allows the variable to be utilized outside of the Import-StigCKL function and inside of the script; $global: would allow it to be used external to the script 
        [XML]$script:CKLData = (Get-Content -Path $File)
    }

    Catch {
    
        Write-Host -ForegroundColor Yellow "Unable to load $File Checklist Data"
        Break
    }
}

function Set-VulnFindingAttribute {
<#
.SYNOPSIS
    Sets a vuln's finding attribute (Status, Comments, Details, etc)

.DESCRIPTION
    Sets a stig's vulnerability attribute (Status, Comments, Details, etc), literally a direct child of VULN element of a stig item from the XML data of the CKL

.PARAMETER VulnID
    Vuln_Num of the vulnerability to Set

.PARAMETER RuleID
    Rule_ID of the vulnerability to Set

.PARAMETER Attribute
    The Attribute you wish to Set

.PARAMETER Value
    The new value for the Attribute
  
.EXAMPLE
    Set-VulnFindingAttribute -CKLData $CKLData -VulnID "V-1111" -Attribute "COMMENTS" -Value "This was checked by script"
#>
[CmdletBinding(SupportsShouldProcess)]
Param (

    $VulnID=$null,
    $RuleID=$null,
    [Parameter(Mandatory=$true)]
    [ValidateSet(
    
        "SEVERITY_JUSTIFICATION",
        "SEVERITY_OVERRIDE",
        "COMMENTS",
        "FINDING_DETAILS",
        "STATUS"
    )]
    $Attribute,
    [Parameter(Mandatory=$true)][string]$Value
)
    #Attribute to set
    $ToSet = $null
    if ($VulnID -ne $null) {

        #If we have vuln get attribute to set by it
        $ToSet = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE='Vuln_Num' and ATTRIBUTE_DATA='$VulnID']").Node.ParentNode
    }

    elseif ($RuleID -ne $null) {

        #If we have rule get attribute to set by it
        $ToSet = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE='Rule_ID' and ATTRIBUTE_DATA='$RuleID']").Node.ParentNode

        if ($ToSet -eq $null) {

            $ToSet = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE='Rule_Ver' and ATTRIBUTE_DATA='$RuleID']").Node.ParentNode
        }
    }

    #If we found the element to set
    if ($ToSet) {

        #Set it
        $ToSet.$Attribute = $Value
        return $true
    }

    else {

        #Otherwise error out
        Write-Error "Vuln $VulnID$RuleID not found!"
    }

    return $false
}

function Set-VulnData {
<#
.SYNOPSIS
    Sets the findings information for a single vuln

.DESCRIPTION
    This is one of the main tools in this module, this will set the result for a given vuln to what you specify

.PARAMETER VulnID
    Vuln_Num of the Vuln to Set

.PARAMETER RuleID
    Rule_ID of the Vuln to Set

.PARAMETER Details
    Finding details

.PARAMETER Comments
    Finding comments

.PARAMETER Result
    Final Result (Open, Not_Reviewed, or NotAFinding)
  
.EXAMPLE
    Set-VulnData -VulnID "V-11111" -Details "Not set correctly" -Comments "Checked by xyz" -Result Open
#>
[CmdletBinding(SupportsShouldProcess)]
Param (

    #Vulnerability ID or $RuleID required for XML search and information update
    $VulnID=$null,
    $RuleID=$null,

    #Finding details, if you wish to update them
    $Details=$null,
    $Comments=$null,

    [Parameter(Mandatory=$true)]
    [ValidateSet(
    
        “Open”,
        ”NotAFinding”,
        ”Not_Reviewed”, 
        “Not_Applicable”
    )]
    $Result
)

    #If we have what we need
    if ($VulnID -ne $null -or $RuleID -ne $null) {

        #Updates vulnerability STATUS
        if ($Result -ne $null) {

            $Res = Set-VulnFindingAttribute -VulnID $VulnID -RuleID $RuleID -Attribute “STATUS” -Value $Result

            if(-not $Res) {
    
                Write-Warning (“Failed to write: status of vuln “+$VulnID+” rule “+$RuleID)
            }
        }

        #Updates vulnerability FINDING_DETAILS
        if ($Details -ne $null) {

            if($Details -eq “”) {

                #Add whitespace to prevent blank String error
                $Details = ” ” 
            }

            $Res = Set-VulnFindingAttribute -VulnID $VulnID -RuleID $RuleID -Attribute “FINDING_DETAILS” -Value $Details

            if(-not $Res) {
    
                Write-Warning (“Failed to write: details of vuln “+$VulnID+” rule “+$RuleID)
            }
        }

        #Updates vulnerability COMMENTS
        if ($Comments -ne $null) {

            if($Comments -eq “”) {

                #Add whitespace to prevent blank String error
                $Comments = ” ” 
            }

            $Res = Set-VulnFindingAttribute -VulnID $VulnID -RuleID $RuleID -Attribute “COMMENTS” -Value $Comments

            if(-not $Res) {
    
                Write-Warning (“Failed to write: comments of vuln “+$VulnID+” rule “+$RuleID)
            }
        }
    }

    else {

        #Write error if we were not passed a vuln or rule
        Write-Error “VulnID or RuleID must be set!”
    }
}

function Export-StigCKL {
[CmdletBinding(SupportsShouldProcess)]
Param (

    [Parameter(Mandatory=$true)]
    [String]$ExportPath,

    #Adds Set-CKLHostData to Checklist
    [Switch]$AddHostData
)

    #Set XML Options to replicate those of the STIG Viewer application
    $XMLSettings = New-Object -TypeName System.XML.XMLWriterSettings
    $XMLSettings.Indent = $true;
    $XMLSettings.IndentChars = ” ”
    $XMLSettings.NewLineChars=”`n”

    $XMLWriter = [System.XML.XMLTextWriter]::Create($ExportPath, $XMLSettings)

    #Save the data
    $CKLData.Save($XMLWriter)
    $XMLWriter.Dispose()
}

#Loop through each checklist specified
foreach($File in $Files) {

    #Call functions
    Import-StigCKL

    Write-Host "`nImporting $File..."

    foreach($VID in $CKLData.Checklist.STIGS.iSTIG.VULN) {

        [Int]$idNum = $($VID.STIG_DATA.Attribute_Data[0].Replace("V-",''))
        
        #Check hashtable for specific Vulnerability ID
        if($VData[[Int]$idNum]) {
        
            [String]$VComment = "$($VData[$idNum][$VID.Status]['Comment']) - $Signature [$(Get-date)]"
            [String]$VDetails = $($VData[$idNum][$VID.Status]['Details'])
            #Set variables for whatever you need in -VulnID, -Result, and -Comments
            Set-VulnData -VulnID $($VID.STIG_DATA.Attribute_Data[0]) -Details $VDetails -Comments $VComment -Result $VID.Status
        }

        #Vulnerability ID doesn't exist in hashtable
        else {
    
            Write-Verbose "Using default comments - No specific comments available for $($VID.STIG_DATA.Attribute_Data[0])"

            [String]$VComment = "$($VData['Default'][$VID.Status]['Comment']) - $Signature [$(Get-date)]"
            [String]$VDetails = $($VData['Default'][$VID.Status]['Details'])
            #Set variables for whatever you need in -VulnID, -Result, and -Comments
            Set-VulnData -VulnID $($VID.STIG_DATA.Attribute_Data[0]) -Details $VDetails -Comments $VComment -Result $VID.Status
        }
    }

    #Do weird things to generate correct filepath to save
    $FileName = $File.Split("\")
    $FilePath = "$SaveDirectory\Updated-$($Filename[$($Filename.Count)-1])"

    #Export new XML data to a separate file; formats for STIG Viewer XML needs; use -AddHostData if you want to set the Hostname, IP, MAC, FQDN settings
    Export-StigCKL -ExportPath $FilePath -AddHostData

    Write-Host -ForegroundColor Green "Updated $File - Saved to $FilePath"
}
