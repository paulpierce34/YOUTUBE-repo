# https://www.youtube.com/@STIG_Automation #

## How to automate STIG process for a localhost Windows machine

## This will allow you to execute powershell scripts on your machine, uncomment if you receive an error that mentions execution policy
#Set-ExecutionPolicy Bypass -Scope Localmachine

# Convert STIG checklist into XML object
[XML]$WindowsCKL = Get-Content -Path "C:\Users\admin\Documents\blankwindows1.ckl"

# Output path with filename
$FinalDestination = "C:\Users\admin\Documents\STIGoutput.ckl"

# All vulnerabilities in STIG checklist assigned to one variable
$Allvulns = $WindowsCKL.CHECKLIST.STIGS.iSTIG.VULN

## Begin foreach vulnerability loop
Foreach ($Vuln in $AllVulns){

## Define variables ##########################
$Status = $Vuln.Status
$Comments = $Vuln.Comments
$Finding_Details = $Vuln.FINDING_DETAILS
$Childnodes = $Vuln.Childnodes
$VulnNum = $Childnodes[0].ATTRIBUTE_DATA
#############################################

## Check if the STIG vulnerability matches '220872'
if ($VulnNum -match "V-220872"){

$DisableThirdParty = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent\" -Name DisableThirdPartySuggestions
$DisableThirdPartyValue = $DisableThirdParty.DisableThirdPartySuggestions

if ($DisableThirdPartyValue -match "1"){
$Vuln.Status = "NotAFinding"
$Vuln.FINDING_DETAILS = "This has been configured accordingly: $DisableThirdPartyValue"
$Vuln.Comments = "Checked by STIG script on x date"
} ## end if statement if the value matches 1
} ## end if vulnerability ID matches 220872
} ## end for loop 


$XMLWriter = [System.XML.XmlWriter]::Create($FinalDestination)  ## creates file at $Destination location with $XMLSettings -- (blank)
$WindowsCKL.Save($XMLWriter) ## Saves the extract document changes above to the xml writer object (which follows the validation scheme for STIG viewer)
$XMLWriter.Flush()
$XMLWriter.Dispose()
