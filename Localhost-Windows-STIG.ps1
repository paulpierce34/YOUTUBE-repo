## How to automate STIG process for a localhost Windows machine

#Set-ExecutionPolicy Bypass -Scope Localmachine

[XML]$WindowsCKL = Get-Content -Path "C:\Users\admin\Documents\blankwindows1.ckl"

$FinalDestination = "C:\Users\admin\Documents\STIGoutput.ckl"

$Allvulns = $WindowsCKL.CHECKLIST.STIGS.iSTIG.VULN

Foreach ($Vuln in $AllVulns){


$Status = $Vuln.Status
$Comments = $Vuln.Comments
$Finding_Details = $Vuln.FINDING_DETAILS


$Childnodes = $Vuln.Childnodes


$VulnNum = $Childnodes[0].ATTRIBUTE_DATA




if ($VulnNum -match "V-220872"){

#write-host $Status

$DisableThirdParty = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent\" -Name DisableThirdPartySuggestions

$DisableThirdPartyValue = $DisableThirdParty.DisableThirdPartySuggestions

if ($DisableThirdPartyValue -match "1"){
$Vuln.Status = "NotAFinding"
$Vuln.FINDING_DETAILS = "This has been configured accordingly: $DisableThirdPartyValue"
$Vuln.Comments = "Checked by STIG script on x date"

}

}

}




$XMLWriter = [System.XML.XmlWriter]::Create($FinalDestination)  ## creates file at $Destination location with $XMLSettings -- (blank)
$WindowsCKL.Save($XMLWriter) ## Saves the extract document changes above to the xml writer object (which follows the validation scheme for STIG viewer)
$XMLWriter.Flush()
$XMLWriter.Dispose()


