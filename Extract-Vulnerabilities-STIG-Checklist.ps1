## Get all open items from a directory of STIG checklists and output to .csv file

$Allitems = Get-Childitem -Path "C:\Users\admin\Documents\*" -Include *.ckl

$VulnStatus = "Not_Reviewed" ## Valid options: NotAFinding, Open, Not_reviewed

$AllObjects = @()

Foreach ($CKL in $Allitems){

[XML]$SingleCKL = Get-Content $CKL

$Eachvuln = $SingleCKL.CHECKLIST.STIGS.iSTIG.VULN

Foreach ($SingleVuln in $Eachvuln){

if ($SingleVuln.Status -match $VulnStatus){

## Saves a matching status item, in this case open since that's what we're looking for, to another variable
$StatusVuln = $SingleVuln

## Some properties saved to variables for future output
$Status = $StatusVuln.Status
$Comments = $StatusVuln.Comments
$FindingDetails = $StatusVuln.FINDING_DETAILS


$Childnodes = $StatusVuln.Childnodes

$Vuln_Num = $Childnodes[0].ATTRIBUTE_DATA
$Severity = $Childnodes[1].ATTRIBUTE_DATA
$RuleTitle = $Childnodes[5].ATTRIBUTE_DATA



$AllObjects += New-Object PSObject -Property @{

Status = $Status;
Comments = $Comments;
Finding_Details = $FindingDetails;
Vuln_Num = $Vuln_Num;
Severity = $Severity;
Rule_Title = $RuleTitle;


}


} ## end of if statement




} ## end of nested for loop






} ## end of foreach checklist for loop


$Allobjects | Select-Object Vuln_Num, Status, Severity, Rule_Title, Finding_Details, Comments | Sort-Object Vuln_Num, Status, Severity, Rule_Title, Finding_Details, Comments | Out-Gridview


if (Test-Path "C:\Users\admin\Documents\testvideo1.csv"){

write-host -Foregroundcolor Green "Successfully created output file here: 'C:\Users\admin\Documents\testvideo.csv'"


}