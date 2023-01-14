# https://www.youtube.com/@STIG_Automation #
## Get all open items from a directory of STIG checklists and output to gridview

## Grab all CKL files from directory
$Allitems = Get-Childitem -Path "C:\Users\admin\Documents\*" -Include *.ckl

## THIS LOOKS FOR WHATEVER STATUS YOU PROVIDE
$VulnStatus = "Not_Reviewed" ## Valid options: NotAFinding, Open, Not_reviewed

## Empty object for later use when we build pretty output
$AllObjects = @()

## Final output path and filename
$Outputpath = "C:\Users\admin\Documents\testvideo1.csv"

## Foreach different checklist in the directory we are looking in
Foreach ($CKL in $Allitems){

## Convert single checklist to XML Object
[XML]$SingleCKL = Get-Content $CKL

## Assign every vulnerability in single STIG checklist to an array variable
$Eachvuln = $SingleCKL.CHECKLIST.STIGS.iSTIG.VULN

## Lets start a foor loop so we can grab info from each individual STIG vuln
Foreach ($SingleVuln in $Eachvuln){

## If this STIG vuln matches the status we're looking for
if ($SingleVuln.Status -match $VulnStatus){

## If the status of the STIG vuln matches the status we're looking for, let's save this to a new variable
$StatusVuln = $SingleVuln

## Some properties saved to variables for future output
$Status = $StatusVuln.Status
$Comments = $StatusVuln.Comments
$FindingDetails = $StatusVuln.FINDING_DETAILS
$Childnodes = $StatusVuln.Childnodes
$Vuln_Num = $Childnodes[0].ATTRIBUTE_DATA
$Severity = $Childnodes[1].ATTRIBUTE_DATA
$RuleTitle = $Childnodes[5].ATTRIBUTE_DATA

## Building a new PSObject in our empty object we defined above called AllObjects
$AllObjects += New-Object PSObject -Property @{

## Properties of the object
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


## Outputs to gridview. Change from Out-Gridview to "Export-CSV Outputpath" if you want to output to a csv file
$Allobjects | Select-Object Vuln_Num, Status, Severity, Rule_Title, Finding_Details, Comments | Sort-Object Vuln_Num, Status, Severity, Rule_Title, Finding_Details, Comments | Out-Gridview

## Extra logic if you wanted to re-assure the user the file has been created, and provide them with the path
if (Test-Path $Outputpath){
write-host -Foregroundcolor Green "Successfully created output file here: $Outputpath"
}
