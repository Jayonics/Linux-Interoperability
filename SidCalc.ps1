

<# Complex regex to split the SID into named capture groups. Additionally, the regex handles a primary group RID, i.e
if a fully qualified SID is provided, all capture groups are applied accordingly.
However, in the case of the ADAttribute: PrimaryGroupID. Only the RID/RelativeID is present.
The Regex effectively deals with this and disregards the other capture groups, only capturing the RID. #>

<# NOTE: While DomainSID is not currently used, it may provide future validation to avoiding collisions of ids
in Multi domain or forest scenarios. #>
function Split-SID {
	[CmdletBinding()]
	param (
		[Parameter(ValueFromPipeline)]
		[ValidateNotNullOrEmpty()]
		[String]$SID
	)
	# This regex splits the SID into Named capture groups. This is used in calculation and in validation.
	[String]$SID -match '^(?(?=^S-1)(?<PrefixLiteral>S-1)-(?<IdentifierAuthority>\d+)-(?<SubAuthority>\d+)-?(?<DomainSID>\d+-{1}\d+-{1}\d+)?-)(?<RelativeID>\d+$)$'
	[System.Collections.Hashtable]$SIDHashMap = $Matches
	return $SIDHashMap
}

function Get-RID {
	[CmdletBinding()]
	param (
		[Parameter(ValueFromPipeline = $true, Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.Collections.Hashtable]$SIDHashMap
	)
	# Assigns the Integer value of the RelativeID section of an SID string.
	[int]$RelativeID = $SIDHashMap.RelativeID
	[int]$PosixID = ($global:IDMapRange["low"] + $RelativeID)
	# Validates that the calculated ID is within the IDMapRange and not null or 0
	if ([int]$PosixID -ge [int]$($global:IDMapRange["high"]) -or ([int]$PosixID -eq 0) -or ([int]$PosixID -eq $null)) {
		Write-Error "Algorithmic PosixID exceedes maximum range limit for the IDMap range definition." | Out-Null
		Write-Error "Algorithmic PosixID exceedes maximum range limit for the IDMap range definition." | Out-Null
		Return $null
	}
	else {
		Return $PosixID
	}
}
