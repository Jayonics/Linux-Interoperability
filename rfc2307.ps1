using namespace Microsoft.ActiveDirectory.Management

Remove-Item "$PSScriptRoot\UserMapping" -Force -Verbose

<# IMPORTANT: THIS IS THE CURRENTLY IMPLEMENTED 'QUICK-FIX' METHOD FOR IDMAPPING.
The 'IDMapRange.json' file, 'IDMapRange' class, and 'Import-IDMapRange' function are not currently implemented.
This method of IDMapping supports a single domain environment.
I highly doubt it will work in a multi domain environment without unforseen consequences. #>
$Global:IDMapRange = @{
	"domain" = "RADUX";
	"low"  = 2000000;
	"high" = 2999999;
}

<# This class represents an IDMapRange and is dynamically instantiated based on the IDMapRange json content.
It's instances are stored inside a Hash Table called $IDMapRanges with the NETBIOS NT domain name being the key
and the IDMapRange class instance being the value.
#>
class IDMapRange {
	[ValidateNotNullOrEmpty()]
	[String]$domain
	[ValidateNotNullOrEmpty()]
	[Int32]$low
	[ValidateNotNullOrEmpty()]
	[Int32]$high
	IDMapRange (
		[String]$domain,
		[Int32]$low,
		[Int32]$high
	) {
		# Validate that the low end is less than the high end.
		if ($low -ge $high) {
			Write-Error "Your IDMapRange is invalid. The `$low: $low must be below the `$high: $high." | Out-Null
			Throw
		}
		# Validate that the domain is not null.
		if ($null -eq $domain) {
			Write-Error "Your specified domain is null. You must specify the appropriate NETBIOS Domain for the range." | Out-Null
			Throw
		} # Warn that BUILTIN is the incorrect syntax to use in the smb.conf idmap range for BUILTIN users.
		elseif ($domain -eq "BUILTIN") {
			Write-Warning "The domain '*' represents BUILTIN in smb.conf, you should use * as the correct syntax in the idmaprange json." | Out-Null
		}

		$this.domain = $domain
		$this.low = $low
		$this.high = $high
	}
}

class UnixAttributes {
	<# This attribute is ignored for now. Despite SambaDocs listing it as an ADUC Unix attribute, it seems to not affect functionality in any way.
	[string] $msSFU30NisDomain #>
	$Object
	UnixAttributes($Object) {
		$HashArgs = @{
			Identity  = $Object.SamAccountName;
			Properties = "uid","uidNumber","gidNumber","primaryGroupID","unixHomeDirectory","loginShell","msSFU30NisDomain","*"
		}
		Switch ($Object.GetType()) {
			([Microsoft.ActiveDirectory.Management.ADUser]) {
				$this.Object = Get-ADUser @HashArgs
			}
			([Microsoft.ActiveDirectory.Management.ADComputer]) {
				$this.Object = Get-ADComputer @HashArgs
			}
			([Microsoft.ActiveDirectory.Management.ADGroup]) {
				$this.Object = Get-ADGroup @HashArgs
			}
			default {
				Write-Error "Invalid object type passed." | Out-Null
				Throw
			}
		}
	}
	[int] ConvertSID ($SID) {
		<# Complex regex to split the SID into named capture groups. Additionally, the regex handles a primary group RID, i.e
		if a fully qualified SID is provided, all capture groups are applied accordingly.
		However, in the case of the ADAttribute: PrimaryGroupID. Only the RID/RelativeID is present.
		The Regex effectively deals with this and disregards the other capture groups, only capturing the RID. #>

		<# NOTE: While DomainSID is not currently used, it may provide future validation to avoiding collisions of ids
		in multi domain, multi forest, and or trust scenarios. #>
		$SID -match '^(?(?=^S-1)(?<PrefixLiteral>S-1)-(?<IdentifierAuthority>\d+)-(?<SubAuthority>\d+)-?(?<DomainSID>\d+-{1}\d+-{1}\d+)?-)(?<RelativeID>\d+$)$'
		$SIDHashMap = $Matches
		# Assigns the Integer value of the RelativeID section of an SID string.
		[int]$RelativeID = $SIDHashMap.RelativeID
		[int]$PosixID = ($global:IDMapRange["low"] + $RelativeID)
		# Validates that the calculated ID is within the IDMapRange and not null or 0
		if ([int]$PosixID -ge [int]$($global:IDMapRange["high"]) -or ([int]$PosixID -eq 0) -or ([int]$PosixID -eq $null)) {
			Write-Error "Algorithmic PosixID exceedes maximum range limit for Winbind Domain definition." | Out-Null
			Return $null
		}
		else {
			Return $PosixID
		}
	}
	[string] GetGroupFromLDAP($Query) {
		$Query -match '(?>^CN=)(?<Group>[^,]+)'
		$Group = $Matches.Group
		$Group = Get-ADGroup -Properties * -Identity $Group
		[string]$Group = $Group.SID
		Return $Group
	}

	# Usefull if you want to see the currently generated attributes.
	[void] GetGeneratedUnixProperties(){
	$this | Format-Table -AutoSize
	}

	# This commits the attributes to Active Directory.
	[void] CommitAttributes() {
		# This section extracts the UNIX attributes from the current class instance and maps them into the true .NET ADObject
		$UnixAttributes = $($this | Select-Object -Property * -ExcludeProperty "Object" )
		$UnixAttributes | Get-Member -MemberType *Property | % {
			$this.Object.($_.Name) = "$($this.($_.Name))";
		}

		Switch ($this.Object.GetType()) {
			([Microsoft.ActiveDirectory.Management.ADUser]) {
				Set-ADUser -Instance $this.Object -Verbose
			}
			([Microsoft.ActiveDirectory.Management.ADComputer]) {
				Set-ADComputer -Instance $this.Object -Verbose
			}
			([Microsoft.ActiveDirectory.Management.ADGroup]) {
				Set-ADGroup -Instance $this.Object -Verbose
			}
			default {
				Write-Error "Invalid object type passed." | Out-Null
				Throw
			}
		}
	}
}
class User:UnixAttributes {
	[string] $uid
	[int] $uidNumber
	<# This was causing an unknown bug in the Commiting of attributes, but it seems likely it should not be needed as Primary Groups are automatically assigned when a user is added to one in ADUC.
	[int] $primaryGroupID
	#>
	[string] $unixHomeDirectory
	[string] $loginShell = "/bin/bash"
	User($Object) : base($Object) {
		$this.uid = $($Object.samAccountName)
		$this.uidNumber = $($this.ConvertSID($Object.SID))
		$this.unixHomeDirectory = "/home/$($Object.samAccountName)@$($global:IDmapRange["domain"])"
		$this.CommitAttributes()
	}
}
class Computer:UnixAttributes {
	[string] $uid
	[int] $uidNumber
		<# This was causing an unknown bug in the Commiting of attributes, but it seems likely it should not be needed as Primary Groups are automatically assigned when a user is added to one in ADUC.
	[int] $primaryGroupID
	#>
	Computer($Object) : base ($Object) {
		$this.uid = $($Object.samAccountName)
		$this.uidNumber = $($this.ConvertSID($Object.SID))
		$this.GetGeneratedUnixProperties()
		$this.CommitAttributes()
	}
}
class Group:UnixAttributes {
	[int] $gidNumber
	Group($Object) : base ($Object) {
		$this.gidNumber = $($this.ConvertSID($Object.SID))
		$this.GetGeneratedUnixProperties()
		$this.CommitAttributes()
	}
}

Enum ObjectType {
	User = 0
	Computer = 1
	Group = 2
}

<# Imports the IDMapRange from a JSON file or JSON content and a creates a hashmap named $IDMapRanges.
The $IDMapRanges hashmap contains the different domains specified in the IDMapRange JSON content.
1. The key is named with the idmaprange domain.
2, The value is an instance of the IDMapRange class containing all the information relevant to an IDMap. #>
function Import-IDMapRange {
	[CmdletBinding()]
	param (
		[Parameter(ValueFromPipeline = $true)]
		# Default to IDMapRange.json in the PSScriptRoot if undefined.
		$File = $(Get-Item -Path "$PSScriptRoot\IDMapRange.json")
	)
	BEGIN {
		<# The switch handles multiple different input formats for the IDMapRange JSON. The function can accept a:
		'Get-Item' (FileInfo) object, retreive the content and parse it's JSON.
		'Get-Content' (File) object, and parse it's JSON.
		and a 'ConvertFrom-Json' pre-parsed automatic object.
		#>
		Switch ($File.GetType()) {
			# FileInfo class is retreived from a 'Get-Item' command, its content is not yet retreived nor interpreted as JSON.
			([System.IO.FileInfo]) {
				$File = $File | Get-Content -ErrorAction:Stop | ConvertFrom-Json -ErrorAction:Stop
			}
			# File class is retreived from a valid 'Get-Content' command, its content is not yet interpreted as JSON.
			([System.IO.File]) {
				$File = $File | ConvertFrom-Json -ErrorAction:Stop
			}
			#([*]){
			#	Write-Error "Invalid object class passed to function, valid object types are 'FileInfo', 'File' and a 'JSON parsed automatic object.'" | Out-Null
			#	Throw
			#}
		}
		$JSON = $File
	}
	PROCESS {
		# Creates a Hashtable collection of all domains specified in the IDMapRange.json
		[System.Collections.Hashtable]$IDMapRanges = @{}
		Foreach ($Range in $JSON) {
			# Ensures that the idmap domain name conforms to the NETBIOS domain naming standard (All Uppercase).
			if ($Range.domain -cmatch "[a-z]") {
				Write-Warning "NT Domain names should be all uppercase to confrom to the NETBIOS naming standard. " | Out-Null
				Write-Warning "The offending domain: $($Range.Domain)" | Out-Null
				$Range.Domain = $Range.Domain.ToUpper()
			}
			# Instantiates one or many IDMapRange classes with parameters determined from the parsed JSON.
			$IDMapRanges += @{ $Range.domain = [IDMapRange]::new($Range.domain, $Range.low, $Range.high) }
			$Range | Format-List
		}
}

	END {
		return [System.Collections.Hashtable]$IDMapRanges
	}
}

<# A Function for bulk processing all Active Directory Users, Groups, and or Computers #>
function Process-ADObjects {
	param (
		[CmdletBInding()]
		[Parameter()]
		[ObjectType]$ObjectType
	)
	$HashArgs = @{
		Filter     = "*";
		Properties = "*";
	}
	switch ($ObjectType) {
		([ObjectType]::Computer) {
			$Objects = Get-ADComputer @HashArgs
		}
		([ObjectType]::User) {
			$Objects = Get-ADUser @HashArgs
		}
		([ObjectType]::Group) {
			$Objects = Get-ADGroup @HashArgs
		}
	}
	ForEach ($Object in $Objects) {
		Switch ($Object.GetType()) {
			([Microsoft.ActiveDirectory.Management.ADUser]) {
				$UnixObject = [User]::new($Object)
			}
			([Microsoft.ActiveDirectory.Management.ADComputer]) {
				$UnixObject = [Computer]::new($Object)
			}
			([Microsoft.ActiveDirectory.Management.ADGroup]) {
				$UnixObject = [Group]::new($Object)
			}
		}
		[array] $UnixClassObjects += $UnixObject
	}
	return $UnixClassObjects
}

<# Creates an ntfs-3g compliant UserMapping file that maps SIDs to Linux UIDs and GIDs.
Additionally, a comment is added above the mapping with the NETBIOS domain & sAMAccountName

This file allows for complete interroporability between Linux and Windows users with a Windows NTFS drive mounted inside Linux.
Normally you would map your local Windows users & groups SIDs to their equivilent local Linux UIDs and GIDs
however because we are authenticating to the domain and using the same credentials on both operating systems, this allows completely mirrored
access/permissions from the perspective of a user that signs in with a domain account when accessing an NTFS filesystem from either Windows or Linux
#>
function New-UserMapping {
    param (
        [UnixAttributes]$UnixAttributes
    )
	Switch ($UnixAttributes.Object.GetType()) {
		([Microsoft.ActiveDirectory.Management.ADUser]) {
			$Mapping = "$($UnixAttributes.Object.uidNumber):$($UnixAttributes.ConvertSID($UnixAttributes.Object.primaryGroupID)):$($UnixAttributes.Object.SID)"
		}
		([Microsoft.ActiveDirectory.Management.ADComputer]) {
			$Mapping = "$($UnixAttributes.Object.uidNumber):$($UnixAttributes.ConvertSID($UnixAttributes.Object.primaryGroupID)):$($UnixAttributes.Object.SID)"
		}
		([Microsoft.ActiveDirectory.Management.ADGroup]) {
			$Mapping = ":$($UnixAttributes.Object.gidNumber):$($UnixAttributes.Object.SID)"
		}
		default {
			Write-Error "Invalid object type passed." | Out-Null
			Throw
		}
	}
	$Comment = "# $($Global:IDMapRange["domain"])\$($UnixAttributes.Object.sAMAccountName)"

	# Begin outputting usermap to file
	$Comment | Out-File -FilePath "$PSScriptRoot\UserMapping" -Append -Force
	$Mapping | Out-File -FilePath "$PSScriptRoot\UserMapping" -Append -Force
}


<# You may optionally process all Active Directory Users, Computers, and groups and generate the attributes.
Or you can choose to process them individually by using a Get-AD*, Assigning it to a variable, and instantiating the UnixAttributes class with it.
The UnixAttributes class checks whether it is a User, Computer, or group, so no extra work is required.
If an invalid object is provided, the instantiated UnixAttributes class will be null.

Once you are ready to commit the unixAttributes to active directory. Run $TheObjectName.CommitAttributes
#>

# Template for assigning unixAttributes to all ADUC objects.
$Users = Process-ADObjects -ObjectType User
$Computers = Process-ADObjects -ObjectType Computer
$Groups = Process-ADObjects -ObjectType Group

# Template for creating a userMapping file for all unixAttributed ADUC Objects.
$Users,$Computers,$Groups | % {
	New-UserMapping -UnixAttributes $_
}
