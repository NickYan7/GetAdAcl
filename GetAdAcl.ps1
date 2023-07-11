function Get-AdAcl {
    [CmdletBinding()]
    Param(
        
        [ValidatePattern('^((CN|OU)=.*)*(DC=.*)*$')]
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$DistinguishedName,

        [Parameter()]
        [switch]$SDDL
    )

    try {
        $AdsiResult = [ADSI]"LDAP://$DistinguishedName"
        $objectAcl = $AdsiResult.psbase.ObjectSecurity
        $objectName = [string]$AdsiResult.samaccountname

        if ($SDDL) {
            return $objectAcl.GetSecurityDescriptorSddlForm(
                [System.Security.AccessControl.AccessControlSections]::All
            )
        } else {
            $AclResult = $objectAcl.GetAccessRules(
                $true,
                $true,
                [System.Security.Principal.SecurityIdentifier]
            ) | Add-Member -MemberType NoteProperty -Name "samaccountname" -Value $objectName -PassThru

            return Convert-AdAcl -AclObjects $AclResult
        }
    }
    catch {
        Write-Error "Error when executing Get-AdAcl: $($error[0])"
    }
}

function Convert-AdAcl {
    [CmdletBinding()]
    Param(

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [psobject]$AclObjects

    )

    Begin {
        $AclResultObject = New-Object 'System.Collections.Generic.List[System.Object]'
    }

    process {
        foreach ($AclRule in $AclObjects) {
            try {
                if ("ExtendedRight" -eq $AclRule.ActiveDirectoryRights) {
                    $ObjectType = Convert-GuidToName -guid $AclRule.objecttype -extended
                } else {
                    $ObjectType = Convert-GuidToName -guid $AclRule.objecttype
                }

                $InheritedObjectType = Convert-GUIDToName -guid $AclRule.inheritedobjecttype
                $IdentityReference = ConvertTo-Name -sid $AclRule.identityReference

                $object = [PSCustomObject]@{
                    sAMaccountName        = $AclRule.samaccountname
                    ActiveDirectoryRights = $AclRule.ActiveDirectoryRights
                    InheritanceType       = $AclRule.InheritanceType
                    ObjectType            = $ObjectType
                    InheritedObjectType   = $inheritedobjecttype
                    ObjectFlags           = $AclRule.ObjectFlags
                    AccessControlType     = $AclRule.accesscontroltype
                    IdentityReference     = $IdentityReference
                    Isinherited           = $AclRule.isinherited
                    InheritanceFlags      = $AclRule.InheritanceFlags
                    PropagationFlags      = $AclRule.PropagationFlags
                }
                $AclResultObject.Add($object)
            }
            catch {
                Write-Error "Error when handling object: $($AclRule.ActiveDirectoryRights)"
            }
        }
    }

    end {
        return $AclResultObject
    }
}

function ConvertTo-Name {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$sid
    )
    try {
        $AdObject = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $ObjectResult = $AdObject.Translate( [System.Security.Principal.NTAccount])
        return [string]$ObjectResult.Value
    }
    catch {
        switch ($sid) {
            #Reference http://support.microsoft.com/kb/243330
            "S-1-0"         { "Null Authority" }
            "S-1-0-0"       { "Nobody" }
            "S-1-1"         { "World Authority" }
            "S-1-1-0"       { "Everyone" }
            "S-1-2"         { "Local Authority" }
            "S-1-2-0"       { "Local" }
            "S-1-2-1"       { "Console Logon" }
            "S-1-3"         { "Creator Authority" }
            "S-1-3-0"       { "Creator Owner" }
            "S-1-3-1"       { "Creator Group" }
            "S-1-3-4"       { "Owner Rights" }
            "S-1-5-80-0"    { "All Services" }
            "S-1-4"         { "Non Unique Authority" }
            "S-1-5"         { "NT Authority" }
            "S-1-5-1"       { "Dialup" }
            "S-1-5-2"       { "Network" }
            "S-1-5-3"       { "Batch" }
            "S-1-5-6"       { "Service" }
            "S-1-5-4"       { "Interactive" }
            "S-1-5-7"       { "Anonymous" }
            "S-1-5-9"       { "Enterprise Domain Controllers"}
            "S-1-5-10"      { "Self" }
            "S-1-5-11"      { "Authenticated Users" }
            "S-1-5-12"      { "Restricted Code" }
            "S-1-5-13"      { "Terminal Server Users" }
            "S-1-5-14"      { "Remote Interactive Logon" }
            "S-1-5-15"      { "This Organization" }
            "S-1-5-17"      { "This Organization" }
            "S-1-5-18"      { "Local System" }
            "S-1-5-19"      { "NT Authority Local Service" }
            "S-1-5-20"      { "NT Authority Network Service" }
            "S-1-5-32-544"  { "Administrators" }
            "S-1-5-32-545"  { "Users"}
            "S-1-5-32-546"  { "Guests" }
            "S-1-5-32-547"  { "Power Users" }
            "S-1-5-32-548"  { "Account Operators" }
            "S-1-5-32-549"  { "Server Operators" }
            "S-1-5-32-550"  { "Print Operators" }
            "S-1-5-32-551"  { "Backup Operators" }
            "S-1-5-32-552"  { "Replicators" }
            "S-1-5-32-554"  { "Pre-Windows 2000 Compatibility Access"}
            "S-1-5-32-555"  { "Remote Desktop Users"}
            "S-1-5-32-556"  { "Network Configuration Operators"}
            "S-1-5-32-557"  { "Incoming forest trust builders"}
            "S-1-5-32-558"  { "Performance Monitor Users"}
            "S-1-5-32-559"  { "Performance Log Users" }
            "S-1-5-32-560"  { "Windows Authorization Access Group"}
            "S-1-5-32-561"  { "Terminal Server License Servers"}
            "S-1-5-32-561"  { "Distributed COM Users"}
            "S-1-5-32-569"  { "Cryptographic Operators" }
            "S-1-5-32-573"  { "Event Log Readers" }
            "S-1-5-32-574"  { "Certificate Services DCOM Access" }
            "S-1-5-32-575"  { "RDS Remote Access Servers" }
            "S-1-5-32-576"  { "RDS Endpoint Servers" }
            "S-1-5-32-577"  { "RDS Management Servers" }
            "S-1-5-32-575"  { "Hyper-V Administrators" }
            "S-1-5-32-579"  { "Access Control Assistance Operators" }
            "S-1-5-32-580"  { "Remote Management Users" }
            
            Default         {$sid}
        }
    }
}

function Convert-GuidToName {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$guid,

        [switch]$extended
    )

    if ("00000000-0000-0000-0000-000000000000" -eq $guid) {
        return "AllObject"
    } else {
        $GuidVal = [Guid]$guid
        $ByteArr = $GuidVal.ToByteArray()
        $ByteStr = ""

        foreach ($byte in $ByteArr) {
            $str = "\" + "{0:x}" -f $byte
            $ByteStr += $str
        }
    }
    
    try {
        if ($extended) {
            $de = new-object directoryservices.directoryentry(
                "LDAP://" + ([adsi]"LDAP://rootdse").psbase.properties.configurationnamingcontext
            )
            $ds = new-object directoryservices.directorysearcher($de)
            
            $ds.propertiestoload.add("displayname") | Out-Null
            $ds.filter = "(rightsguid=$guid)"
            $result = $ds.findone()
    
        } else {
            $de = new-object directoryservices.directoryentry(
                "LDAP://" + ([adsi]"LDAP://rootdse").psbase.properties.schemanamingcontext
            )
            $ds = new-object directoryservices.directorysearcher($de)
            $ds.filter = "(|(schemaidguid=$bytestr)(attributesecurityguid=$bytestr))"
            $ds.propertiestoload.add("ldapdisplayname") | Out-Null
            $result = $ds.findone()
        }
    }
    catch {
        Write-Error "Error when search AD: $($Error[0])"
    }

    if ($null -eq $result) {
        return $guid
    } else {
        if ($extended) {
            return $result.Properties.displayname
        } else {
            return $result.Properties.ldapdisplayname
        }
    }
}
