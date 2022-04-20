Function Update-User {
    [CmdletBinding(
            ConfirmImpact="None",
            DefaultParameterSetName="Site",
            HelpURI="",
            SupportsPaging=$False,
            SupportsShouldProcess=$False,
            PositionalBinding=$True
        )] Param (
        [Alias('UserName','Logon')]
        [ValidateNotNull()]
        [String]$sAMAccountName,
        [ValidateNotNull()]
        [string]$WorkgroupDomain,
        [ValidateNotNull()]
        [String]$Name,
        [ValidateNotNull()]
        [String]$Description,
        [ValidateNotNull()]
        [String]$FullName,
        [ValidateNotNull()]
        [String]$SetPassword,
        [Switch]$GeneratePassword,
        [bool]$PasswordExpired,
        [Switch]$CreateIfNot,
        [Parameter(Mandatory=$False)]
        [ValidateSet(1,2,8,16,32,64,128,256,512,2048,4096,8192,65536,131072,
        262144,524288,1048576,2097152,4194304,8388608,16777216,67108864)]
        [Array]$RemoveFlags,
        [Parameter(Mandatory=$False)]
        [ValidateSet(1,2,8,16,32,64,128,256,512,2048,4096,8192,65536,131072,
        262144,524288,1048576,2097152,4194304,8388608,16777216,67108864)]
        [Array]$AddFlags,
        [ValidateNotNull()]
        [Int]$SetFlag = 0,
        [string[]]$AddGroups,
        [string[]]$RemoveGroups
    )

    @{
        1, 2, 8, 16, 32, 64, 128, 256, 512, 2048, 4096, 8192, 65536, 131072,262144, 524288, 1048576, 2097152, 4194304, 8388608, 16777216, 67108864
    }
    <#
        |───────────────────────────────────────────────────────────────────────────────┐
        | Property flag						| Value in hexadecimal  | Value in decimal  |
        ├───────────────────────────────────┼───────────────────────┼───────────────────┤
        | SCRIPT							| 0x0001				| 1					|
        | ACCOUNTDISABLE					| 0x0002				| 2					|
        | HOMEDIR_REQUIRED					| 0x0008				| 8					|
        | LOCKOUT							| 0x0010				| 16				|
        | PASSWD_NOTREQD					| 0x0020				| 32				|
        | PASSWD_CANT_CHANGE				| 0x0040				| 64				|
        | ENCRYPTED_TEXT_PWD_ALLOWED		| 0x0080				| 128				|
        | TEMP_DUPLICATE_ACCOUNT			| 0x0100				| 256				|
        | NORMAL_ACCOUNT					| 0x0200				| 512				|
        | INTERDOMAIN_TRUST_ACCOUNT			| 0x0800				| 2048				|
        | WORKSTATION_TRUST_ACCOUNT			| 0x1000				| 4096				|
        | SERVER_TRUST_ACCOUNT				| 0x2000				| 8192				|
        | DONT_EXPIRE_PASSWORD				| 0x10000				| 65536				|
        | MNS_LOGON_ACCOUNT					| 0x20000				| 131072			|
        | SMARTCARD_REQUIRED				| 0x40000				| 262144			|
        | TRUSTED_FOR_DELEGATION			| 0x80000				| 524288			|
        | NOT_DELEGATED						| 0x100000				| 1048576			|
        | USE_DES_KEY_ONLY					| 0x200000				| 2097152			|
        | DONT_REQ_PREAUTH					| 0x400000				| 4194304			|
        | PASSWORD_EXPIRED					| 0x800000				| 8388608			|
        | TRUSTED_TO_AUTH_FOR_DELEGATION	| 0x1000000				| 16777216			|
        | PARTIAL_SECRETS_ACCOUNT			| 0x04000000			| 67108864			|
        └───────────────────────────────────────────────────────────────────────────────┘
    #>

    Function New-Password {
        PARAM(
            [Int]$PasswordLength            = 64,
            [Int]$MinUpperCase              = 5,
            [Int]$MinLowerCase              = 5,
            [Int]$MinSpecialCharacters      = 5,
            [Int]$MinNumbers                = 5,
            [Int]$ConsecutiveCharClass      = 0,
            [Int]$ConsecutiveCharCheckCount = 1000,
            [String]$LowerCase              = 'abcdefghiklmnoprstuvwxyz',
            [String]$UpperCase              = 'ABCDEFGHKLMNOPRSTUVWXYZ',
            [String]$Numbers                = '1234567890',
            [String]$SpecialCharacters      = '!"$%&/()=?}][{@#*+',
            [String]$PasswordProfile        = '',

            #Advanced Options
            [Bool]$EnhancedEntrophy = $True
        )

        If ([String]::IsNullOrEmpty($PasswordProfile) -eq $False) {
            #You can define custom password profiles here for easy reference later on.
            New-Variable -Force -Name:'PasswordProfiles' -Value:@{
                'iDrac' = [PSCustomObject]@{PasswordLength=20;SpecialCharacters="+&?>-}|.!(',_[`"@#)*;$]/§%=<:{@";}
            }

            If ($PasswordProfile -in $PasswordProfiles.Keys) {
                $PasswordProfiles[$PasswordProfile] |Get-Member -MemberType NoteProperty |ForEach-Object {
                    Set-Variable -Name $_.name -Value $PasswordProfiles[$PasswordProfile].($_.name)
                }
            }
        }

        New-Variable -Force -Name:'PassBldr' -Value @{}
        New-Variable -Force -Name:'CharacterClass' -Value:([String]::Empty)
        ForEach ($CharacterClass in @("UpperCase","LowerCase","SpecialCharacters","Numbers")) {
            $Characters = (Get-Variable -Name:$CharacterClass -ValueOnly)
            If ($Characters.Length -gt 0) {
                $PassBldr[$CharacterClass] = [PSCustomObject]@{
                    Min        = (Get-Variable -Name:"min$CharacterClass" -ValueOnly);
                    Characters = $Characters
                    Length     = $Characters.length
                }
            }
        }

        #Sanity Check(s)
        $MinimumChars = $MinUpperCase + $MinLowerCase + $MinSpecialCharacters + $MinNumbers
        If ($MinimumChars -gt $PasswordLength) {
            Write-Error -Message:"Specified number of minimum characters ($MinimumChars) is greater than password length ($PasswordLength)."
            Return
        }

        #New-Variable -Force -Name:'Random' -Value:(New-Object -TypeName:'System.Random')
        New-Variable -Force -Name:'Randomizer' -Value:$Null
        New-Variable -Force -Name:'Random' -Value:([ScriptBlock]::Create({
            Param([Int]$Max=[Int32]::MaxValue,[Int32]$Min=1)
            if ($Min -gt $Max) {
                Write-Warning  "[$($myinvocation.ScriptLineNumber)] Min ($Min) must be less than Max ($Max)."
                return -1
            }

            if ($EnhancedEntrophy) {
                if ($Null -eq $Randomizer) {
                    Set-Variable -Name:'Randomizer' -Value:(New-Object -TypeName:'System.Security.Cryptography.RNGCryptoServiceProvider') -Scope:1
                }
                #initialize everything
                $Difference=$Max-$Min
                [Byte[]] $bytes = 1..4  #4 byte array for int32/uint32

                #generate the number
                $Randomizer.getbytes($bytes)
                $Number = [System.BitConverter]::ToUInt32(($bytes),0)
                return ([Int32]($Number % $Difference + $Min))

            } Else {
                if ($Null -eq $Randomizer) {
                    Set-Variable -Name:'Randomizer' -Value:(New-Object -TypeName:'System.Random') -Scope:1
                }
                return ([Int]$Randomizer.Next($Min,$Max))
            }
        }))

        $GetString = [ScriptBlock]::Create({
            Param([Int]$Length,[String]$Characters)
            Return ([String]$Characters[(1..$Length |ForEach-Object {& $Random $Characters.length})] -replace " ","")
        })

        $CreatePassword = [scriptblock]::Create({
            New-Variable -Name Password -Value ([System.Text.StringBuilder]::new()) -Force

            #Meet the minimum requirements for each character class
            ForEach ($CharacterClass in $PassBldr.Values) {
                If ($CharacterClass.Min -gt 0) {
                    $Null = $Password.Append([string](Invoke-Command $GetString -ArgumentList $CharacterClass.Min,$CharacterClass.Characters))
                }
            }

            #Now meet the minimum length requirements.
            If ([Int]($PasswordLength-$Password.length) -gt 0) {
                $Null = $Password.Append((Invoke-Command $GetString -ArgumentList ($PasswordLength-$Password.length),($PassBldr.Values.Characters -join "")))
            }

            return (([Char[]]$Password.ToString() | Get-Random -Count $Password.Length) -join "")
        })

        Switch ([Int]$ConsecutiveCharClass) {
            '0' { New-Variable -Name NewPassword -Value (& $CreatePassword) -Force }
            {$_ -gt 0} {
                New-Variable -Name CheckPass    -Value $False -Force
                New-Variable -Name CheckCount   -Value ([Int]0) -Force
                For ($I=0; $I -le $ConsecutiveCharCheckCount -and $CheckPass -eq $False; $I++) {
                    New-Variable -Name NewPassword -Value (& $CreatePassword) -Force
                    $TestPassed = 0
                    ForEach ($CharClass in $PassBldr.Values) {
                        IF ([Regex]::IsMatch([Regex]::Escape($NewPassword),"[$([Regex]::Escape($CharClass.Characters))]{$ConsecutiveCharClass}") -eq $False) {
                            $TestPassed++
                        }
                    }
                    if ($TestPassed -eq $CheckClasses.Count) {
                        $CheckPass = $True
                    }
                }
            }
            Default {Write-Warning -Message "This shouldn't be possible, how did you get here?!"}
        }

        Return $NewPassword
    }

    # Write pretty and more useful errors.
    Trap {
        $host.UI.WriteErrorLine("Failed to execute command: '$(($_.InvocationInfo.line -replace '\r*\n','').trim())'")
        $host.UI.WriteErrorLine("$($_.Exception.Message -replace '\r*\n', '') [$($_.Exception.GetType().FullName)]")
        Continue
    }

    If ($WorkgroupDomain) {
        $WorkgroupDomain = "$WorkgroupDomain/"
    }

    If ($Create -or $CreateIfNot) {
        New-Variable -Force -Name:'ADSI' -Value:(New-Object -TypeName:'ADSI' -ArgumentList:"WinNT://$($WorkgroupDomain)$($Env:ComputerName)")
        New-Variable -Force -Name:'LocalUser' -Value:($ADSI.Children | Where-Object -FilterScript:{$_.SchemaClassName -eq 'User' -and $_.name -eq $sAMAccountName})

        If ([String]::IsNullOrEmpty($LocalUser)) {
            If ($CreateIfNot) {
                Set-Variable -Name:'LocalUser' -Value:($ADSI.Create('user',$sAMAccountName))
                Set-Variable -Name:'GeneratePassword' -Value:$True
            } Else {
                throw "Account '$UserName' not found"
            }
        }
    } Else {
        New-Variable -Force -Name:'LocalUser' -Value:(New-Object -TypeName:'ADSI' -ArgumentList:"WinNT://$($WorkgroupDomain)$($Env:ComputerName)/$($sAMAccountName),user")
    }

    #Universal function for updating account properties.
    New-Variable -Name:'ApplyChanges' -Value:([scriptblock]::Create({
        $LocalUser.CommitChanges()
        $LocalUser.RefreshCache()
    }))


    #Update Password Stuff
    If ($GeneratePassword) {
        $SetPassword = New-Password
    }

    If ($SetPassword) {
        $LocalUser.SetPassword(($SetPassword))
        & $ApplyChanges
    }

    New-Variable -Name:'UpdateFlag' -Value:([scriptblock]::Create({
        Param ($Expression,$InitialFlags,$Action,$Flag)

        If ([Boolean]($LocalUser.UserFlags.value -BAND $Flag)) {
            If ($Action -eq 'Add') {
                Write-Verbose -Message:"UserFlags already set properly for userFlag '$flag'"
            } Else {
                Invoke-Command -ScriptBlock:([ScriptBlock]::Create($Expression)) -NoNewScope -Verbose
            }
        } Else {
            Write-Verbose -Message:"$($Action.trim('e'))ing flag '$flag' to $($LocalUser.name)"
            Invoke-Command -ScriptBlock:([ScriptBlock]::Create($Expression)) -NoNewScope -Verbose
        }

        & $ApplyChanges
        if ($LocalUser.UserFlags.Value -eq $StartingValue) {
            Write-Warning -Message:"Unable to $Action flag '$flag'."
        } else {
            Write-Verbose -Message:"Successfully $Action`ed flag '$flag'."
        }
    }))

    #Update userFlag values.
    If ($SetFlag) {
        $LocalUser.Put('userflags', $Flag)
        & $ApplyChanges
    } ElseIf (($AddFlags.Count + $RemoveFlags.Count) -gt 0) {
        New-Variable -Name:'InitalFlag' -Value $LocalUser.UserFlags[0]
        ForEach ($Action in @('Add','Remove')) {
            ForEach ($Flag in (Get-Variable -Name:("$($Action)Flags") -ValueOnly)) {
                If ($Action -eq 'Add') {
                    & $UpdateFlag {$LocalUser.Put('userflags', ($LocalUser.UserFlags[0] -BOR $Flag))} $LocalUser.UserFlags[0] $Action $Flag
                } Else {
                    & $UpdateFlag {$LocalUser.Put('userflags', ($LocalUser.UserFlags[0] -BXOR $Flag))} $LocalUser.UserFlags[0] $Action $Flag
                }
            }
        }
    }

    #Set NonFlag based options.
    New-Variable -Force -Name:'ParamValue' -Value:($Null)
    ForEach ($Parameter in @('Name','Description','FullName')) {
        $ParamValue = (Get-Variable -Name:$Parameter -ValueOnly).ToString()
        If (-Not ([String]::IsNullOrEmpty($ParamValue))) {
            $LocalUser.($Parameter) = $ParamValue
            & $ApplyChanges
        }
    }

    #Update Group Membership
    If (($AddGroups.Count + $RemoveGroups.Count) -gt 0) {
        New-Variable -Force -Name:'TargetGroup' -Value:$null
        New-Variable -Force -Name:'TargetGroupMembers' -Value:$null
        ForEach ($Action in @('Add','Remove')) {
            ForEach ($Group in (Get-Variable -Name:("$($Action)Groups") -ValueOnly)) {
                $TargetGroup = (New-Object -TypeName:'ADSI' -ArgumentList:"WinNT://$($WorkgroupDomain)$($Env:ComputerName)/$($Group),group")
                If ([string]::IsNullOrEmpty($TargetGroup.path)) {
                    Write-Warning -Message:"Unable to locate group '$Group'."
                } else {
                    $TargetGroupMembers = (($TargetGroup).Invoke("Members") |ForEach-Object { $_.GetType().InvokeMember("Name", 'GetProperty', $Null, $_, $Null) })
                    if ($Action -eq 'Add') {
                        If ($TargetGroupMembers -contains $LocalUser.Name) {
                            Write-Verbose -Message:"Group '$($TargetGroup.name) already contains user '$($LocalUser.Name)'."
                        } Else {
                            $TargetGroup.Add($LocalUser.path)
                        }
                    } Else {
                        If ($TargetGroupMembers -NotContains $LocalUser.Name) {
                            Write-Verbose -Message:"Group '$($TargetGroup.name) does not contain'$($LocalUser.Name)'."
                        } Else {
                            $TargetGroup.Remove($LocalUser.path)
                        }
                    }
                }
            }
        }
    }
}
Function Start-CimQuery {
    [CmdletBinding(
        ConfirmImpact = 'None',
        DefaultParameterSetName = 'Default',
        HelpURI = '',
        SupportsPaging = $False,
        SupportsShouldProcess = $True,
        PositionalBinding = $True
    )]Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$ClassName,
        [Parameter(Position = 1)]
        [String]$NameSpace = 'root\CIMV2',
        [Parameter(Position = 2)]
        [CimSession]$CimSession,
        [Parameter(Position = 3)]
        [string[]]$Property = '*',
        [Parameter(Position = 4)]
        [Switch]$NewCimSession,
        [Parameter(Position = 0)]
        [HashTable]$QuickSetup
    )

    $Step = [int]1
    $ErrorActionPreference = 'Stop'

    Write-Debug -Message:("Step $Step` Initalizing Variables Variables"); $Step++
    @('Result') | ForEach-Object { New-Variable -Name:$_ -Value:$Null }
    New-Variable -Name:'CimInstSplat' -Value:(@{'Property' = $Property; 'NameSpace' = $NameSpace })
    New-Variable -Name:'CimProperties' -Value:@('ClassName', 'NameSpace', 'CimSession', 'Property')


    Write-Debug -Message:('Step $Step: Quickstep Check.'); $Step++
    If ($QuickSetup) {
        ForEach ($Param in $QuickSetup.GetEnumerator()) {
            Write-Verbose -Message:"ForEach-Param: $($param.Key)"
            If ($Param.Key -in $CimProperties) {
                Write-Verbose -Message:('Adding ''{0}'' key with value ''{1}'' to CimInstSplat.' -f
                    $Param.Key, $Param.Value)
                $CimInstSplat[$Param.Key] = $Param.Value
            } Else {
                Write-Warning -Message:'CimProperty {0} does not match a valid CimSession property.'
            }
        }
        $Null = $PSBoundParameters.Remove('QuickSetup')
    }

    Write-Debug -Message:("Step $Step` Add PSBound Parameters to CimInstSplat."); $Step++
    ForEach ($Param in $PSBoundParameters.GetEnumerator()) {
        If ($Param.Key -in $CimProperties) {
            Write-Debug -Message:"Adding $($Param.Key) ot `$CimInstSplat."
            Write-Verbose -Message:('Adding ''{0}'' key with value ''{1}'' to CimInstSplat.' -f
                $Param.Key, $Param.Value)
            $CimInstSplat[$Param.Key] = $Param.Value
        } Else {
            Write-Debug -Message:"Skipping $($Param.Key); Not in `$CimProperties."
        }
    }


    Write-Debug -Message:("Step $Step` CimSession Check"); $Step++
    If (('CimSession' -NotIn $CimInstSplat.keys) -or $NewCimSession) {
        Write-Verbose -Message:'Attempting to create a DCOM CimSession for LocalHost.'
        $lMSG = 'Creating LocalCimSession: {0}'
        $CimInstSplat['CimSession'] = (
            New-CimSession -ComputerName:'LocalHost' -SessionOption:(
                New-CimSessionOption -Protocol:'Dcom'
            )
        )
        Write-Debug -Message:($lMSG -f 'Success')
    }


    Write-Debug -Message:("Step $Step`: CimSession Check"); $Step++
    $lMSG = 'Get-CimInstance command result: {0}'
    Try {
        Set-Variable -Name:'Result' -Value:(
            Get-CimInstance @CimInstSplat | Select-Object -Property $CimInstSplat.Property)
        Write-Information -MessageData:($lMSG -f 'Success')
    } Catch [Microsoft.Management.Infrastructure.CimException] {
        If ($NewCimSession) {
            Throw $_
        } Else {
            Start-CimQuery -QuickSetup:$CimInstSplat -NewCimSession
        }
    } Catch {
        Throw $_
    }
    Write-Debug -Message:($lMSG -f 'Success')

    Return $Result
}

New-Variable -Force -Name:'NVSplat' -Value:@{'Verbose' = $Verbose; Force = $True }
New-Variable -Force -Name:'NameValidation' -Value:"^[a-z0-9\ \(\)\.\_\~\'\{\}\|\$\!\@\#\%\^\&\-\`]{1,20}$"

#Initialize Variables
@('LocalCimSession', 'ComputerSystem', 'Users', 'AdminAccountName') | ForEach-Object {
    New-Variable @NVSplat -Name:$_ -Value:$Null
}

#Create DCOM CIM Session for use in CimQueries
$LocalCimSession = New-CimSession -ComputerName:"localhost" –SessionOption (New-CimSessionOption –Protocol:'DCOM')

#Load Basic System Information
$ComputerSystem = Start-CimQuery -CimSession:$LocalCimSession -QuickSetup:@{
    ClassName  = 'Win32_ComputerSystem';
    NameSpace  = 'root/cimv2';
    Property   = 'Name', 'DNSHostName', 'Domain', 'DomainRole', 'Workgroup', 'PartOfDomain'
}

#Only run if system is MemberWorkstation or MemberServer.
If ($ComputerSystem.DomainRole -in @(1,3)) {

    #Add Computer Membership Property
    If (-NOT [String]::IsNullOrWhiteSpace($env:Userdomain)) {
        $ComputerSystem | Add-Member -Force -MemberType:'NoteProperty' -Name:'JoinedNetwork' -Value:$env:Userdomain
    } Else {
        Throw '$env:USERDOMAIN is empty.'
    }

    #Get Local User Information
    $Users = Start-CimQuery -CimSession:$LocalCimSession -QuickSetup:@{
        ClassName = 'Win32_UserAccount';
        NameSpace = 'root/cimv2';
        Property  = 'Status', 'Caption', 'PasswordExpires', 'Description', 'Name', 'Domain', 'LocalAccount', 'SID',
        'SIDType', 'AccountType', 'Disabled', 'FullName', 'Lockout', 'PasswordChangeable', 'PasswordRequired'
        Filter    = "Domain = '$env:COMPUTERNAME'"
    }

    #Harden the the BuiltIn Guest and Administrator accounts.
    ForEach ($User in $Users.Where({ $_.sid -IMatch '[a-z0-9-]+-50[0-1]' })) {
        Update-User -sAMAccountName:($User.Name) -AddFlags:'2' -GeneratePassword -RemoveFlags:(
            '1', '8', '32', '128', '512', '65536', '131072','524288', '2097152', '4194304')
    }

    #Determine Account Name
    Switch ($NameGenMethod) {
        'LAPS' {
            If (Test-Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd') {
                New-Variable @NVSplat -Name:'LAPSPolicies' -Value:(
                    Get-ItemProperty -Path:(
                        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd\'
                    )
                )
                If ($LAPSPolicies.Contains('AdminAccountName')) {
                    If ([String]::IsNullOrEmpty($LAPSPolicies.Contains('AdminAccountName'))) {
                        If ($LAPSPolicies.AdminAccountName -match $NameValidation) {
                            $AdminAccountName = $LAPSPolicies.AdminAccountName
                        } Else {
                            Throw ("Username $($LAPSPolicies.AdminAccountName) is either not between 1 and 20 " +
                            "characters in length of contains one of the following invalid characters: " +
                            "`"/\[]:;|=,+*?<>")
                        }
                    } Else {
                        Throw 'AdminAccountName registry key was found, however, it appears to be empty.'
                    }
                } Else {
                    Throw 'Found AdmPwd registry key, however, unable to locate AdminAccountName key.'
                }
            } Else {
                Throw 'Unable to locate AdmPwd registry key.'
            }
        }
        'Auto' {
            If ("$($ComputerSystem.JoinedNetwork)Admin" -gt 15) {
                Write-Warning -Message:'Auto Generated admin account name is longer than 20 characters. Trimming' +
                " name to '$($ComputerSystem.JoinedNetwork.substring(0,15))Admin'"
                $AdminAccountName = "$($ComputerSystem.JoinedNetwork.substring(0,15))Admin"
            } Else {
                $AdminAccountName = "$($ComputerSystem.JoinedNetwork)Admin"
            }
        }
        'Manual' {
            $AdminAccountName = $ADMAccountName
        }
    }

    #Create and configure LocalAdmin
    If (-NOT [String]::IsNullOrEmpty($AdminAccountName)) {
        Update-User -UserName:$AdminAccountName -CreateIfNot -AddGroups:'Administrators', 'Users' -RemoveFlags:(
            '2', '8', '16', '32', '64', '65536', '262144', '8388608')
    } Else {
        Throw "AdminAccountName is null or empty. Appears no valid AdminAccountName could be determined."
    }

} Else {
    Write-Information -Message:'System is not domain joined, exiting script.'
}
