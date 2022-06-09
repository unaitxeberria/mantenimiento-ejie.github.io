function Test-ADCredential {
    [CmdletBinding()]
    Param
    (
        [string]$Server
        [string]$UserName,
        [string]$Password
    )
    #$Server   = '54.78.59.220:3490'
    #$UserName = 'proveedor-1'
    #$Password = 'e8PTZGQB6DUUrAKN()ax'
    if (!($UserName) -or !($Password)) {
        Write-Warning 'Test-ADCredential: Please specify both user name and password'
    } else {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($server)
        $DS.ValidateCredentials($UserName, $Password)
    }
}

function Get-NestedMember {

    [CmdletBinding()]
    PARAM(
        [String[]]$GroupName,
        [String]$RelationShipPath,
        [Int]$MaxDepth
    )
    TRY {
        $FunctionName = (Get-Variable -Name MyInvocation -Scope 0 -ValueOnly).MyCommand

        Write-Verbose -Message "[$FunctionName] Check if ActiveDirectory Module is available"
        if (-not(Get-Module Activedirectory -ErrorAction Stop)) {
            Write-Verbose -Message "[$FunctionName] Loading ActiveDirectory Module"
            Import-Module -Name ActiveDirectory -ErrorAction Stop
        }


        $DepthCount = 1
        FOREACH ($Group in $GroupName) {
            Write-Verbose -Message "[$FunctionName] Group '$Group'"

            $GroupObject = Get-ADGroup -Identity $Group -ErrorAction Stop

            IF ($GroupObject) {
                Write-Verbose -Message "[$FunctionName] Group '$Group' - Retrieving members"

                $GroupObject | Get-ADGroupMember -ErrorAction Stop | ForEach-Object -Process {

                    $ParentGroup = $GroupObject.Name
                    IF ($RelationShipPath -notlike ".\ $($GroupObject.samaccountname) \*") {
                        if ($PSBoundParameters["RelationShipPath"]) {

                            $RelationShipPath = "$RelationShipPath \ $($GroupObject.samaccountname)"

                        }
                        Else { $RelationShipPath = ".\ $($GroupObject.samaccountname)" }

                        Write-Verbose -Message "[$FunctionName] Group '$Group' - Name:$($_.name) | ObjectClass:$($_.ObjectClass)"
                        $CurrentObject = $_
                        switch ($_.ObjectClass) {
                            "group" {
                                $CurrentObject | Select-Object Name, SamAccountName, ObjectClass, DistinguishedName, @{Label = "ParentGroup"; Expression = { $ParentGroup } }, @{Label = "RelationShipPath"; Expression = { $RelationShipPath } }

                                if (-not($DepthCount -lt $MaxDepth)) {
                                    Get-NestedMember -GroupName $CurrentObject.Name -RelationShipPath $RelationShipPath
                                    $DepthCount++
                                }
                            }
                            default { $CurrentObject | Select-Object Name, SamAccountName, ObjectClass, DistinguishedName, @{Label = "ParentGroup"; Expression = { $ParentGroup } }, @{Label = "RelationShipPath"; Expression = { $RelationShipPath } } }
                        }
                    }
                    ELSE { Write-Warning -Message "[$FunctionName] Circular group membership detected with $($GroupObject.samaccountname)" }
                }
            }
            ELSE {
                Write-Warning -Message "[$FunctionName] Can't find the group $Group"
            }
        }
    }
    CATCH {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

Function Get-AccountLockedOut {


    [CmdletBinding()]
    param (
        [string]$DomainName = $env:USERDOMAIN,
        [Parameter()]
        [ValidateNotNullorEmpty()]
        [string]$UserName = '*',
        [datetime]$StartTime = (Get-Date).AddDays(-1),
        [PSCredential]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        TRY {
            $TimeDifference = (Get-Date) - $StartTime

            Write-Verbose -Message "[BEGIN] Looking for PDC..."

            function Get-PDCServer {
                PARAM (
                    $Domain = $env:USERDOMAIN,
                    [pscredential]
                    $Credential = [System.Management.Automation.PSCredential]::Empty
                )

                IF ($PSBoundParameters['Credential']) {

                    [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain(
                        (New-Object -TypeName System.DirectoryServices.ActiveDirectory.DirectoryContext -ArgumentList 'Domain', $Domain, $($Credential.UserName), $($Credential.GetNetworkCredential().password))
                    ).PdcRoleOwner.name
                }
                ELSE {
                    [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain(
                        (New-Object -TypeName System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain))
                    ).PdcRoleOwner.name
                }
            }

            Write-Verbose -Message "[BEGIN] PDC is $(Get-PDCServer)"
        }
        CATCH {
            $PSCmdlet.ThrowTerminatingError($_)
        }

    }
    PROCESS {
        TRY {
            $Splatting = @{ }
            IF ($PSBoundParameters['Credential']) {
                Write-Verbose -Message "[PROCESS] Credential Specified"
                $Splatting.Credential = $Credential
                #$Splatting.ComputerName = $(Get-PDCServer -Domain ejie.eus -Credential e8PTZGQB6DUUrAKN()ax)
                $Splatting.ComputerName = $(Get-PDCServer -Domain $DomainName -Credential $Credential)
            }
            ELSE {
                $Splatting.ComputerName = $(Get-PDCServer -Domain $DomainName)
            }
            Write-Verbose -Message "[PROCESS] Querying PDC for LockedOut Account in the last Days:$($TimeDifference.days) Hours: $($TimeDifference.Hours) Minutes: $($TimeDifference.Minutes) Seconds: $($TimeDifference.seconds)"
            Invoke-Command @Splatting -ScriptBlock {
                Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4740; StartTime = $Using:StartTime } |
                    Where-Object -FilterScript { $_.Properties[0].Value -like "$Using:UserName" } |
                    Select-Object -Property TimeCreated,
                    @{ Label = 'UserName'; Expression = { $_.Properties[0].Value } },
                    @{ Label = 'ClientName'; Expression = { $_.Properties[1].Value } }
            } | Select-Object -Property TimeCreated, UserName, ClientName
        }
        CATCH {
            $PSCmdlet.ThrowTerminatingError($_)
        }
    }
}

Function Get-DomainComputer {

    [CmdletBinding()]
    PARAM(
        [Parameter(
            ValueFromPipelineByPropertyName=$true,
            ValueFromPipeline=$true)]
        [Alias("Computer")]
        [String[]]$ComputerName,

        [Alias("ResultLimit","Limit")]
        [int]$SizeLimit='100',

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [Alias("Domain")]
        [String]$DomainDN=$(([adsisearcher]"").Searchroot.path),

        [Alias("RunAs")]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty

    )

    PROCESS{
        IF ($ComputerName){
            Write-Verbose -Message "One or more ComputerName specified"
            FOREACH ($item in $ComputerName){
                TRY{
                    Write-Verbose -Message "COMPUTERNAME: $item"
                    $Searcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ErrorAction 'Stop' -ErrorVariable ErrProcessNewObjectSearcher
                    $Searcher.Filter = "(&(objectCategory=Computer)(name=$item))"
                    $Searcher.SizeLimit = $SizeLimit
                    $Searcher.SearchRoot = $DomainDN

                    IF ($PSBoundParameters['DomainDN']){
                        IF ($DomainDN -notlike "LDAP://*") {$DomainDN = "LDAP://$DomainDN"}
                        Write-Verbose -Message "Different Domain specified: $DomainDN"
                        $Searcher.SearchRoot = $DomainDN}

                    IF ($PSBoundParameters['Credential']) {
                        Write-Verbose -Message "Different Credential specified: $($Credential.UserName)"
                        $Domain = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList $DomainDN,$($Credential.UserName),$($Credential.GetNetworkCredential().password) -ErrorAction 'Stop' -ErrorVariable ErrProcessNewObjectCred
                        $Searcher.SearchRoot = $Domain}
                    Write-Verbose -Message "Starting the ADSI Search..."
                    FOREACH ($Computer in $($Searcher.FindAll())){
                        Write-Verbose -Message "$($Computer.properties.name)"
                        New-Object -TypeName PSObject -ErrorAction 'Continue' -ErrorVariable ErrProcessNewObjectOutput -Property @{
                            "Name" = $($Computer.properties.name)
                            "DNShostName"    = $($Computer.properties.dnshostname)
                            "Description" = $($Computer.properties.description)
                            "OperatingSystem"=$($Computer.Properties.operatingsystem)
                            "WhenCreated" = $($Computer.properties.whencreated)
                            "DistinguishedName" = $($Computer.properties.distinguishedname)}
                    }

                    Write-Verbose -Message "ADSI Search completed"
                }
                CATCH{
                    Write-Warning -Message ('{0}: {1}' -f $item, $_.Exception.Message)
                    IF ($ErrProcessNewObjectSearcher){Write-Warning -Message "PROCESS BLOCK - Error during the creation of the searcher object"}
                    IF ($ErrProcessNewObjectCred){Write-Warning -Message "PROCESS BLOCK - Error during the creation of the alternate credential object"}
                    IF ($ErrProcessNewObjectOutput){Write-Warning -Message "PROCESS BLOCK - Error during the creation of the output object"}
                }
            }


        }
        ELSE {
            Write-Verbose -Message "No ComputerName specified"
            TRY{
                
                Write-Verbose -Message "List All object"
                $Searcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ErrorAction 'Stop' -ErrorVariable ErrProcessNewObjectSearcherALL
                $Searcher.Filter = "(objectCategory=Computer)"
                $Searcher.SizeLimit = $SizeLimit

                
                IF ($PSBoundParameters['DomainDN']){
                    $DomainDN = "LDAP://$DomainDN"
                    Write-Verbose -Message "Different Domain specified: $DomainDN"
                    $Searcher.SearchRoot = $DomainDN}

                IF ($PSBoundParameters['Credential']) {
                    Write-Verbose -Message "Different Credential specified: $($Credential.UserName)"
                    $DomainDN = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList $DomainDN, $Credential.UserName,$Credential.GetNetworkCredential().password -ErrorAction 'Stop' -ErrorVariable ErrProcessNewObjectCredALL
                    $Searcher.SearchRoot = $DomainDN}
                Write-Verbose -Message "Starting the ADSI Search..."
                FOREACH ($Computer in $($Searcher.FindAll())){
                    TRY{
                        Write-Verbose -Message "$($Computer.properties.name)"
                        New-Object -TypeName PSObject -ErrorAction 'Continue' -ErrorVariable ErrProcessNewObjectOutputALL -Property @{
                            "Name" = $($Computer.properties.name)
                            "DNShostName"    = $($Computer.properties.dnshostname)
                            "Description" = $($Computer.properties.description)
                            "OperatingSystem"=$($Computer.Properties.operatingsystem)
                            "WhenCreated" = $($Computer.properties.whencreated)
                            "DistinguishedName" = $($Computer.properties.distinguishedname)}
                    }
                    CATCH{
                        Write-Warning -Message ('{0}: {1}' -f $Computer, $_.Exception.Message)
                        IF ($ErrProcessNewObjectOutputALL){Write-Warning -Message "PROCESS BLOCK - Error during the creation of the output object"}
                    }
                }

                Write-Verbose -Message "ADSI Search completed"

            }

            CATCH{
                Write-Warning -Message "Something Wrong happened"
                IF ($ErrProcessNewObjectSearcherALL){Write-Warning -Message "PROCESS BLOCK - Error during the creation of the searcher object"}
                IF ($ErrProcessNewObjectCredALL){Write-Warning -Message "PROCESS BLOCK - Error during the creation of the alternate credential object"}

            }
        }
    }
    END{Write-Verbose -Message "Script Completed"}
}
