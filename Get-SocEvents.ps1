[CmdletBinding()]
param(
    [int]$HoursBack = 16,
    [int]$MaxEvents = 200,

    # Common Tier 1 SOC Security log events by default
    [int[]]$EventIds = @(
        4625, # Failed logon
        4624, # Successful logon
        4634, # Logoff
        4648, # Logon with explicit credentials
        4672, # Special privileges assigned
        4688, # Process creation
        4720, # User account created
        4722, # User account enabled
        4723, # Password change attempted
        4724, # Password reset attempted
        4725, # User account disabled
        4726, # User account deleted
        4728, # Member added to global security group
        4729, # Member removed from global security group
        4732, # Member added to local security group
        4733, # Member removed from local security group
        4768, # Kerberos TGT requested
        4769, # Kerberos service ticket requested
        4771, # Kerberos pre-auth failed
        4776  # NTLM authentication
    ),

    [string]$OutputCsv = $null


)

function Get-EventLogDetailed {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LogName,
        [int[]]$Id,
        [int]$HoursBack = 16,
        [int]$MaxEvents = 200
    )

    $filter = @{
        LogName   = $LogName
        StartTime = (Get-Date).AddHours(-$HoursBack)
    }

    if ($Id) {
        $filter.Id = $Id
    }

    Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents |
        Sort-Object TimeCreated
}

function Get-EventDataValue {
    param(
        [Parameter(Mandatory)]
        [System.Diagnostics.Eventing.Reader.EventRecord]$Event,
        [Parameter(Mandatory)]
        [string]$Name
    )

    $xml = [xml]$Event.ToXml()
    $node = $xml.Event.EventData.Data | Where-Object { $_.Name -eq $Name }
    return $node.'#text'
}

# --- Main ---

$events = Get-EventLogDetailed -LogName 'Security' -Id $EventIds -HoursBack $HoursBack -MaxEvents $MaxEvents

$parsed = $events | ForEach-Object {

    # Parse a more human-friendly FailureReason from 4625 message text
    $failureReason = $null
    if ($_.Id -eq 4625) {
        $failureLine = $_.Message -split "`r?`n" | Where-Object { $_ -match 'Failure Reason' } | Select-Object -First 1
        if ($failureLine) {
            $failureReason = ($failureLine -replace '.*Failure Reason:\s*','').Trim()
        }
    }

    # Short message (first few lines) for quick console viewing
    $messageShort = ($_.Message -split "`r?`n" | Select-Object -First 3) -join ' '

    [pscustomobject]@{
        TimeCreated   = $_.TimeCreated
        EventId       = $_.Id
        LogName       = $_.LogName
        Computer      = $_.MachineName

        # Subject (caller) info
        SubjectUser   = Get-EventDataValue -Event $_ -Name 'SubjectUserName'
        SubjectDomain = Get-EventDataValue -Event $_ -Name 'SubjectDomainName'

        # Target info (account being acted on)
        TargetUser    = Get-EventDataValue -Event $_ -Name 'TargetUserName'
        TargetDomain  = Get-EventDataValue -Event $_ -Name 'TargetDomainName'

        # Network / logon context
        IpAddress     = Get-EventDataValue -Event $_ -Name 'IpAddress'
        IpPort        = Get-EventDataValue -Event $_ -Name 'IpPort'
        LogonType     = Get-EventDataValue -Event $_ -Name 'LogonType'
        Workstation   = Get-EventDataValue -Event $_ -Name 'WorkstationName'
        ProcessName   = Get-EventDataValue -Event $_ -Name 'ProcessName'
        AuthPackage   = Get-EventDataValue -Event $_ -Name 'AuthenticationPackageName'
        LogonProcess  = Get-EventDataValue -Event $_ -Name 'LogonProcessName'

        # Status codes + parsed failure reason for 4625
        Status        = Get-EventDataValue -Event $_ -Name 'Status'
        SubStatus     = Get-EventDataValue -Event $_ -Name 'SubStatus'
        FailureReason = $failureReason

        # Message views
        MessageShort  = $messageShort     # Easier to read in console
        MessageFull   = $_.Message        # Full raw message from event log
    }
}

# 🔽 Sort parsed output by EventId (grouping) and then TimeCreated
$parsed = $parsed | Sort-Object EventId, TimeCreated

if ($OutputCsv) {
    $parsed | Export-Csv -Path $OutputCsv -NoTypeInformation
    Write-Host "Exported $($parsed.Count) events to $OutputCsv"
} else {
    $parsed | Format-Table -AutoSize
}
