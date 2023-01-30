$identity = $datasource.selectedUser.id
$Permission = $datasource.Permission

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

# Connect to Office 365
try {
    Write-Information "Connecting to Office 365.."

    $module = Import-Module ExchangeOnlineManagement

    $securePassword = ConvertTo-SecureString $ExchangeOnlineAdminPassword -AsPlainText -Force
    $credential = [System.Management.Automation.PSCredential]::new($ExchangeOnlineAdminUsername,$securePassword)

    $exchangeSession = Connect-ExchangeOnline -Credential $credential -ShowBanner:$false -ShowProgress:$false -TrackPerformance:$false -ErrorAction Stop 

    Write-Information "Successfully connected to Office 365"
}
catch {
    Write-Error "Could not connect to Exchange Online, error: $_"
}

# Get current mailbox permissions
try {
    if ($Permission.ToLower() -eq "fullaccess") {
        $currentPermissions =  Get-Mailbox -Filter * -RecipientTypeDetails SharedMailbox -ResultSize Unlimited | Get-MailboxPermission -User $identity -ResultSize Unlimited # Returns identity
        $currentPermissionsMailboxes = $currentPermissions.Identity    

        $mailboxes = foreach ($currentPermissionsMailbox in $currentPermissionsMailboxes) {
            Get-EXOMailbox -Identity $currentPermissionsMailbox -ErrorAction SilentlyContinue
        }
    }
    elseif ($Permission.ToLower() -eq "sendas") {
        $currentPermissions = Get-Mailbox -Filter * -RecipientTypeDetails SharedMailbox -ResultSize Unlimited | Get-EXORecipientPermission -Trustee $identity -AccessRights 'SendAs' -ResultSize Unlimited  # Returns identity
        $currentPermissionsMailboxes = $currentPermissions.Identity

        $mailboxes = foreach ($currentPermissionsMailbox in $currentPermissionsMailboxes) {
            Get-EXOMailbox -Identity $currentPermissionsMailbox -ErrorAction SilentlyContinue
        }
    }
    elseif ($Permission.ToLower() -eq "sendonbehalf") {
        $currentPermissions = Get-Mailbox -Filter * -RecipientTypeDetails SharedMailbox -ResultSize Unlimited | Where-Object { $_.GrantSendOnBehalfTo -match $identity }  # Returns full mailbox object

        $mailboxes = $currentPermissions
    }
    else {
        throw "Could not match right '$($Permission)' to FullAccess, SendAs or SendOnBehalf"
    }

    
    $mailboxes = $mailboxes | Sort-Object -Property Displayname
    Write-Information -Message "Found $Permission permissions for user $($identity): $(@($mailboxes).Count)"

    foreach ($mailbox in $mailboxes) {
        $returnObject = @{
            name="$($mailbox.displayName)";
            id="$($mailbox.id)";
            primarySmtpAddress ="$($mailbox.PrimarySmtpAddress)";
            userPrincipalName ="$($mailbox.UserPrincipalName)"
        }
        Write-Output $returnObject
    }

}
catch {
    Write-Error "Error searching $Permissions permissions for user $($identity). Error: $_"
}
finally {
    Write-Information "Disconnecting from Office 365.."
    $exchangeSessionEnd = Disconnect-ExchangeOnline -Confirm:$false -Verbose:$false -ErrorAction Stop
    Write-Information "Successfully disconnected from Office 365"
}
