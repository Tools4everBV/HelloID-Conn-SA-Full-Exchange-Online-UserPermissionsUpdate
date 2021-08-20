# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

# Connect to Office 365
try{
    Write-Information "Connecting to Office 365.."

    $module = Import-Module ExchangeOnlineManagement

    $securePassword = ConvertTo-SecureString $ExchangeOnlineAdminPassword -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential ($ExchangeOnlineAdminUsername, $securePassword)

    $exchangeSession = Connect-ExchangeOnline -Credential $credential -ShowBanner:$false -ShowProgress:$false -TrackPerformance:$false -ErrorAction Stop 

    Write-Information "Successfully connected to Office 365"
}catch{
    Write-Error "Could not connect to Exchange Online, error: $_"
}

try {      
    $exchangeMailboxes = Get-Mailbox -Filter * -RecipientTypeDetails SharedMailbox -resultSize unlimited

    $mailboxes = $exchangeMailboxes
    $resultCount = @($mailboxes).Count
    
    Write-Information "Result count: $resultCount"
    
    if($resultCount -gt 0){
        foreach($mailbox in $mailboxes){
            $returnObject = @{
                name="$($mailbox.displayName)";
                id="$($mailbox.id)";
                primarySmtpAddress ="$($mailbox.PrimarySmtpAddress)";
                userPrincipalName ="$($mailbox.UserPrincipalName)"
            }

            Write-Output $returnObject
        }
    }
} catch {
    $errorDetailsMessage = ($_.ErrorDetails.Message | ConvertFrom-Json).error.message
    Write-Error ("Error searching for Exchange Shared mailboxes. Error: $($_)" + $errorDetailsMessage)
} finally {
    Write-Information "Disconnecting from Office 365.."
    $exchangeSessionEnd = Disconnect-ExchangeOnline -Confirm:$false -Verbose:$false -ErrorAction Stop
    Write-Information "Successfully disconnected from Office 365"
}
