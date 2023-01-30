# Fixed values
$AutoMapping = $false

try {
    # Set TLS to accept TLS, TLS 1.1 and TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

    # Connect to Office 365
    try{
        Hid-Write-Status -Event Information -Message "Connecting to Office 365.."

        $module = Import-Module ExchangeOnlineManagement

        $securePassword = ConvertTo-SecureString $ExchangeOnlineAdminPassword -AsPlainText -Force
        $credential = [System.Management.Automation.PSCredential]::new($ExchangeOnlineAdminUsername,$securePassword)

        $exchangeSession = Connect-ExchangeOnline -Credential $credential -ShowBanner:$false -ShowProgress:$false -TrackPerformance:$false -ErrorAction Stop 

        Hid-Write-Status -Event Information -Message "Successfully connected to Office 365"
    }catch{
        Write-Error "Could not connect to Exchange Online, error: $_"
    }

    Hid-Write-Status -Event Information -Message "Checking if user with identity '$($identity)' exists"
    $user = Get-User -Identity $identity -ErrorAction Stop
    if ($user.Name.Count -eq 0) {
        throw "Could not find user with identity '$($identity)'"
    }

    # Add permissions to users
    try { 
        HID-Write-Status -Event Information -Message "Adding permission $($permission) to user $($identity) for $mailboxesToAdd" 
        $mailboxesToAddJson = $mailboxesToAdd | ConvertFrom-Json
        foreach ($mailbox in $mailboxesToAddJson.id) {
            if($permission.ToLower() -eq "fullaccess"){
                if($AutoMapping){
                    Add-MailboxPermission -Identity $mailbox -AccessRights FullAccess -InheritanceType All -AutoMapping:$true -User $user.id -ErrorAction Stop
                }else{
                    Add-MailboxPermission -Identity $mailbox -AccessRights FullAccess -InheritanceType All -AutoMapping:$false -User $user.id -ErrorAction Stop
                }
            }elseif($permission.ToLower() -eq "sendas"){
                Add-RecipientPermission -Identity $mailbox -AccessRights SendAs -Confirm:$false -Trustee $User.id -ErrorAction Stop
            }elseif($permission.ToLower() -eq "sendonbehalf"){
                Set-Mailbox -Identity $mailbox -GrantSendOnBehalfTo @{add="$($user.id)"} -Confirm:$false -ErrorAction Stop
            }else{
                throw "Could not match right '$($permission)' to FullAccess, SendAs or SendOnBehalf"
            }
            HID-Write-Status -Event Success -Message "Added permission $($permission) to user $($identity) for $mailbox"
            HID-Write-Summary -Event Success -Message "Added permission $($permission) to user $($identity) for $mailbox"
        }
    } catch {
        HID-Write-Status -Event Error -Message "Error adding permission $($permission) to user $($identity) for $mailbox . Error: $_"
        HID-Write-Summary -Event Failed -Message "Error adding permission $($permission) to user $($identity) for $mailbox"
    }

    # Remove permissions from users
    try { 
        HID-Write-Status -Event Information -Message "Removing permission $($permission) to user $($identity) for $mailboxesToRemove" 
        $mailboxesToRemoveJson = $mailboxesToRemove | ConvertFrom-Json
        foreach ($mailbox in $mailboxesToRemoveJson.id) {
            if($permission.ToLower() -eq "fullaccess"){
                Remove-MailboxPermission -Identity $mailbox -AccessRights FullAccess -InheritanceType All -User $User.id -Confirm:$false -ErrorAction Stop
            }elseif($permission.ToLower() -eq "sendas"){
                Remove-RecipientPermission -Identity $mailbox -AccessRights SendAs -Confirm:$false -Trustee $User.id -ErrorAction Stop
            }elseif($permission.ToLower() -eq "sendonbehalf"){
                Set-Mailbox -Identity $mailbox -GrantSendOnBehalfTo @{remove="$($user.id)"} -Confirm:$false -ErrorAction Stop
            }else{
                throw "Could not match right '$($permission)' to FullAccess, SendAs or SendOnBehalf"
            }
            HID-Write-Status -Event Success -Message "Removed permission $($permission) to user $($identity) for $mailbox"
            HID-Write-Summary -Event Success -Message "Removed permission $($permission) to user $($identity) for $mailbox"          
        }
    } catch {
        HID-Write-Status -Event Error -Message "Error removing permission $($permission) to user $($identity) for $mailbox . Error: $_"
        HID-Write-Summary -Event Failed -Message "Error removing permission $($permission) to user $($identity) for $mailbox"
    }
} catch {
    HID-Write-Status -Message "Error updating permission $($permission) to user $($identity). Error: $_" -Event Error
    HID-Write-Summary -Message "Error updating permission $($permission) to user $($identity)." -Event Failed
} finally {
    Hid-Write-Status -Event Information -Message "Disconnecting from Office 365.."
    $exchangeSessionEnd = Disconnect-ExchangeOnline -Confirm:$false -Verbose:$false -ErrorAction Stop
    Hid-Write-Status -Event Information -Message "Successfully disconnected from Office 365"
}
