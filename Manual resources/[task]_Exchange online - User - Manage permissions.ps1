# Fixed values
$AutoMapping = $false

$permission = $form.permission
$identity = $form.gridUser.id
$mailboxesToAdd = $form.permissionList.leftToRight
$mailboxesToRemove = $form.permissionList.rightToLeft

try {
    # Set TLS to accept TLS, TLS 1.1 and TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

    # Connect to Office 365
    try {
        $module = Import-Module ExchangeOnlineManagement

        $securePassword = ConvertTo-SecureString $ExchangeOnlineAdminPassword -AsPlainText -Force
        $credential = [System.Management.Automation.PSCredential]::new($ExchangeOnlineAdminUsername, $securePassword)

        $exchangeSession = Connect-ExchangeOnline -Credential $credential -ShowBanner:$false -ShowProgress:$false -TrackPerformance:$false -ErrorAction Stop 

    }
    catch {     
        $Log = @{
            Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
            System            = "Exchange On-Premise" # optional (free format text) 
            Message           = "Could not connect to Exchange Online, error: $_" # required (free format text) 
            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $exchangeConnectionUri # optional (free format text) 
            TargetIdentifier  = $([string]$session.GUID) # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log
    }

    $user = Get-User -Identity $identity -ErrorAction Stop
    if ($user.Name.Count -eq 0) {
        throw "Could not find user with identity '$($identity)'"
    }

    # Add permissions to users
    try { 
        foreach ($mailbox in $mailboxesToAdd.id) {
            if ($permission.ToLower() -eq "fullaccess") {
                if ($AutoMapping) {
                    Add-MailboxPermission -Identity $mailbox -AccessRights FullAccess -InheritanceType All -AutoMapping:$true -User $user.id -ErrorAction Stop
                }
                else {
                    Add-MailboxPermission -Identity $mailbox -AccessRights FullAccess -InheritanceType All -AutoMapping:$false -User $user.id -ErrorAction Stop
                }
            }
            elseif ($permission.ToLower() -eq "sendas") {
                Add-RecipientPermission -Identity $mailbox -AccessRights SendAs -Confirm:$false -Trustee $User.id -ErrorAction Stop
            }
            elseif ($permission.ToLower() -eq "sendonbehalf") {
                Set-Mailbox -Identity $mailbox -GrantSendOnBehalfTo @{add = "$($user.id)" } -Confirm:$false -ErrorAction Stop
            }
            else {
                throw "Could not match right '$($permission)' to FullAccess, SendAs or SendOnBehalf"
            }

            $Log = @{
                Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
                System            = "Exchange Online" # optional (free format text) 
                Message           = "Successfully added permission $($permission) for user $($user.name) [$($user.guid)] to $mailbox" # required (free format text) 
                IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                TargetDisplayName = $user.name # optional (free format text) 
                TargetIdentifier  = $user.GUID # optional (free format text) 
            }

            Write-Information -Tags "Audit" -MessageData $log    

        }
    }
    catch {
        $Log = @{
            Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
            System            = "Exchange Online" # optional (free format text) 
            Message           = "failed to add permission $($permission) for user $($user.name) [$($user.guid)] to $mailbox" # required (free format text) 
            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $user.name # optional (free format text) 
            TargetIdentifier  = $user.GUID # optional (free format text) 
        }

        Write-Information -Tags "Audit" -MessageData $log    
        write-error "Error adding permission $($permission) to user  $($user.name) [$($user.guid)] for $mailbox . Error: $_"
    }

    # Remove permissions from users
    try { 

        foreach ($mailbox in $mailboxesToRemove.id) {
            if ($permission.ToLower() -eq "fullaccess") {
                Remove-MailboxPermission -Identity $mailbox -AccessRights FullAccess -InheritanceType All -User $User.id -Confirm:$false -ErrorAction Stop
            }
            elseif ($permission.ToLower() -eq "sendas") {
                Remove-RecipientPermission -Identity $mailbox -AccessRights SendAs -Confirm:$false -Trustee $User.id -ErrorAction Stop
            }
            elseif ($permission.ToLower() -eq "sendonbehalf") {
                Set-Mailbox -Identity $mailbox -GrantSendOnBehalfTo @{remove = "$($user.id)" } -Confirm:$false -ErrorAction Stop
            }
            else {
                throw "Could not match right '$($permission)' to FullAccess, SendAs or SendOnBehalf"
            }

            $Log = @{
                Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
                System            = "Exchange Online" # optional (free format text) 
                Message           = "Successfully removed permission $($permission) for user $($user.name) [$($user.guid)] from $mailbox" # required (free format text) 
                IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                TargetDisplayName = $user.name # optional (free format text) 
                TargetIdentifier  = $user.GUID # optional (free format text) 
            }

            Write-Information -Tags "Audit" -MessageData $log    

        }
    }
    catch {
        $Log = @{
            Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
            System            = "Exchange Online" # optional (free format text) 
            Message           = "failed removing permission $($permission) for user $($user.name) [$($user.guid)] from $mailbox" # required (free format text) 
            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $user.name # optional (free format text) 
            TargetIdentifier  = $user.GUID # optional (free format text) 
        }

        Write-Information -Tags "Audit" -MessageData $log 
        write-error "Error removing permission $($permission) for user $($user.name) [$($user.guid)] from $mailbox . Error: $_"
    } 
}
catch {
    $Log = @{
        Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
        System            = "Exchange Online" # optional (free format text) 
        Message           = "error updating permission $($permission) for user $($user.name) [$($user.guid)] to $mailbox" # required (free format text) 
        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $user.name # optional (free format text) 
        TargetIdentifier  = $user.GUID # optional (free format text) 
    }

    Write-Information -Tags "Audit" -MessageData $log    
    write-error "Error updating permissions for $($user.name) [$($user.guid)] for $mailbox. Error: $_"

}
finally {
    $exchangeSessionEnd = Disconnect-ExchangeOnline -Confirm:$false -Verbose:$false -ErrorAction Stop
}
