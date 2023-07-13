# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

#HelloID variables
#Note: when running this script inside HelloID; portalUrl and API credentials are provided automatically (generate and save API credentials first in your admin panel!)
$portalUrl = "https://CUSTOMER.helloid.com"
$apiKey = "API_KEY"
$apiSecret = "API_SECRET"
$delegatedFormAccessGroupNames = @("") #Only unique names are supported. Groups must exist!
$delegatedFormCategories = @("Exchange Online") #Only unique names are supported. Categories will be created if not exists
$script:debugLogging = $false #Default value: $false. If $true, the HelloID resource GUIDs will be shown in the logging
$script:duplicateForm = $false #Default value: $false. If $true, the HelloID resource names will be changed to import a duplicate Form
$script:duplicateFormSuffix = "_tmp" #the suffix will be added to all HelloID resource names to generate a duplicate form with different resource names

#The following HelloID Global variables are used by this form. No existing HelloID global variables will be overriden only new ones are created.
#NOTE: You can also update the HelloID Global variable values afterwards in the HelloID Admin Portal: https://<CUSTOMER>.helloid.com/admin/variablelibrary
$globalHelloIDVariables = [System.Collections.Generic.List[object]]@();

#Global variable #1 >> ExchangeOnlineAdminPassword
$tmpName = @'
ExchangeOnlineAdminPassword
'@ 
$tmpValue = "" 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "True"});

#Global variable #2 >> ExchangeOnlineAdminUsername
$tmpName = @'
ExchangeOnlineAdminUsername
'@ 
$tmpValue = @'
ramon@schoulens.onmicrosoft.com
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});


#make sure write-information logging is visual
$InformationPreference = "continue"

# Check for prefilled API Authorization header
if (-not [string]::IsNullOrEmpty($portalApiBasic)) {
    $script:headers = @{"authorization" = $portalApiBasic}
    Write-Information "Using prefilled API credentials"
} else {
    # Create authorization headers with HelloID API key
    $pair = "$apiKey" + ":" + "$apiSecret"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $key = "Basic $base64"
    $script:headers = @{"authorization" = $Key}
    Write-Information "Using manual API credentials"
}

# Check for prefilled PortalBaseURL
if (-not [string]::IsNullOrEmpty($portalBaseUrl)) {
    $script:PortalBaseUrl = $portalBaseUrl
    Write-Information "Using prefilled PortalURL: $script:PortalBaseUrl"
} else {
    $script:PortalBaseUrl = $portalUrl
    Write-Information "Using manual PortalURL: $script:PortalBaseUrl"
}

# Define specific endpoint URI
$script:PortalBaseUrl = $script:PortalBaseUrl.trim("/") + "/"  

# Make sure to reveive an empty array using PowerShell Core
function ConvertFrom-Json-WithEmptyArray([string]$jsonString) {
    # Running in PowerShell Core?
    if($IsCoreCLR -eq $true){
        $r = [Object[]]($jsonString | ConvertFrom-Json -NoEnumerate)
        return ,$r  # Force return value to be an array using a comma
    } else {
        $r = [Object[]]($jsonString | ConvertFrom-Json)
        return ,$r  # Force return value to be an array using a comma
    }
}

function Invoke-HelloIDGlobalVariable {
    param(
        [parameter(Mandatory)][String]$Name,
        [parameter(Mandatory)][String][AllowEmptyString()]$Value,
        [parameter(Mandatory)][String]$Secret
    )

    $Name = $Name + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        $uri = ($script:PortalBaseUrl + "api/v1/automation/variables/named/$Name")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
    
        if ([string]::IsNullOrEmpty($response.automationVariableGuid)) {
            #Create Variable
            $body = @{
                name     = $Name;
                value    = $Value;
                secret   = $Secret;
                ItemType = 0;
            }    
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl + "api/v1/automation/variable")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $variableGuid = $response.automationVariableGuid

            Write-Information "Variable '$Name' created$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        } else {
            $variableGuid = $response.automationVariableGuid
            Write-Warning "Variable '$Name' already exists$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        }
    } catch {
        Write-Error "Variable '$Name', message: $_"
    }
}

function Invoke-HelloIDAutomationTask {
    param(
        [parameter(Mandatory)][String]$TaskName,
        [parameter(Mandatory)][String]$UseTemplate,
        [parameter(Mandatory)][String]$AutomationContainer,
        [parameter(Mandatory)][String][AllowEmptyString()]$Variables,
        [parameter(Mandatory)][String]$PowershellScript,
        [parameter()][String][AllowEmptyString()]$ObjectGuid,
        [parameter()][String][AllowEmptyString()]$ForceCreateTask,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $TaskName = $TaskName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        $uri = ($script:PortalBaseUrl +"api/v1/automationtasks?search=$TaskName&container=$AutomationContainer")
        $responseRaw = (Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false) 
        $response = $responseRaw | Where-Object -filter {$_.name -eq $TaskName}
    
        if([string]::IsNullOrEmpty($response.automationTaskGuid) -or $ForceCreateTask -eq $true) {
            #Create Task

            $body = @{
                name                = $TaskName;
                useTemplate         = $UseTemplate;
                powerShellScript    = $PowershellScript;
                automationContainer = $AutomationContainer;
                objectGuid          = $ObjectGuid;
                variables           = (ConvertFrom-Json-WithEmptyArray($Variables));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/automationtasks/powershell")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $taskGuid = $response.automationTaskGuid

            Write-Information "Powershell task '$TaskName' created$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        } else {
            #Get TaskGUID
            $taskGuid = $response.automationTaskGuid
            Write-Warning "Powershell task '$TaskName' already exists$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        }
    } catch {
        Write-Error "Powershell task '$TaskName', message: $_"
    }

    $returnObject.Value = $taskGuid
}

function Invoke-HelloIDDatasource {
    param(
        [parameter(Mandatory)][String]$DatasourceName,
        [parameter(Mandatory)][String]$DatasourceType,
        [parameter(Mandatory)][String][AllowEmptyString()]$DatasourceModel,
        [parameter()][String][AllowEmptyString()]$DatasourceStaticValue,
        [parameter()][String][AllowEmptyString()]$DatasourcePsScript,        
        [parameter()][String][AllowEmptyString()]$DatasourceInput,
        [parameter()][String][AllowEmptyString()]$AutomationTaskGuid,
        [parameter(Mandatory)][Ref]$returnObject
    )

    $DatasourceName = $DatasourceName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    $datasourceTypeName = switch($DatasourceType) { 
        "1" { "Native data source"; break} 
        "2" { "Static data source"; break} 
        "3" { "Task data source"; break} 
        "4" { "Powershell data source"; break}
    }
    
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/datasource/named/$DatasourceName")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
      
        if([string]::IsNullOrEmpty($response.dataSourceGUID)) {
            #Create DataSource
            $body = @{
                name               = $DatasourceName;
                type               = $DatasourceType;
                model              = (ConvertFrom-Json-WithEmptyArray($DatasourceModel));
                automationTaskGUID = $AutomationTaskGuid;
                value              = (ConvertFrom-Json-WithEmptyArray($DatasourceStaticValue));
                script             = $DatasourcePsScript;
                input              = (ConvertFrom-Json-WithEmptyArray($DatasourceInput));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
      
            $uri = ($script:PortalBaseUrl +"api/v1/datasource")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
              
            $datasourceGuid = $response.dataSourceGUID
            Write-Information "$datasourceTypeName '$DatasourceName' created$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        } else {
            #Get DatasourceGUID
            $datasourceGuid = $response.dataSourceGUID
            Write-Warning "$datasourceTypeName '$DatasourceName' already exists$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        }
    } catch {
      Write-Error "$datasourceTypeName '$DatasourceName', message: $_"
    }

    $returnObject.Value = $datasourceGuid
}

function Invoke-HelloIDDynamicForm {
    param(
        [parameter(Mandatory)][String]$FormName,
        [parameter(Mandatory)][String]$FormSchema,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $FormName = $FormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/forms/$FormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if(([string]::IsNullOrEmpty($response.dynamicFormGUID)) -or ($response.isUpdated -eq $true)) {
            #Create Dynamic form
            $body = @{
                Name       = $FormName;
                FormSchema = (ConvertFrom-Json-WithEmptyArray($FormSchema));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/forms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $formGuid = $response.dynamicFormGUID
            Write-Information "Dynamic form '$formName' created$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        } else {
            $formGuid = $response.dynamicFormGUID
            Write-Warning "Dynamic form '$FormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        }
    } catch {
        Write-Error "Dynamic form '$FormName', message: $_"
    }

    $returnObject.Value = $formGuid
}


function Invoke-HelloIDDelegatedForm {
    param(
        [parameter(Mandatory)][String]$DelegatedFormName,
        [parameter(Mandatory)][String]$DynamicFormGuid,
        [parameter()][Array][AllowEmptyString()]$AccessGroups,
        [parameter()][String][AllowEmptyString()]$Categories,
        [parameter(Mandatory)][String]$UseFaIcon,
        [parameter()][String][AllowEmptyString()]$FaIcon,
        [parameter()][String][AllowEmptyString()]$task,
        [parameter(Mandatory)][Ref]$returnObject
    )
    $delegatedFormCreated = $false
    $DelegatedFormName = $DelegatedFormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$DelegatedFormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if([string]::IsNullOrEmpty($response.delegatedFormGUID)) {
            #Create DelegatedForm
            $body = @{
                name            = $DelegatedFormName;
                dynamicFormGUID = $DynamicFormGuid;
                isEnabled       = "True";
                useFaIcon       = $UseFaIcon;
                faIcon          = $FaIcon;
                task            = ConvertFrom-Json -inputObject $task;
            }
            if(-not[String]::IsNullOrEmpty($AccessGroups)) { 
                $body += @{
                    accessGroups    = (ConvertFrom-Json-WithEmptyArray($AccessGroups));
                }
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Information "Delegated form '$DelegatedFormName' created$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
            $delegatedFormCreated = $true

            $bodyCategories = $Categories
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$delegatedFormGuid/categories")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $bodyCategories
            Write-Information "Delegated form '$DelegatedFormName' updated with categories"
        } else {
            #Get delegatedFormGUID
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Warning "Delegated form '$DelegatedFormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
        }
    } catch {
        Write-Error "Delegated form '$DelegatedFormName', message: $_"
    }

    $returnObject.value.guid = $delegatedFormGuid
    $returnObject.value.created = $delegatedFormCreated
}


<# Begin: HelloID Global Variables #>
foreach ($item in $globalHelloIDVariables) {
	Invoke-HelloIDGlobalVariable -Name $item.name -Value $item.value -Secret $item.secret 
}
<# End: HelloID Global Variables #>


<# Begin: HelloID Data sources #>
<# Begin: DataSource "exchange-online-user-manage-permissions-generate-table-mailbox-permissions" #>
$tmpPsScript = @'
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
'@ 
$tmpModel = @'
[{"key":"name","type":0},{"key":"id","type":0},{"key":"primarySmtpAddress","type":0},{"key":"userPrincipalName","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"selectedUser","type":0,"options":1},{"description":null,"translateDescription":false,"inputFieldType":1,"key":"Permission","type":0,"options":1}]
'@ 
$dataSourceGuid_1 = [PSCustomObject]@{} 
$dataSourceGuid_1_Name = @'
exchange-online-user-manage-permissions-generate-table-mailbox-permissions
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_1_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_1) 
<# End: DataSource "exchange-online-user-manage-permissions-generate-table-mailbox-permissions" #>

<# Begin: DataSource "exchange-online-user-manage-permissions-generate-table-mailbox" #>
$tmpPsScript = @'
# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

# Connect to Office 365
try{
    Write-Information "Connecting to Office 365.."

    $module = Import-Module ExchangeOnlineManagement

    $securePassword = ConvertTo-SecureString $ExchangeOnlineAdminPassword -AsPlainText -Force
    $credential = [System.Management.Automation.PSCredential]::new($ExchangeOnlineAdminUsername,$securePassword)

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
'@ 
$tmpModel = @'
[{"key":"name","type":0},{"key":"id","type":0},{"key":"primarySmtpAddress","type":0},{"key":"userPrincipalName","type":0}]
'@ 
$tmpInput = @'
[]
'@ 
$dataSourceGuid_2 = [PSCustomObject]@{} 
$dataSourceGuid_2_Name = @'
exchange-online-user-manage-permissions-generate-table-mailbox
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_2_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_2) 
<# End: DataSource "exchange-online-user-manage-permissions-generate-table-mailbox" #>

<# Begin: DataSource "exchange-online-user-manage-permissions-generate-table-user-wildcard" #>
$tmpPsScript = @'
# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

# Connect to Office 365
try{
    Write-Information "Connecting to Office 365.."

    $module = Import-Module ExchangeOnlineManagement

    $securePassword = ConvertTo-SecureString $ExchangeOnlineAdminPassword -AsPlainText -Force
    $credential = [System.Management.Automation.PSCredential]::new($ExchangeOnlineAdminUsername,$securePassword)

    $exchangeSession = Connect-ExchangeOnline -Credential $credential -ShowBanner:$false -ShowProgress:$false -TrackPerformance:$false -ErrorAction Stop 

    Write-Information "Successfully connected to Office 365"
}catch{
    Write-Error "Could not connect to Exchange Online, error: $_"
}

try {
    $searchValue = $datasource.searchValue
    $searchQuery = "*$searchValue*"
    
    if(-not [String]::IsNullOrEmpty($searchValue)) {
        Write-information "searchQuery: $searchQuery"    
            
        $exchangeUsers = Get-User -Filter "{Alias -like '$searchQuery' -or UserPrincipalName -like '$searchQuery' -or Name -like '$searchQuery'}" -resultSize unlimited

        $users = $exchangeUsers
        $resultCount = @($users).Count
        
        Write-Information "Result count: $resultCount"
        
        if($resultCount -gt 0){
            foreach($user in $users){
                $displayValue = $user.displayName + " [" + $user.UserPrincipalName + "]"
                $returnObject = @{
                    name=$displayValue;
                    UserPrincipalName="$($user.UserPrincipalName)";
                    id="$($user.id)";
                }

                Write-Output $returnObject
            }
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
'@ 
$tmpModel = @'
[{"key":"name","type":0},{"key":"id","type":0},{"key":"UserPrincipalName","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"searchValue","type":0,"options":1}]
'@ 
$dataSourceGuid_0 = [PSCustomObject]@{} 
$dataSourceGuid_0_Name = @'
exchange-online-user-manage-permissions-generate-table-user-wildcard
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_0_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_0) 
<# End: DataSource "exchange-online-user-manage-permissions-generate-table-user-wildcard" #>
<# End: HelloID Data sources #>

<# Begin: Dynamic Form "Exchange online - User - Manage permissions" #>
$tmpSchema = @"
[{"label":"Details","fields":[{"templateOptions":{},"type":"markdown","summaryVisibility":"Show","body":"Retrieving this information from Exchange takes an average of +/- 10 seconds.  \nPlease wait while we load the data.","requiresTemplateOptions":false,"requiresKey":false,"requiresDataSource":false},{"key":"searchMailbox","templateOptions":{"label":"Search","placeholder":""},"type":"input","summaryVisibility":"Hide element","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"gridUser","templateOptions":{"label":"User","required":false,"grid":{"columns":[{"headerName":"Name","field":"name"},{"headerName":"User Principal Name","field":"UserPrincipalName"},{"headerName":"Id","field":"id"}],"height":300,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_0","input":{"propertyInputs":[{"propertyName":"searchValue","otherFieldValue":{"otherFieldKey":"searchMailbox"}}]}},"useFilter":true,"useDefault":false},"type":"grid","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":true}]},{"label":"User Permissions","fields":[{"templateOptions":{},"type":"markdown","summaryVisibility":"Show","body":"Retrieving this information from Exchange takes an average of +/- 30 seconds.  \nPlease wait while we load the data.","requiresTemplateOptions":false,"requiresKey":false,"requiresDataSource":false},{"key":"permission","templateOptions":{"label":"Permission","required":false,"useObjects":true,"useDataSource":false,"useFilter":false,"options":[{"value":"fullaccess","text":"Full Access"},{"value":"sendas","text":"Send As"},{"value":"sendonbehalf","text":"Send on Behalf"}]},"type":"dropdown","summaryVisibility":"Show","textOrLabel":"text","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"permissionList","templateOptions":{"label":"Permissions","required":false,"filterable":true,"useDataSource":true,"dualList":{"options":[{"guid":"75ea2890-88f8-4851-b202-626123054e14","Name":"Apple"},{"guid":"0607270d-83e2-4574-9894-0b70011b663f","Name":"Pear"},{"guid":"1ef6fe01-3095-4614-a6db-7c8cd416ae3b","Name":"Orange"}],"optionKeyProperty":"id","optionDisplayProperty":"name"},"destinationDataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_1","input":{"propertyInputs":[{"propertyName":"selectedUser","otherFieldValue":{"otherFieldKey":"gridUser"}},{"propertyName":"Permission","otherFieldValue":{"otherFieldKey":"permission"}}]}},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_2","input":{"propertyInputs":[]}}},"type":"duallist","summaryVisibility":"Show","sourceDataSourceIdentifierSuffix":"source-datasource","destinationDataSourceIdentifierSuffix":"destination-datasource","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false}]}]
"@ 

$dynamicFormGuid = [PSCustomObject]@{} 
$dynamicFormName = @'
Exchange online - User - Manage permissions
'@ 
Invoke-HelloIDDynamicForm -FormName $dynamicFormName -FormSchema $tmpSchema  -returnObject ([Ref]$dynamicFormGuid) 
<# END: Dynamic Form #>

<# Begin: Delegated Form Access Groups and Categories #>
$delegatedFormAccessGroupGuids = @()
if(-not[String]::IsNullOrEmpty($delegatedFormAccessGroupNames)){
    foreach($group in $delegatedFormAccessGroupNames) {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/groups/$group")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
            $delegatedFormAccessGroupGuid = $response.groupGuid
            $delegatedFormAccessGroupGuids += $delegatedFormAccessGroupGuid
            
            Write-Information "HelloID (access)group '$group' successfully found$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormAccessGroupGuid })"
        } catch {
            Write-Error "HelloID (access)group '$group', message: $_"
        }
    }
    if($null -ne $delegatedFormAccessGroupGuids){
        $delegatedFormAccessGroupGuids = ($delegatedFormAccessGroupGuids | Select-Object -Unique | ConvertTo-Json -Depth 100 -Compress)
    }
}

$delegatedFormCategoryGuids = @()
foreach($category in $delegatedFormCategories) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories/$category")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $response = $response | Where-Object {$_.name.en -eq $category}
        
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid
        
        Write-Information "HelloID Delegated Form category '$category' successfully found$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    } catch {
        Write-Warning "HelloID Delegated Form category '$category' not found"
        $body = @{
            name = @{"en" = $category};
        }
        $body = ConvertTo-Json -InputObject $body -Depth 100

        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid

        Write-Information "HelloID Delegated Form category '$category' successfully created$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    }
}
$delegatedFormCategoryGuids = (ConvertTo-Json -InputObject $delegatedFormCategoryGuids -Depth 100 -Compress)
<# End: Delegated Form Access Groups and Categories #>

<# Begin: Delegated Form #>
$delegatedFormRef = [PSCustomObject]@{guid = $null; created = $null} 
$delegatedFormName = @'
Exchange online - User - Manage permissions
'@
$tmpTask = @'
{"name":"Exchange online - User - Manage permissions","script":"# Fixed values\r\n$AutoMapping = $false\r\n\r\n$permission = $form.permission\r\n$identity = $form.gridUser.id\r\n$mailboxesToAdd = $form.permissionList.leftToRight\r\n$mailboxesToRemove = $form.permissionList.rightToLeft\r\n\r\ntry {\r\n    # Set TLS to accept TLS, TLS 1.1 and TLS 1.2\r\n    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12\r\n\r\n    # Connect to Office 365\r\n    try {\r\n        $module = Import-Module ExchangeOnlineManagement\r\n\r\n        $securePassword = ConvertTo-SecureString $ExchangeOnlineAdminPassword -AsPlainText -Force\r\n        $credential = [System.Management.Automation.PSCredential]::new($ExchangeOnlineAdminUsername, $securePassword)\r\n\r\n        $exchangeSession = Connect-ExchangeOnline -Credential $credential -ShowBanner:$false -ShowProgress:$false -TrackPerformance:$false -ErrorAction Stop \r\n\r\n    }\r\n    catch {     \r\n        $Log = @{\r\n            Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \r\n            System            = \"Exchange Online\" # optional (free format text) \r\n            Message           = \"Could not connect to Exchange Online, error: $_\" # required (free format text) \r\n            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n            TargetDisplayName = $exchangeConnectionUri # optional (free format text) \r\n            TargetIdentifier  = $([string]$session.GUID) # optional (free format text) \r\n        }\r\n        #send result back  \r\n        Write-Information -Tags \"Audit\" -MessageData $log\r\n    }\r\n\r\n    $user = Get-User -Identity $identity -ErrorAction Stop\r\n    if ($user.Name.Count -eq 0) {\r\n        throw \"Could not find user with identity \u0027$($identity)\u0027\"\r\n    }\r\n\r\n    # Add permissions to users\r\n    try { \r\n        foreach ($mailbox in $mailboxesToAdd.id) {\r\n            if ($permission.ToLower() -eq \"fullaccess\") {\r\n                if ($AutoMapping) {\r\n                    Add-MailboxPermission -Identity $mailbox -AccessRights FullAccess -InheritanceType All -AutoMapping:$true -User $user.id -ErrorAction Stop\r\n                }\r\n                else {\r\n                    Add-MailboxPermission -Identity $mailbox -AccessRights FullAccess -InheritanceType All -AutoMapping:$false -User $user.id -ErrorAction Stop\r\n                }\r\n            }\r\n            elseif ($permission.ToLower() -eq \"sendas\") {\r\n                Add-RecipientPermission -Identity $mailbox -AccessRights SendAs -Confirm:$false -Trustee $User.id -ErrorAction Stop\r\n            }\r\n            elseif ($permission.ToLower() -eq \"sendonbehalf\") {\r\n                Set-Mailbox -Identity $mailbox -GrantSendOnBehalfTo @{add = \"$($user.id)\" } -Confirm:$false -ErrorAction Stop\r\n            }\r\n            else {\r\n                throw \"Could not match right \u0027$($permission)\u0027 to FullAccess, SendAs or SendOnBehalf\"\r\n            }\r\n\r\n            $Log = @{\r\n                Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \r\n                System            = \"Exchange Online\" # optional (free format text) \r\n                Message           = \"Successfully added permission $($permission) for user $($user.name) [$($user.guid)] to $mailbox\" # required (free format text) \r\n                IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                TargetDisplayName = $user.name # optional (free format text) \r\n                TargetIdentifier  = $user.GUID # optional (free format text) \r\n            }\r\n\r\n            Write-Information -Tags \"Audit\" -MessageData $log    \r\n\r\n        }\r\n    }\r\n    catch {\r\n        $Log = @{\r\n            Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \r\n            System            = \"Exchange Online\" # optional (free format text) \r\n            Message           = \"failed to add permission $($permission) for user $($user.name) [$($user.guid)] to $mailbox\" # required (free format text) \r\n            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n            TargetDisplayName = $user.name # optional (free format text) \r\n            TargetIdentifier  = $user.GUID # optional (free format text) \r\n        }\r\n\r\n        Write-Information -Tags \"Audit\" -MessageData $log    \r\n        write-error \"Error adding permission $($permission) to user  $($user.name) [$($user.guid)] for $mailbox . Error: $_\"\r\n    }\r\n\r\n    # Remove permissions from users\r\n    try { \r\n\r\n        foreach ($mailbox in $mailboxesToRemove.id) {\r\n            if ($permission.ToLower() -eq \"fullaccess\") {\r\n                Remove-MailboxPermission -Identity $mailbox -AccessRights FullAccess -InheritanceType All -User $User.id -Confirm:$false -ErrorAction Stop\r\n            }\r\n            elseif ($permission.ToLower() -eq \"sendas\") {\r\n                Remove-RecipientPermission -Identity $mailbox -AccessRights SendAs -Confirm:$false -Trustee $User.id -ErrorAction Stop\r\n            }\r\n            elseif ($permission.ToLower() -eq \"sendonbehalf\") {\r\n                Set-Mailbox -Identity $mailbox -GrantSendOnBehalfTo @{remove = \"$($user.id)\" } -Confirm:$false -ErrorAction Stop\r\n            }\r\n            else {\r\n                throw \"Could not match right \u0027$($permission)\u0027 to FullAccess, SendAs or SendOnBehalf\"\r\n            }\r\n\r\n            $Log = @{\r\n                Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \r\n                System            = \"Exchange Online\" # optional (free format text) \r\n                Message           = \"Successfully removed permission $($permission) for user $($user.name) [$($user.guid)] from $mailbox\" # required (free format text) \r\n                IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                TargetDisplayName = $user.name # optional (free format text) \r\n                TargetIdentifier  = $user.GUID # optional (free format text) \r\n            }\r\n\r\n            Write-Information -Tags \"Audit\" -MessageData $log    \r\n\r\n        }\r\n    }\r\n    catch {\r\n        $Log = @{\r\n            Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \r\n            System            = \"Exchange Online\" # optional (free format text) \r\n            Message           = \"failed removing permission $($permission) for user $($user.name) [$($user.guid)] from $mailbox\" # required (free format text) \r\n            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n            TargetDisplayName = $user.name # optional (free format text) \r\n            TargetIdentifier  = $user.GUID # optional (free format text) \r\n        }\r\n\r\n        Write-Information -Tags \"Audit\" -MessageData $log \r\n        write-error \"Error removing permission $($permission) for user $($user.name) [$($user.guid)] from $mailbox . Error: $_\"\r\n    } \r\n}\r\ncatch {\r\n    $Log = @{\r\n        Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \r\n        System            = \"Exchange Online\" # optional (free format text) \r\n        Message           = \"error updating permission $($permission) for user $($user.name) [$($user.guid)] to $mailbox\" # required (free format text) \r\n        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n        TargetDisplayName = $user.name # optional (free format text) \r\n        TargetIdentifier  = $user.GUID # optional (free format text) \r\n    }\r\n\r\n    Write-Information -Tags \"Audit\" -MessageData $log    \r\n    write-error \"Error updating permissions for $($user.name) [$($user.guid)] for $mailbox. Error: $_\"\r\n\r\n}\r\nfinally {\r\n    $exchangeSessionEnd = Disconnect-ExchangeOnline -Confirm:$false -Verbose:$false -ErrorAction Stop\r\n}","runInCloud":false}
'@ 

Invoke-HelloIDDelegatedForm -DelegatedFormName $delegatedFormName -DynamicFormGuid $dynamicFormGuid -AccessGroups $delegatedFormAccessGroupGuids -Categories $delegatedFormCategoryGuids -UseFaIcon "True" -FaIcon "fa fa-pencil-square-o" -task $tmpTask -returnObject ([Ref]$delegatedFormRef) 
<# End: Delegated Form #>

