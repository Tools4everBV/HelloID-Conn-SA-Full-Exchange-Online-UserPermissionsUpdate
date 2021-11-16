<!-- Description -->
## Description
This HelloID Service Automation Delegated Form provides Exchange Online (Office365) user functionality. The following steps will be performed:
 1. Search and select the target user
 2. Select a permission (Full Access, Send As or Send on Behalf)
 3. Modify mailboxes to which the user has permissions
 4. After confirmation the updates are processed (add or remove premissions)
 
## Versioning
| Version | Description | Date |
| - | - | - |
| 1.0.1   | Added version number and updated all-in-one script | 2021/11/16  |
| 1.0.0   | Initial release | 2021/04/29  |

<!-- TABLE OF CONTENTS -->
## Table of Contents
- [HelloID-Conn-SA-Source-HelloID-SelfserviceProducts](#helloid-conn-sa-source-helloid-selfserviceproducts)
  - [Version](#version)
  - [Description](#description)
  - [Table of Contents](#table-of-contents)
  - [All-in-one PowerShell setup script](#all-in-one-powershell-setup-script)
  - [Getting started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Post-setup configuration](#post-setup-configuration)
  - [Manual resources](#manual-resources)
    - [Powershell data source 'exchange-online-shared-mailbox-manage-permissions-generate-table-mailbox-wildcard'](#powershell-data-source-exchange-online-shared-mailbox-manage-permissions-generate-table-mailbox-wildcard)
    - [Powershell data source 'Exchange-user-generate-table-sharedmailbox-manage-generate-table-users-permission'](#powershell-data-source-exchange-user-generate-table-sharedmailbox-manage-generate-table-users-permission)
    - [Powershell data source 'Exchange-user-generate-table-sharedmailbox-manage-generate-table-users'](#powershell-data-source-exchange-user-generate-table-sharedmailbox-manage-generate-table-users)
    - [Delegated form task 'exchange-online-shared-mailbox-manage-permissions-set'](#delegated-form-task-exchange-online-shared-mailbox-manage-permissions-set)
  - [Known limitations](#known-limitations)
- [HelloID Docs](#helloid-docs)
- [Forum Thread](#forum-thread)

## All-in-one PowerShell setup script
The PowerShell script "createform.ps1" contains a complete PowerShell script using the HelloID API to create the complete Form including user defined variables, tasks and data sources.

 _Please note that this script asumes none of the required resources do exists within HelloID. The script does not contain versioning or source control_

## Getting started

### Prerequisites

- [ ] Exchange Online PowerShell V2 module
  This HelloID Service Automation Delegated Form uses the [Exchange Online PowerShell V2 module](https://docs.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps)

### Post-setup configuration
| Variable name                 | Description               | Example value     |
| ----------------------------- | ------------------------- | ----------------- |
| ExchangeOnlineAdminUsername   |Exchange admin account     | user@domain.com   |
| ExchangeOnlineAdminPassword   | Exchange admin password   | ********          |


## Manual resources
This Delegated Form uses the following resources in order to run

### Powershell data source 'exchange-online-user-manage-permissions-generate-table-user-wildcard'
This Static data source queries the Exchange Online users based on a wildcard.

### Powershell data source 'exchange-online-user-manage-permissions-generate-table-mailbox'
This Static data source queries the Exchange Online mailboxes.

### Powershell data source 'exchange-online-user-manage-permissions-generate-table-mailbox-permissions'
This Static data source queries the Exchange Online mailboxes the selected user has permissions to.

### Delegated form task 'exchange-online-user-manage-permissions-set'
This delegated form task will update the permissions for the user to the mailboxes in Exchange.

## Known limitations
 * Querying the mailboxes to which the user has 'Full Access' or 'Send As'permissions to can take extremely long, depending on the amount of mailboxes. Sadly, we cannot improve this since we have to check the permissions for each mailbox. To improve the performance we would advise to make use of permissions groups and assign these to the users. (Azure) AD groups can be queried much faster than Exchange permissions

## Getting help
_If you need help, feel free to ask questions on our [forum](https://forum.helloid.com/forum/helloid-connectors/service-automation/304-helloid-sa-exchange-online-update-user-permissions)_

## HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/
