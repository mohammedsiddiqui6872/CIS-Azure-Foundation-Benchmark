@{
    BenchmarkVersion = 'v5.0.0'
    BenchmarkDate    = '09-30-2025'
    TotalControls    = 152

    Controls = @(
        # =====================================================================
        # SECTION 2: ANALYTICS SERVICES - Azure Databricks (11 controls)
        # =====================================================================
        @{
            ControlId        = '2.1.1'
            Title            = "Ensure that Azure Databricks is deployed in a customer-managed virtual network (VNet)"
            Section          = 'Analytics Services'
            Subsection       = 'Azure Databricks'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS211-DatabricksVNet'
            Description      = 'Azure Databricks should be deployed within a customer-managed VNet for network isolation and security control.'
            Remediation      = 'Deploy Azure Databricks workspace with VNet injection enabled. This cannot be changed after deployment - a new workspace must be created.'
            References       = @('https://learn.microsoft.com/en-us/azure/databricks/security/network/classic/vnet-inject')
            CISControls      = @('v8:12.2', 'v7:14.1')
        }
        @{
            ControlId        = '2.1.2'
            Title            = "Ensure that network security groups are configured for Databricks subnets"
            Section          = 'Analytics Services'
            Subsection       = 'Azure Databricks'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS212-DatabricksNSG'
            Description      = 'Network security groups should be associated with the subnets used by Azure Databricks to control network traffic.'
            Remediation      = 'Associate NSGs with the public and private subnets used by Azure Databricks workspaces.'
            References       = @('https://learn.microsoft.com/en-us/azure/databricks/security/network/classic/vnet-inject')
            CISControls      = @('v8:12.2', 'v7:9.4')
        }
        @{
            ControlId        = '2.1.3'
            Title            = "Ensure that traffic is encrypted between cluster worker nodes"
            Section          = 'Analytics Services'
            Subsection       = 'Azure Databricks'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 2
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'Encrypt traffic between Databricks cluster worker nodes to protect data in transit.'
            Remediation      = 'Enable encryption for inter-node traffic in the Databricks cluster configuration. Add init scripts or configure workspace settings for encryption.'
            ManualGuidance   = 'Navigate to Azure Databricks workspace > Clusters > Cluster Configuration. Verify that encryption is enabled for inter-node communication. Check cluster policies and init scripts for encryption settings.'
            References       = @('https://learn.microsoft.com/en-us/azure/databricks/security/encryption')
            CISControls      = @('v8:3.10', 'v7:14.4')
        }
        @{
            ControlId        = '2.1.4'
            Title            = "Ensure that users and groups are synced from Microsoft Entra ID to Azure Databricks"
            Section          = 'Analytics Services'
            Subsection       = 'Azure Databricks'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'Users and groups should be synced from Microsoft Entra ID to Azure Databricks for centralized identity management.'
            Remediation      = 'Configure SCIM provisioning from Microsoft Entra ID to Azure Databricks to sync users and groups automatically.'
            ManualGuidance   = 'Navigate to Microsoft Entra ID > Enterprise Applications > Azure Databricks > Provisioning. Verify that provisioning is configured and active with users/groups being synced.'
            References       = @('https://learn.microsoft.com/en-us/azure/databricks/administration-guide/users-groups/scim/')
            CISControls      = @('v8:6.7', 'v7:16.2')
        }
        @{
            ControlId        = '2.1.5'
            Title            = "Ensure that Unity Catalog is configured for Azure Databricks"
            Section          = 'Analytics Services'
            Subsection       = 'Azure Databricks'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'Unity Catalog provides centralized governance for data and AI assets in Azure Databricks.'
            Remediation      = 'Configure Unity Catalog for the Azure Databricks workspace to enable centralized data governance, fine-grained access control, and data lineage.'
            ManualGuidance   = 'Navigate to Azure Databricks workspace > Data section. Verify Unity Catalog is configured with metastores, catalogs, and schemas properly set up.'
            References       = @('https://learn.microsoft.com/en-us/azure/databricks/data-governance/unity-catalog/')
            CISControls      = @('v8:3.3', 'v7:14.6')
        }
        @{
            ControlId        = '2.1.6'
            Title            = "Ensure that usage is restricted and expiry is enforced for Databricks personal access tokens"
            Section          = 'Analytics Services'
            Subsection       = 'Azure Databricks'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'Personal access tokens (PAT) in Databricks should have restricted usage and enforced expiry to limit exposure.'
            Remediation      = 'Configure workspace-level token management to restrict PAT creation and enforce maximum lifetime policies.'
            ManualGuidance   = 'Navigate to Azure Databricks workspace > Admin Settings > Token Management. Verify that token lifetime is restricted and token creation permissions are limited.'
            References       = @('https://learn.microsoft.com/en-us/azure/databricks/administration-guide/access-control/tokens')
            CISControls      = @('v8:6.2', 'v7:16.4')
        }
        @{
            ControlId        = '2.1.7'
            Title            = "Ensure that diagnostic log delivery is configured for Azure Databricks"
            Section          = 'Analytics Services'
            Subsection       = 'Azure Databricks'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS217-DatabricksDiagnostics'
            Description      = 'Diagnostic logs should be configured and delivered to a monitoring solution for Azure Databricks workspaces.'
            Remediation      = 'Configure diagnostic settings for each Azure Databricks workspace to send logs to Log Analytics, Storage Account, or Event Hub.'
            References       = @('https://learn.microsoft.com/en-us/azure/databricks/administration-guide/account-settings/azure-diagnostic-logs')
            CISControls      = @('v8:8.2', 'v7:6.2')
        }
        @{
            ControlId        = '2.1.8'
            Title            = "Ensure critical data in Azure Databricks is encrypted with customer-managed keys (CMK)"
            Section          = 'Analytics Services'
            Subsection       = 'Azure Databricks'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 2
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'Critical data stored in Azure Databricks should be encrypted using customer-managed keys for additional control over encryption.'
            Remediation      = 'Configure customer-managed keys (CMK) for Azure Databricks workspace encryption using Azure Key Vault.'
            ManualGuidance   = 'Navigate to Azure Databricks workspace > Encryption. Verify that customer-managed keys are configured and the Key Vault reference is valid.'
            References       = @('https://learn.microsoft.com/en-us/azure/databricks/security/keys/customer-managed-keys')
            CISControls      = @('v8:3.11', 'v7:14.8')
        }
        @{
            ControlId        = '2.1.9'
            Title            = "Ensure 'No Public IP' is set to 'Enabled'"
            Section          = 'Analytics Services'
            Subsection       = 'Azure Databricks'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS219-DatabricksNoPublicIP'
            Description      = 'Azure Databricks workspaces should be configured with No Public IP enabled to prevent cluster nodes from having public IP addresses.'
            Remediation      = 'Enable the No Public IP setting for Azure Databricks workspaces. New workspaces should be deployed with this setting; existing workspaces may need redeployment.'
            References       = @('https://learn.microsoft.com/en-us/azure/databricks/security/network/secure-cluster-connectivity')
            CISControls      = @('v8:12.2', 'v7:9.2')
        }
        @{
            ControlId        = '2.1.10'
            Title            = "Ensure 'Allow Public Network Access' is set to 'Disabled'"
            Section          = 'Analytics Services'
            Subsection       = 'Azure Databricks'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS2110-DatabricksPublicAccess'
            Description      = 'Public network access to Azure Databricks workspaces should be disabled to restrict access to private networks only.'
            Remediation      = 'Set Allow Public Network Access to Disabled on the Azure Databricks workspace network settings.'
            References       = @('https://learn.microsoft.com/en-us/azure/databricks/security/network/front-end/private-link')
            CISControls      = @('v8:12.2', 'v7:9.2')
        }
        @{
            ControlId        = '2.1.11'
            Title            = "Ensure private endpoints are used to access Azure Databricks workspaces"
            Section          = 'Analytics Services'
            Subsection       = 'Azure Databricks'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 2
            Severity         = 'High'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS2111-DatabricksPrivateEndpoints'
            Description      = 'Private endpoints should be used to access Azure Databricks workspaces for secure connectivity over the Microsoft backbone network.'
            Remediation      = 'Create private endpoints for Azure Databricks workspaces and configure DNS settings appropriately.'
            References       = @('https://learn.microsoft.com/en-us/azure/databricks/security/network/front-end/private-link')
            CISControls      = @('v8:12.2', 'v7:14.1')
        }

        # =====================================================================
        # SECTION 3: COMPUTE SERVICES - Virtual Machines (1 control)
        # =====================================================================
        @{
            ControlId        = '3.1.1'
            Title            = "Ensure only MFA enabled identities can access privileged Virtual Machine"
            Section          = 'Compute Services'
            Subsection       = 'Virtual Machines'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 2
            Severity         = 'High'
            CheckPattern     = 'ManualCheck'
            Description      = 'Only identities with MFA enabled should have privileged access to virtual machines.'
            Remediation      = 'Configure Conditional Access policies to require MFA for privileged VM access. Use Azure AD authentication for VM login.'
            ManualGuidance   = 'Review Conditional Access policies for VM access. Ensure MFA is required for any identity with administrative access to virtual machines. Check Azure AD login integration for VMs.'
            References       = @('https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mfa-howitworks')
            CISControls      = @('v8:6.4', 'v7:4.5')
        }

        # =====================================================================
        # SECTION 5: IDENTITY SERVICES (28 controls)
        # =====================================================================

        # 5.1 Security Defaults (Per-User MFA)
        @{
            ControlId        = '5.1.1'
            Title            = "Ensure that 'security defaults' is enabled in Microsoft Entra ID"
            Section          = 'Identity Services'
            Subsection       = 'Security Defaults (Per-User MFA)'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'GraphAPIProperty'
            GraphEndpoint    = 'policies/identitySecurityDefaultsEnforcementPolicy'
            PropertyPath     = 'IsEnabled'
            ExpectedValue    = $true
            Description      = 'Security defaults provide secure default settings managed by Microsoft. When enabled, all users must register for MFA.'
            Remediation      = 'Navigate to Microsoft Entra ID > Properties > Manage security defaults > Enable security defaults = Yes.'
            References       = @('https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults')
            CISControls      = @('v8:6.3', 'v7:4.5')
        }
        @{
            ControlId        = '5.1.2'
            Title            = "Ensure that 'multifactor authentication' is 'enabled' for all users"
            Section          = 'Identity Services'
            Subsection       = 'Security Defaults (Per-User MFA)'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Critical'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS512-MFAAllUsers'
            Description      = 'All users should have multifactor authentication enabled to protect against credential compromise.'
            Remediation      = 'Enable MFA for all users through Security Defaults, Conditional Access policies, or Per-User MFA settings.'
            References       = @('https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-userstates')
            CISControls      = @('v8:6.3', 'v7:4.5')
        }
        @{
            ControlId        = '5.1.3'
            Title            = "Ensure that 'Allow users to remember multifactor authentication on devices they trust' is disabled"
            Section          = 'Identity Services'
            Subsection       = 'Security Defaults (Per-User MFA)'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'The remember MFA feature should be disabled to ensure users authenticate with MFA on every sign-in.'
            Remediation      = 'Navigate to Microsoft Entra ID > Users > Per-user MFA > Service settings. Set "Allow users to remember MFA on devices they trust" to disabled.'
            ManualGuidance   = 'Navigate to Microsoft Entra ID > Users > Per-user MFA > Service settings. Verify "Allow users to remember multi-factor authentication on devices they trust" is not checked.'
            References       = @('https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-mfasettings')
            CISControls      = @('v8:6.3', 'v7:4.5')
        }

        # 5.2 Conditional Access
        @{
            ControlId        = '5.2.1'
            Title            = "Ensure that 'trusted locations' are defined"
            Section          = 'Identity Services'
            Subsection       = 'Conditional Access'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 2
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'Trusted locations should be defined to establish known network locations for Conditional Access policies.'
            Remediation      = 'Navigate to Microsoft Entra ID > Security > Conditional Access > Named locations. Define trusted locations based on IP ranges or countries.'
            ManualGuidance   = 'Navigate to Microsoft Entra ID > Security > Conditional Access > Named locations. Verify that named locations are defined with appropriate IP ranges or country selections.'
            References       = @('https://learn.microsoft.com/en-us/entra/identity/conditional-access/location-condition')
            CISControls      = @('v8:12.1', 'v7:11.1')
        }
        @{
            ControlId        = '5.2.2'
            Title            = "Ensure that an exclusionary geographic Conditional Access policy is considered"
            Section          = 'Identity Services'
            Subsection       = 'Conditional Access'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 2
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'An exclusionary geographic Conditional Access policy should block access from countries/regions where the organization does not operate.'
            Remediation      = 'Create a Conditional Access policy that blocks access from all countries except those where the organization operates.'
            ManualGuidance   = 'Navigate to Microsoft Entra ID > Security > Conditional Access > Policies. Verify a policy exists that blocks sign-ins from untrusted geographic locations.'
            References       = @('https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-location')
            CISControls      = @('v8:12.1', 'v7:11.1')
        }
        @{
            ControlId        = '5.2.3'
            Title            = "Ensure that an exclusionary device code flow policy is considered"
            Section          = 'Identity Services'
            Subsection       = 'Conditional Access'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 2
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'A Conditional Access policy should be considered to block or restrict device code flow authentication to prevent phishing attacks.'
            Remediation      = 'Create a Conditional Access policy that blocks device code flow for most users, allowing exceptions only where necessary.'
            ManualGuidance   = 'Navigate to Microsoft Entra ID > Security > Conditional Access > Policies. Verify a policy exists that addresses device code flow authentication.'
            References       = @('https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-flows')
            CISControls      = @('v8:6.3', 'v7:4.5')
        }
        @{
            ControlId        = '5.2.4'
            Title            = "Ensure that a multifactor authentication policy exists for all users"
            Section          = 'Identity Services'
            Subsection       = 'Conditional Access'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 2
            Severity         = 'High'
            CheckPattern     = 'ManualCheck'
            Description      = 'A Conditional Access policy should require MFA for all users to ensure strong authentication across the organization.'
            Remediation      = 'Create a Conditional Access policy targeting all users that requires multifactor authentication for all cloud apps.'
            ManualGuidance   = 'Navigate to Microsoft Entra ID > Security > Conditional Access > Policies. Verify a policy exists targeting All Users requiring MFA for All Cloud Apps.'
            References       = @('https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-all-users-mfa')
            CISControls      = @('v8:6.3', 'v7:4.5')
        }
        @{
            ControlId        = '5.2.5'
            Title            = "Ensure that multifactor authentication is required for risky sign-ins"
            Section          = 'Identity Services'
            Subsection       = 'Conditional Access'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 2
            Severity         = 'High'
            CheckPattern     = 'ManualCheck'
            Description      = 'MFA should be required for sign-ins identified as risky by Identity Protection.'
            Remediation      = 'Create a Conditional Access policy that requires MFA when sign-in risk is medium or high.'
            ManualGuidance   = 'Navigate to Microsoft Entra ID > Security > Conditional Access > Policies. Verify a risk-based policy requires MFA for medium and high risk sign-ins.'
            References       = @('https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-risk')
            CISControls      = @('v8:6.3', 'v7:4.5')
        }
        @{
            ControlId        = '5.2.6'
            Title            = "Ensure that multifactor authentication is required for Windows Azure Service Management API"
            Section          = 'Identity Services'
            Subsection       = 'Conditional Access'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 2
            Severity         = 'High'
            CheckPattern     = 'ManualCheck'
            Description      = 'MFA should be required when accessing the Windows Azure Service Management API to protect administrative actions.'
            Remediation      = 'Create a Conditional Access policy targeting the Windows Azure Service Management API app that requires MFA.'
            ManualGuidance   = 'Navigate to Microsoft Entra ID > Security > Conditional Access > Policies. Verify a policy targets the Windows Azure Service Management API and requires MFA.'
            References       = @('https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-azure-management')
            CISControls      = @('v8:6.3', 'v7:4.5')
        }
        @{
            ControlId        = '5.2.7'
            Title            = "Ensure that multifactor authentication is required to access Microsoft Admin Portals"
            Section          = 'Identity Services'
            Subsection       = 'Conditional Access'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 2
            Severity         = 'High'
            CheckPattern     = 'ManualCheck'
            Description      = 'MFA should be required when accessing Microsoft Admin Portals to protect administrative interfaces.'
            Remediation      = 'Create a Conditional Access policy targeting Microsoft Admin Portals that requires MFA.'
            ManualGuidance   = 'Navigate to Microsoft Entra ID > Security > Conditional Access > Policies. Verify a policy targets Microsoft Admin Portals and requires MFA.'
            References       = @('https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-admin-mfa')
            CISControls      = @('v8:6.3', 'v7:4.5')
        }
        @{
            ControlId        = '5.2.8'
            Title            = "Ensure a Token Protection Conditional Access policy is considered"
            Section          = 'Identity Services'
            Subsection       = 'Conditional Access'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 2
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'Token protection binds tokens to the device they were issued to, preventing token theft and replay attacks.'
            Remediation      = 'Create a Conditional Access policy with token protection enabled to prevent token replay attacks.'
            ManualGuidance   = 'Navigate to Microsoft Entra ID > Security > Conditional Access > Policies. Verify a policy with session control "Require token protection for sign-in sessions" is configured.'
            References       = @('https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-token-protection')
            CISControls      = @('v8:6.3', 'v7:16.4')
        }

        # 5.3 Periodic Identity Reviews
        @{
            ControlId        = '5.3.1'
            Title            = "Ensure that Azure admin accounts are not used for daily operations"
            Section          = 'Identity Services'
            Subsection       = 'Periodic Identity Reviews'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'ManualCheck'
            Description      = 'Dedicated administrative accounts should not be used for daily operations to minimize attack surface.'
            Remediation      = 'Create separate accounts for administrative tasks. Do not use admin accounts for email, web browsing, or other daily activities.'
            ManualGuidance   = 'Review admin account usage patterns. Ensure admin accounts are not used for daily activities like email or web browsing. Consider implementing privileged access workstations.'
            References       = @('https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices')
            CISControls      = @('v8:5.4', 'v7:4.1')
        }
        @{
            ControlId        = '5.3.2'
            Title            = "Ensure that guest users are reviewed on a regular basis"
            Section          = 'Identity Services'
            Subsection       = 'Periodic Identity Reviews'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'Guest user accounts should be regularly reviewed and removed when no longer needed.'
            Remediation      = 'Implement a regular access review for guest users using Microsoft Entra Access Reviews or a manual process.'
            ManualGuidance   = 'Navigate to Microsoft Entra ID > Users > Filter by User type = Guest. Review each guest account for continued business need. Consider setting up automated access reviews.'
            References       = @('https://learn.microsoft.com/en-us/entra/identity/users/clean-up-stale-guest-accounts')
            CISControls      = @('v8:6.1', 'v7:16.8')
        }
        @{
            ControlId        = '5.3.3'
            Title            = "Ensure that use of the 'User Access Administrator' role is restricted"
            Section          = 'Identity Services'
            Subsection       = 'Periodic Identity Reviews'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS533-UserAccessAdmin'
            Description      = 'The User Access Administrator role allows assigning access to Azure resources. This role should be tightly restricted.'
            Remediation      = 'Remove unnecessary User Access Administrator role assignments, especially at the root scope (/).'
            References       = @('https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles')
            CISControls      = @('v8:6.1', 'v7:4.1')
        }
        @{
            ControlId        = '5.3.4'
            Title            = "Ensure that all 'privileged' role assignments are periodically reviewed"
            Section          = 'Identity Services'
            Subsection       = 'Periodic Identity Reviews'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'ManualCheck'
            Description      = 'Privileged role assignments should be periodically reviewed to ensure least privilege access.'
            Remediation      = 'Configure access reviews for privileged roles using Microsoft Entra Privileged Identity Management or establish a manual review process.'
            ManualGuidance   = 'Navigate to Microsoft Entra ID > Roles and administrators. Review users assigned to privileged roles (Global Administrator, Security Administrator, etc.). Ensure assignments are still needed.'
            References       = @('https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-create-roles-and-resource-roles-review')
            CISControls      = @('v8:6.1', 'v7:4.1')
        }
        @{
            ControlId        = '5.3.5'
            Title            = "Ensure disabled user accounts do not have read, write, or owner permissions"
            Section          = 'Identity Services'
            Subsection       = 'Periodic Identity Reviews'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'ManualCheck'
            Description      = 'Disabled user accounts should not retain any Azure RBAC role assignments.'
            Remediation      = 'Remove all Azure RBAC role assignments from disabled user accounts across all subscriptions and resource groups.'
            ManualGuidance   = 'Cross-reference disabled Entra ID accounts with Azure RBAC role assignments. Remove any role assignments found on disabled accounts.'
            References       = @('https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-list-portal')
            CISControls      = @('v8:6.1', 'v7:16.8')
        }
        @{
            ControlId        = '5.3.6'
            Title            = "Ensure 'Tenant Creator' role assignments are periodically reviewed"
            Section          = 'Identity Services'
            Subsection       = 'Periodic Identity Reviews'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'The Tenant Creator role allows creating new tenants. Assignments should be periodically reviewed.'
            Remediation      = 'Review and remove unnecessary Tenant Creator role assignments. Restrict this role to authorized personnel only.'
            ManualGuidance   = 'Navigate to Microsoft Entra ID > Roles and administrators > Tenant Creator. Review all assignments and remove those that are no longer needed.'
            References       = @('https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference')
            CISControls      = @('v8:6.1', 'v7:4.1')
        }
        @{
            ControlId        = '5.3.7'
            Title            = "Ensure all non-privileged role assignments are periodically reviewed"
            Section          = 'Identity Services'
            Subsection       = 'Periodic Identity Reviews'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'Non-privileged role assignments should also be periodically reviewed to ensure least privilege.'
            Remediation      = 'Establish a review process for all role assignments, including non-privileged ones, to ensure they are still necessary.'
            ManualGuidance   = 'Review Azure RBAC role assignments across subscriptions. Verify that each assignment is still needed and follows least privilege principles.'
            References       = @('https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-list-portal')
            CISControls      = @('v8:6.1', 'v7:4.1')
        }

        # 5.4 - 5.28 Identity Settings
        @{
            ControlId        = '5.4'
            Title            = "Ensure that 'Restrict non-admin users from creating tenants' is set to 'Yes'"
            Section          = 'Identity Services'
            Subsection       = 'Authorization Policies'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'GraphAPIProperty'
            GraphEndpoint    = 'policies/authorizationPolicy'
            PropertyPath     = 'defaultUserRolePermissions.allowedToCreateTenants'
            ExpectedValue    = $false
            Description      = 'Non-admin users should not be able to create tenants to prevent unauthorized tenant creation.'
            Remediation      = 'Set defaultUserRolePermissions.allowedToCreateTenants to false via Microsoft Graph API or the Entra admin center.'
            References       = @('https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions')
            CISControls      = @('v8:6.1', 'v7:4.1')
        }
        @{
            ControlId        = '5.5'
            Title            = "Ensure that 'Number of methods required to reset' is set to '2'"
            Section          = 'Identity Services'
            Subsection       = 'Password Reset'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'Password reset should require at least 2 authentication methods to verify identity.'
            Remediation      = 'Navigate to Microsoft Entra ID > Password reset > Authentication methods. Set "Number of methods required to reset" to 2.'
            ManualGuidance   = 'Navigate to Microsoft Entra ID > Password reset > Authentication methods. Verify that "Number of methods required to reset" is set to 2.'
            References       = @('https://learn.microsoft.com/en-us/entra/identity/authentication/howto-sspr-deployment')
            CISControls      = @('v8:6.3', 'v7:4.5')
        }
        @{
            ControlId        = '5.6'
            Title            = "Ensure that account 'Lockout threshold' is less than or equal to '10'"
            Section          = 'Identity Services'
            Subsection       = 'Password Protection'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'The lockout threshold should be set to 10 or fewer attempts to protect against brute force attacks.'
            Remediation      = 'Navigate to Microsoft Entra ID > Security > Authentication methods > Password protection. Set lockout threshold to 10 or less.'
            ManualGuidance   = 'Navigate to Microsoft Entra ID > Security > Authentication methods > Password protection. Verify the lockout threshold is 10 or less.'
            References       = @('https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout')
            CISControls      = @('v8:6.3', 'v7:4.4')
        }
        @{
            ControlId        = '5.7'
            Title            = "Ensure that account 'Lockout duration in seconds' is greater than or equal to '60'"
            Section          = 'Identity Services'
            Subsection       = 'Password Protection'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'Account lockout duration should be at least 60 seconds to slow down brute force attacks.'
            Remediation      = 'Navigate to Microsoft Entra ID > Security > Authentication methods > Password protection. Set lockout duration to 60 seconds or more.'
            ManualGuidance   = 'Navigate to Microsoft Entra ID > Security > Authentication methods > Password protection. Verify lockout duration in seconds is 60 or greater.'
            References       = @('https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout')
            CISControls      = @('v8:6.3', 'v7:4.4')
        }
        @{
            ControlId        = '5.8'
            Title            = "Ensure that a 'Custom banned password list' is set to 'Enforce'"
            Section          = 'Identity Services'
            Subsection       = 'Password Protection'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'A custom banned password list should be configured and enforced to prevent use of commonly compromised passwords.'
            Remediation      = 'Navigate to Microsoft Entra ID > Security > Authentication methods > Password protection. Enable "Enforce custom list" and add organization-specific banned passwords.'
            ManualGuidance   = 'Navigate to Microsoft Entra ID > Security > Authentication methods > Password protection. Verify "Enforce custom list" is set to Yes and the list contains appropriate entries.'
            References       = @('https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad')
            CISControls      = @('v8:5.2', 'v7:4.4')
        }
        @{
            ControlId        = '5.9'
            Title            = "Ensure that 'Number of days before users are asked to re-confirm their authentication information' is not set to '0'"
            Section          = 'Identity Services'
            Subsection       = 'Password Reset'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'Users should be periodically required to re-confirm their authentication information for password reset.'
            Remediation      = 'Navigate to Microsoft Entra ID > Password reset > Registration. Set "Number of days before users are asked to re-confirm" to a non-zero value (e.g., 180).'
            ManualGuidance   = 'Navigate to Microsoft Entra ID > Password reset > Registration. Verify "Number of days before users are asked to re-confirm their authentication information" is not 0.'
            References       = @('https://learn.microsoft.com/en-us/entra/identity/authentication/howto-sspr-deployment')
            CISControls      = @('v8:6.3', 'v7:4.5')
        }
        @{
            ControlId        = '5.10'
            Title            = "Ensure that 'Notify users on password resets?' is set to 'Yes'"
            Section          = 'Identity Services'
            Subsection       = 'Password Reset'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'Users should be notified when their password is reset to detect unauthorized password changes.'
            Remediation      = 'Navigate to Microsoft Entra ID > Password reset > Notifications. Set "Notify users on password resets?" to Yes.'
            ManualGuidance   = 'Navigate to Microsoft Entra ID > Password reset > Notifications. Verify "Notify users on password resets?" is set to Yes.'
            References       = @('https://learn.microsoft.com/en-us/entra/identity/authentication/howto-sspr-deployment')
            CISControls      = @('v8:6.3', 'v7:4.5')
        }
        @{
            ControlId        = '5.11'
            Title            = "Ensure that 'Notify all admins when other admins reset their password?' is set to 'Yes'"
            Section          = 'Identity Services'
            Subsection       = 'Password Reset'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'All admins should be notified when another admin resets their password to detect unauthorized admin password changes.'
            Remediation      = 'Navigate to Microsoft Entra ID > Password reset > Notifications. Set "Notify all admins when other admins reset their password?" to Yes.'
            ManualGuidance   = 'Navigate to Microsoft Entra ID > Password reset > Notifications. Verify "Notify all admins when other admins reset their password?" is set to Yes.'
            References       = @('https://learn.microsoft.com/en-us/entra/identity/authentication/howto-sspr-deployment')
            CISControls      = @('v8:6.3', 'v7:4.5')
        }
        @{
            ControlId        = '5.12'
            Title            = "Ensure that 'User consent for applications' is set to 'Do not allow user consent'"
            Section          = 'Identity Services'
            Subsection       = 'Application Consent'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'ManualCheck'
            Description      = 'User consent for applications should be disabled to prevent users from granting access to potentially malicious applications.'
            Remediation      = 'Navigate to Microsoft Entra ID > Enterprise applications > Consent and permissions > User consent settings. Set to "Do not allow user consent".'
            ManualGuidance   = 'Navigate to Microsoft Entra ID > Enterprise applications > Consent and permissions > User consent settings. Verify it is set to "Do not allow user consent".'
            References       = @('https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent')
            CISControls      = @('v8:6.1', 'v7:4.1')
        }
        @{
            ControlId        = '5.13'
            Title            = "Ensure that 'User consent for applications' is set to 'Allow user consent for apps from verified publishers, for selected permissions'"
            Section          = 'Identity Services'
            Subsection       = 'Application Consent'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'If not completely blocking user consent, restrict it to verified publishers and selected low-risk permissions only.'
            Remediation      = 'Configure user consent to allow only apps from verified publishers with pre-approved permissions using consent policies.'
            ManualGuidance   = 'Navigate to Microsoft Entra ID > Enterprise applications > Consent and permissions. Verify consent is restricted to verified publishers with selected permissions.'
            References       = @('https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent')
            CISControls      = @('v8:6.1', 'v7:4.1')
        }
        @{
            ControlId        = '5.14'
            Title            = "Ensure that 'Users can register applications' is set to 'No'"
            Section          = 'Identity Services'
            Subsection       = 'Application Registration'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'GraphAPIProperty'
            GraphEndpoint    = 'policies/authorizationPolicy'
            PropertyPath     = 'defaultUserRolePermissions.allowedToCreateApps'
            ExpectedValue    = $false
            Description      = 'Users should not be able to register applications to prevent creation of unauthorized service principals.'
            Remediation      = 'Set AllowedToCreateApps to false via the Authorization Policy in Microsoft Entra admin center or Graph API.'
            References       = @('https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions')
            CISControls      = @('v8:6.1', 'v7:4.1')
        }
        @{
            ControlId        = '5.15'
            Title            = "Ensure that 'Guest users access restrictions' is set to 'Guest user access is restricted to properties and memberships of their own directory objects'"
            Section          = 'Identity Services'
            Subsection       = 'Guest Access'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'GraphAPIProperty'
            GraphEndpoint    = 'policies/authorizationPolicy'
            PropertyPath     = 'guestUserRoleId'
            ExpectedValue    = '2af84b1e-32c8-42b7-82bc-daa82404023b'
            Description      = 'Guest user access should be restricted to their own directory objects to prevent unauthorized data access.'
            Remediation      = 'Set guestUserRoleId to 2af84b1e-32c8-42b7-82bc-daa82404023b via the Authorization Policy.'
            References       = @('https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions')
            CISControls      = @('v8:6.1', 'v7:14.6')
        }
        @{
            ControlId        = '5.16'
            Title            = "Ensure that 'Guest invite restrictions' is set to 'Only users assigned to specific admin roles' or 'No one'"
            Section          = 'Identity Services'
            Subsection       = 'Guest Access'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS516-GuestInviteRestrictions'
            Description      = 'Guest invite restrictions should be set to allow only specific admin roles or no one to invite guests.'
            Remediation      = 'Set allowInvitesFrom to adminsAndGuestInviters or none via the Authorization Policy.'
            References       = @('https://learn.microsoft.com/en-us/entra/external-id/external-collaboration-settings-configure')
            CISControls      = @('v8:6.1', 'v7:14.6')
        }
        @{
            ControlId        = '5.17'
            Title            = "Ensure that 'Restrict access to Microsoft Entra admin center' is set to 'Yes'"
            Section          = 'Identity Services'
            Subsection       = 'User Settings'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'Access to the Microsoft Entra admin center should be restricted to prevent non-admin users from viewing directory information.'
            Remediation      = 'Navigate to Microsoft Entra ID > User settings. Set "Restrict access to Microsoft Entra admin center" to Yes.'
            ManualGuidance   = 'Navigate to Microsoft Entra ID > User settings. Verify "Restrict access to Microsoft Entra admin center" is set to Yes.'
            References       = @('https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions')
            CISControls      = @('v8:6.1', 'v7:4.1')
        }
        @{
            ControlId        = '5.18'
            Title            = "Ensure that 'Restrict user ability to access groups features in My Groups' is set to 'Yes'"
            Section          = 'Identity Services'
            Subsection       = 'Group Settings'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Low'
            CheckPattern     = 'ManualCheck'
            Description      = 'Users ability to access group features in My Groups should be restricted.'
            Remediation      = 'Navigate to Microsoft Entra ID > Groups > General. Set "Restrict user ability to access groups features in My Groups" to Yes.'
            ManualGuidance   = 'Navigate to Microsoft Entra ID > Groups > General. Verify the setting is set to Yes.'
            References       = @('https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions')
            CISControls      = @('v8:6.1', 'v7:4.1')
        }
        @{
            ControlId        = '5.19'
            Title            = "Ensure that 'Users can create security groups in Azure portals, API or PowerShell' is set to 'No'"
            Section          = 'Identity Services'
            Subsection       = 'Group Settings'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'Users should not be able to create security groups to prevent unauthorized group creation.'
            Remediation      = 'Navigate to Microsoft Entra ID > Groups > General. Set "Users can create security groups" to No.'
            ManualGuidance   = 'Navigate to Microsoft Entra ID > Groups > General. Verify "Users can create security groups in Azure portals, API or PowerShell" is set to No.'
            References       = @('https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions')
            CISControls      = @('v8:6.1', 'v7:4.1')
        }
        @{
            ControlId        = '5.20'
            Title            = "Ensure that 'Owners can manage group membership requests in My Groups' is set to 'No'"
            Section          = 'Identity Services'
            Subsection       = 'Group Settings'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Low'
            CheckPattern     = 'ManualCheck'
            Description      = 'Group owners managing membership requests should be restricted for centralized access control.'
            Remediation      = 'Navigate to Microsoft Entra ID > Groups > General. Set "Owners can manage group membership requests in My Groups" to No.'
            ManualGuidance   = 'Navigate to Microsoft Entra ID > Groups > General. Verify the setting is set to No.'
            References       = @('https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions')
            CISControls      = @('v8:6.1', 'v7:4.1')
        }
        @{
            ControlId        = '5.21'
            Title            = "Ensure that 'Users can create Microsoft 365 groups in Azure portals, API or PowerShell' is set to 'No'"
            Section          = 'Identity Services'
            Subsection       = 'Group Settings'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 2
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'Users should not be able to create Microsoft 365 groups to prevent uncontrolled group proliferation.'
            Remediation      = 'Navigate to Microsoft Entra ID > Groups > General. Set "Users can create Microsoft 365 groups" to No.'
            ManualGuidance   = 'Navigate to Microsoft Entra ID > Groups > General. Verify "Users can create Microsoft 365 groups in Azure portals, API or PowerShell" is set to No.'
            References       = @('https://learn.microsoft.com/en-us/microsoft-365/solutions/manage-creation-of-groups')
            CISControls      = @('v8:6.1', 'v7:4.1')
        }
        @{
            ControlId        = '5.22'
            Title            = "Ensure that 'Require Multifactor Authentication to register or join devices with Microsoft Entra' is set to 'Yes'"
            Section          = 'Identity Services'
            Subsection       = 'Device Settings'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'MFA should be required to register or join devices to prevent unauthorized device registration.'
            Remediation      = 'Navigate to Microsoft Entra ID > Devices > Device settings. Set "Require Multifactor Authentication to register or join devices" to Yes.'
            ManualGuidance   = 'Navigate to Microsoft Entra ID > Devices > Device settings. Verify "Require Multi-Factor Authentication to register or join devices with Microsoft Entra" is set to Yes.'
            References       = @('https://learn.microsoft.com/en-us/entra/identity/devices/device-management-azure-portal')
            CISControls      = @('v8:6.3', 'v7:4.5')
        }
        @{
            ControlId        = '5.23'
            Title            = "Ensure that no custom subscription administrator roles exist"
            Section          = 'Identity Services'
            Subsection       = 'Role Definitions'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS523-CustomAdminRoles'
            Description      = 'Custom roles with subscription-level wildcard (*) actions should not exist as they provide excessive permissions.'
            Remediation      = 'Remove or modify custom roles that have wildcard actions at the subscription scope. Use built-in roles or create more restrictive custom roles.'
            References       = @('https://learn.microsoft.com/en-us/azure/role-based-access-control/custom-roles')
            CISControls      = @('v8:6.1', 'v7:4.1')
        }
        @{
            ControlId        = '5.24'
            Title            = "Ensure that a custom role is assigned permissions for administering resource locks"
            Section          = 'Identity Services'
            Subsection       = 'Role Definitions'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 2
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'A custom role should be created and assigned for administering resource locks to follow least privilege.'
            Remediation      = 'Create a custom role with Microsoft.Authorization/locks/* permissions and assign it to designated lock administrators.'
            ManualGuidance   = 'Verify a custom role exists with permissions for Microsoft.Authorization/locks/*. Check that this role is assigned to appropriate administrators.'
            References       = @('https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources')
            CISControls      = @('v8:6.1', 'v7:4.1')
        }
        @{
            ControlId        = '5.25'
            Title            = "Ensure that 'Subscription leaving Microsoft Entra tenant' and 'Subscription entering Microsoft Entra tenant' is set to 'Permit no one'"
            Section          = 'Identity Services'
            Subsection       = 'Subscription Policies'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'ManualCheck'
            Description      = 'Subscription transfer policies should be set to permit no one to prevent unauthorized subscription movement.'
            Remediation      = 'Navigate to Microsoft Entra ID > Manage > Subscription policies. Set both leaving and entering to "Permit no one".'
            ManualGuidance   = 'Navigate to Microsoft Entra ID > Manage > Subscription policies. Verify both "Subscription leaving" and "Subscription entering" are set to "Permit no one".'
            References       = @('https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/manage-azure-subscription-policy')
            CISControls      = @('v8:6.1', 'v7:4.1')
        }
        @{
            ControlId        = '5.26'
            Title            = "Ensure fewer than 5 users have global administrator assignment"
            Section          = 'Identity Services'
            Subsection       = 'Role Assignments'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Critical'
            CheckPattern     = 'ManualCheck'
            Description      = 'The number of global administrators should be fewer than 5 to minimize the attack surface.'
            Remediation      = 'Review and reduce global administrator assignments to fewer than 5. Use more specific roles where possible.'
            ManualGuidance   = 'Navigate to Microsoft Entra ID > Roles and administrators > Global Administrator. Count the total assigned users. Ensure fewer than 5 have this role.'
            References       = @('https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices')
            CISControls      = @('v8:6.1', 'v7:4.1')
        }
        @{
            ControlId        = '5.27'
            Title            = "Ensure there are between 2 and 3 subscription owners"
            Section          = 'Identity Services'
            Subsection       = 'Role Assignments'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS527-SubscriptionOwners'
            Description      = 'There should be between 2 and 3 subscription owners to balance access and risk.'
            Remediation      = 'Adjust the number of subscription owners to be between 2 and 3. Minimum 2 for availability, maximum 3 for security.'
            References       = @('https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles')
            CISControls      = @('v8:6.1', 'v7:4.1')
        }
        @{
            ControlId        = '5.28'
            Title            = "Ensure passwordless authentication methods are considered"
            Section          = 'Identity Services'
            Subsection       = 'Authentication Methods'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'Passwordless authentication methods should be considered and implemented where possible for stronger security.'
            Remediation      = 'Enable passwordless authentication methods such as FIDO2 security keys, Windows Hello for Business, or Microsoft Authenticator passwordless sign-in.'
            ManualGuidance   = 'Navigate to Microsoft Entra ID > Security > Authentication methods. Verify that passwordless methods (FIDO2, Windows Hello, Authenticator) are enabled and users are adopting them.'
            References       = @('https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-passwordless')
            CISControls      = @('v8:6.3', 'v7:4.5')
        }

        # =====================================================================
        # SECTION 6: MANAGEMENT AND GOVERNANCE SERVICES (22 controls)
        # =====================================================================

        # 6.1.1 Configuring Diagnostic Settings
        @{
            ControlId        = '6.1.1.1'
            Title            = "Ensure that a 'Diagnostic Setting' exists for Subscription Activity Logs"
            Section          = 'Management and Governance Services'
            Subsection       = 'Configuring Diagnostic Settings'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS6111-SubscriptionDiagnostics'
            Description      = 'A diagnostic setting should be configured for subscription activity logs to ensure they are captured.'
            Remediation      = 'Create a diagnostic setting for the subscription that sends activity logs to a Log Analytics workspace, storage account, or event hub.'
            References       = @('https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings')
            CISControls      = @('v8:8.2', 'v7:6.2')
        }
        @{
            ControlId        = '6.1.1.2'
            Title            = "Ensure Diagnostic Setting captures appropriate categories"
            Section          = 'Management and Governance Services'
            Subsection       = 'Configuring Diagnostic Settings'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS6112-DiagnosticCategories'
            Description      = 'Diagnostic settings should capture Administrative, Alert, Policy, and Security categories.'
            Remediation      = 'Update the diagnostic setting to enable Administrative, Alert, Policy, and Security categories.'
            References       = @('https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings')
            CISControls      = @('v8:8.2', 'v7:6.2')
        }
        @{
            ControlId        = '6.1.1.3'
            Title            = "Ensure the storage account containing the container with activity logs is encrypted with customer-managed key (CMK)"
            Section          = 'Management and Governance Services'
            Subsection       = 'Configuring Diagnostic Settings'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 2
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'The storage account used for activity logs should be encrypted with a customer-managed key for additional control.'
            Remediation      = 'Configure customer-managed key encryption on the storage account used for activity log storage.'
            ManualGuidance   = 'Identify the storage account used for activity logs. Verify it uses CMK encryption under Settings > Encryption.'
            References       = @('https://learn.microsoft.com/en-us/azure/storage/common/customer-managed-keys-overview')
            CISControls      = @('v8:3.11', 'v7:14.8')
        }
        @{
            ControlId        = '6.1.1.4'
            Title            = "Ensure that logging for Azure Key Vault is 'Enabled'"
            Section          = 'Management and Governance Services'
            Subsection       = 'Configuring Diagnostic Settings'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS6114-KeyVaultLogging'
            Description      = 'Diagnostic logging should be enabled for all Azure Key Vaults to capture audit and access events.'
            Remediation      = 'Configure diagnostic settings on each Key Vault to send audit logs to a Log Analytics workspace.'
            References       = @('https://learn.microsoft.com/en-us/azure/key-vault/general/logging')
            CISControls      = @('v8:8.2', 'v7:6.2')
        }
        @{
            ControlId        = '6.1.1.5'
            Title            = "Ensure that Network Security Group Flow logs are captured and sent to Log Analytics"
            Section          = 'Management and Governance Services'
            Subsection       = 'Configuring Diagnostic Settings'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'NSG flow logs should be captured and sent to Log Analytics for network traffic analysis.'
            Remediation      = 'Enable NSG flow logs and configure them to send to a Log Analytics workspace.'
            ManualGuidance   = 'Navigate to Network Watcher > NSG flow logs. Verify flow logs are enabled for all NSGs and configured to send to Log Analytics.'
            References       = @('https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-overview')
            CISControls      = @('v8:8.2', 'v7:6.2')
        }
        @{
            ControlId        = '6.1.1.6'
            Title            = "Ensure that logging for Azure AppService 'HTTP logs' is enabled"
            Section          = 'Management and Governance Services'
            Subsection       = 'Configuring Diagnostic Settings'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS6116-AppServiceHTTPLogs'
            Description      = 'HTTP logging should be enabled for Azure App Services to capture web request information.'
            Remediation      = 'Configure diagnostic settings on App Services to enable HTTP logging.'
            References       = @('https://learn.microsoft.com/en-us/azure/app-service/troubleshoot-diagnostic-logs')
            CISControls      = @('v8:8.2', 'v7:6.2')
        }
        @{
            ControlId        = '6.1.1.7'
            Title            = "Ensure that virtual network flow logs are captured and sent to Log Analytics"
            Section          = 'Management and Governance Services'
            Subsection       = 'Configuring Diagnostic Settings'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'Virtual network flow logs should be captured and sent to Log Analytics.'
            Remediation      = 'Enable VNet flow logs and configure them to send to a Log Analytics workspace.'
            ManualGuidance   = 'Navigate to Network Watcher > VNet flow logs. Verify flow logs are enabled for virtual networks and configured to send to Log Analytics.'
            References       = @('https://learn.microsoft.com/en-us/azure/network-watcher/vnet-flow-logs-overview')
            CISControls      = @('v8:8.2', 'v7:6.2')
        }
        @{
            ControlId        = '6.1.1.8'
            Title            = "Ensure that a Microsoft Entra diagnostic setting exists to send Microsoft Graph activity logs to an appropriate destination"
            Section          = 'Management and Governance Services'
            Subsection       = 'Configuring Diagnostic Settings'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'Microsoft Graph activity logs should be sent to an appropriate log destination for audit and monitoring.'
            Remediation      = 'Configure a diagnostic setting in Microsoft Entra ID to send Microsoft Graph activity logs to Log Analytics or a storage account.'
            ManualGuidance   = 'Navigate to Microsoft Entra ID > Monitoring > Diagnostic settings. Verify a setting exists that captures MicrosoftGraphActivityLogs.'
            References       = @('https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-configure-diagnostic-settings')
            CISControls      = @('v8:8.2', 'v7:6.2')
        }
        @{
            ControlId        = '6.1.1.9'
            Title            = "Ensure that a Microsoft Entra diagnostic setting exists to send Microsoft Entra activity logs to an appropriate destination"
            Section          = 'Management and Governance Services'
            Subsection       = 'Configuring Diagnostic Settings'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'Microsoft Entra activity logs should be sent to an appropriate destination for monitoring and audit.'
            Remediation      = 'Configure a diagnostic setting to send Microsoft Entra sign-in and audit logs to Log Analytics or a storage account.'
            ManualGuidance   = 'Navigate to Microsoft Entra ID > Monitoring > Diagnostic settings. Verify settings capture SignInLogs and AuditLogs.'
            References       = @('https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-configure-diagnostic-settings')
            CISControls      = @('v8:8.2', 'v7:6.2')
        }
        @{
            ControlId        = '6.1.1.10'
            Title            = "Ensure that Intune logs are captured and sent to Log Analytics"
            Section          = 'Management and Governance Services'
            Subsection       = 'Configuring Diagnostic Settings'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'Intune diagnostic logs should be captured and sent to Log Analytics for device management monitoring.'
            Remediation      = 'Configure diagnostic settings in Microsoft Intune to send logs to a Log Analytics workspace.'
            ManualGuidance   = 'Navigate to Microsoft Intune admin center > Tenant administration > Diagnostics settings. Verify logs are configured to send to Log Analytics.'
            References       = @('https://learn.microsoft.com/en-us/mem/intune/fundamentals/review-logs-using-azure-monitor')
            CISControls      = @('v8:8.2', 'v7:6.2')
        }

        # 6.1.2 Monitoring using Activity Log Alerts (11 controls)
        @{
            ControlId        = '6.1.2.1'
            Title            = "Ensure that Activity Log Alert exists for Create Policy Assignment"
            Section          = 'Management and Governance Services'
            Subsection       = 'Monitoring using Activity Log Alerts'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ActivityLogAlert'
            OperationName    = 'Microsoft.Authorization/policyAssignments/write'
            Description      = 'An activity log alert should exist to notify when a policy assignment is created.'
            Remediation      = 'Create an Activity Log Alert for the operation Microsoft.Authorization/policyAssignments/write.'
            References       = @('https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/activity-log-alerts')
            CISControls      = @('v8:8.11', 'v7:6.3')
        }
        @{
            ControlId        = '6.1.2.2'
            Title            = "Ensure that Activity Log Alert exists for Delete Policy Assignment"
            Section          = 'Management and Governance Services'
            Subsection       = 'Monitoring using Activity Log Alerts'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ActivityLogAlert'
            OperationName    = 'Microsoft.Authorization/policyAssignments/delete'
            Description      = 'An activity log alert should exist to notify when a policy assignment is deleted.'
            Remediation      = 'Create an Activity Log Alert for the operation Microsoft.Authorization/policyAssignments/delete.'
            References       = @('https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/activity-log-alerts')
            CISControls      = @('v8:8.11', 'v7:6.3')
        }
        @{
            ControlId        = '6.1.2.3'
            Title            = "Ensure that Activity Log Alert exists for Create or Update Network Security Group"
            Section          = 'Management and Governance Services'
            Subsection       = 'Monitoring using Activity Log Alerts'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ActivityLogAlert'
            OperationName    = 'Microsoft.Network/networkSecurityGroups/write'
            Description      = 'An activity log alert should exist to notify when an NSG is created or updated.'
            Remediation      = 'Create an Activity Log Alert for the operation Microsoft.Network/networkSecurityGroups/write.'
            References       = @('https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/activity-log-alerts')
            CISControls      = @('v8:8.11', 'v7:6.3')
        }
        @{
            ControlId        = '6.1.2.4'
            Title            = "Ensure that Activity Log Alert exists for Delete Network Security Group"
            Section          = 'Management and Governance Services'
            Subsection       = 'Monitoring using Activity Log Alerts'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ActivityLogAlert'
            OperationName    = 'Microsoft.Network/networkSecurityGroups/delete'
            Description      = 'An activity log alert should exist to notify when an NSG is deleted.'
            Remediation      = 'Create an Activity Log Alert for the operation Microsoft.Network/networkSecurityGroups/delete.'
            References       = @('https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/activity-log-alerts')
            CISControls      = @('v8:8.11', 'v7:6.3')
        }
        @{
            ControlId        = '6.1.2.5'
            Title            = "Ensure that Activity Log Alert exists for Create or Update Security Solution"
            Section          = 'Management and Governance Services'
            Subsection       = 'Monitoring using Activity Log Alerts'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ActivityLogAlert'
            OperationName    = 'Microsoft.Security/securitySolutions/write'
            Description      = 'An activity log alert should exist to notify when a security solution is created or updated.'
            Remediation      = 'Create an Activity Log Alert for the operation Microsoft.Security/securitySolutions/write.'
            References       = @('https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/activity-log-alerts')
            CISControls      = @('v8:8.11', 'v7:6.3')
        }
        @{
            ControlId        = '6.1.2.6'
            Title            = "Ensure that Activity Log Alert exists for Delete Security Solution"
            Section          = 'Management and Governance Services'
            Subsection       = 'Monitoring using Activity Log Alerts'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ActivityLogAlert'
            OperationName    = 'Microsoft.Security/securitySolutions/delete'
            Description      = 'An activity log alert should exist to notify when a security solution is deleted.'
            Remediation      = 'Create an Activity Log Alert for the operation Microsoft.Security/securitySolutions/delete.'
            References       = @('https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/activity-log-alerts')
            CISControls      = @('v8:8.11', 'v7:6.3')
        }
        @{
            ControlId        = '6.1.2.7'
            Title            = "Ensure that Activity Log Alert exists for Create or Update SQL Server Firewall Rule"
            Section          = 'Management and Governance Services'
            Subsection       = 'Monitoring using Activity Log Alerts'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ActivityLogAlert'
            OperationName    = 'Microsoft.Sql/servers/firewallRules/write'
            Description      = 'An activity log alert should exist to notify when a SQL Server firewall rule is created or updated.'
            Remediation      = 'Create an Activity Log Alert for the operation Microsoft.Sql/servers/firewallRules/write.'
            References       = @('https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/activity-log-alerts')
            CISControls      = @('v8:8.11', 'v7:6.3')
        }
        @{
            ControlId        = '6.1.2.8'
            Title            = "Ensure that Activity Log Alert exists for Delete SQL Server Firewall Rule"
            Section          = 'Management and Governance Services'
            Subsection       = 'Monitoring using Activity Log Alerts'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ActivityLogAlert'
            OperationName    = 'Microsoft.Sql/servers/firewallRules/delete'
            Description      = 'An activity log alert should exist to notify when a SQL Server firewall rule is deleted.'
            Remediation      = 'Create an Activity Log Alert for the operation Microsoft.Sql/servers/firewallRules/delete.'
            References       = @('https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/activity-log-alerts')
            CISControls      = @('v8:8.11', 'v7:6.3')
        }
        @{
            ControlId        = '6.1.2.9'
            Title            = "Ensure that Activity Log Alert exists for Create or Update Public IP Address rule"
            Section          = 'Management and Governance Services'
            Subsection       = 'Monitoring using Activity Log Alerts'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ActivityLogAlert'
            OperationName    = 'Microsoft.Network/publicIPAddresses/write'
            Description      = 'An activity log alert should exist to notify when a Public IP Address is created or updated.'
            Remediation      = 'Create an Activity Log Alert for the operation Microsoft.Network/publicIPAddresses/write.'
            References       = @('https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/activity-log-alerts')
            CISControls      = @('v8:8.11', 'v7:6.3')
        }
        @{
            ControlId        = '6.1.2.10'
            Title            = "Ensure that Activity Log Alert exists for Delete Public IP Address rule"
            Section          = 'Management and Governance Services'
            Subsection       = 'Monitoring using Activity Log Alerts'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ActivityLogAlert'
            OperationName    = 'Microsoft.Network/publicIPAddresses/delete'
            Description      = 'An activity log alert should exist to notify when a Public IP Address is deleted.'
            Remediation      = 'Create an Activity Log Alert for the operation Microsoft.Network/publicIPAddresses/delete.'
            References       = @('https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/activity-log-alerts')
            CISControls      = @('v8:8.11', 'v7:6.3')
        }
        @{
            ControlId        = '6.1.2.11'
            Title            = "Ensure that an Activity Log Alert exists for Service Health"
            Section          = 'Management and Governance Services'
            Subsection       = 'Monitoring using Activity Log Alerts'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS61211-ServiceHealthAlert'
            Description      = 'An activity log alert should exist for Service Health events to monitor Azure service issues.'
            Remediation      = 'Create an Activity Log Alert for Service Health events covering Incident, Maintenance, and Security categories.'
            References       = @('https://learn.microsoft.com/en-us/azure/service-health/alerts-activity-log-service-notifications-portal')
            CISControls      = @('v8:8.11', 'v7:6.3')
        }

        # 6.1.3 Application Insights
        @{
            ControlId        = '6.1.3.1'
            Title            = "Ensure Application Insights are Configured"
            Section          = 'Management and Governance Services'
            Subsection       = 'Configuring Application Insights'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS6131-ApplicationInsights'
            Description      = 'Application Insights should be configured for application monitoring and diagnostics.'
            Remediation      = 'Create and configure Application Insights resources for your applications.'
            References       = @('https://learn.microsoft.com/en-us/azure/azure-monitor/app/app-insights-overview')
            CISControls      = @('v8:8.2', 'v7:6.2')
        }

        # 6.1.4 - 6.2 Additional
        @{
            ControlId        = '6.1.4'
            Title            = "Ensure that Azure Monitor Resource Logging is Enabled for All Services that Support it"
            Section          = 'Management and Governance Services'
            Subsection       = 'Resource Logging'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'Resource logging should be enabled for all Azure services that support diagnostic logging.'
            Remediation      = 'Configure diagnostic settings on all Azure resources that support logging.'
            ManualGuidance   = 'Review all Azure resources and verify diagnostic settings are configured for each resource that supports logging. Use Azure Policy to enforce diagnostic settings at scale.'
            References       = @('https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings')
            CISControls      = @('v8:8.2', 'v7:6.2')
        }
        @{
            ControlId        = '6.1.5'
            Title            = "Ensure that SKU Basic/Consumption is not used on artifacts that need to be monitored"
            Section          = 'Management and Governance Services'
            Subsection       = 'Resource SKUs'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Low'
            CheckPattern     = 'ManualCheck'
            Description      = 'Basic/Consumption SKUs may not support diagnostic logging. Use Standard or Premium SKUs for production workloads.'
            Remediation      = 'Upgrade resources from Basic/Consumption SKUs to Standard or Premium where monitoring is required.'
            ManualGuidance   = 'Review all production resources and ensure they are not using Basic or Consumption SKUs that lack monitoring capabilities.'
            References       = @('https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings')
            CISControls      = @('v8:8.2', 'v7:6.2')
        }
        @{
            ControlId        = '6.2'
            Title            = "Ensure that Resource Locks are set for Mission-Critical Azure Resources"
            Section          = 'Management and Governance Services'
            Subsection       = 'Resource Locks'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'Resource locks should be applied to mission-critical Azure resources to prevent accidental deletion or modification.'
            Remediation      = 'Apply CanNotDelete or ReadOnly locks to mission-critical resources, resource groups, or subscriptions.'
            ManualGuidance   = 'Identify mission-critical resources and verify they have appropriate resource locks applied. Navigate to the resource > Settings > Locks.'
            References       = @('https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources')
            CISControls      = @('v8:3.3', 'v7:14.6')
        }

        # =====================================================================
        # SECTION 7: NETWORKING SERVICES (16 controls)
        # =====================================================================
        @{
            ControlId        = '7.1'
            Title            = "Ensure that RDP access from the Internet is evaluated and restricted"
            Section          = 'Networking Services'
            Subsection       = 'Network Security Groups'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Critical'
            CheckPattern     = 'NSGPortCheck'
            Port             = 3389
            Protocol         = 'TCP'
            ServiceName      = 'RDP'
            Description      = 'RDP access (port 3389) from the Internet should be restricted to prevent unauthorized remote access.'
            Remediation      = 'Remove or restrict NSG rules that allow inbound RDP (port 3389) from the Internet (0.0.0.0/0 or *).'
            References       = @('https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview')
            CISControls      = @('v8:4.4', 'v7:9.2')
        }
        @{
            ControlId        = '7.2'
            Title            = "Ensure that SSH access from the Internet is evaluated and restricted"
            Section          = 'Networking Services'
            Subsection       = 'Network Security Groups'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Critical'
            CheckPattern     = 'NSGPortCheck'
            Port             = 22
            Protocol         = 'TCP'
            ServiceName      = 'SSH'
            Description      = 'SSH access (port 22) from the Internet should be restricted to prevent unauthorized remote access.'
            Remediation      = 'Remove or restrict NSG rules that allow inbound SSH (port 22) from the Internet (0.0.0.0/0 or *).'
            References       = @('https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview')
            CISControls      = @('v8:4.4', 'v7:9.2')
        }
        @{
            ControlId        = '7.3'
            Title            = "Ensure that UDP access from the Internet is evaluated and restricted"
            Section          = 'Networking Services'
            Subsection       = 'Network Security Groups'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'NSGPortCheck'
            Port             = -1
            Protocol         = 'UDP'
            ServiceName      = 'UDP'
            Description      = 'UDP access from the Internet should be restricted to prevent unauthorized access.'
            Remediation      = 'Remove or restrict NSG rules that allow inbound UDP from the Internet (0.0.0.0/0 or *).'
            References       = @('https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview')
            CISControls      = @('v8:4.4', 'v7:9.2')
        }
        @{
            ControlId        = '7.4'
            Title            = "Ensure that HTTP(S) access from the Internet is evaluated and restricted"
            Section          = 'Networking Services'
            Subsection       = 'Network Security Groups'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'NSGPortCheck'
            Port             = @(80, 443)
            Protocol         = 'TCP'
            ServiceName      = 'HTTP/HTTPS'
            Description      = 'HTTP/HTTPS access from the Internet should be evaluated and restricted where not needed.'
            Remediation      = 'Review and restrict NSG rules allowing inbound HTTP/HTTPS from the Internet to only necessary resources.'
            References       = @('https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview')
            CISControls      = @('v8:4.4', 'v7:9.2')
        }
        @{
            ControlId        = '7.5'
            Title            = "Ensure that network security group flow log retention days is set to greater than or equal to 90"
            Section          = 'Networking Services'
            Subsection       = 'Flow Logs'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS75-NSGFlowLogRetention'
            Description      = 'NSG flow log retention should be at least 90 days for adequate audit trail.'
            Remediation      = 'Set NSG flow log retention to 90 days or more.'
            References       = @('https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-overview')
            CISControls      = @('v8:8.1', 'v7:6.4')
        }
        @{
            ControlId        = '7.6'
            Title            = "Ensure that Network Watcher is 'Enabled' for Azure Regions that are in use"
            Section          = 'Networking Services'
            Subsection       = 'Network Watcher'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS76-NetworkWatcher'
            Description      = 'Network Watcher should be enabled in all regions where Azure resources are deployed.'
            Remediation      = 'Enable Network Watcher in all Azure regions that contain resources.'
            References       = @('https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-create')
            CISControls      = @('v8:12.2', 'v7:6.6')
        }
        @{
            ControlId        = '7.7'
            Title            = "Ensure that Public IP addresses are Evaluated on a Periodic Basis"
            Section          = 'Networking Services'
            Subsection       = 'Public IP Addresses'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'Public IP addresses should be periodically reviewed to ensure they are still needed and properly secured.'
            Remediation      = 'Review all public IP addresses and remove those that are no longer needed. Ensure remaining ones are properly secured.'
            ManualGuidance   = 'Navigate to Public IP addresses in the Azure portal. Review each public IP for continued business need and appropriate security controls.'
            References       = @('https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses')
            CISControls      = @('v8:12.2', 'v7:9.2')
        }
        @{
            ControlId        = '7.8'
            Title            = "Ensure that virtual network flow log retention days is set to greater than or equal to 90"
            Section          = 'Networking Services'
            Subsection       = 'Flow Logs'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS78-VNetFlowLogRetention'
            Description      = 'Virtual network flow log retention should be at least 90 days.'
            Remediation      = 'Set virtual network flow log retention to 90 days or more.'
            References       = @('https://learn.microsoft.com/en-us/azure/network-watcher/vnet-flow-logs-overview')
            CISControls      = @('v8:8.1', 'v7:6.4')
        }
        @{
            ControlId        = '7.9'
            Title            = "Ensure 'Authentication type' is set to 'Azure Active Directory' only for Azure VPN Gateway point-to-site configuration"
            Section          = 'Networking Services'
            Subsection       = 'VPN Gateway'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'VPN Gateway P2S should use Azure AD authentication for stronger identity verification.'
            Remediation      = 'Configure VPN Gateway point-to-site to use Azure Active Directory authentication only.'
            ManualGuidance   = 'Navigate to VPN Gateway > Point-to-site configuration. Verify that the authentication type is set to Azure Active Directory.'
            References       = @('https://learn.microsoft.com/en-us/azure/vpn-gateway/openvpn-azure-ad-tenant')
            CISControls      = @('v8:6.3', 'v7:4.5')
        }
        @{
            ControlId        = '7.10'
            Title            = "Ensure Azure Web Application Firewall (WAF) is enabled on Azure Application Gateway"
            Section          = 'Networking Services'
            Subsection       = 'Application Gateway'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS710-AppGatewayWAF'
            Description      = 'WAF should be enabled on Application Gateways to protect web applications from common exploits.'
            Remediation      = 'Enable WAF on Application Gateways by upgrading to WAF_v2 SKU and configuring WAF policy.'
            References       = @('https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/ag-overview')
            CISControls      = @('v8:13.10', 'v7:18.9')
        }
        @{
            ControlId        = '7.11'
            Title            = "Ensure subnets are associated with network security groups"
            Section          = 'Networking Services'
            Subsection       = 'Network Security Groups'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS711-SubnetNSG'
            Description      = 'All subnets should be associated with NSGs to control inbound and outbound traffic.'
            Remediation      = 'Associate network security groups with all subnets that do not have special requirements (like GatewaySubnet).'
            References       = @('https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview')
            CISControls      = @('v8:12.2', 'v7:9.4')
        }
        @{
            ControlId        = '7.12'
            Title            = "Ensure the SSL policy's 'Min protocol version' is set to 'TLSv1_2' or higher on Azure Application Gateway"
            Section          = 'Networking Services'
            Subsection       = 'Application Gateway'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS712-AppGatewayTLS'
            Description      = 'Application Gateways should enforce TLS 1.2 or higher to prevent use of older vulnerable protocols.'
            Remediation      = 'Set the SSL policy minimum protocol version to TLSv1_2 or higher on all Application Gateways.'
            References       = @('https://learn.microsoft.com/en-us/azure/application-gateway/application-gateway-ssl-policy-overview')
            CISControls      = @('v8:3.10', 'v7:14.4')
        }
        @{
            ControlId        = '7.13'
            Title            = "Ensure 'HTTP2' is set to 'Enabled' on Azure Application Gateway"
            Section          = 'Networking Services'
            Subsection       = 'Application Gateway'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Low'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS713-AppGatewayHTTP2'
            Description      = 'HTTP/2 should be enabled on Application Gateways for improved performance and security.'
            Remediation      = 'Enable HTTP/2 on the Application Gateway configuration.'
            References       = @('https://learn.microsoft.com/en-us/azure/application-gateway/configuration-listeners')
            CISControls      = @('v8:3.10', 'v7:14.4')
        }
        @{
            ControlId        = '7.14'
            Title            = "Ensure request body inspection is enabled in Azure Web Application Firewall policy on Azure Application Gateway"
            Section          = 'Networking Services'
            Subsection       = 'Application Gateway'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS714-WAFRequestBodyInspection'
            Description      = 'WAF request body inspection should be enabled to detect malicious payloads in request bodies.'
            Remediation      = 'Enable request body inspection in the WAF policy settings on the Application Gateway.'
            References       = @('https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/application-gateway-waf-request-size-limits')
            CISControls      = @('v8:13.10', 'v7:18.9')
        }
        @{
            ControlId        = '7.15'
            Title            = "Ensure bot protection is enabled in Azure Web Application Firewall policy on Azure Application Gateway"
            Section          = 'Networking Services'
            Subsection       = 'Application Gateway'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS715-WAFBotProtection'
            Description      = 'Bot protection should be enabled in WAF policy to protect against automated attacks.'
            Remediation      = 'Enable bot protection rule set in the WAF policy on the Application Gateway.'
            References       = @('https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/bot-protection-overview')
            CISControls      = @('v8:13.10', 'v7:18.9')
        }
        @{
            ControlId        = '7.16'
            Title            = "Ensure Azure Network Security Perimeter is used to secure Azure platform-as-a-service resources"
            Section          = 'Networking Services'
            Subsection       = 'Network Security Perimeter'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 2
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'Azure Network Security Perimeter should be used to secure PaaS resources with network-level access control.'
            Remediation      = 'Configure Azure Network Security Perimeter for PaaS resources that support it.'
            ManualGuidance   = 'Review Azure PaaS resources and verify Network Security Perimeter is configured where available and applicable.'
            References       = @('https://learn.microsoft.com/en-us/azure/private-link/network-security-perimeter-concepts')
            CISControls      = @('v8:12.2', 'v7:14.1')
        }

        # =====================================================================
        # SECTION 8: SECURITY SERVICES (29 controls)
        # =====================================================================

        # 8.1 Microsoft Defender for Cloud
        @{
            ControlId        = '8.1.1.1'
            Title            = "Ensure Microsoft Defender CSPM is set to 'On'"
            Section          = 'Security Services'
            Subsection       = 'Microsoft Defender for Cloud'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 2
            Severity         = 'High'
            CheckPattern     = 'DefenderPlan'
            DefenderPlanName = 'CloudPosture'
            ExpectedTier     = 'Standard'
            Description      = 'Microsoft Defender CSPM should be enabled for cloud security posture management.'
            Remediation      = 'Enable Defender CSPM from Microsoft Defender for Cloud > Environment settings > Defender plans.'
            References       = @('https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-cloud-security-posture-management')
            CISControls      = @('v8:2.1', 'v7:3.1')
        }
        @{
            ControlId        = '8.1.2.1'
            Title            = "Ensure Microsoft Defender for APIs is set to 'On'"
            Section          = 'Security Services'
            Subsection       = 'Microsoft Defender for Cloud'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'DefenderPlan'
            DefenderPlanName = 'Api'
            ExpectedTier     = 'Standard'
            Description      = 'Microsoft Defender for APIs should be enabled to protect API endpoints.'
            Remediation      = 'Enable Defender for APIs from Microsoft Defender for Cloud > Environment settings.'
            References       = @('https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-apis-introduction')
            CISControls      = @('v8:13.10', 'v7:18.9')
        }
        @{
            ControlId        = '8.1.3.1'
            Title            = "Ensure that Defender for Servers is set to 'On'"
            Section          = 'Security Services'
            Subsection       = 'Microsoft Defender for Cloud'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'DefenderPlan'
            DefenderPlanName = 'VirtualMachines'
            ExpectedTier     = 'Standard'
            Description      = 'Microsoft Defender for Servers should be enabled to protect server workloads.'
            Remediation      = 'Enable Defender for Servers from Microsoft Defender for Cloud > Environment settings.'
            References       = @('https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-servers-introduction')
            CISControls      = @('v8:10.1', 'v7:8.1')
        }
        @{
            ControlId        = '8.1.3.2'
            Title            = "Ensure that 'Vulnerability assessment for machines' component status is set to 'On'"
            Section          = 'Security Services'
            Subsection       = 'Microsoft Defender for Cloud'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'ManualCheck'
            Description      = 'Vulnerability assessment should be enabled for all machines to identify security vulnerabilities.'
            Remediation      = 'Enable the vulnerability assessment component in Defender for Servers settings.'
            ManualGuidance   = 'Navigate to Microsoft Defender for Cloud > Environment settings > Defender plans > Servers > Settings. Verify Vulnerability assessment for machines is On.'
            References       = @('https://learn.microsoft.com/en-us/azure/defender-for-cloud/deploy-vulnerability-assessment-vm')
            CISControls      = @('v8:7.5', 'v7:3.1')
        }
        @{
            ControlId        = '8.1.3.3'
            Title            = "Ensure that 'Endpoint protection' component status is set to 'On'"
            Section          = 'Security Services'
            Subsection       = 'Microsoft Defender for Cloud'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS8133-EndpointProtection'
            Description      = 'Endpoint protection component should be enabled in Defender for Servers.'
            Remediation      = 'Enable the Endpoint protection component in Defender for Servers plan settings.'
            References       = @('https://learn.microsoft.com/en-us/azure/defender-for-cloud/integration-defender-for-endpoint')
            CISControls      = @('v8:10.1', 'v7:8.1')
        }
        @{
            ControlId        = '8.1.3.4'
            Title            = "Ensure that 'Agentless scanning for machines' component status is set to 'On'"
            Section          = 'Security Services'
            Subsection       = 'Microsoft Defender for Cloud'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'Agentless scanning should be enabled for machine vulnerability detection without agent deployment.'
            Remediation      = 'Enable agentless scanning component in Defender for Servers settings.'
            ManualGuidance   = 'Navigate to Defender for Cloud > Environment settings > Defender plans > Servers > Settings. Verify Agentless scanning for machines is On.'
            References       = @('https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-agentless-data-collection')
            CISControls      = @('v8:7.5', 'v7:3.1')
        }
        @{
            ControlId        = '8.1.3.5'
            Title            = "Ensure that 'File Integrity Monitoring' component status is set to 'On'"
            Section          = 'Security Services'
            Subsection       = 'Microsoft Defender for Cloud'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'File Integrity Monitoring should be enabled to detect unauthorized changes to critical system files.'
            Remediation      = 'Enable File Integrity Monitoring in Defender for Servers settings.'
            ManualGuidance   = 'Navigate to Defender for Cloud > Environment settings > Defender plans > Servers > Settings. Verify File Integrity Monitoring is On.'
            References       = @('https://learn.microsoft.com/en-us/azure/defender-for-cloud/file-integrity-monitoring-overview')
            CISControls      = @('v8:8.5', 'v7:14.9')
        }
        @{
            ControlId        = '8.1.4.1'
            Title            = "Ensure That Microsoft Defender for Containers Is Set To 'On'"
            Section          = 'Security Services'
            Subsection       = 'Microsoft Defender for Cloud'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'DefenderPlan'
            DefenderPlanName = 'Containers'
            ExpectedTier     = 'Standard'
            Description      = 'Microsoft Defender for Containers should be enabled to protect container workloads.'
            Remediation      = 'Enable Defender for Containers from Microsoft Defender for Cloud > Environment settings.'
            References       = @('https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction')
            CISControls      = @('v8:10.1', 'v7:8.1')
        }
        @{
            ControlId        = '8.1.5.1'
            Title            = "Ensure That Microsoft Defender for Storage Is Set To 'On'"
            Section          = 'Security Services'
            Subsection       = 'Microsoft Defender for Cloud'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'DefenderPlan'
            DefenderPlanName = 'StorageAccounts'
            ExpectedTier     = 'Standard'
            Description      = 'Microsoft Defender for Storage should be enabled to protect storage accounts.'
            Remediation      = 'Enable Defender for Storage from Microsoft Defender for Cloud > Environment settings.'
            References       = @('https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-storage-introduction')
            CISControls      = @('v8:10.1', 'v7:8.1')
        }
        @{
            ControlId        = '8.1.5.2'
            Title            = "Ensure Advanced Threat Protection Alerts for Storage Accounts Are Monitored"
            Section          = 'Security Services'
            Subsection       = 'Microsoft Defender for Cloud'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'Advanced Threat Protection alerts for storage accounts should be actively monitored.'
            Remediation      = 'Configure alert notifications and establish monitoring processes for storage threat protection alerts.'
            ManualGuidance   = 'Navigate to Microsoft Defender for Cloud > Security alerts. Verify that storage-related alerts are being reviewed and addressed.'
            References       = @('https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-storage-introduction')
            CISControls      = @('v8:10.1', 'v7:8.1')
        }
        @{
            ControlId        = '8.1.6.1'
            Title            = "Ensure That Microsoft Defender for App Services Is Set To 'On'"
            Section          = 'Security Services'
            Subsection       = 'Microsoft Defender for Cloud'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'DefenderPlan'
            DefenderPlanName = 'AppServices'
            ExpectedTier     = 'Standard'
            Description      = 'Microsoft Defender for App Service should be enabled to protect web applications.'
            Remediation      = 'Enable Defender for App Services from Microsoft Defender for Cloud > Environment settings.'
            References       = @('https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-app-service-introduction')
            CISControls      = @('v8:10.1', 'v7:8.1')
        }
        @{
            ControlId        = '8.1.7.1'
            Title            = "Ensure That Microsoft Defender for Azure Cosmos DB Is Set To 'On'"
            Section          = 'Security Services'
            Subsection       = 'Microsoft Defender for Cloud'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'DefenderPlan'
            DefenderPlanName = 'CosmosDbs'
            ExpectedTier     = 'Standard'
            Description      = 'Microsoft Defender for Azure Cosmos DB should be enabled.'
            Remediation      = 'Enable Defender for Cosmos DB from Microsoft Defender for Cloud > Environment settings.'
            References       = @('https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-defender-for-cosmos')
            CISControls      = @('v8:10.1', 'v7:8.1')
        }
        @{
            ControlId        = '8.1.7.2'
            Title            = "Ensure That Microsoft Defender for Open-Source Relational Databases Is Set To 'On'"
            Section          = 'Security Services'
            Subsection       = 'Microsoft Defender for Cloud'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'DefenderPlan'
            DefenderPlanName = 'OpenSourceRelationalDatabases'
            ExpectedTier     = 'Standard'
            Description      = 'Microsoft Defender for Open-Source Relational Databases should be enabled.'
            Remediation      = 'Enable Defender for Open-Source Relational Databases from Microsoft Defender for Cloud > Environment settings.'
            References       = @('https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-databases-introduction')
            CISControls      = @('v8:10.1', 'v7:8.1')
        }
        @{
            ControlId        = '8.1.7.3'
            Title            = "Ensure That Microsoft Defender for (Managed Instance) Azure SQL Databases Is Set To 'On'"
            Section          = 'Security Services'
            Subsection       = 'Microsoft Defender for Cloud'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'DefenderPlan'
            DefenderPlanName = 'SqlServers'
            ExpectedTier     = 'Standard'
            Description      = 'Microsoft Defender for Azure SQL Databases should be enabled.'
            Remediation      = 'Enable Defender for SQL Databases from Microsoft Defender for Cloud > Environment settings.'
            References       = @('https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-sql-introduction')
            CISControls      = @('v8:10.1', 'v7:8.1')
        }
        @{
            ControlId        = '8.1.7.4'
            Title            = "Ensure That Microsoft Defender for SQL Servers on Machines Is Set To 'On'"
            Section          = 'Security Services'
            Subsection       = 'Microsoft Defender for Cloud'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'DefenderPlan'
            DefenderPlanName = 'SqlServerVirtualMachines'
            ExpectedTier     = 'Standard'
            Description      = 'Microsoft Defender for SQL Servers on Machines should be enabled.'
            Remediation      = 'Enable Defender for SQL on Machines from Microsoft Defender for Cloud > Environment settings.'
            References       = @('https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-sql-introduction')
            CISControls      = @('v8:10.1', 'v7:8.1')
        }
        @{
            ControlId        = '8.1.8.1'
            Title            = "Ensure That Microsoft Defender for Key Vault Is Set To 'On'"
            Section          = 'Security Services'
            Subsection       = 'Microsoft Defender for Cloud'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'DefenderPlan'
            DefenderPlanName = 'KeyVaults'
            ExpectedTier     = 'Standard'
            Description      = 'Microsoft Defender for Key Vault should be enabled.'
            Remediation      = 'Enable Defender for Key Vault from Microsoft Defender for Cloud > Environment settings.'
            References       = @('https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-key-vault-introduction')
            CISControls      = @('v8:10.1', 'v7:8.1')
        }
        @{
            ControlId        = '8.1.9.1'
            Title            = "Ensure That Microsoft Defender for Resource Manager Is Set To 'On'"
            Section          = 'Security Services'
            Subsection       = 'Microsoft Defender for Cloud'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'DefenderPlan'
            DefenderPlanName = 'Arm'
            ExpectedTier     = 'Standard'
            Description      = 'Microsoft Defender for Resource Manager should be enabled.'
            Remediation      = 'Enable Defender for Resource Manager from Microsoft Defender for Cloud > Environment settings.'
            References       = @('https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-resource-manager-introduction')
            CISControls      = @('v8:10.1', 'v7:8.1')
        }
        @{
            ControlId        = '8.1.10'
            Title            = "Ensure that Microsoft Defender for Cloud is configured to check VM operating systems for updates"
            Section          = 'Security Services'
            Subsection       = 'Microsoft Defender for Cloud'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS8110-VMUpdateCheck'
            Description      = 'Defender for Cloud should be configured to check VMs for missing OS updates.'
            Remediation      = 'Enable system update recommendations in Defender for Cloud or configure Azure Update Manager.'
            References       = @('https://learn.microsoft.com/en-us/azure/defender-for-cloud/apply-security-baseline')
            CISControls      = @('v8:7.3', 'v7:3.4')
        }
        @{
            ControlId        = '8.1.11'
            Title            = "Ensure that Microsoft Cloud Security Benchmark policies are not set to 'Disabled'"
            Section          = 'Security Services'
            Subsection       = 'Microsoft Defender for Cloud'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'MCSB policies should not be disabled to maintain security posture assessment.'
            Remediation      = 'Review and re-enable any disabled MCSB policies in the Defender for Cloud environment settings.'
            ManualGuidance   = 'Navigate to Defender for Cloud > Environment settings > Security policies. Verify no MCSB policies are disabled.'
            References       = @('https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-regulatory-compliance')
            CISControls      = @('v8:2.1', 'v7:3.1')
        }
        @{
            ControlId        = '8.1.12'
            Title            = "Ensure That 'All users with the following roles' is set to 'Owner'"
            Section          = 'Security Services'
            Subsection       = 'Microsoft Defender for Cloud'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS8112-SecurityContactRoles'
            Description      = 'Security contact notifications should be configured for users with the Owner role.'
            Remediation      = 'Configure security contact settings to notify all users with the Owner role.'
            References       = @('https://learn.microsoft.com/en-us/azure/defender-for-cloud/configure-email-notifications')
            CISControls      = @('v8:17.2', 'v7:19.1')
        }
        @{
            ControlId        = '8.1.13'
            Title            = "Ensure 'Additional email addresses' is Configured with a Security Contact Email"
            Section          = 'Security Services'
            Subsection       = 'Microsoft Defender for Cloud'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS8113-SecurityContactEmail'
            Description      = 'Additional email addresses should be configured for security contact notifications.'
            Remediation      = 'Configure at least one additional security contact email address in Defender for Cloud settings.'
            References       = @('https://learn.microsoft.com/en-us/azure/defender-for-cloud/configure-email-notifications')
            CISControls      = @('v8:17.2', 'v7:19.1')
        }
        @{
            ControlId        = '8.1.14'
            Title            = "Ensure that 'Notify about alerts with the following severity (or higher)' is enabled"
            Section          = 'Security Services'
            Subsection       = 'Microsoft Defender for Cloud'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS8114-AlertNotifications'
            Description      = 'Alert notifications should be configured for high severity or higher alerts.'
            Remediation      = 'Enable alert notifications for high severity in Defender for Cloud > Email notifications settings.'
            References       = @('https://learn.microsoft.com/en-us/azure/defender-for-cloud/configure-email-notifications')
            CISControls      = @('v8:17.2', 'v7:19.1')
        }
        @{
            ControlId        = '8.1.15'
            Title            = "Ensure that 'Notify about attack paths with the following risk level (or higher)' is enabled"
            Section          = 'Security Services'
            Subsection       = 'Microsoft Defender for Cloud'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS8115-AttackPathNotifications'
            Description      = 'Attack path notifications should be enabled for appropriate risk levels.'
            Remediation      = 'Enable attack path notifications in Defender for Cloud > Email notification settings.'
            References       = @('https://learn.microsoft.com/en-us/azure/defender-for-cloud/configure-email-notifications')
            CISControls      = @('v8:17.2', 'v7:19.1')
        }
        @{
            ControlId        = '8.1.16'
            Title            = "Ensure that Microsoft Defender External Attack Surface Monitoring (EASM) is enabled"
            Section          = 'Security Services'
            Subsection       = 'Microsoft Defender for Cloud'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'EASM should be enabled to discover and monitor the external attack surface.'
            Remediation      = 'Enable and configure Microsoft Defender External Attack Surface Monitoring.'
            ManualGuidance   = 'Navigate to Microsoft Defender for Cloud and verify EASM is enabled and configured with appropriate discovery groups.'
            References       = @('https://learn.microsoft.com/en-us/azure/external-attack-surface-management/')
            CISControls      = @('v8:12.1', 'v7:9.1')
        }

        # 8.2 Microsoft Defender for IoT
        @{
            ControlId        = '8.2.1'
            Title            = "Ensure That Microsoft Defender for IoT Hub Is Set To 'On'"
            Section          = 'Security Services'
            Subsection       = 'Microsoft Defender for IoT'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'Microsoft Defender for IoT Hub should be enabled for IoT workloads.'
            Remediation      = 'Enable Defender for IoT on each IoT Hub from the IoT Hub security settings.'
            ManualGuidance   = 'Navigate to IoT Hub > Defender for IoT > Settings. Verify that Defender for IoT is enabled.'
            References       = @('https://learn.microsoft.com/en-us/azure/defender-for-iot/organizations/overview')
            CISControls      = @('v8:10.1', 'v7:8.1')
        }

        # 8.3 Key Vault
        @{
            ControlId        = '8.3.1'
            Title            = "Ensure that the Expiration Date is set for all Keys in RBAC Key Vaults"
            Section          = 'Security Services'
            Subsection       = 'Key Vault'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'KeyVaultKeyExpiry'
            VaultType        = 'RBAC'
            Description      = 'All keys in RBAC Key Vaults should have an expiration date set.'
            Remediation      = 'Set an expiration date on all keys in RBAC Key Vaults.'
            References       = @('https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys')
            CISControls      = @('v8:3.11', 'v7:14.4')
        }
        @{
            ControlId        = '8.3.2'
            Title            = "Ensure that the Expiration Date is set for all Keys in Non-RBAC Key Vaults"
            Section          = 'Security Services'
            Subsection       = 'Key Vault'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'KeyVaultKeyExpiry'
            VaultType        = 'NonRBAC'
            Description      = 'All keys in Non-RBAC Key Vaults should have an expiration date set.'
            Remediation      = 'Set an expiration date on all keys in Non-RBAC Key Vaults.'
            References       = @('https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys')
            CISControls      = @('v8:3.11', 'v7:14.4')
        }
        @{
            ControlId        = '8.3.3'
            Title            = "Ensure that the Expiration Date is set for all Secrets in RBAC Key Vaults"
            Section          = 'Security Services'
            Subsection       = 'Key Vault'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'KeyVaultSecretExpiry'
            VaultType        = 'RBAC'
            Description      = 'All secrets in RBAC Key Vaults should have an expiration date set.'
            Remediation      = 'Set an expiration date on all secrets in RBAC Key Vaults.'
            References       = @('https://learn.microsoft.com/en-us/azure/key-vault/secrets/about-secrets')
            CISControls      = @('v8:3.11', 'v7:14.4')
        }
        @{
            ControlId        = '8.3.4'
            Title            = "Ensure that the Expiration Date is set for all Secrets in Non-RBAC Key Vaults"
            Section          = 'Security Services'
            Subsection       = 'Key Vault'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'KeyVaultSecretExpiry'
            VaultType        = 'NonRBAC'
            Description      = 'All secrets in Non-RBAC Key Vaults should have an expiration date set.'
            Remediation      = 'Set an expiration date on all secrets in Non-RBAC Key Vaults.'
            References       = @('https://learn.microsoft.com/en-us/azure/key-vault/secrets/about-secrets')
            CISControls      = @('v8:3.11', 'v7:14.4')
        }
        @{
            ControlId        = '8.3.5'
            Title            = "Ensure 'Purge protection' is set to 'Enabled'"
            Section          = 'Security Services'
            Subsection       = 'Key Vault'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'KeyVaultProperty'
            PropertyPath     = 'EnablePurgeProtection'
            ExpectedValue    = $true
            Description      = 'Purge protection should be enabled on Key Vaults to prevent permanent deletion during retention period.'
            Remediation      = 'Enable purge protection on all Key Vaults. Note: this cannot be disabled once enabled.'
            References       = @('https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview')
            CISControls      = @('v8:3.3', 'v7:14.6')
        }
        @{
            ControlId        = '8.3.6'
            Title            = "Ensure that Role Based Access Control for Azure Key Vault is enabled"
            Section          = 'Security Services'
            Subsection       = 'Key Vault'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'KeyVaultProperty'
            PropertyPath     = 'EnableRbacAuthorization'
            ExpectedValue    = $true
            Description      = 'RBAC should be enabled for Key Vault access control instead of vault access policies.'
            Remediation      = 'Enable RBAC authorization on Key Vaults and migrate from access policies.'
            References       = @('https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide')
            CISControls      = @('v8:6.1', 'v7:4.1')
        }
        @{
            ControlId        = '8.3.7'
            Title            = "Ensure Public Network Access is Disabled"
            Section          = 'Security Services'
            Subsection       = 'Key Vault'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'KeyVaultProperty'
            PropertyPath     = 'PublicNetworkAccess'
            ExpectedValue    = 'Disabled'
            Description      = 'Public network access to Key Vaults should be disabled.'
            Remediation      = 'Disable public network access on Key Vaults and configure private endpoints.'
            References       = @('https://learn.microsoft.com/en-us/azure/key-vault/general/private-link-service')
            CISControls      = @('v8:12.2', 'v7:14.1')
        }
        @{
            ControlId        = '8.3.8'
            Title            = "Ensure Private Endpoints are used to access Azure Key Vault"
            Section          = 'Security Services'
            Subsection       = 'Key Vault'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS838-KeyVaultPrivateEndpoints'
            Description      = 'Private endpoints should be configured for Key Vault access.'
            Remediation      = 'Create private endpoints for each Key Vault and configure DNS settings.'
            References       = @('https://learn.microsoft.com/en-us/azure/key-vault/general/private-link-service')
            CISControls      = @('v8:12.2', 'v7:14.1')
        }
        @{
            ControlId        = '8.3.9'
            Title            = "Ensure automatic key rotation is enabled within Azure Key Vault"
            Section          = 'Security Services'
            Subsection       = 'Key Vault'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS839-KeyRotation'
            Description      = 'Automatic key rotation should be configured for keys in Key Vault.'
            Remediation      = 'Configure automatic key rotation policies on keys in Key Vault.'
            References       = @('https://learn.microsoft.com/en-us/azure/key-vault/keys/how-to-configure-key-rotation')
            CISControls      = @('v8:3.11', 'v7:14.4')
        }
        @{
            ControlId        = '8.3.10'
            Title            = "Ensure that Azure Key Vault Managed HSM is used when required"
            Section          = 'Security Services'
            Subsection       = 'Key Vault'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 2
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'Managed HSM should be used for workloads requiring FIPS 140-2 Level 3 validated HSMs.'
            Remediation      = 'Deploy Azure Key Vault Managed HSM for workloads requiring higher security assurance.'
            ManualGuidance   = 'Evaluate workloads requiring FIPS 140-2 Level 3 compliance and deploy Managed HSM where necessary.'
            References       = @('https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/overview')
            CISControls      = @('v8:3.11', 'v7:14.4')
        }
        @{
            ControlId        = '8.3.11'
            Title            = "Ensure certificate 'Validity Period (in months)' is less than or equal to '12'"
            Section          = 'Security Services'
            Subsection       = 'Key Vault'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS8311-CertificateValidity'
            Description      = 'Certificate validity period should not exceed 12 months to ensure regular rotation.'
            Remediation      = 'Set certificate issuance policies to limit validity period to 12 months or less.'
            References       = @('https://learn.microsoft.com/en-us/azure/key-vault/certificates/about-certificates')
            CISControls      = @('v8:3.11', 'v7:14.4')
        }

        # 8.4 Azure Bastion
        @{
            ControlId        = '8.4.1'
            Title            = "Ensure an Azure Bastion Host Exists"
            Section          = 'Security Services'
            Subsection       = 'Azure Bastion'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 2
            Severity         = 'Medium'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS841-BastionHost'
            Description      = 'An Azure Bastion host should exist to provide secure RDP/SSH connectivity without exposing public IPs.'
            Remediation      = 'Deploy an Azure Bastion host in a virtual network to enable secure management access.'
            References       = @('https://learn.microsoft.com/en-us/azure/bastion/bastion-overview')
            CISControls      = @('v8:12.2', 'v7:9.2')
        }

        # 8.5 DDoS Protection
        @{
            ControlId        = '8.5'
            Title            = "Ensure Azure DDoS Network Protection is enabled on virtual networks"
            Section          = 'Security Services'
            Subsection       = 'DDoS Protection'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS85-DDoSProtection'
            Description      = 'Azure DDoS Network Protection should be enabled on virtual networks.'
            Remediation      = 'Enable Azure DDoS Network Protection plan and associate it with virtual networks.'
            References       = @('https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview')
            CISControls      = @('v8:13.10', 'v7:18.9')
        }

        # =====================================================================
        # SECTION 9: STORAGE SERVICES (23 controls)
        # =====================================================================

        # 9.1 Azure Files
        @{
            ControlId        = '9.1.1'
            Title            = "Ensure soft delete for Azure File Shares is Enabled"
            Section          = 'Storage Services'
            Subsection       = 'Azure Files'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'StorageFileProperty'
            CheckType        = 'SoftDelete'
            Description      = 'Soft delete should be enabled for Azure File Shares to protect against accidental deletion.'
            Remediation      = 'Enable soft delete for file shares on each storage account with a retention period of at least 7 days.'
            References       = @('https://learn.microsoft.com/en-us/azure/storage/files/storage-files-enable-soft-delete')
            CISControls      = @('v8:11.3', 'v7:10.1')
        }
        @{
            ControlId        = '9.1.2'
            Title            = "Ensure 'SMB protocol version' is set to 'SMB 3.1.1' or higher for SMB file shares"
            Section          = 'Storage Services'
            Subsection       = 'Azure Files'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'StorageFileProperty'
            CheckType        = 'SMBVersion'
            Description      = 'SMB protocol version should be set to 3.1.1 or higher for secure file share access.'
            Remediation      = 'Set the minimum SMB protocol version to 3.1.1 on storage account file share settings.'
            References       = @('https://learn.microsoft.com/en-us/azure/storage/files/files-smb-protocol')
            CISControls      = @('v8:3.10', 'v7:14.4')
        }
        @{
            ControlId        = '9.1.3'
            Title            = "Ensure 'SMB channel encryption' is set to 'AES-256-GCM' or higher for SMB file shares"
            Section          = 'Storage Services'
            Subsection       = 'Azure Files'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'StorageFileProperty'
            CheckType        = 'SMBEncryption'
            Description      = 'SMB channel encryption should use AES-256-GCM or stronger for file share security.'
            Remediation      = 'Configure SMB channel encryption to use AES-256-GCM on the storage account.'
            References       = @('https://learn.microsoft.com/en-us/azure/storage/files/files-smb-protocol')
            CISControls      = @('v8:3.10', 'v7:14.4')
        }

        # 9.2 Azure Blob Storage
        @{
            ControlId        = '9.2.1'
            Title            = "Ensure that soft delete for blobs on Azure Blob Storage storage accounts is Enabled"
            Section          = 'Storage Services'
            Subsection       = 'Azure Blob Storage'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'StorageBlobProperty'
            CheckType        = 'BlobSoftDelete'
            Description      = 'Blob soft delete should be enabled to protect against accidental blob deletion.'
            Remediation      = 'Enable blob soft delete on all storage accounts with a retention period of at least 7 days.'
            References       = @('https://learn.microsoft.com/en-us/azure/storage/blobs/soft-delete-blob-overview')
            CISControls      = @('v8:11.3', 'v7:10.1')
        }
        @{
            ControlId        = '9.2.2'
            Title            = "Ensure that soft delete for containers on Azure Blob Storage storage accounts is Enabled"
            Section          = 'Storage Services'
            Subsection       = 'Azure Blob Storage'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'StorageBlobProperty'
            CheckType        = 'ContainerSoftDelete'
            Description      = 'Container soft delete should be enabled to protect against accidental container deletion.'
            Remediation      = 'Enable container soft delete on all storage accounts with a retention period of at least 7 days.'
            References       = @('https://learn.microsoft.com/en-us/azure/storage/blobs/soft-delete-container-overview')
            CISControls      = @('v8:11.3', 'v7:10.1')
        }
        @{
            ControlId        = '9.2.3'
            Title            = "Ensure 'Versioning' is set to 'Enabled' on Azure Blob Storage storage accounts"
            Section          = 'Storage Services'
            Subsection       = 'Azure Blob Storage'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'StorageBlobProperty'
            CheckType        = 'BlobVersioning'
            Description      = 'Blob versioning should be enabled to maintain previous versions of blobs for recovery purposes.'
            Remediation      = 'Enable blob versioning on all storage accounts.'
            References       = @('https://learn.microsoft.com/en-us/azure/storage/blobs/versioning-overview')
            CISControls      = @('v8:11.3', 'v7:10.1')
        }

        # 9.3 Storage Accounts
        @{
            ControlId        = '9.3.1.1'
            Title            = "Ensure that 'Enable key rotation reminders' is enabled for each Storage Account"
            Section          = 'Storage Services'
            Subsection       = 'Storage Accounts - Secrets and Keys'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS9311-KeyRotationReminders'
            Description      = 'Key rotation reminders should be enabled to ensure storage account keys are rotated regularly.'
            Remediation      = 'Enable key rotation reminders on each storage account.'
            References       = @('https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage')
            CISControls      = @('v8:3.11', 'v7:14.4')
        }
        @{
            ControlId        = '9.3.1.2'
            Title            = "Ensure that Storage Account access keys are periodically regenerated"
            Section          = 'Storage Services'
            Subsection       = 'Storage Accounts - Secrets and Keys'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS9312-KeyRegeneration'
            Description      = 'Storage account access keys should be regenerated periodically to minimize the window of compromised keys.'
            Remediation      = 'Regenerate storage account access keys on a regular schedule (at least every 90 days).'
            References       = @('https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage')
            CISControls      = @('v8:3.11', 'v7:14.4')
        }
        @{
            ControlId        = '9.3.1.3'
            Title            = "Ensure 'Allow storage account key access' for Azure Storage Accounts is 'Disabled'"
            Section          = 'Storage Services'
            Subsection       = 'Storage Accounts - Secrets and Keys'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'StorageAccountProperty'
            PropertyPath     = 'AllowSharedKeyAccess'
            ExpectedValue    = $false
            Description      = 'Shared key access should be disabled to enforce Azure AD authentication for storage accounts.'
            Remediation      = 'Disable shared key access on storage accounts and use Azure AD authentication instead.'
            References       = @('https://learn.microsoft.com/en-us/azure/storage/common/shared-key-authorization-prevent')
            CISControls      = @('v8:6.1', 'v7:4.1')
        }
        @{
            ControlId        = '9.3.2.1'
            Title            = "Ensure Private Endpoints are used to access Storage Accounts"
            Section          = 'Storage Services'
            Subsection       = 'Storage Accounts - Networking'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS9321-StoragePrivateEndpoints'
            Description      = 'Private endpoints should be used for storage account access.'
            Remediation      = 'Create private endpoints for storage accounts and configure DNS settings.'
            References       = @('https://learn.microsoft.com/en-us/azure/storage/common/storage-private-endpoints')
            CISControls      = @('v8:12.2', 'v7:14.1')
        }
        @{
            ControlId        = '9.3.2.2'
            Title            = "Ensure that 'Public Network Access' is 'Disabled' for storage accounts"
            Section          = 'Storage Services'
            Subsection       = 'Storage Accounts - Networking'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'StorageAccountProperty'
            PropertyPath     = 'PublicNetworkAccess'
            ExpectedValue    = 'Disabled'
            Description      = 'Public network access should be disabled on storage accounts.'
            Remediation      = 'Disable public network access on storage accounts and use private endpoints.'
            References       = @('https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security')
            CISControls      = @('v8:12.2', 'v7:14.1')
        }
        @{
            ControlId        = '9.3.2.3'
            Title            = "Ensure default network access rule for storage accounts is set to deny"
            Section          = 'Storage Services'
            Subsection       = 'Storage Accounts - Networking'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'StorageAccountProperty'
            PropertyPath     = 'NetworkRuleSet.DefaultAction'
            ExpectedValue    = 'Deny'
            Description      = 'The default network access rule should be set to deny to restrict access to allowed networks only.'
            Remediation      = 'Set the default network access rule to Deny on all storage accounts.'
            References       = @('https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security')
            CISControls      = @('v8:12.2', 'v7:14.1')
        }
        @{
            ControlId        = '9.3.3.1'
            Title            = "Ensure that 'Default to Microsoft Entra authorization in the Azure portal' is set to 'Enabled'"
            Section          = 'Storage Services'
            Subsection       = 'Storage Accounts - Identity and Access Management'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'StorageAccountProperty'
            PropertyPath     = 'DefaultToOAuthAuthentication'
            ExpectedValue    = $true
            Description      = 'Storage accounts should default to Microsoft Entra authorization in the Azure portal.'
            Remediation      = 'Enable "Default to Microsoft Entra authorization in the Azure portal" on storage accounts.'
            References       = @('https://learn.microsoft.com/en-us/azure/storage/blobs/authorize-data-operations-portal')
            CISControls      = @('v8:6.1', 'v7:4.1')
        }
        @{
            ControlId        = '9.3.4'
            Title            = "Ensure that 'Secure transfer required' is set to 'Enabled'"
            Section          = 'Storage Services'
            Subsection       = 'Storage Accounts'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'StorageAccountProperty'
            PropertyPath     = 'EnableHttpsTrafficOnly'
            ExpectedValue    = $true
            Description      = 'Secure transfer should be required to enforce HTTPS connections to storage accounts.'
            Remediation      = 'Enable "Secure transfer required" on all storage accounts.'
            References       = @('https://learn.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer')
            CISControls      = @('v8:3.10', 'v7:14.4')
        }
        @{
            ControlId        = '9.3.5'
            Title            = "Ensure 'Allow Azure services on the trusted services list to access this storage account' is Enabled for Storage Account Access"
            Section          = 'Storage Services'
            Subsection       = 'Storage Accounts'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS935-TrustedServices'
            Description      = 'Trusted Azure services should be allowed to bypass network rules to access storage accounts.'
            Remediation      = 'Enable "Allow Azure services on the trusted services list" on the storage account network rules.'
            References       = @('https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security')
            CISControls      = @('v8:12.2', 'v7:14.1')
        }
        @{
            ControlId        = '9.3.6'
            Title            = "Ensure the 'Minimum TLS version' for storage accounts is set to 'Version 1.2'"
            Section          = 'Storage Services'
            Subsection       = 'Storage Accounts'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'High'
            CheckPattern     = 'StorageAccountProperty'
            PropertyPath     = 'MinimumTlsVersion'
            ExpectedValue    = 'TLS1_2'
            Description      = 'Storage accounts should enforce TLS 1.2 as the minimum version.'
            Remediation      = 'Set the minimum TLS version to TLS 1.2 on all storage accounts.'
            References       = @('https://learn.microsoft.com/en-us/azure/storage/common/transport-layer-security-configure-minimum-version')
            CISControls      = @('v8:3.10', 'v7:14.4')
        }
        @{
            ControlId        = '9.3.7'
            Title            = "Ensure 'Cross Tenant Replication' is not enabled"
            Section          = 'Storage Services'
            Subsection       = 'Storage Accounts'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'StorageAccountProperty'
            PropertyPath     = 'AllowCrossTenantReplication'
            ExpectedValue    = $false
            Description      = 'Cross-tenant replication should be disabled to prevent data from being replicated to external tenants.'
            Remediation      = 'Disable cross-tenant replication on all storage accounts.'
            References       = @('https://learn.microsoft.com/en-us/azure/storage/blobs/object-replication-overview')
            CISControls      = @('v8:3.3', 'v7:14.6')
        }
        @{
            ControlId        = '9.3.8'
            Title            = "Ensure that 'Allow Blob Anonymous Access' is set to 'Disabled'"
            Section          = 'Storage Services'
            Subsection       = 'Storage Accounts'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Critical'
            CheckPattern     = 'StorageAccountProperty'
            PropertyPath     = 'AllowBlobPublicAccess'
            ExpectedValue    = $false
            Description      = 'Anonymous blob access should be disabled to prevent unauthorized data access.'
            Remediation      = 'Disable "Allow Blob public access" on all storage accounts.'
            References       = @('https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent')
            CISControls      = @('v8:3.3', 'v7:14.6')
        }
        @{
            ControlId        = '9.3.9'
            Title            = "Ensure Azure Resource Manager Delete locks are applied to Azure Storage Accounts"
            Section          = 'Storage Services'
            Subsection       = 'Storage Accounts'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'ManualCheck'
            Description      = 'Delete locks should be applied to critical storage accounts to prevent accidental deletion.'
            Remediation      = 'Apply CanNotDelete resource locks to critical storage accounts.'
            ManualGuidance   = 'Navigate to each critical storage account > Settings > Locks. Verify a CanNotDelete lock exists.'
            References       = @('https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources')
            CISControls      = @('v8:3.3', 'v7:14.6')
        }
        @{
            ControlId        = '9.3.10'
            Title            = "Ensure Azure Resource Manager ReadOnly locks are considered for Azure Storage Accounts"
            Section          = 'Storage Services'
            Subsection       = 'Storage Accounts'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 1
            Severity         = 'Low'
            CheckPattern     = 'ManualCheck'
            Description      = 'ReadOnly locks should be considered for storage accounts to prevent accidental modifications.'
            Remediation      = 'Consider applying ReadOnly resource locks to storage accounts where appropriate.'
            ManualGuidance   = 'Evaluate if ReadOnly locks are appropriate for storage accounts. Note: ReadOnly locks can prevent operations like key regeneration.'
            References       = @('https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources')
            CISControls      = @('v8:3.3', 'v7:14.6')
        }
        @{
            ControlId        = '9.3.11'
            Title            = "Ensure Redundancy is set to 'geo-redundant storage (GRS)' on critical Azure Storage Accounts"
            Section          = 'Storage Services'
            Subsection       = 'Storage Accounts'
            AssessmentStatus = 'Automated'
            ProfileLevel     = 1
            Severity         = 'Medium'
            CheckPattern     = 'Custom'
            CheckFunction    = 'Test-CIS9311-StorageRedundancy'
            Description      = 'Critical storage accounts should use geo-redundant storage for disaster recovery.'
            Remediation      = 'Set storage account redundancy to GRS, RA-GRS, GZRS, or RA-GZRS for critical data.'
            References       = @('https://learn.microsoft.com/en-us/azure/storage/common/storage-redundancy')
            CISControls      = @('v8:11.3', 'v7:10.1')
        }
    )
}
