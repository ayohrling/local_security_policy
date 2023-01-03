# Puppet Local Security Policy

created by Paul Cannon at email paulscannon at gmail dot com

forked and updated by Adam Yohrling at email aryohrling at gmail dot com

## Local_security_policy features
Configure local security policy (LSP) for Windows servers.
LSP is key to a baseline configuration of the following security features:
### Account Policy
  * Password Policy
  * Account Lockout Policy
### Local Policy
  * Audit Policy
  * User Rights Assignment
  * Security Options

This module uses types and providers to list, update, and validate settings.

## Use
The title and name of the resources is exact match of what is in Local Security Policy GUI.  If you are uncertain of the setting name and values just use `puppet resource local_security_policy` to pipe them all into a file and make adjustments as necessary.
The block will look like this
```
local_security_policy { 'Audit account logon events': <- Title / Name
  ensure         => present,              <- Always present
  policy_setting => "AuditAccountLogon",  <- The secedit file key. Informational purposes only, not for use in manifest definitions
  policy_type    => "Event Audit",        <- The secedit file section, Informational purposes only, not for use in manifest definitions
  policy_value   => 'Success,Failure',    <- Values
}
```


### Listing all settings
Show all `local_security_policy` resources available on server
```
puppet resource local_security_policy
```
Show a single `local_security_policy` resources available on server
```
puppet resource local_security_policy 'Maximum password age'
```

### More examples
Example Password Policy
```
local_security_policy { 'Maximum password age':
  ensure => present,
  policy_value => '90',
}
```

Example Audit Policy
```
local_security_policy { 'Audit account logon events':
  ensure => present,
  policy_value => 'Success,Failure',
}
```

Example User Rights Policy
```
local_security_policy { 'Allow log on locally':
  ensure => present,
  policy_value => 'Administrators',
}
```
Example Security Settings
```
local_security_policy { 'System cryptography: Use FIPS compiant algorithms for encryption, hashing, and signing':
  ensure => present,
  policy_value => 1 ,
}
```

### Full list of settings available
      Access Credential Manager as a trusted caller
      Access this computer from the network
      Account lockout duration
      Account lockout threshold
      Accounts: Administrator account status
      Accounts: Block Microsoft accounts
      Accounts: Guest account status
      Accounts: Limit local account use of blank passwords to console logon only
      Accounts: Rename administrator account
      Accounts: Rename guest account
      Accounts: Require Login to Change Password
      Act as part of the operating system
      Add workstations to domain
      Adjust memory quotas for a process
      Allow log on locally
      Allow log on through Remote Desktop Services
      Audit account logon events
      Audit account management
      Audit: Audit the access of global system objects
      Audit: Audit the use of Backup and Restore privilege
      Audit directory service access
      Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings
      Audit logon events
      Audit object access
      Audit policy change
      Audit privilege use
      Audit process tracking
      Audit: Shut down system immediately if unable to log security audits
      Audit system events
      Back up files and directories
      Bypass traverse checking
      Change the system time
      Change the time zone
      Create a pagefile
      Create a token object
      Create global objects
      Create permanent shared objects
      Create symbolic links
      DCOM: Machine Access Restrictions in Security Descriptor Definition Language (SDDL) syntax
      DCOM: Machine Launch Restrictions in Security Descriptor Definition Language (SDDL) syntax
      Debug programs
      Deny access to this computer from the network
      Deny log on as a batch job
      Deny log on as a service
      Deny log on locally
      Deny log on through Remote Desktop Services
      Devices: Allowed to format and eject removable media
      Devices: Allow undock without having to log on
      Devices: Prevent users from installing printer drivers
      Devices: Restrict CD-ROM access to locally logged-on user only
      Devices: Restrict floppy access to locally logged-on user only
      Domain member: Digitally encrypt or sign secure channel data (always)
      Domain member: Digitally encrypt secure channel data (when possible)
      Domain member: Digitally sign secure channel data (when possible)
      Domain member: Disable machine account password changes
      Domain member: Maximum machine account password age
      Domain member: Require strong (Windows 2000 or later) session key
      EnableAdminAccount
      Enable computer and user accounts to be trusted for delegation
      Enforce password history
      Force shutdown from a remote system
      Generate security audits
      Impersonate a client after authentication
      Increase a process working set
      Increase scheduling priority
      Interactive logon: Display user information when the session is locked
      Interactive logon: Do not display last user name
      Interactive logon: Don't display last signed-in
      Interactive logon: Don't display username at sign-in
      Interactive logon: Do not require CTRL+ALT+DEL
      Interactive logon: Machine account lockout threshold
      Interactive logon: Machine inactivity limit
      Interactive logon: Message text for users attempting to log on
      Interactive logon: Message title for users attempting to log on
      Interactive logon: Number of previous logons to cache (in case domain controller is not available)
      Interactive logon: Prompt user to change password before expiration
      Interactive logon: Require Domain Controller authentication to unlock workstation
      Interactive logon: Require Windows Hello for Business or smart card
      Interactive logon: Require smart card
      Interactive logon: Smart card removal behavior
      Load and unload device drivers
      Lock pages in memory
      Log on as a batch job
      Log on as a service
      Manage auditing and security log
      Maximum password age
      Microsoft network client: Digitally sign communications (always)
      Microsoft network client: Digitally sign communications (if server agrees)
      Microsoft network client: Send unencrypted password to third-party SMB servers
      Microsoft network server: Amount of idle time required before suspending session
      Microsoft network server: Attempt S4U2Self to obtain claim information
      Microsoft network server: Digitally sign communications (always)
      Microsoft network server: Digitally sign communications (if client agrees)
      Microsoft network server: Disconnect clients when logon hours expire
      Microsoft network server: Server SPN target name validation level
      Minimum password age
      Minimum password length
      Minimum password length audit
      Modify an object label
      Modify firmware environment values
      Network access: Allow anonymous SID/name translation
      Network access: Do not allow anonymous enumeration of SAM accounts
      Network access: Do not allow anonymous enumeration of SAM accounts and shares
      Network access: Do not allow storage of passwords and credentials for network authentication
      Network access: Let Everyone permissions apply to anonymous users
      Network access: Named Pipes that can be accessed anonymously
      Network access: Remotely accessible registry paths
      Network access: Remotely accessible registry paths and sub-paths
      Network access: Restrict anonymous access to Named Pipes and Shares
      Network access: Restrict clients allowed to make remote calls to SAM
      Network access: Shares that can be accessed anonymously
      Network access: Sharing and security model for local accounts
      Network security: All Local System to use computer identity for NTLM
      Network security: Allow LocalSystem NULL session fallback
      Network security: Allow PKU2U authentication requests to this computer to use online identities
      Network security: Configure encryption types allowed for Kerberos
      Network security: Do not store LAN Manager hash value on next password change
      Network security: Force logoff when logon hours expire
      Network security: LAN Manager authentication level
      Network security: LDAP client signing requirements
      Network security: Minimum session security for NTLM SSP based (including secure RPC) clients
      Network security: Minimum session security for NTLM SSP based (including secure RPC) servers
      Network security: Restrict NTLM: Add remote server exceptions for NTLM authentication
      Network security: Restrict NTLM: Add server exceptions in this domain
      Network security: Restrict NTLM: Audit Incoming NTLM Traffic
      Network security: Restrict NTLM: Audit NTLM authentication in this domain
      Network security: Restrict NTLM: Incoming NTLM traffic
      Network security: Restrict NTLM: NTLM authentication in this domain
      Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers
      Obtain an impersonation token for another user in the same session
      Password must meet complexity requirements
      Perform volume maintenance tasks
      Profile single process
      Profile system performance
      Recovery console: Allow automatic administrative logon
      Recovery console: Allow floppy copy and access to all drives and all folders
      Relax minimum password length limits
      Remove computer from docking station
      Replace a process level token
      Reset account lockout counter after
      Restore files and directories
      Shutdown: Allow system to be shut down without having to log on
      Shutdown: Clear virtual memory pagefile
      Shut down the system
      Store passwords using reversible encryption
      Synchronize directory service data
      System cryptography: Force strong key protection for user keys stored on the computer
      System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing
      System objects: Require case insensitivity for non-Windows subsystems
      System objects: Strengthen default permissions of internal system objects (e.g., Symbolic Links)
      System settings: Optional subsystems
      System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies
      Take ownership of files or other objects
      User Account Control: Admin Approval Mode for the Built-in Administrator account
      User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop
      User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode
      User Account Control: Behavior of the elevation prompt for standard users
      User Account Control: Detect application installations and prompt for elevation
      User Account Control: Only elevate executables that are signed and validated
      User Account Control: Only elevate UIAccess applications that are installed in secure locations
      User Account Control: Run all administrators in Admin Approval Mode
      User Account Control: Switch to the secure desktop when prompting for elevation
      User Account Control: Virtualize file and registry write failures to per-user locations



## How this works
The `local_security_policy` module works by using `secedit /export` to export a list of currently set policies.  The module will then
take the user defined resources and compare the values against the exported policies.  If the values on the system do not match
the defined resource, the module will run `secedit /configure` to configure the policy on the system.  If the policy already
exists on the system no change will be made.

In order to make setting these polices easier, this module uses the policy description from the Local Security Policy
management console and translates that into the appropriate entries in the file used by `secedit /configure`.  Similarly, the module is
able to translate user and group names into the SID and name values that are used by User Rights Assignment policies.

New policy maps require values for the key, name, and policy_type. Policies that require user and group conversion to SID values require `data_type: :principal` to perform the translation.  Policies that require the value to be enclosed in double-quotes require `data_type: :quoted_string`. Policies that modify registry values also require a value for `reg_type`. 
The following `reg_type` values are supported:

```
    REG_NONE 0
    REG_SZ 1
    REG_EXPAND_SZ 2
    REG_BINARY 3
    REG_DWORD 4
    REG_DWORD_LITTLE_ENDIAN 4
    REG_DWORD_BIG_ENDIAN 5
    REG_LINK 6
    REG_MULTI_SZ 7
    REG_RESOURCE_LIST 8
    REG_FULL_RESOURCE_DESCRIPTOR 9
    REG_RESOURCE_REQUIREMENTS_LIST 10
    REG_QWORD 11
    REG_QWORD_LITTLE_ENDIAN 11
```
Here are examples of working policy definitions from lib\puppet_x\lsp\security_policy.rb: 

```
'Accounts: Rename administrator account' => {
                name: 'NewAdministratorName',
                policy_type: 'System Access',
                data_type: :quoted_string
            },
 'Recovery console: Allow floppy copy and access to all drives and all folders' => {
                name: 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SetCommand',
                reg_type: '4',
                policy_type: 'Registry Values',
            },
  'Allow log on locally' => {
                name: 'SeInteractiveLogonRight',
                policy_type: 'Privilege Rights',
                data_type: :principal,
      },
```

In the first example above, the key `Accounts: Rename administrator account ` is what the user will define as the 'name' in the resource.  In the policy definitions included in the module, this is the name shown in the Local Security Policy management console.  It is recommended to make this something descriptive and easy to remember, or a description pulled from the Operating System.
The name `'NewAdministratorName'` is the key used in the import file used by `secedit /configure`.
The policy_type `'System Access'` is the section name in the import file used by `secedit /configure`.
The data_type `':quoted_string'` indicates that this value must be enclosed in double-quotes in the import file used by `secedit /configure`.

To modify these settings, you would define the following resources in your Puppet configuration:

```
local_security_policy { 'Accounts: Rename administrator account':
  ensure => present,
  policy_value => 'MyAdminAccount',
}

local_security_policy { 'Recovery console: Allow floppy copy and access to all drives and all folders':
  ensure => present,
  policy_value => '0',
}

local_security_policy { 'Allow log on locally':
  ensure => present,
  policy_value => 'Administrators',
}
```
Assuming all of the desired values are different than what is currently set in the OS, this would result in the following INI file, which would be imported by `secedit /configure`:

```
[Unicode]
Unicode=yes
[System Access]
NewAdministratorName = "MyAdminAccount"
[Registry Values]
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SetCommand=4,0
[Privilege Rights]
SeInteractiveLogonRight = *S-1-5-32-544
[Version]
signature="$CHICAGO$"
Revision=1

```

## Commands Used

## TODO: Future release
* Handle unsupported policies
* Validate users in active directory are being handled.
