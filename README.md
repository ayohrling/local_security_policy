# Puppet Local Security Policy

created by Paul Cannon at email paulscannon at gmail dot com

forked and updated by Adam Yohrling at email aryohrling at gmail dot com

## Local_security_policy features
Configure, local security policy (LSP) for windows servers.  
LSP is key to a baseline configuration of the following security features:
### Account Policy
  * Password Policy
  * Account Lockout Policy
### Local Policy
  * Audit Policy
  * User Rights Assignment
  * Security Options
  * Registry Values


This module uses types and providers to list, update, validate settings

## Use
The title and name of the resources is exact match of what is in secedit GUI.  If you are uncertain of the setting name and values just user 'resource' to pipe them all into a file and make adjustments as necessary.
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
Show all local_security_policy resources available on server
```
puppet resource local_security_policy
```
Show a single local_security_policy resources available on server
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
  policy_value => '90',
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
      Accounts: Block Microsoft accounts
      Accounts: Limit local account use of blank passwords to console logon only
      Accounts: Rename administrator account
      Accounts: Rename guest account
      Accounts: Require Login to Change Password
      Act as part of the operating system
      Add workstations to domain
      Adjust memory quotas for a process
      Allow log on locally
      Allow log on through Remote Desktop Services
      Allow Online Tips
      Allow users to enable online speech recognition services
      Audit account logon events
      Audit account management
      Audit directory service access
      Audit logon events
      Audit object access
      Audit policy change
      Audit privilege use
      Audit process tracking
      Audit system events
      Audit: Audit the access of global system objects
      Audit: Audit the use of Backup and Restore privilege
      Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings
      Audit: Shut down system immediately if unable to log security audits
      Back up files and directories
      Boot-Start Driver Initialization Policy
      Bypass traverse checking
      Change the system time
      Change the time zone
      Configure registry policy processing:  Do not apply during periodic background processing
      Configure registry policy processing:  Process even if the Group Policy objects have not changed
      Continue experiences on this device
      Create a pagefile
      Create a token object
      Create global objects
      Create permanent shared objects
      Create symbolic links
      Debug programs
      Deny access to this computer from the network
      Deny log on as a batch job
      Deny log on as a service
      Deny log on locally
      Deny log on through Remote Desktop Services
      Devices: Allow undock without having to log on
      Devices: Allowed to format and eject removable media
      Devices: Prevent users from installing printer drivers
      Devices: Restrict CD-ROM access to locally logged-on user only
      Disable IPv6
      Devices: Restrict floppy access to locally logged-on user only
      Do not allow password expiration time longer than required by policy
      Domain member: Digitally encrypt or sign secure channel data (always)
      Domain member: Digitally encrypt secure channel data (when possible)
      Domain member: Digitally sign secure channel data (when possible)
      Domain member: Disable machine account password changes
      Domain member: Maximum machine account password age
      Domain member: Require strong (Windows 2000 or later) session key
      Enable computer and user accounts to be trusted for delegation
      Enable Font Providers
      Enable insecure guest logons
      Enable Local Admin Password Management
      EnableAdminAccount
      Enforce password history
      Force shutdown from a remote system
      Generate security audits
      Impersonate a client after authentication
      Increase a process working set
      Increase scheduling priority
      Interactive logon: Display user information when the session is locked
      Interactive logon: Do not display last user name
      Interactive logon: Do not require CTRL+ALT+DEL
      Interactive logon: Machine account lockout threshold
      Interactive logon: Machine inactivity limit
      Interactive logon: Message text for users attempting to log on
      Interactive logon: Message title for users attempting to log on
      Interactive logon: Number of previous logons to cache (in case domain controller is not available)
      Interactive logon: Prompt user to change password before expiration
      Interactive logon: Require Domain Controller authentication to unlock workstation
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
      Microsoft network server: Digitally sign communications (always)
      Microsoft network server: Digitally sign communications (if client agrees)
      Microsoft network server: Disconnect clients when logon hours expire
      Microsoft network server: Server SPN target name validation level
      Minimum password age
      Minimum password length
      Modify an object label
      Modify firmware environment values
      MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)
      MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)
      MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)
      NetBIOS Node Type
      Network access: Allow anonymous SID/name translation
      Network access: Do not allow anonymous enumeration of SAM accounts
      Network access: Do not allow anonymous enumeration of SAM accounts and shares
      Network access: Do not allow storage of passwords and credentials for network authentication
      Network access: Let Everyone permissions apply to anonymous users
      Network access: Named Pipes that can be accessed anonymously
      Network access: Remotely accessible registry paths
      Network access: Remotely accessible registry paths and sub-paths
      Network access: Restrict anonymous access to Named Pipes and Shares
      Network access: Shares that can be accessed anonymously
      Network access: Sharing and security model for local accounts
      Network security: All Local System to use computer identity for NTLM
      Network security: Do not store LAN Manager hash value on next password change
      Network security: Force logoff when logon hours expire
      Network security: LAN Manager authentication level
      Network security: LDAP client signing requirements
      Network security: Minimum session security for NTLM SSP based (including secure RPC) clients
      Network security: Minimum session security for NTLM SSP based (including secure RPC) servers
      Password must meet complexity requirements
      PCHealth Error Reporting
      Perform volume maintenance tasks
      Prevent enabling lock screen camera
      Prevent enabling lock screen slide show
      Prohibit use of Internet Connection Sharing on your DNS domain network
      Profile single process
      Profile system performance
      Recovery console: Allow automatic administrative logon
      Recovery console: Allow floppy copy and access to all drives and all folders
      Remove computer from docking station
      Replace a process level token
      Reset account lockout counter after
      Restore files and directories
      Shut down the system
      Shutdown: Allow system to be shut down without having to log on
      Shutdown: Clear virtual memory pagefile
      Store passwords using reversible encryption
      Synchronize directory service data
      System cryptography: Force strong key protection for user keys stored on the computer
      System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing
      System objects: Require case insensitivity for non-Windows subsystems
      System objects: Strengthen default permissions of internal system objects (e.g., Symbolic Links)
      System settings: Optional subsystems
      System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies
      Take ownership of files or other objects
      Turn off handwriting recognition error reporting
      Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com
      Turn off Microsoft Peer-to-Peer Networking Services
      Turn off multicast name resolution
      Turn off Registration if URL connection is referring to Microsoft.com
      Turn off the "Publish to Web" task for files and folders
      Turn off the Windows Messenger Customer Experience Improvement Program
      Turn off Windows Customer Experience Improvement Program
      Turn off Windows Error Reporting
      Turn on Windows Defender protection against Potentially Unwanted Applications
      User Account Control: Admin Approval Mode for the Built-in Administrator account
      User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop
      User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode
      User Account Control: Behavior of the elevation prompt for standard users
      User Account Control: Detect application installations and prompt for elevation
      User Account Control: Only elevate UIAccess applications that are installed in secure locations
      User Account Control: Only elevate executables that are signed and validated
      User Account Control: Run all administrators in Admin Approval Mode
      User Account Control: Switch to the secure desktop when prompting for elevation
      User Account Control: Virtualize file and registry write failures to per-user locations
      WDigest Authentication


## How this works
The local_security_policy works by using `secedit /export` to export a list of currently set policies.  The module will then
take the user defined resource and compare the values against the exported policies.  If the values on the system do not match
the defined resource, the module will run `secedit /configure` to configure the policy on the system.  If the policy already
exists on the system no change will be made.

In order to make setting these polices easier, this module has extracted some of the difficult to lookup or remember pieces
of a policy and placed them in a map for easy translation and value conversion.  This means that you only need to remember the user
instead of the sid value, as well as the policy description instead of the special key that needs to be set.  The mappings
below define how this translation works.  If there is no map for your policy you will need to add to `lib/puppet_x/lsp/security_policy.rb`

```
'Accounts: Rename administrator account' => {
                :name => 'NewAdministratorName',
                :policy_type => 'System Access',
                :data_type => :quoted_string
            },
 'Recovery console: Allow floppy copy and access to all drives and all folders' => {
                :name => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SetCommand',
                :reg_type => '4',
                :policy_type => 'Registry Values',
            },
```

The key `Accounts: Rename administrator account ` in the first hash is what the user will define as the name in the resource name. 
Instead of remembering the policy name, the description will help us remember what the policy is for.  When defining new policy
maps you will need to define the key, name, policy_type, and optionally, data_type or reg_type.  

Currently for data_type there is only `:quoted_string`.  However, for reg_type(integer value) there are many values which are listed below:

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
## Useful lookup tools:

The following online tools have been useful in finding and adding new policy mappings:

- https://getadmx.com
- https://gpsearch.azurewebsites.net

## Commands Used

## TODO: Future release
* Handle unsupported policies
* Validate users in active directory are being handled.
