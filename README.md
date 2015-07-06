# Puppet Local Security Policy

created by Paul Cannon at email paulscannon at gmail dot com

forked and updated by Adam Yohrling at email aryohrling at gmail dot com

## Local_security_policy features
Configure, local security policy (LSP) for windows servers.  
LSP is key to a baseline configuration of the following security features:
### Account Policy
  * Password Policy
  * Account Lockout Policy
  qqqqq
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
	  ####Password policy Mappings
      'Enforce password history'
      'Maximum password age'
      'Minimum password age'
      'Minimum password length'
      'Password must meet complexity requirements'
      'Store passwords using reversible encryption'
      'Account lockout threshold'
      'Account lockout duration'
      'Reset account lockout counter after'
      'Accounts: Rename administrator account'
      'Accounts: Rename guest account'
      ####Audit Policy Mappings
      'Audit account logon events'
      'Audit account management'
      'Audit directory service access'
      'Audit logon events'
      'Audit object access'
      'Audit policy change'
      'Audit privilege use'
      'Audit process tracking'
      'Audit system events'
      ####User rights mapping
      'Access Credential Manager as a trusted caller'
      'Access this computer from the network'
      'Act as part of the operating system'
      'Add workstations to domain'
      'Adjust memory quotas for a process'
      'Allow log on locally'
      'Allow log on through Remote Desktop Services'
      'Back up files and directories'
      'Bypass traverse checking'
      'Change the system time'
      'Change the time zone'
      'Create a pagefile'
      'Create a token object'
      'Create global objects'
      'Create permanent shared objects'
      'Create symbolic links'
      'Debug programs'
      'Deny access to this computer from the network'
      'Deny log on as a batch job'
      'Deny log on as a service'
      'Deny log on locally'
      'Deny log on through Remote Desktop Services'
      'Enable computer and user accounts to be trusted for delegation'
      'Force shutdown from a remote system'
      'Generate security audits'
      'Impersonate a client after authentication'
      'Increase a process working set'
      'Increase scheduling priority'
      'Load and unload device drivers'
      'Lock pages in memory'
      'Log on as a batch job'
      'Log on as a service'
      'Manage auditing and security log'
      'Modify an object label'
      'Modify firmware environment values'
      'Perform volume maintenance tasks'
      'Profile single process'
      'Profile system performance'
      'Remove computer from docking station'
      'Replace a process level token'
      'Restore files and directories'
      'Shut down the system'
      'Synchronize directory service data'
      'Take ownership of files or other objects'
      ####Registry Keys
      'Recovery console: Allow automatic adminstrative logon'
      'Recovery console: Allow floppy copy and access to all drives and all folders'
      'Interactive logon: Number of previous logons to cache (in case domain controller is not available)'
      'Interactive logon: Require Domain Controller authentication to unlock workstation'
      'Interactive logon: Prompt user to change password before expiration'
      'Interactive logon: Smart card removal behavior'
      'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode'
      'User Account Control: Behavior of the elevation prompt for standard users'
      'Interactive logon: Do not require CTRL+ALT+DEL'
      'Interactive logon: Do not display last user name'
      'User Account Control: Detect application installations and prompt for elevation'
      'User Account Control: Run all administrators in Admin Approval Mode'
      'User Account Control: Only elevate UIAccess applicaitons that are installed in secure locations'
      'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop'
      'User Account Control: Virtualize file and registry write failures to per-user locations'
      'User Account Control: Admin Approval Mode for the built-in Administrator account'
      'Interactive logon: Message title for users attempting to log on'
      'Interactive logon: Message text for users attempting to log on'
      'User Account Control: Switch to the secure desktop when prompting for elevation'
      'Interactive logon: Require smart card'
      'Shutdown: Allow system to be shut down without having to log on'
      'Devices: Allow undock without having to log on'
      'User Account Control: Only elevate executables that are signed and validated'
      'System settings: Use Certificate Rules on WIndows Executables for Software Restriction Policies'
      'Audit: Audit the access of global system objects'
      'Audit: Shut down system immediately if unable to log security audits'
      'Network access: Do not allow storage of passwords and credentials for network authentication'
      'Network access: let Everyone permissions apply to anonymous users'
      'System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing'
      'System cryptography: Force strong key protection for user keys stored on the computer'
      'Audit: Audit the use of Backup and Restore priviliege'
      'Accounts: Limit local account use of blank passwords to console logon only'
      'Network security: All Local System to use computer identiry for NTLM'
      'Network access: Remotely accessible registry paths'


## TODO: Future release
* Validate users in active directory are being handled.
