#!/usr/bin/env ruby
# frozen_string_literal: true

require 'puppet/provider'

# class SecurityPolicy
class SecurityPolicy
  attr_reader :wmic_cmd
  EVENT_TYPES = ['Success,Failure', 'Success', 'Failure', 'No auditing', 0, 1, 2, 3].freeze
  REGISTRY_TYPES = [1, 3, 4, 7].freeze

  def initialize
    # suppose to make an instance method for wmic
    @wmic_cmd = Puppet::Provider::CommandDefiner.define('wmic', 'wmic', Puppet::Provider)
  end

  def wmic(args = [])
    case args[0]
    when 'useraccount'
      @useraccount ||= wmic_cmd.execute(args).force_encoding('utf-16le').encode('utf-8', universal_newline: true).delete("\xEF\xBB\xBF")
    when 'group'
      @groupaccount ||= wmic_cmd.execute(args).force_encoding('utf-16le').encode('utf-8', universal_newline: true).delete("\xEF\xBB\xBF")
    else
      # will not cache
      wmic_cmd.execute(args).force_encoding('utf-16le').encode('utf-8', universal_newline: true).delete("\xEF\xBB\xBF")
    end
  end

  # collect all the local accounts using wmic
  def local_accounts
    ary = []
    ['useraccount', 'group'].each do |lu|
      wmic([lu, 'where', "(domain=\"#{ENV['COMPUTERNAME']}\")", 'get', 'name,sid', '/format:csv']).split("\n").each do |line|
        if line.include? "#{ENV['COMPUTERNAME']},"
          ary << line.strip.split(',')
        end
      end
    end
    ary
  end

  def user_sid_array
    @user_sid_array ||= local_accounts + builtin_accounts
  end

  def user_to_sid(value)
    sid = user_sid_array.find do |_home, user, _sid|
      user == value
    end
    if sid.nil?
      value
    else
      '*' + sid[2]
    end
  end

  # convert the sid to a user
  def sid_to_user(value)
    value = value.gsub(%r{(^\*)}, '')
    user = user_sid_array.find do |_home, _user, sid|
      value == sid
    end
    if user.nil?
      value
    else
      user[1]
    end
  end

  def convert_privilege_right(ensure_value, policy_value)
    # we need to convert users to sids first
    if ensure_value.to_s == 'absent'
      ''
    else
      sids = []
      policy_value.split(',').sort.each do |suser|
        suser.strip!
        sids << user_to_sid(suser)
      end
      sids.sort.join(',')
    end
  end

  # converts the policy value inside the policy hash to conform to the secedit standards
  def convert_policy_hash(policy_hash)
    value = case policy_hash[:policy_type]
            when 'Privilege Rights'
              convert_privilege_right(policy_hash[:ensure], policy_hash[:policy_value])
            when 'Event Audit'
              event_to_audit_id(policy_hash[:policy_value])
            when 'Registry Values'
              SecurityPolicy.convert_registry_value(policy_hash[:name], policy_hash[:policy_value])
            else
              policy_hash[:policy_value]
            end
    policy_hash[:policy_value] = value
    policy_hash
  end

  def builtin_accounts
    # more accounts and SIDs can be found at https://support.microsoft.com/en-us/kb/243330
    ary = [
      ['', 'NULL', 'S-1-0'],
      ['', 'NOBODY', 'S-1-0-0'],
      ['', 'EVERYONE', 'S-1-1-0'],
      ['', 'LOCAL', 'S-1-2-0'],
      ['', 'CONSOLE_LOGON', 'S-1-2-1'],
      ['', 'CREATOR_OWNER', 'S-1-3-0'],
      ['', 'CREATER_GROUP', 'S-1-3-1'],
      ['', 'OWNER_SERVER', 'S-1-3-2'],
      ['', 'GROUP_SERVER', 'S-1-3-3'],
      ['', 'OWNER_RIGHTS', 'S-1-3-4'],
      ['', 'NT_AUTHORITY', 'S-1-5'],
      ['', 'DIALUP', 'S-1-5-1'],
      ['', 'NETWORK', 'S-1-5-2'],
      ['', 'BATCH', 'S-1-5-3'],
      ['', 'INTERACTIVE', 'S-1-5-4'],
      ['', 'SERVICE', 'S-1-5-6'],
      ['', 'ANONYMOUS', 'S-1-5-7'],
      ['', 'PROXY', 'S-1-5-8'],
      ['', 'ENTERPRISE_DOMAIN_CONTROLLERS', 'S-1-5-9'],
      ['', 'PRINCIPAAL_SELF', 'S-1-5-10'],
      ['', 'AUTHENTICATED_USERS', 'S-1-5-11'],
      ['', 'RESTRICTED_CODE', 'S-1-5-12'],
      ['', 'TERMINAL_SERVER_USER', 'S-1-5-13'],
      ['', 'REMOTE_INTERACTIVE_LOGON', 'S-1-5-14'],
      ['', 'THIS_ORGANIZATION', 'S-1-5-15'],
      ['', 'IUSER', 'S-1-5-17'],
      ['', 'LOCAL_SYSTEM', 'S-1-5-18'],
      ['', 'LOCAL_SERVICE', 'S-1-5-19'],
      ['', 'NETWORK_SERVICE', 'S-1-5-20'],
      ['', 'COMPOUNDED_AUTHENTICATION', 'S-1-5-21-0-0-0-496'],
      ['', 'CLAIMS_VALID', 'S-1-5-21-0-0-0-497'],
      ['', 'BUILTIN_ADMINISTRATORS', 'S-1-5-32-544'],
      ['', 'BUILTIN_USERS', 'S-1-5-32-545'],
      ['', 'BUILTIN_GUESTS', 'S-1-5-32-546'],
      ['', 'POWER_USERS', 'S-1-5-32-547'],
      ['', 'ACCOUNT_OPERATORS', 'S-1-5-32-548'],
      ['', 'SERVER_OPERATORS', 'S-1-5-32-549'],
      ['', 'PRINTER_OPERATORS', 'S-1-5-32-550'],
      ['', 'BACKUP_OPERATORS', 'S-1-5-32-551'],
      ['', 'REPLICATOR', 'S-1-5-32-552'],
      ['', 'ALIAS_PREW2KCOMPACC', 'S-1-5-32-554'],
      ['', 'REMOTE_DESKTOP', 'S-1-5-32-555'],
      ['', 'NETWORK_CONFIGURATION_OPS', 'S-1-5-32-556'],
      ['', 'INCOMING_FOREST_TRUST_BUILDERS', 'S-1-5-32-557'],
      ['', 'PERMON_USERS', 'S-1-5-32-558'],
      ['', 'PERFLOG_USERS', 'S-1-5-32-559'],
      ['', 'WINDOWS_AUTHORIZATION_ACCESS_GROUP', 'S-1-5-32-560'],
      ['', 'TERMINAL_SERVER_LICENSE_SERVERS', 'S-1-5-32-561'],
      ['', 'DISTRIBUTED_COM_USERS', 'S-1-5-32-562'],
      ['', 'IIS_USERS', 'S-1-5-32-568'],
      ['', 'CRYPTOGRAPHIC_OPERATORS', 'S-1-5-32-569'],
      ['', 'EVENT_LOG_READERS', 'S-1-5-32-573'],
      ['', 'CERTIFICATE_SERVICE_DCOM_ACCESS', 'S-1-5-32-574'],
      ['', 'RDS_REMOTE_ACCESS_SERVERS', 'S-1-5-32-575'],
      ['', 'RDS_ENDPOINT_SERVERS', 'S-1-5-32-576'],
      ['', 'RDS_MANAGEMENT_SERVERS', 'S-1-5-32-577'],
      ['', 'HYPER_V_ADMINS', 'S-1-5-32-578'],
      ['', 'ACCESS_CONTROL_ASSISTANCE_OPS', 'S-1-5-32-579'],
      ['', 'REMOTE_MANAGEMENT_USERS', 'S-1-5-32-580'],
      ['', 'WRITE_RESTRICTED_CODE', 'S-1-5-32-558'],
      ['', 'NTLM_AUTHENTICATION', 'S-1-5-64-10'],
      ['', 'SCHANNEL_AUTHENTICATION', 'S-1-5-64-14'],
      ['', 'DIGEST_AUTHENTICATION', 'S-1-5-64-21'],
      ['', 'THIS_ORGANIZATION_CERTIFICATE', 'S-1-5-65-1'],
      ['', 'NT_SERVICE', 'S-1-5-80'],
      ['', 'NT_SERVICE\\ALL_SERVICES', 'S-1-5-80-0'],
      ['', 'NT_SERVICE\\WdiServiceHost', 'S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420'],
      ['', 'USER_MODE_DRIVERS', 'S-1-5-84-0-0-0-0-0'],
      ['', 'LOCAL_ACCOUNT', 'S-1-5-113'],
      ['', 'LOCAL_ACCOUNT_AND_MEMBER_OF_ADMINISTRATORS_GROUP', 'S-1-5-114'],
      ['', 'OTHER_ORGANIZATION', 'S-1-5-1000'],
      ['', 'ALL_APP_PACKAGES', 'S-1-15-2-1'],
      ['', 'ML_UNTRUSTED', 'S-1-16-0'],
      ['', 'ML_LOW', 'S-1-16-4096'],
      ['', 'ML_MEDIUM', 'S-1-16-8192'],
      ['', 'ML_MEDIUM_PLUS', 'S-1-16-8448'],
      ['', 'ML_HIGH', 'S-1-15-12288'],
      ['', 'ML_SYSTEM', 'S-1-16-16384'],
      ['', 'ML_PROTECTED_PROCESS', 'S-1-16-20480'],
      ['', 'AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY', 'S-1-18-1'],
      ['', 'SERVICE_ASSERTED_IDENTITY', 'S-1-18-2'],
    ]
    ary
  end

  # Converts a event number to a word
  def self.event_audit_mapper(policy_value)
    case policy_value.to_s
    when 3
      'Success,Failure'
    when 2
      'Failure'
    when 1
      'Success'
    else
      'No auditing'
    end
  end

  # Converts a event number to a word
  def self.event_to_audit_id(event_audit_name)
    case event_audit_name
    when 'Success,Failure'
      3
    when 'Failure'
      2
    when 'Success'
      1
    when 'No auditing'
      0
    else
      event_audit_name
    end
  end

  # returns the key and hash value given the policy name
  def self.find_mapping_from_policy_name(name)
    key, value = lsp_mapping.find do |_key, hash|
      hash[:name] == name
    end
    unless key && value
      raise KeyError, "#{name} is not a valid policy"
    end
    [key, value]
  end

  # returns the key and hash value given the policy desc
  def self.find_mapping_from_policy_desc(desc)
    name = desc.downcase
    _key, value = lsp_mapping.find do |key, _hash|
      key.downcase == name
    end
    unless value
      raise KeyError, "#{desc} is not a valid policy"
    end
    value
  end

  def self.valid_lsp?(name)
    lsp_mapping.keys.include?(name)
  end

  def self.convert_registry_value(name, value)
    value = value.to_s
    return value if value.split(',').count > 1 && REGISTRY_TYPES.include?(value.split(',')[0].to_i)
    policy_hash = find_mapping_from_policy_desc(name)
    "#{policy_hash[:reg_type]},#{value}"
  end

  # converts the policy value to machine values
  def self.convert_policy_value(policy_hash, value)
    sp = SecurityPolicy.new
    # I would rather not have to look this info up, but the type code will not always have this info handy
    # without knowing the policy type we can't figure out what to convert
    policy_type = find_mapping_from_policy_desc(policy_hash[:name])[:policy_type]
    case policy_type.to_s
    when 'Privilege Rights'
      sp.convert_privilege_right(policy_hash[:ensure], value)
    when 'Event Audit'
      event_to_audit_id(value)
    when 'Registry Values'
      # convert the value to a datatype/value
      convert_registry_value(policy_hash[:name], value)
    else
      value
    end
  end

  def self.lsp_mapping
    @lsp_mapping ||= {
      # Password policy Mappings
      'Enforce password history' => {
        name: 'PasswordHistorySize',
        policy_type: 'System Access',
      },
      'Maximum password age' => {
        name: 'MaximumPasswordAge',
        policy_type: 'System Access',
      },
      'Minimum password age' => {
        name: 'MinimumPasswordAge',
        policy_type: 'System Access',
      },
      'Minimum password length' => {
        name: 'MinimumPasswordLength',
        policy_type: 'System Access',
      },
      'Password must meet complexity requirements' => {
        name: 'PasswordComplexity',
        policy_type: 'System Access',
      },
      'Store passwords using reversible encryption' => {
        name: 'ClearTextPassword',
        policy_type: 'System Access',
      },
      'Account lockout threshold' => {
        name: 'LockoutBadCount',
        policy_type: 'System Access',
      },
      'Account lockout duration' => {
        name: 'LockoutDuration',
        policy_type: 'System Access',
      },
      'Reset account lockout counter after' => {
        name: 'ResetLockoutCount',
        policy_type: 'System Access',
      },
      'Accounts: Rename administrator account' => {
        name: 'NewAdministratorName',
        policy_type: 'System Access',
        data_type: :quoted_string,
      },
      'Accounts: Administrator account status' => {
        name: 'EnableAdminAccount',
        policy_type: 'System Access',
      },
      'Accounts: Rename guest account' => {
        name: 'NewGuestName',
        policy_type: 'System Access',
        data_type: :quoted_string,
      },
      'Accounts: Require Login to Change Password' => {
        name: 'RequireLogonToChangePassword',
        policy_type: 'System Access',
      },
      'Network security: Force logoff when logon hours expire' => {
        name: 'ForceLogoffWhenHourExpire',
        policy_type: 'System Access',
      },
      'Network access: Allow anonymous SID/name translation' => {
        name: 'LSAAnonymousNameLookup',
        policy_type: 'System Access',
      },
      'EnableAdminAccount' => {
        name: 'EnableAdminAccount',
        policy_type: 'System Access',
      },
      'EnableGuestAccount' => {
        name: 'EnableGuestAccount',
        policy_type: 'System Access',
      },
      # Audit Policy Mappings
      'Audit account logon events' => {
        name: 'AuditAccountLogon',
        policy_type: 'Event Audit',
      },
      'Audit account management' => {
        name: 'AuditAccountManage',
        policy_type: 'Event Audit',
      },
      'Audit directory service access' => {
        name: 'AuditDSAccess',
        policy_type: 'Event Audit',
      },
      'Audit logon events' => {
        name: 'AuditLogonEvents',
        policy_type: 'Event Audit',
      },
      'Audit object access' => {
        name: 'AuditObjectAccess',
        policy_type: 'Event Audit',
      },
      'Audit policy change' => {
        name: 'AuditPolicyChange',
        policy_type: 'Event Audit',
      },
      'Audit privilege use' => {
        name: 'AuditPrivilegeUse',
        policy_type: 'Event Audit',
      },
      'Audit process tracking' => {
        name: 'AuditProcessTracking',
        policy_type: 'Event Audit',
      },
      'Audit system events' => {
        name: 'AuditSystemEvents',
        policy_type: 'Event Audit',
      },
      'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      # User rights mapping
      'Access Credential Manager as a trusted caller' => {
        name: 'SeTrustedCredManAccessPrivilege',
        policy_type: 'Privilege Rights',
      },
      'Access this computer from the network' => {
        name: 'SeNetworkLogonRight',
        policy_type: 'Privilege Rights',
      },
      'Act as part of the operating system' => {
        name: 'SeTcbPrivilege',
        policy_type: 'Privilege Rights',
      },
      'Add workstations to domain' => {
        name: 'SeMachineAccountPrivilege',
        policy_type: 'Privilege Rights',
      },
      'Adjust memory quotas for a process' => {
        name: 'SeIncreaseQuotaPrivilege',
        policy_type: 'Privilege Rights',
      },
      'Allow log on locally' => {
        name: 'SeInteractiveLogonRight',
        policy_type: 'Privilege Rights',
      },
      'Allow log on through Remote Desktop Services' => {
        name: 'SeRemoteInteractiveLogonRight',
        policy_type: 'Privilege Rights',
      },
      'Back up files and directories' => {
        name: 'SeBackupPrivilege',
        policy_type: 'Privilege Rights',
      },
      'Bypass traverse checking' => {
        name: 'SeChangeNotifyPrivilege',
        policy_type: 'Privilege Rights',
      },
      'Change the system time' => {
        name: 'SeSystemtimePrivilege',
        policy_type: 'Privilege Rights',
      },
      'Change the time zone' => {
        name: 'SeTimeZonePrivilege',
        policy_type: 'Privilege Rights',
      },
      'Create a pagefile' => {
        name: 'SeCreatePagefilePrivilege',
        policy_type: 'Privilege Rights',
      },
      'Create a token object' => {
        name: 'SeCreateTokenPrivilege',
        policy_type: 'Privilege Rights',
      },
      'Create global objects' => {
        name: 'SeCreateGlobalPrivilege',
        policy_type: 'Privilege Rights',
      },
      'Create permanent shared objects' => {
        name: 'SeCreatePermanentPrivilege',
        policy_type: 'Privilege Rights',
      },
      'Create symbolic links' => {
        name: 'SeCreateSymbolicLinkPrivilege',
        policy_type: 'Privilege Rights',
      },
      'Debug programs' => {
        name: 'SeDebugPrivilege',
        policy_type: 'Privilege Rights',
      },
      'Deny access to this computer from the network' => {
        name: 'SeDenyNetworkLogonRight',
        policy_type: 'Privilege Rights',
      },
      'Deny log on as a batch job' => {
        name: 'SeDenyBatchLogonRight',
        policy_type: 'Privilege Rights',
      },
      'Deny log on as a service' => {
        name: 'SeDenyServiceLogonRight',
        policy_type: 'Privilege Rights',
      },
      'Deny log on locally' => {
        name: 'SeDenyInteractiveLogonRight',
        policy_type: 'Privilege Rights',
      },
      'Deny log on through Remote Desktop Services' => {
        name: 'SeDenyRemoteInteractiveLogonRight',
        policy_type: 'Privilege Rights',
      },
      'Enable computer and user accounts to be trusted for delegation' => {
        name: 'SeEnableDelegationPrivilege',
        policy_type: 'Privilege Rights',
      },
      'Force shutdown from a remote system' => {
        name: 'SeRemoteShutdownPrivilege',
        policy_type: 'Privilege Rights',
      },
      'Generate security audits' => {
        name: 'SeAuditPrivilege',
        policy_type: 'Privilege Rights',
      },
      'Impersonate a client after authentication' => {
        name: 'SeImpersonatePrivilege',
        policy_type: 'Privilege Rights',
      },
      'Increase a process working set' => {
        name: 'SeIncreaseWorkingSetPrivilege',
        policy_type: 'Privilege Rights',
      },
      'Increase scheduling priority' => {
        name: 'SeIncreaseBasePriorityPrivilege',
        policy_type: 'Privilege Rights',
      },
      'Load and unload device drivers' => {
        name: 'SeLoadDriverPrivilege',
        policy_type: 'Privilege Rights',
      },
      'Lock pages in memory' => {
        name: 'SeLockMemoryPrivilege',
        policy_type: 'Privilege Rights',
      },
      'Log on as a batch job' => {
        name: 'SeBatchLogonRight',
        policy_type: 'Privilege Rights',
      },
      'Log on as a service' => {
        name: 'SeServiceLogonRight',
        policy_type: 'Privilege Rights',
      },
      'Manage auditing and security log' => {
        name: 'SeSecurityPrivilege',
        policy_type: 'Privilege Rights',
      },
      'Modify an object label' => {
        name: 'SeRelabelPrivilege',
        policy_type: 'Privilege Rights',
      },
      'Modify firmware environment values' => {
        name: 'SeSystemEnvironmentPrivilege',
        policy_type: 'Privilege Rights',
      },
      'Perform volume maintenance tasks' => {
        name: 'SeManageVolumePrivilege',
        policy_type: 'Privilege Rights',
      },
      'Profile single process' => {
        name: 'SeProfileSingleProcessPrivilege',
        policy_type: 'Privilege Rights',
      },
      'Profile system performance' => {
        name: 'SeSystemProfilePrivilege',
        policy_type: 'Privilege Rights',
      },
      'Remove computer from docking station' => {
        name: 'SeUndockPrivilege',
        policy_type: 'Privilege Rights',
      },
      'Replace a process level token' => {
        name: 'SeAssignPrimaryTokenPrivilege',
        policy_type: 'Privilege Rights',
      },
      'Restore files and directories' => {
        name: 'SeRestorePrivilege',
        policy_type: 'Privilege Rights',
      },
      'Shut down the system' => {
        name: 'SeShutdownPrivilege',
        policy_type: 'Privilege Rights',
      },
      'Synchronize directory service data' => {
        name: 'SeSyncAgentPrivilege',
        policy_type: 'Privilege Rights',
      },
      'Take ownership of files or other objects' => {
        name: 'SeTakeOwnershipPrivilege',
        policy_type: 'Privilege Rights',
      },
      # Registry Keys
      'Recovery console: Allow automatic administrative logon' => {
        name: 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SecurityLevel',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Recovery console: Allow floppy copy and access to all drives and all folders' => {
        name: 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SetCommand',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' => {
        name: 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount',
        reg_type: '1',
        policy_type: 'Registry Values',
      },
      'Interactive logon: Require Domain Controller authentication to unlock workstation' => {
        name: 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Interactive logon: Prompt user to change password before expiration' => {
        name: 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Interactive logon: Smart card removal behavior' => {
        name: 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption',
        reg_type: '1',
        policy_type: 'Registry Values',
      },
      'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'User Account Control: Behavior of the elevation prompt for standard users' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Interactive logon: Do not require CTRL+ALT+DEL' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Interactive logon: Do not display last user name' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'User Account Control: Detect application installations and prompt for elevation' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'User Account Control: Run all administrators in Admin Approval Mode' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'User Account Control: Only elevate UIAccess applications that are installed in secure locations' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'User Account Control: Virtualize file and registry write failures to per-user locations' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'User Account Control: Admin Approval Mode for the Built-in Administrator account' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Interactive logon: Message title for users attempting to log on' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption',
        reg_type: '1',
        policy_type: 'Registry Values',
      },
      'Interactive logon: Message text for users attempting to log on' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText',
        reg_type: '7',
        policy_type: 'Registry Values',
      },
      'User Account Control: Switch to the secure desktop when prompting for elevation' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Interactive logon: Require smart card' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ScForceOption',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Shutdown: Allow system to be shut down without having to log on' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Devices: Allow undock without having to log on' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\UndockWithoutLogon',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'User Account Control: Only elevate executables that are signed and validated' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies' => {
        name: 'MACHINE\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers\AuthenticodeEnabled',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Audit: Audit the access of global system objects' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\AuditBaseObjects',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Audit: Shut down system immediately if unable to log security audits' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Network access: Do not allow storage of passwords and credentials for network authentication' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Network access: Let Everyone permissions apply to anonymous users' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Network access: Sharing and security model for local accounts' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\Enabled',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'System cryptography: Force strong key protection for user keys stored on the computer' => {
        name: 'MACHINE\Software\Policies\Microsoft\Cryptography\ForceKeyProtection',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Audit: Audit the use of Backup and Restore privilege' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\FullPrivilegeAuditing',
        reg_type: '3',
        policy_type: 'Registry Values',
      },
      'Accounts: Block Microsoft accounts' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\NoConnectedUser',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Accounts: Limit local account use of blank passwords to console logon only' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Network security: All Local System to use computer identity for NTLM' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\UseMachineId',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Network access: Remotely accessible registry paths' => {
        name: 'MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine',
        reg_type: '7',
        policy_type: 'Registry Values',
      },
      'Devices: Restrict CD-ROM access to locally logged-on user only' => {
        name: 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateCDRoms',
        reg_type: '1',
        policy_type: 'Registry Values',
      },
      'Devices: Restrict floppy access to locally logged-on user only' => {
        name: 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateFloppies',
        reg_type: '1',
        policy_type: 'Registry Values',
      },
      'Devices: Allowed to format and eject removable media' => {
        name: 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateDASD',
        reg_type: '1',
        policy_type: 'Registry Values',
      },
      'Devices: Prevent users from installing printer drivers' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Domain member: Digitally encrypt or sign secure channel data (always)' => {
        name: 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Domain member: Digitally encrypt secure channel data (when possible)' => {
        name: 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Domain member: Digitally sign secure channel data (when possible)' => {
        name: 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Domain member: Disable machine account password changes' => {
        name: 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Domain member: Maximum machine account password age' => {
        name: 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Domain member: Require strong (Windows 2000 or later) session key' => {
        name: 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Interactive logon: Display user information when the session is locked' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLockedUserId',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Interactive logon: Machine inactivity limit' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Interactive logon: Machine account lockout threshold' => {
        name: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\MaxDevicePasswordFailedAttempts',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Microsoft network client: Digitally sign communications (always)' => {
        name: 'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Microsoft network client: Digitally sign communications (if server agrees)' => {
        name: 'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Microsoft network client: Send unencrypted password to third-party SMB servers' => {
        name: 'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Microsoft network server: Server SPN target name validation level' => {
        name: 'MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\SmbServerNameHardeningLevel',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Microsoft network server: Amount of idle time required before suspending session' => {
        name: 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Microsoft network server: Digitally sign communications (always)' => {
        name: 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Microsoft network server: Digitally sign communications (if client agrees)' => {
        name: 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Microsoft network server: Disconnect clients when logon hours expire' => {
        name: 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogOff',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Network access: Named Pipes that can be accessed anonymously' => {
        name: 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes',
        reg_type: '7',
        policy_type: 'Registry Values',
      },
      'Network access: Shares that can be accessed anonymously' => {
        name: 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares',
        reg_type: '7',
        policy_type: 'Registry Values',
      },
      'Network access: Do not allow anonymous enumeration of SAM accounts and shares' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Network access: Do not allow anonymous enumeration of SAM accounts' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Network access: Remotely accessible registry paths and sub-paths' => {
        name: 'MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine',
        reg_type: '7',
        policy_type: 'Registry Values',
      },
      'Network access: Restrict anonymous access to Named Pipes and Shares' => {
        name: 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Network security: Do not store LAN Manager hash value on next password change' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Network security: LAN Manager authentication level' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'Network security: LDAP client signing requirements' => {
        name: 'MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity',
        reg_type: '4',
        policy_type: 'Registry Values',
      },
      'System objects: Require case insensitivity for non-Windows subsystems' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'System objects: Strengthen default permissions of internal system objects (e.g., Symbolic Links)' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode',
        policy_type: 'Registry Values',
        reg_type: '4',
      },
      'System settings: Optional subsystems' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Session Manager\SubSystems\optional',
        policy_type: 'Registry Values',
        reg_type: '7',
      },
      'Shutdown: Clear virtual memory pagefile' => {
        name: 'MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management\ClearPageFileAtShutdown',
        policy_type: 'Registry Values',
        reg_type: '4',
      },

    }
  end
end
