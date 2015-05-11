require 'puppet/util/inifile'

Puppet::Type.type(:local_security_policy).provide(:policy) do
  #Look at yumrepo/inifile.rb
  #
  #TODO
  # Finalize the registry key settings
  # Add in registry value translateion (ex: 1=enable 0=disable)
  # Add in ignore case for the title/name
  # Implement self.post_resource_eval (need to collect all resource updates the run secedit to make one call)


  mk_resource_methods

  def self.lsp_mapping
    {
      # Password policy Mappings
      'Enforce password history' => {
        'name' => 'PasswordHistorySize',
        'type' => 'System Access',
      },
      'Maximum password age' => {
        'name' => 'MaximumPasswordAge',
        'type' => 'System Access',
        },
      'Minimum password age' => {
        'name' => 'MinimumPasswordAge',
        'type' => 'System Access',
      },
      'Minimum password length' => {
        'name' => 'MinimumPasswordLength',
        'type' => 'System Access',
      },
      'Password must meet complexity requirements' => {
        'name' => 'PasswordComplexity',
        'type' => 'System Access',
      },
      'Store passwords using reversible encryption' => {
        'name' => 'ClearTextPassword',
        'type' => 'System Access',
      },
      'Account lockout threshold' => {
        'name' => 'LockoutBadCount',
        'type' => 'System Access',
      },
      'Account lockout duration' => {
        'name' => 'LockoutDuration',
        'type' => 'System Access',
      },
      'Reset account lockout counter after' => {
        'name' => 'ResetLockoutCount',
        'type' => 'System Access',
      },
      'Accounts: Rename administrator account' => {
        'name' => 'NewAdministratorName',
        'type' => 'System Access',
      },
      'Accounts: Rename guest account' => {
        'name' => 'NewGuestName',
        'type' => 'System Access',
      },
      # Audit Policy Mappings

      'Audit account logon events' => {
        'name' => 'AuditAccountLogon',
        'type' => 'Event Audit',
      },
      'Audit account management' => {
        'name' => 'AuditAccountManage',
        'type' => 'Event Audit',
      },
      'Audit directory service access' => {
        'name' => 'AuditDSAccess',
        'type' => 'Event Audit',
      },
      'Audit logon events' => {
        'name' => 'AuditLogonEvents',
        'type' => 'Event Audit',
      },
      'Audit object access' => {
        'name' => 'AuditObjectAccess',
        'type' => 'Event Audit',
      },
      'Audit policy change' => {
        'name' => 'AuditPolicyChange',
        'type' => 'Event Audit',
      },
      'Audit privilege use' => {
        'name' => 'AuditPrivilegeUse',
        'type' => 'Event Audit',
      },
      'Audit process tracking' => {
        'name' => 'AuditProcessTraking',
        'type' => 'Event Audit',
      },
      'Audit system events' => {
        'name' => 'AuditSystemEvents',
        'type' => 'Event Audit',
      },
      #User rights mapping
      'Access Credential Manager as a trusted caller' => {
        'name' => 'SeTrustedCredManAccessPrivilege',
        'type' => 'Privilege Rights',
      },
      'Access this computer from the network' => {
        'name' => 'SeNetworkLogonRight',
        'type' => 'Privilege Rights',
      },
      'Act as part of the operating system' => {
        'name' => 'SeTcbPrivilege',
        'type' => 'Privilege Rights',
      },
      'Add workstations to domain' => {
        'name' => 'SeMachineAccountPrivilege',
        'type' => 'Privilege Rights',
      },
      'Adjust memory quotas for a process' => {
        'name' => 'SeIncreaseQuotaPrivilege',
        'type' => 'Privilege Rights',
      },
      'Allow log on locally' => {
        'name' => 'SeInteractiveLogonRight',
        'type' => 'Privilege Rights',
      },
      'Allow log on through Remote Desktop Services' => {
        'name' => 'SeRemoteInteractiveLogonRight',
        'type' => 'Privilege Rights',
      },
      'Back up files and directories' => {
        'name' => 'SeBackupPrivilege',
        'type' => 'Privilege Rights',
      },
      'Bypass traverse checking' => {
        'name' => 'SeChangeNotifyPrivilege',
        'type' => 'Privilege Rights',
      },
      'Change the system time' => {
        'name' => 'SeSystemtimePrivilege',
        'type' => 'Privilege Rights',
      },
      'Change the time zone' => {
        'name' => 'SeTimeZonePrivilege',
        'type' => 'Privilege Rights',
      },
      'Create a pagefile' => {
        'name' => 'SeCreatePagefilePrivilege',
        'type' => 'Privilege Rights',
      },
      'Create a token object' => {
        'name' => 'SeAssignPrimaryTokenPrivilege',
        'type' => 'Privilege Rights',
      },
      'Create global objects' => {
        'name' => 'SeCreateGlobalPrivilege',
        'type' => 'Privilege Rights',
      },
      'Create permanent shared objects' => {
        'name' => 'SeCreatePermanentPrivilege',
        'type' => 'Privilege Rights',
      },
      'Create symbolic links' => {
        'name' => 'SeCreateSymbolicLinkPrivilege',
        'type' => 'Privilege Rights',
      },
      'Debug programs' => {
        'name' => 'SeDebugPrivilege',
        'type' => 'Privilege Rights',
      },
      'Deny access to this computer from the network' => {
        'name' => 'SeDenyNetworkLogonRight',
        'type' => 'Privilege Rights',
      },
      'Deny log on as a batch job' => {
        'name' => 'SeDenyBatchLogonRight',
        'type' => 'Privilege Rights',
      },
      'Deny log on as a service' => {
        'name' => 'SeDenyServiceLogonRight',
        'type' => 'Privilege Rights',
      },
      'Deny log on locally' => {
        'name' => 'SeDenyInteractiveLogonRight',
        'type' => 'Privilege Rights',
      },
      'Deny log on through Remote Desktop Services' => {
        'name' => 'SeDenyRemoteInteractiveLogonRight',
        'type' => 'Privilege Rights',
      },
      'Enable computer and user accounts to be trusted for delegation' => {
        'name' => 'SeEnableDelegationPrivilege',
        'type' => 'Privilege Rights',
      },
      'Force shutdown from a remote system' => {
        'name' => 'SeRemoteShutdownPrivilege',
        'type' => 'Privilege Rights',
      },
      'Generate security audits' => {
        'name' => 'SeAuditPrivilege',
        'type' => 'Privilege Rights',
      },
      'Impersonate a client after authentication' => {
        'name' => 'SeImpersonatePrivilege',
        'type' => 'Privilege Rights',
      },
      'Increase a process working set' => {
        'name' => 'SeIncreaseWorkingSetPrivilege',
        'type' => 'Privilege Rights',
      },
      'Increase scheduling priority' => {
        'name' => 'SeIncreaseBasePriorityPrivilege',
        'type' => 'Privilege Rights',
      },
      'Load and unload device drivers' => {
        'name' => 'SeLoadDriverPrivilege',
        'type' => 'Privilege Rights',
      },
      'Lock pages in memory' => {
        'name' => 'SeLockMemoryPrivilege',
        'type' => 'Privilege Rights',
      },
      'Log on as a batch job' => {
        'name' => 'SeBatchLogonRight',
        'type' => 'Privilege Rights',
      },
      'Log on as a service' => {
        'name' => 'SeServiceLogonRight',
        'type' => 'Privilege Rights',
      },
      'Manage auditing and security log' => {
        'name' => 'SeSecurityPrivilege',
        'type' => 'Privilege Rights',
      },
      'Modify an object label' => {
        'name' => 'SeRelabelPrivilege',
        'type' => 'Privilege Rights',
      },
      'Modify firmware environment values' => {
        'name' => 'SeSystemEnvironmentPrivilege',
        'type' => 'Privilege Rights',
      },
      'Perform volume maintenance tasks' => {
        'name' => 'SeManageVolumePrivilege',
        'type' => 'Privilege Rights',
      },
      'Profile single process' => {
        'name' => 'SeProfileSingleProcessPrivilege',
        'type' => 'Privilege Rights',
      },
      'Profile system performance' => {
        'name' => 'SeSystemProfilePrivilege',
        'type' => 'Privilege Rights',
      },
      'Remove computer from docking station' => {
        'name' => 'SeUndockPrivilege',
        'type' => 'Privilege Rights',
      },
      'Replace a process level token' => {
        'name' => 'SeAssignPrimaryTokenPrivilege',
        'type' => 'Privilege Rights',
      },
      'Restore files and directories' => {
        'name' => 'SeRestorePrivilege',
        'type' => 'Privilege Rights',
      },
      'Shut down the system' => {
        'name' => 'SeShutdownPrivilege',
        'type' => 'Privilege Rights',
      },
      'Synchronize directory service data' => {
        'name' => 'SeSyncAgentPrivilege',
        'type' => 'Privilege Rights',
      },
      'Take ownership of files or other objects' => {
        'name' => 'SeTakeOwnershipPrivilege',
        'type' => 'Privilege Rights',
      },
      #Registry Keys
      'Recovery console: Allow automatic adminstrative logon' => {
          'name' => 'MACHINE\Software\Microsoft\Windows MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SecurityLevel',
            'reg_type' => '4',
            'type' => 'Registry Values',
      },
      'Recovery console: Allow floppy copy and access to all drives and all folders' => {
          'name' => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SetCommand',
            'reg_type' => '4',
            'type' => 'Registry Values',
      },
      'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' => {
        'name' => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount',
            'reg_type' => '1',
            'type' => 'Registry Values',
      },
      'Interactive logon: Require Domain Controller authentication to unlock workstation' => {
          'name' => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon',
            'reg_type' => '4',
            'type' => 'Registry Values',
      },
      'Interactive logon: Prompt user to change password before expiration' => {
          'name' => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning',
            'reg_type' => '4',
            'type' => 'Registry Values',
      },
      'Interactive logon: Smart card removal behavior' => {
          'name' => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption',
            'reg_type' => '1',
            'type' => 'Registry Values',
      },
      'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' => {
          'name' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin',
            'reg_type' => '4',
            'type' => 'Registry Values',
      },
      'User Account Control: Behavior of the elevation prompt for standard users' => {
          'name' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser',
            'reg_type' => '4',
            'type' => 'Registry Values',
      },
      'Interactive logon: Do not require CTRL+ALT+DEL' => {
          'name' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD',
            'reg_type' => '4',
            'type' => 'Registry Values',
      },
      'Interactive logon: Do not display last user name' => {
          'name' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName',
            'reg_type' => '4',
            'type' => 'Registry Values',
      },
      'User Account Control: Detect application installations and prompt for elevation' => {
          'name' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection',
            'reg_type' => '4',
            'type' => 'Registry Values',
      },
      'User Account Control: Run all administrators in Admin Approval Mode' => {
          'name' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA',
            'reg_type' => '4',
            'type' => 'Registry Values',
      },
      'User Account Control: Only elevate UIAccess applicaitons that are installed in secure locations' => {
          'name' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths',
            'reg_type' => '4',
            'type' => 'Registry Values',
      },
      'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' => {
          'name' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle',
            'reg_type' => '4',
            'type' => 'Registry Values',
      },
      'User Account Control: Virtualize file and registry write failures to per-user locations' => {
          'name' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization',
            'reg_type' => '4',
            'type' => 'Registry Values',
      },
      'User Account Control: Admin Approval Mode for the built-in Administrator account' => {
          'name' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken',
            'reg_type' => '4',
            'type' => 'Registry Values',
      },
      'Interactive logon: Message title for users attempting to log on' => {
          'name' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption',
            'reg_type' => '1',
            'type' => 'Registry Values',
      },
      'Interactive logon: Message text for users attempting to log on' => {
          'name' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText',
            'reg_type' => '7',
            'type' => 'Registry Values',
      },
      'User Account Control: Switch to the secure desktop when prompting for elevation' => {
          'name' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop',
            'reg_type' => '4',
            'type' => 'Registry Values',
      },
      'Interactive logon: Require smart card' => {
          'name' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ScForceOption',
            'reg_type' => '4',
            'type' => 'Registry Values',
      },
      'Shutdown: Allow system to be shut down without having to log on' => {
          'name' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon',
            'reg_type' => '4',
            'type' => 'Registry Values',
      },
      'Devices: Allow undock without having to log on' => {
          'name' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\UndockWithoutLogon',
            'reg_type' => '4',
            'type' => 'Registry Values',
      },
      'User Account Control: Only elevate executables that are signed and validated' => {
          'name' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures',
            'reg_type' => '4',
            'type' => 'Registry Values',
      },
      'System settings: Use Certificate Rules on WIndows Executables for Software Restriction Policies' => {
          'name' => 'MACHINE\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers\AuthenticodeEnabled',
            'reg_type' => '4',
            'type' => 'Registry Values',
      },
      'Audit: Audit the access of global system objects' => {
          'name' => 'MACHINE\System\CurrentControlSet\Control\Lsa\AuditBaseObjects',
            'reg_type' => '4',
            'type' => 'Registry Values',
      },
      'Audit: Shut down system immediately if unable to log security audits' => {
          'name' => 'MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail',
            'reg_type' => '4',
            'type' => 'Registry Values',
      },
      'Network access: Do not allow storage of passwords and credentials for network authentication' => {
          'name' => 'MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds',
            'reg_type' => '4',
            'type' => 'Registry Values',
      },
      'Network access: let Everyone permissions apply to anonymous users' => {
          'name' => 'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous',
            'reg_type' => '4',
            'type' => 'Registry Values',
      },
      'System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing' => {
          'name' => 'MACHINE\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\Enabled',
            'reg_type' => '4',
            'type' => 'Registry Values',
      },
      'System cryptography: Force strong key protection for user keys stored on the computer' => {
          'name' => 'MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest',
            'reg_type' => '4',
            'type' => 'Registry Values',
      },
      'Audit: Audit the use of Backup and Restore priviliege' => {
          'name' => 'MACHINE\System\CurrentControlSet\Control\Lsa\FullPrivilegeAuditing',
            'reg_type' => '3',
            'type' => 'Registry Values',
      },
      'Accounts: Limit local account use of blank passwords to console logon only' => {
          'name' => 'MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse',
            'reg_type' => '4',
            'type' => 'Registry Values',
      },
      'Network security: All Local System to use computer identiry for NTLM' => {
          'name' => 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec',
            'reg_type' => '4',
            'type' => 'Registry Values',
      },
      'Network access: Remotely accessible registry paths' => {
          'name' => 'MACHINE\System\Current\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine',
      },
    }

  end

  def self.get_policy_settings
    @sid_ary = user_sid_array
    instances = []
    policy_sections = {}
    policy_section = ""
    inffile = 'c:\\windows\\temp\\secedit.inf'
    system('secedit','/export','/cfg',inffile,'/quiet')
    inflines = File.read(inffile).force_encoding("utf-16le").encode("utf-8").split("\r\n")
    #inflines = File.read('/tmp/secedit.inf').split("\n")
    inflines.each do |line|
      if line.start_with?('[')
        if line
          line.strip!
          policy_section = line[1..-2]
          policy_sections[policy_section] =  Array.new
        end
      else
        if ! policy_sections[policy_section].nil?
          policy_setting, policy_value = line.split('=')
          if policy_setting and policy_value
            policy_setting.strip!
            policy_value.strip!
            policy_sections[policy_section] << [policy_setting, policy_value]
          end
        end
      end
    end
    policy_sections.each do |section_header, value_pair|

      if section_header and section_header != "Unicode" and section_header != "Version"

        value_pair.each do |policy_setting, policy_value|
          policy = lsp_mapping.select{|key,hash| hash["name"] == policy_setting}.keys[0]
          if ! policy
            policy = "Unknown Policy Mapping: #{policy_setting}"
          end
          reg_type = ""
          #Address special returns and show human readable strings
          if section_header == "Privilege Rights"
            users =  Array.new
            policy_value.split(",").each do |sid|
              users << sid_to_user(sid)
            end
            policy_value = users.sort.join(",")
          elsif section_header == 'Event Audit'
            case policy_value.to_s
            when 3
              policy_value = "Success,Failure"
            when 2
              policy_value = "Failure"
            when 1
              policy_value = "Success"
            else
              policy_value = "No auditing"
            end
          elsif section_header == 'Registry Values'
            pv = policy_value.split(",")
            reg_type = pv[0]
            policy_value = pv[1]
          end
          attributes_hash = {:name => policy, :ensure => :present, :provider => :policy, :policy_type => section_header ,:policy_setting => policy_setting, :policy_value => policy_value, :reg_type => reg_type }
          instances << new(attributes_hash)
        end
      end
    end


    instances
  end

  def self.instances
    get_policy_settings

  end

  def initialize(value={})
    super(value)
    @property_flush = {}
  end

  def self.user_to_sid(value)
    sid = @sid_ary.select{ |home,user,sid| user.match(/^#{value}$/)}
    if sid.nil? or sid.empty?
      sid = value
    else
      sid = '*' + sid[0][2]
    end
    sid
  end

  def self.sid_to_user(value)
    value.gsub!(/(^\*)/ , '')
    user = @sid_ary.select { |home,user,sid| sid.match(/^#{value}$/)}
    if user.nil? or user.empty?
      user = value
    else
      user = user[0][1]
    end
    user
  end

  def self.user_sid_array
    ary = [
     ["","EVERYONE","S-1-1-0"],
     ["","LOCAL","S-1-2-0"],
     ["","CONSOLE_LOGON","S-1-2-1"],
     ["","CREATOR_OWNER","S-1-3-0"],
     ["","CREATER_GROUP","S-1-3-1"],
     ["","OWNER_SERVER","S-1-3-2"],
     ["","GROUP_SERVER","S-1-3-3"],
     ["","OWNER_RIGHTS","S-1-3-4"],
     ["","NT_AUTHORITY","S-1-5"],
     ["","DIALUP","S-1-5-1"],
     ["","NETWORK","S-1-5-2"],
     ["","BATCH","S-1-5-3"],
     ["","INTERACTIVE","S-1-5-4"],
     ["","SERVICE","S-1-5-6"],
     ["","ANONYMOUS","S-1-5-7"],
     ["","PROXY","S-1-5-8"],
     ["","ENTERPRISE_DOMAIN_CONTROLLERS","S-1-5-9"],
     ["","PRINCIPAAL_SELF","S-1-5-10"],
     ["","AUTHENTICATED_USERS","S-1-5-11"],
     ["","RESTRICTED_CODE","S-1-5-12"],
     ["","TERMINAL_SERVER_USER","S-1-5-13"],
     ["","REMOTE_INTERACTIVE_LOGON","S-1-5-14"],
     ["","THIS_ORGANIZATION","S-1-5-15"],
     ["","IUSER","S-1-5-17"],
     ["","LOCAL_SYSTEM","S-1-5-18"],
     ["","LOCAL_SERVICE","S-1-5-19"],
     ["","NETWORK_SERVICE","S-1-5-20"],
     ["","COMPOUNDED_AUTHENTICATION","S-1-5-21-0-0-0-496"],
     ["","CLAIMS_VALID","S-1-5-21-0-0-0-497"],
     ["","BUILTIN_ADMINISTRATORS","S-1-5-32-544"],
     ["","BUILTIN_USERS","S-1-5-32-545"],
     ["","BUILTIN_GUESTS","S-1-5-32-546"],
     ["","POWER_USERS","S-1-5-32-547"],
     ["","ACCOUNT_OPERATORS","S-1-5-32-548"],
     ["","SERVER_OPERATORS","S-1-5-32-549"],
     ["","PRINTER_OPERATORS","S-1-5-32-550"],
     ["","BACKUP_OPERATORS","S-1-5-32-551"],
     ["","REPLICATOR","S-1-5-32-552"],
     ["","ALIAS_PREW2KCOMPACC","S-1-5-32-554"],
     ["","REMOTE_DESKTOP","S-1-5-32-555"],
     ["","NETWORK_CONFIGURATION_OPS","S-1-5-32-556"],
     ["","INCOMING_FOREST_TRUST_BUILDERS","S-1-5-32-557"],
     ["","PERMON_USERS","S-1-5-32-558"],
     ["","PERFLOG_USERS","S-1-5-32-559"],
     ["","WINDOWS_AUTHORIZATION_ACCESS_GROUP","S-1-5-32-560"],
     ["","TERMINAL_SERVER_LICENSE_SERVERS","S-1-5-32-561"],
     ["","DISTRIBUTED_COM_USERS","S-1-5-32-562"],
     ["","IIS_USERS","S-1-5-32-568"],
     ["","CRYPTOGRAPHIC_OPERATORS","S-1-5-32-569"],
     ["","EVENT_LOG_READERS","S-1-5-32-573"],
     ["","CERTIFICATE_SERVICE_DCOM_ACCESS","S-1-5-32-574"],
     ["","RDS_REMOTE_ACCESS_SERVERS","S-1-5-32-575"],
     ["","RDS_ENDPOINT_SERVERS","S-1-5-32-576"],
     ["","RDS_MANAGEMENT_SERVERS","S-1-5-32-577"],
     ["","HYPER_V_ADMINS","S-1-5-32-578"],
     ["","ACCESS_CONTROL_ASSISTANCE_OPS","S-1-5-32-579"],
     ["","REMOTE_MANAGEMENT_USERS","S-1-5-32-580"],
     ["","WRITE_RESTRICTED_CODE","S-1-5-32-558"],
     ["","NTLM_AUTHENTICATION","S-1-5-64-10"],
     ["","SCHANNEL_AUTHENTICATION","S-1-5-64-14"],
     ["","DIGEST_AUTHENTICATION","S-1-5-64-21"],
     ["","THIS_ORGANIZATION_CERTIFICATE","S-1-5-65-1"],
     ["","NT_SERVICE","S-1-5-80"],
     ["","NT_SERVICE\\ALL_SERVICES","S-1-5-80-0"],
     ["","NT_SERVICE\\WdiServiceHost","S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420"],
     ["","USER_MODE_DRIVERS","S-1-5-84-0-0-0-0-0"],
     ["","LOCAL_ACCOUNT","S-1-5-113"],
     ["","LOCAL_ACCOUNT_AND_MEMBER_OF_ADMINISTRATORS_GROUP","S-1-5-114"],
     ["","OTHER_ORGANIZATION","S-1-5-1000"],
     ["","ALL_APP_PACKAGES","S-1-15-2-1"],
     ["","ML_UNTRUSTED","S-1-16-0"],
     ["","ML_LOW","S-1-16-4096"],
     ["","ML_MEDIUM","S-1-16-8192"],
     ["","ML_MEDIUM_PLUS","S-1-16-8448"],
     ["","ML_HIGH","S-1-15-12288"],
     ["","ML_SYSTEM","S-1-16-16384"],
     ["","ML_PROTECTED_PROCESS","S-1-16-20480"],
     ["","AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY","S-1-18-1"],
     ["","SERVICE_ASSERTED_IDENTITY","S-1-18-2"]
    ]
    ["useraccount","group"].each do |lu|
      `wmic #{lu} get name,sid /format:csv`.split("\n").each do |line|
        if line.include? ","
          ary << line.split(",")
        end
      end
    end
    ary
  end

  def flush
    sid_ary = [
     ["","EVERYONE","S-1-1-0"],
     ["","LOCAL","S-1-2-0"],
     ["","CONSOLE_LOGON","S-1-2-1"],
     ["","CREATOR_OWNER","S-1-3-0"],
     ["","CREATER_GROUP","S-1-3-1"],
     ["","OWNER_SERVER","S-1-3-2"],
     ["","GROUP_SERVER","S-1-3-3"],
     ["","OWNER_RIGHTS","S-1-3-4"],
     ["","NT_AUTHORITY","S-1-5"],
     ["","DIALUP","S-1-5-1"],
     ["","NETWORK","S-1-5-2"],
     ["","BATCH","S-1-5-3"],
     ["","INTERACTIVE","S-1-5-4"],
     ["","SERVICE","S-1-5-6"],
     ["","ANONYMOUS","S-1-5-7"],
     ["","PROXY","S-1-5-8"],
     ["","ENTERPRISE_DOMAIN_CONTROLLERS","S-1-5-9"],
     ["","PRINCIPAAL_SELF","S-1-5-10"],
     ["","AUTHENTICATED_USERS","S-1-5-11"],
     ["","RESTRICTED_CODE","S-1-5-12"],
     ["","TERMINAL_SERVER_USER","S-1-5-13"],
     ["","REMOTE_INTERACTIVE_LOGON","S-1-5-14"],
     ["","THIS_ORGANIZATION","S-1-5-15"],
     ["","IUSER","S-1-5-17"],
     ["","LOCAL_SYSTEM","S-1-5-18"],
     ["","LOCAL_SERVICE","S-1-5-19"],
     ["","NETWORK_SERVICE","S-1-5-20"],
     ["","COMPOUNDED_AUTHENTICATION","S-1-5-21-0-0-0-496"],
     ["","CLAIMS_VALID","S-1-5-21-0-0-0-497"],
     ["","BUILTIN_ADMINISTRATORS","S-1-5-32-544"],
     ["","BUILTIN_USERS","S-1-5-32-545"],
     ["","BUILTIN_GUESTS","S-1-5-32-546"],
     ["","POWER_USERS","S-1-5-32-547"],
     ["","ACCOUNT_OPERATORS","S-1-5-32-548"],
     ["","SERVER_OPERATORS","S-1-5-32-549"],
     ["","PRINTER_OPERATORS","S-1-5-32-550"],
     ["","BACKUP_OPERATORS","S-1-5-32-551"],
     ["","REPLICATOR","S-1-5-32-552"],
     ["","ALIAS_PREW2KCOMPACC","S-1-5-32-554"],
     ["","REMOTE_DESKTOP","S-1-5-32-555"],
     ["","NETWORK_CONFIGURATION_OPS","S-1-5-32-556"],
     ["","INCOMING_FOREST_TRUST_BUILDERS","S-1-5-32-557"],
     ["","PERMON_USERS","S-1-5-32-558"],
     ["","PERFLOG_USERS","S-1-5-32-559"],
     ["","WINDOWS_AUTHORIZATION_ACCESS_GROUP","S-1-5-32-560"],
     ["","TERMINAL_SERVER_LICENSE_SERVERS","S-1-5-32-561"],
     ["","DISTRIBUTED_COM_USERS","S-1-5-32-562"],
     ["","IIS_USERS","S-1-5-32-568"],
     ["","CRYPTOGRAPHIC_OPERATORS","S-1-5-32-569"],
     ["","EVENT_LOG_READERS","S-1-5-32-573"],
     ["","CERTIFICATE_SERVICE_DCOM_ACCESS","S-1-5-32-574"],
     ["","RDS_REMOTE_ACCESS_SERVERS","S-1-5-32-575"],
     ["","RDS_ENDPOINT_SERVERS","S-1-5-32-576"],
     ["","RDS_MANAGEMENT_SERVERS","S-1-5-32-577"],
     ["","HYPER_V_ADMINS","S-1-5-32-578"],
     ["","ACCESS_CONTROL_ASSISTANCE_OPS","S-1-5-32-579"],
     ["","REMOTE_MANAGEMENT_USERS","S-1-5-32-580"],
     ["","WRITE_RESTRICTED_CODE","S-1-5-32-558"],
     ["","NTLM_AUTHENTICATION","S-1-5-64-10"],
     ["","SCHANNEL_AUTHENTICATION","S-1-5-64-14"],
     ["","DIGEST_AUTHENTICATION","S-1-5-64-21"],
     ["","THIS_ORGANIZATION_CERTIFICATE","S-1-5-65-1"],
     ["","NT_SERVICE","S-1-5-80"],
     ["","NT_SERVICE\\ALL_SERVICES","S-1-5-80-0"],
     ["","NT_SERVICE\\WdiServiceHost","S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420"],
     ["","USER_MODE_DRIVERS","S-1-5-84-0-0-0-0-0"],
     ["","LOCAL_ACCOUNT","S-1-5-113"],
     ["","LOCAL_ACCOUNT_AND_MEMBER_OF_ADMINISTRATORS_GROUP","S-1-5-114"],
     ["","OTHER_ORGANIZATION","S-1-5-1000"],
     ["","ALL_APP_PACKAGES","S-1-15-2-1"],
     ["","ML_UNTRUSTED","S-1-16-0"],
     ["","ML_LOW","S-1-16-4096"],
     ["","ML_MEDIUM","S-1-16-8192"],
     ["","ML_MEDIUM_PLUS","S-1-16-8448"],
     ["","ML_HIGH","S-1-15-12288"],
     ["","ML_SYSTEM","S-1-16-16384"],
     ["","ML_PROTECTED_PROCESS","S-1-16-20480"],
     ["","AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY","S-1-18-1"],
     ["","SERVICE_ASSERTED_IDENTITY","S-1-18-2"]
    ]
    ["useraccount","group"].each do |lu|
      `wmic #{lu} get name,sid /format:csv`.split("\n").each do |line|
        if line.include? ","
          sid_ary << line.split(",")
        end
      end
    end
    if @property_flush
      time = Time.now
      time = time.strftime("%Y%m%d%H%M%S")
      infout = "c:\\windows\\temp\\infimport-#{time}.inf"
      sdbout = "c:\\windows\\temp\\sdbimport-#{time}.inf"
      if not @property_hash[:policy_setting].nil?
        policy_setting = @property_hash[:policy_setting]
      else
        policy_setting = self.class.lsp_mapping[resource[:name]]['name']
      end
      if not @property_hash[:policy_type].nil?
        policy_type = @property_hash[:policy_type]
      else
        policy_type = self.class.lsp_mapping[resource[:name]]['type']
      end
      pv = ""
      if policy_type == 'Privilege Rights'
        sids = Array.new
        resource[:policy_value].split(",").sort.each do |suser|
          suser.strip!
          #sid = sid_ary.select { |home,user,sid| user.match(/^#{suser}$/)}
          #if ! sid.nil? and ! sid.empty?
          #  sids << '*'+sid[0][2]
          #end
          sids << user_to_sid(suser)
        end
        pv = sids.join(",")
      elsif policy_type == 'Event Audit'
        if resource[:policy_value] == 'No auditing'
          pv = 0
        else
          pv = 0
          resource[:policy_value].split(",").split do |ssetting|
            if setting.strip! == 'Success'
              pv += 1
            elsif setting.strip! == 'Failure'
              pv += 2
            end
          end
        end
      elsif policy_type == 'Registry Values'
        pv = @property_hash[:reg_type] + "," + resource[:policy_value].to_s
      else
        pv = resource[:policy_value]
      end
      file = File.open(infout, 'w')
      file.puts '[' + policy_type + ']'
      file.puts  "#{policy_setting} = #{pv}"
      file.puts '[Version]'
      file.puts 'signature="$CHICAGO$"'
      file.close
      system('secedit','/configure','/db',sdbout, '/cfg',infout,'/quiet')
      #comment this out if you want to debug the import
      #File.delete(infout)
      #File.delete(sdbout)
      @property_hash = resource.to_hash
    end
  end

  def create
    @property_flush[:ensure] == :present
  end

  def destroy
    #Destroy not an option for now.  LSP Settings should be set to something.
  end


  def self.prefetch(resources)
    instances.each do |prov|
      if resource = resources[prov.name]
        resource.provider = prov
      end
    end
  end

  def exists?
    @property_hash[:ensure] == :present
  end

end
