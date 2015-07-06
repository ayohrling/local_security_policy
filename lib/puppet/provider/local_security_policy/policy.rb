require 'fileutils'

begin
  require "puppet_x/twp/inifile"
  require "puppet_x/lsp/security_policy"
rescue LoadError => detail
  require 'pathname' # JJM WORK_AROUND #14073
  module_base = Pathname.new(__FILE__).dirname
  require module_base + "../../../" + "puppet_x/twp/inifile.rb"
  require module_base + "../../../" + "puppet_x/lsp/security_policy.rb"
end

Puppet::Type.type(:local_security_policy).provide(:policy) do
  desc 'Puppet type that models the local security policy'

  #
  # TODO Finalize the registry key settings
  # TODO Add in registry value translation (ex: 1=enable 0=disable)
  # TODO Implement self.post_resource_eval (need to collect all resource updates the run secedit to make one call)
  # limit access to windows hosts only
  confine :operatingsystem => :windows
  # limit access to systems with these commands since this is the tools we need
  commands :wmic => 'wmic', :secedit => 'secedit'

  mk_resource_methods

  # export the policy settings to the specified file and return the filename
  def self.export_policy_settings(inffile=nil)
    inffile ||= temp_file
    secedit(['/export', '/cfg', inffile, '/quiet'])
    inffile
  end

  # export and then read the policy settings from a file into a inifile object
  # caches the IniFile object during the puppet run
  def self.read_policy_settings(inffile=nil)
    inffile ||= temp_file
    unless @file_object
      export_policy_settings(inffile)
      File.open inffile, 'r:IBM437' do |file|
        # remove /r/n and remove the BOM
        inffile_content = file.read.force_encoding('utf-16le').encode('utf-8', :universal_newline => true).gsub("\xEF\xBB\xBF", '')
        @file_object ||= PuppetX::IniFile.new(:content => inffile_content)
      end
    end
    @file_object
  end

  # exports the current list of policies into a file and then parses that file into
  # provider instances.  If an item is found on the system but not in the lsp_mapping,
  # that policy is not supported only because we cannot match the description
  def self.find_policy_settings
    settings = []
    inf = read_policy_settings
    # need to find the policy, section_header, policy_setting, policy_value and reg_type
    inf.each do |section, parameter_name, parameter_value|
      next if section == 'Unicode'
      next if section == 'Version'
      begin
        policy_desc, policy_values = SecurityPolicy.find_mapping_from_policy_name(parameter_name)
        policy_hash = {
            :name => policy_desc,
            :ensure => :present,
            :policy_type => section ,
            :policy_setting => parameter_name,
            :policy_value => parameter_value,
        }
        # some of these values need to be converted from machine
        #policy_hash[:policy_value] = SecurityPolicy.convert_policy_value(policy_hash, parameter_value)
        inst = new(policy_hash)
        settings << inst
      rescue KeyError => e
        Puppet.debug e.message
      end
    end
    settings
  end

  # find all the instances of this provider and type
  def self.instances
    find_policy_settings
  end

  def initialize(value={})
    super(value)
  end

  # create the resource and convert any user supplied values to computer terms
  def create
    begin
      write_policy_to_system(resource)
    rescue KeyError => e
      Puppet.debug e.message
      # send helpful debug message to user here
    end
  end

  # this is currently not implemented correctly on purpose until we can figure out how to safely remove
  def destroy
    @property_hash[:ensure] = :absent
    #Destroy not an option for now.  LSP Settings should be set to something.
    # we need some default destroy values in the mappings so we know ahead of time what to put unless the user supplies
    # but this would just ensure a value the setting should go back to
  end

  def self.prefetch(resources)
    policies = instances
    resources.keys.each do |name|
      found_pol = policies.find { |pol| pol.name == name }
      if found_pol
        resources[name].provider = found_pol
      end
    end
  end

  def exists?
    @property_hash[:ensure] == :present
  end

  # gets the property hash from the provider
  def to_hash
    instance_variable_get('@property_hash')
  end

  # required for easier mocking, this could be a Tempfile too
  def self.temp_file
    'c:\\windows\\temp\\secedit.inf'
  end

  def temp_file
    'c:\\windows\\temp\\secedit.inf'
  end

  # writes out one policy at a time using the InfFile Class and secedit
  def write_policy_to_system(policy_hash)
    time = Time.now
    time = time.strftime("%Y%m%d%H%M%S")
    infout = "c:\\windows\\temp\\infimport-#{time}.inf"
    sdbout = "c:\\windows\\temp\\sdbimport-#{time}.inf"
    #logout = "c:\\windows\\temp\\logout-#{time}.inf"
    status = nil
    begin
      # read the system state into the inifile object for easy variable setting
      inf = PuppetX::IniFile.new
      # these sections need to be here by default
      inf["Version"] = {"signature"=>"$CHICAGO$", "Revision"=>1}
      inf["Unicode"] = {"Unicode"=>"yes"}
      section = policy_hash[:policy_type]
      section_value = {policy_hash[:policy_setting] => policy_hash[:policy_value]}
      # we can utilize the IniFile class to write out the data in ini format
      inf[section] = section_value
      inf.write(:filename => infout, :encoding => 'utf-8')
      secedit(['/configure', '/db', sdbout, '/cfg',infout])
    ensure
      FileUtils.rm_f(temp_file)
      FileUtils.rm_f(infout)
      FileUtils.rm_f(sdbout)
      #FileUtils.rm_f(logout)
    end
  end
end