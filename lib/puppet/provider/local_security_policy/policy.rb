# frozen_string_literal: true

require 'fileutils'

begin
  require 'puppet_x/twp/inifile'
  require 'puppet_x/lsp/security_policy'
rescue LoadError => _e
  require 'pathname' # JJM WORK_AROUND #14073
  mod = Puppet::Module.find('local_security_policy', Puppet[:environment].to_s)
  if mod
    require File.join(mod.path, 'lib/puppet_x/twp/inifile')
    require File.join(mod.path, 'lib/puppet_x/lsp/security_policy')
  else # received nil, fallback to old style
    module_base = Pathname.new(__FILE__).dirname
    require File.join(module_base, '../../../', 'puppet_x/twp/inifile')
    require File.join(module_base, '../../../', 'puppet_x/lsp/security_policy')
  end
end

Puppet::Type.type(:local_security_policy).provide(:policy) do
  desc 'Puppet type that models the local security policy'

  #
  # TODO Finalize the registry key settings
  # TODO Add in registry value translation (ex: 1=enable 0=disable)
  # limit access to windows hosts only
  confine operatingsystem: :windows
  # limit access to systems with these commands since this is the tools we need
  commands secedit: 'secedit'

  mk_resource_methods

  # export the policy settings to the specified file and return the filename
  def self.export_policy_settings(inffile = nil)
    inffile ||= temp_file
    secedit(['/export', '/cfg', inffile, '/quiet'])
    inffile
  end

  # export and then read the policy settings from a file into a inifile object
  # caches the IniFile object during the puppet run
  def self.read_policy_settings(inffile = nil)
    inffile ||= temp_file
    unless @file_object
      export_policy_settings(inffile)
      File.open inffile, 'r:IBM437' do |file|
        # remove /r/n and remove the BOM
        inffile_content = file.read.force_encoding('utf-16le').encode('utf-8', universal_newline: true).delete("\xEF\xBB\xBF")
        @file_object ||= PuppetX::IniFile.new(content: inffile_content)
      end
    end
    @file_object
  end

  # converts any values that might be of a certain type specified in the mapping
  # converts everything to a string
  # returns the value
  def self.fixup_value(value, type)
    value = value.to_s.strip
    case type
    when :quoted_string
      value = "\"#{value}\""
    when :principal
      sids = value.split(',').map do |suser|
        (suser =~ %r{^(\*S-1-.+)$}) ? suser.to_s : ("*#{Puppet::Util::Windows::SID.name_to_sid(suser)}")
      end
      value = sids.sort.join(',')
    end
    value
  end

  # exports the current list of policies into a file and then parses that file into
  # provider instances.  If an item is found on the system but not in the lsp_mapping,
  # that policy is not supported only because we cannot match the description
  # furthermore, if a policy is in the mapping but not in the system we would consider
  # that resource absent
  def self.instances
    settings = []
    inf = read_policy_settings
    # need to find the policy, section_header, policy_setting, policy_value and reg_type
    inf.each do |section, parameter_name, parameter_value|
      next if section == 'Unicode'
      next if section == 'Version'

      begin
        ensure_value = parameter_value.nil? ? :absent : :present
        policy_desc, policy_values = SecurityPolicy.find_mapping_from_policy_name(parameter_name)
        policy_hash = {
          name: policy_desc,
          ensure: ensure_value,
          policy_type: section,
          policy_setting: parameter_name,
          policy_value: fixup_value(parameter_value, policy_values[:data_type]),
        }
        inst = new(policy_hash)
        settings << inst
      rescue KeyError => e
        Puppet.debug e.message
      end
    end
    settings
  end

  # the flush method is called once the resource's properties have been synced.
  # Rather than writing this policy on its own, the first policy to be flushed writes
  # every policy the catalog is going to change in a single secedit call.  Windows
  # then validates the final combination of settings instead of each individual
  # change, which is the only way interdependent policies (ex: the lockout reset
  # counter may not exceed the lockout duration) can be satisfied regardless of the
  # order puppet happens to evaluate them in.  Writing here rather than in
  # self.post_resource_eval also means a rejected policy raises inside the resource
  # harness, so the run reports a failed resource instead of only logging an error.
  def flush
    begin
      self.class.apply_policy(resource)
    rescue KeyError => e
      Puppet.debug e.message
      # send helpful debug message to user here
    end
    @property_hash = resource.to_hash
  end

  def initialize(value = {})
    super
    @property_flush = {}
  end

  # create the resource and convert any user supplied values to computer terms
  def create
    # do everything in flush method
  end

  # this is currently not implemented correctly on purpose until we can figure out how to safely remove
  def destroy
    @property_hash[:ensure] = :absent
    # Destroy not an option for now.  LSP Settings should be set to something.
    # we need some default destroy values in the mappings so we know ahead of time what to put unless the user supplies
    # but this would just ensure a value the setting should go back to
  end

  def self.prefetch(resources)
    reset_run_state
    # remember every policy in the catalog so the first one to be flushed can write
    # all of them in one go
    @catalog_resources = resources.values
    policies = instances
    resources.each_key do |name|
      if found_pol = policies.find { |pol| pol.name == name } # rubocop:disable Lint/AssignmentInCondition
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

  # the resources of this type in the catalog, captured during prefetch
  def self.catalog_resources
    @catalog_resources ||= []
  end

  # clears the state that is only valid for the duration of one puppet run.  A puppet
  # agent daemon reuses this process for every run, so none of it may be carried over
  def self.reset_run_state
    @catalog_resources = []
    @batched_policies = nil
    @batch_failed = false
    @file_object = nil
  end

  # called by the transaction once every local_security_policy resource has been
  # evaluated
  def self.post_resource_eval
    reset_run_state
  end

  # writes the policy for the resource being flushed.  The first resource to get here
  # writes every policy the catalog is going to change in one secedit call, so the
  # rest are already applied by the time they are flushed.  If that combined write was
  # rejected, each remaining policy is written on its own instead.
  def self.apply_policy(resource)
    # a noop resource is only reported, it must never be written to the system
    return if resource.noop?

    return apply_batch(resource) unless @batched_policies

    # a policy that was left out of the batch still has to be written when it is
    # flushed, and everything is rewritten individually once the batch has failed
    return if !@batch_failed && @batched_policies.include?(resource[:name])

    write_policies_to_system([resource.to_hash])
  end

  # writes every policy the catalog is going to change with a single secedit call.  If
  # windows rejects the combination, only the policy that triggered the write is
  # retried here, so the resource that ends up marked failed is the one whose own value
  # could not be applied rather than whichever resource happened to be flushed first.
  def self.apply_batch(resource)
    policies = batchable_policies(resource)
    @batched_policies = policies.map { |policy_hash| policy_hash[:name] }
    # assume the worst until the write comes back clean so that an unexpected error
    # cannot leave the remaining policies thinking they were already written
    @batch_failed = true
    begin
      write_policies_to_system(policies)
      @batch_failed = false
    rescue Puppet::ExecutionFailure => e
      Puppet.debug("Applying all local security policies at once failed, writing them one at a time: #{e.message}")
      write_policies_to_system([resource.to_hash])
    end
  end

  # the policies to write in the batched secedit call: the policy being flushed plus
  # every other policy in the catalog that puppet is going to change this run
  def self.batchable_policies(resource)
    others = catalog_resources.reject { |other| other.ref == resource.ref }
    [resource.to_hash] + others.select { |other| batchable?(other) }.map(&:to_hash)
  end

  # whether a policy that has not been flushed yet may be included in the batched
  # write.  Only policies puppet is definitely going to change this run qualify, so
  # that batching can never change a policy the transaction was not going to touch
  def self.batchable?(resource)
    # noop resources are reported but never written
    return false if resource.noop?
    # a policy that already matches the system does not need to be written at all
    return false unless out_of_sync?(resource)
    # the transaction may well skip these, leave them to their own flush
    return false if resource[:schedule]
    return false if resource[:require] || resource[:subscribe]
    return false if missing_tags?(resource)

    true
  rescue StandardError => e
    # if anything about another resource cannot be worked out, leave that policy to
    # its own flush rather than guessing and writing it here
    Puppet.debug("Not including #{resource.ref} in the batched policy write: #{e.message}")
    false
  end

  # mirrors Puppet::Transaction#missing_tags?; a resource filtered out by --tags is
  # never evaluated and so must not be written
  def self.missing_tags?(resource)
    tags = Puppet[:tags].to_s.split(',').map(&:strip).reject(&:empty?)
    return false if tags.empty?

    !resource.tagged?(*tags)
  end

  # whether the policy on the system differs from the policy in the catalog
  def self.out_of_sync?(resource)
    resource.properties.any? { |property| !property.safe_insync?(property.retrieve) }
  end

  # writes out the given policies using the InfFile Class and a single secedit call
  def self.write_policies_to_system(policy_hashes)
    time = Time.now
    time = time.strftime('%Y%m%d%H%M%S')
    infout = "c:\\windows\\temp\\infimport-#{time}.inf"
    sdbout = "c:\\windows\\temp\\sdbimport-#{time}.inf"
    # logout = "c:\\windows\\temp\\logout-#{time}.inf"
    begin
      # read the system state into the inifile object for easy variable setting
      inf = PuppetX::IniFile.new
      # these sections need to be here by default
      inf['Version'] = { 'signature' => '$CHICAGO$', 'Revision' => 1 }
      inf['Unicode'] = { 'Unicode' => 'yes' }
      policy_hashes.each do |policy_hash|
        # policies that share an inf section are all written into that same section
        inf[policy_hash[:policy_type]][policy_hash[:policy_setting]] = policy_hash[:policy_value]
      end
      # we can utilize the IniFile class to write out the data in ini format
      inf.write(filename: infout, encoding: 'utf-8')
      secedit(['/configure', '/db', sdbout, '/cfg', infout])
    ensure
      FileUtils.rm_f(temp_file)
      FileUtils.rm_f(infout)
      FileUtils.rm_f(sdbout)
      # FileUtils.rm_f(logout)
    end
  end

  # writes out a single policy on its own
  def write_policy_to_system(policy_hash)
    self.class.write_policies_to_system([policy_hash])
  end
end
