# frozen_string_literal: true

require 'fileutils'
require 'puppet/util/skip_tags'

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

  # clears the state that is only valid for the duration of one puppet run.  A puppet
  # agent daemon reuses this process for every run, so none of it may be carried over
  def self.reset_run_state
    @batched_policies = nil
    @file_object = nil
  end

  # called by the transaction once every local_security_policy resource has been
  # evaluated
  def self.post_resource_eval
    reset_run_state
  end

  # writes the policy for the resource being flushed.  The first resource to get here
  # writes every policy the catalog is going to change in one secedit call, so the rest
  # are already applied by the time they are flushed.  Any policy that call did not
  # apply is written on its own, which is what reports the failure against the policy
  # that could not be applied.
  def self.apply_policy(resource)
    # a noop resource is only reported, it must never be written to the system
    return if resource.noop?

    apply_batch(resource) unless @batched_policies
    return if @batched_policies.include?(resource[:name])

    write_policies_to_system([resource.to_hash])
  end

  # writes every policy the catalog is going to change with a single secedit call and
  # records which policies that call applied.  secedit applies the settings it accepts
  # before reporting an error, so a rejected batch is re-read rather than written off:
  # only the policies that really did not land are written again, each by the resource
  # that owns it.
  def self.apply_batch(resource)
    policies = batchable_policies(resource)
    # nothing counts as applied until secedit has been run
    @batched_policies = []
    begin
      write_policies_to_system(policies)
      @batched_policies = policies.map { |policy_hash| policy_hash[:name] }
    rescue Puppet::ExecutionFailure => e
      Puppet.warning("Applying the local security policies together failed, the ones that were not applied will be written individually: #{e.message}")
      @batched_policies = policies_matching_system(policies)
    end
  end

  # the names of the given policies whose value already matches what the system
  # reports, so that a rejected batch does not rewrite the settings secedit accepted
  def self.policies_matching_system(policies)
    # the cached export was taken before the write
    @file_object = nil
    current = instances.to_h { |instance| [instance.name, instance.policy_value.to_s] }
    policies.select { |policy_hash| current[policy_hash[:name]] == policy_hash[:policy_value].to_s }
            .map { |policy_hash| policy_hash[:name] }
  rescue StandardError => e
    Puppet.debug("Could not re-read the policy settings after the rejected batch: #{e.message}")
    []
  end

  # the policies to write in the batched secedit call: the policy being flushed plus
  # every other policy in the catalog that puppet is going to change this run
  def self.batchable_policies(resource)
    policies = [resource.to_hash]
    settings = policies.map { |policy_hash| policy_hash.values_at(:policy_type, :policy_setting) }
    peers(resource).each do |other|
      next unless batchable?(other)

      policy_hash = other.to_hash
      setting = policy_hash.values_at(:policy_type, :policy_setting)
      # several policy titles can map to the same secedit setting and an inf file only
      # holds one value per setting, so rather than silently dropping one of the values
      # the second policy is left to its own write
      if settings.include?(setting)
        Puppet.warning("#{other.ref} writes the same secedit setting as another policy in this catalog and will be applied on its own")
        next
      end
      settings << setting
      policies << policy_hash
    end
    policies
  end

  # the other resources of this type in the catalog
  def self.peers(resource)
    catalog = resource.catalog
    return [] unless catalog

    catalog.resources.select { |other| other.instance_of?(resource.class) && other.ref != resource.ref }
  end

  # whether a policy that has not been flushed yet may be included in the batched
  # write.  Only policies puppet is definitely going to change this run qualify, so
  # that batching can never change a policy the transaction was not going to touch
  def self.batchable?(resource)
    # noop resources are reported but never written
    return false if resource.noop?
    # this provider cannot remove a policy, and a policy with no value would be written
    # into the inf as a bare `Setting =` line which secedit can reject
    return false unless resource[:ensure] == :present
    return false if resource[:policy_value].nil?
    # a deferred value is only resolved once the transaction evaluates that resource,
    # until then to_hash hands back the unresolved wrapper object
    return false if deferred?(resource)
    # a policy that already matches the system does not need to be written at all
    return false unless out_of_sync?(resource)
    # anything the transaction may skip is left to its own flush
    return false if may_be_skipped?(resource)

    true
  rescue StandardError => e
    # if anything about another resource cannot be worked out, leave that policy to
    # its own flush rather than guessing and writing it here
    Puppet.debug("Not including #{resource.ref} in the batched policy write: #{e.message}")
    false
  end

  # mirrors the checks in Puppet::Transaction#skip? that this provider is able to make
  def self.may_be_skipped?(resource)
    return true if resource.virtual?
    return true if resource[:schedule]
    return true if tag_filtered?(resource)

    depends_on_others?(resource)
  end

  # Puppet::Transaction#skip_tags? and #missing_tags?, both of which are ignored when
  # the catalog is not a host config
  def self.tag_filtered?(resource)
    catalog = resource.catalog
    return false if catalog && !catalog.host_config?

    skip_tags = Puppet::Util::SkipTags.new(Puppet[:skip_tags]).tags
    return true if !skip_tags.empty? && resource.tagged?(*skip_tags)

    # the transaction parses Puppet[:tags] through Puppet::Util::Tagging, which splits
    # qualified tags, unlike the skip tags above
    tags = Object.new.extend(Puppet::Util::Tagging).tap { |tagger| tagger.tags = Puppet[:tags] }.tags
    !tags.empty? && !resource.tagged?(*tags)
  end

  # whether the transaction could skip this resource because something it depends on
  # failed first.  Relationships declared with chaining arrows or with before/notify are
  # stored on the other end of the edge, so the relationship graph is the only place all
  # of a resource's dependencies can be seen; containment whits are not dependencies
  def self.depends_on_others?(resource)
    catalog = resource.catalog
    return !resource[:require].nil? || !resource[:subscribe].nil? unless catalog

    whit = Puppet::Type.type(:whit)
    catalog.relationship_graph.direct_dependencies_of(resource).any? { |dependency| !dependency.instance_of?(whit) }
  end

  # whether any of the resource's values is still an unresolved Deferred.  Deferred
  # values are only resolved when the transaction evaluates that resource, so writing
  # one out from another resource's batch would put the wrapper object into the inf
  def self.deferred?(resource)
    return false unless defined?(Puppet::Pops::Evaluator::DeferredValue)

    resource.to_hash.each_value.any? { |value| deferred_value?(value) }
  end

  def self.deferred_value?(value)
    case value
    when Puppet::Pops::Evaluator::DeferredValue then true
    when Array then value.any? { |element| deferred_value?(element) }
    when Hash then value.any? { |key, element| deferred_value?(key) || deferred_value?(element) }
    else false
    end
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
end
