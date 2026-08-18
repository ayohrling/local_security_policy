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
    self.class.apply_policy(resource)
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
    @run_tags = nil
    @run_skip_tags = nil
    @file_object = nil
  end

  # called by the transaction once every local_security_policy resource has been
  # evaluated
  def self.post_resource_eval
    reset_run_state
  end

  # writes the policy for the resource being flushed.  The first resource that can share
  # an inf file writes every policy the catalog is going to change in one secedit call,
  # so the rest are already applied by the time they are flushed.  Any policy that call
  # did not apply is written on its own, which is what reports the failure against the
  # policy that could not be applied.
  def self.apply_policy(resource)
    # a noop resource is only reported, it must never be written to the system
    return if resource.noop?

    # a policy that cannot go into a shared inf file is written on its own, and the
    # batch is left for the next resource to trigger
    unless writable_in_batch?(resource)
      write_policies_to_system([resource.to_hash])
      return
    end

    apply_batch(resource) unless @batched_policies
    return if @batched_policies.include?(resource[:name])

    write_policies_to_system([resource.to_hash])
  end

  # writes every policy the catalog is going to change with a single secedit call, then
  # reads the settings back to record which of them actually landed.  secedit applies
  # the settings it accepts before reporting an error, and can skip an individual
  # setting while still exiting zero, so reading back is the only trustworthy answer.
  # Whatever did not land is written again by the resource that owns it.
  def self.apply_batch(resource)
    batched = [resource] + batchable_peers(resource)
    @batched_policies = Set.new
    begin
      write_policies_to_system(batched.map(&:to_hash))
    rescue Puppet::ExecutionFailure => e
      Puppet.warning("Applying the local security policies together failed, the ones that were not applied will be written individually: #{e.message}")
    end
    @batched_policies = applied_policies(batched)
  end

  # the names of the policies whose value now matches what the system reports, decided
  # with the same in sync test that decided to write them in the first place
  def self.applied_policies(batched)
    # the cached export was taken before the write
    @file_object = nil
    current = instances.to_h { |instance| [instance.name, instance.policy_value] }
    batched.select { |resource| in_sync_with?(resource, current[resource[:name]]) }
           .to_set { |resource| resource[:name] }
  rescue StandardError => e
    Puppet.debug("Could not re-read the policy settings after the batched write: #{e.message}")
    Set.new
  end

  def self.in_sync_with?(resource, value)
    property = resource.property(:policy_value)
    !property.nil? && property.safe_insync?(value)
  end

  # the other policies in the catalog that puppet is going to change this run and that
  # can share an inf file with the policy being flushed
  def self.batchable_peers(resource)
    settings = [setting_key(resource)]
    peers(resource).select do |other|
      next false unless batchable?(other)

      setting = setting_key(other)
      # several policy titles can map to the same secedit setting and an inf file only
      # holds one value per setting, so rather than silently dropping one of the values
      # the second policy is left to its own write
      if settings.include?(setting)
        Puppet.warning("#{other.ref} writes the same secedit setting as another policy in this catalog and will be applied on its own")
        next false
      end
      settings << setting
      true
    end
  end

  # the inf section and key a policy is written to
  def self.setting_key(resource)
    [resource[:policy_type], resource[:policy_setting]]
  end

  # the other resources of this type in the catalog
  def self.peers(resource)
    catalog = resource.catalog
    return [] unless catalog

    catalog.resources.select { |other| other.instance_of?(resource.class) && other.ref != resource.ref }
  end

  # whether a policy can be written into a shared inf file at all.  This provider cannot
  # remove a policy, and a policy with no value would be written as a bare `Setting =`
  # line which secedit can reject, taking every other policy in the file down with it
  def self.writable_in_batch?(resource)
    resource[:ensure] == :present && !resource[:policy_value].nil?
  end

  # whether a policy that has not been flushed yet may be included in the batched write.
  # Only policies puppet is definitely going to change this run qualify, so that batching
  # can never change a policy the transaction was not going to touch
  def self.batchable?(resource)
    reason = unbatchable_reason(resource)
    return true unless reason

    # an operator wondering why batching did not help has no other way to see this
    Puppet.debug("Not including #{resource.ref} in the batched policy write because #{reason}")
    false
  end

  def self.unbatchable_reason(resource)
    # noop and virtual resources are reported but never written
    return 'it is noop' if resource.noop?
    return 'it is virtual' if resource.virtual?
    return 'it is not ensured present, or has no value to set' unless writable_in_batch?(resource)
    # a deferred value is only resolved once the transaction evaluates that resource
    return 'its value has not been resolved yet' if deferred?(resource)
    return 'it already matches the system' unless out_of_sync?(resource)
    # anything the transaction may skip is left to its own flush
    return 'it is filtered out by --tags or --skip_tags' if tag_filtered?(resource)
    return 'it has a schedule, which may not match when it is evaluated' if unscheduled?(resource)
    return 'something it depends on may fail first' if depends_on_others?(resource)

    nil
  rescue StandardError => e
    # if anything about another resource cannot be worked out, leave that policy to its
    # own flush rather than guessing and writing it here
    "it could not be assessed: #{e.message}"
  end

  # Puppet::Transaction#skip_tags? and #missing_tags?, both of which are ignored when the
  # catalog is not a host config
  def self.tag_filtered?(resource)
    catalog = resource.catalog
    return false if catalog && !catalog.host_config?

    return true if !run_skip_tags.empty? && resource.tagged?(*run_skip_tags)

    !run_tags.empty? && !resource.tagged?(*run_tags)
  end

  # the transaction matches both tag lists without splitting qualified tags
  # (Puppet::Transaction#split_qualified_tags? is false), which is what SkipTags does
  def self.run_tags
    @run_tags ||= Puppet::Util::SkipTags.new(Puppet[:tags]).tags
  end

  def self.run_skip_tags
    @run_skip_tags ||= Puppet::Util::SkipTags.new(Puppet[:skip_tags]).tags
  end

  # Puppet::Transaction#scheduled?.  Only the ignoreschedules case is mirrored exactly,
  # otherwise the presence of a schedule is taken as "may be skipped", which is the safe
  # direction: the policy is written on its own instead of not at all
  def self.unscheduled?(resource)
    return false if Puppet[:ignoreschedules]

    !resource[:schedule].nil?
  end

  # whether the transaction could skip this resource because something it depends on
  # failed first.  Relationships declared with chaining arrows or with before/notify are
  # stored on the other end of the edge, so the relationship graph is the only place all
  # of a resource's dependencies can be seen; containment whits are not dependencies
  def self.depends_on_others?(resource)
    whit = Puppet::Type.type(:whit)
    resource.catalog.relationship_graph.direct_dependencies_of(resource).any? { |dependency| !dependency.instance_of?(whit) }
  end

  # whether any of the resource's values is still an unresolved Deferred.  Deferred values
  # are only resolved when the transaction evaluates that resource, so writing one out
  # from another resource's batch would put the wrapper object into the inf.  Checked the
  # same way as Puppet::Transaction#resolve_resource and Puppet::Type.validate
  def self.deferred?(resource)
    resource.parameters.each_value.any? { |parameter| parameter.value.instance_of?(Puppet::Pops::Evaluator::DeferredValue) }
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
