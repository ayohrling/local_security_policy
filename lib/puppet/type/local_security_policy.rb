# frozen_string_literal: true

begin
  require 'puppet_x/lsp/security_policy'
rescue LoadError => _detail
  require 'pathname' # JJM WORK_AROUND #14073
  mod = Puppet::Module.find('local_security_policy', Puppet[:environment].to_s)
  if mod
    require File.join(mod.path, 'lib/puppet_x/lsp/security_policy')
  else # received nil, fallback to old style
    module_base = Pathname.new(__FILE__).dirname
    require File.join(module_base, '../../', 'puppet_x/lsp/security_policy')
  end
end

Puppet::Type.newtype(:local_security_policy) do
  @doc = 'Puppet type that models the local security policy'

  ensurable

  newparam(:name, namevar: true) do
    desc 'Local Security Setting Name. What you see it the GUI.'
    validate do |value|
      raise ArgumentError, "Invalid Policy name: #{value}" unless SecurityPolicy.valid_lsp?(value)
    end
  end

  newproperty(:policy_type) do
    newvalues('System Access', 'Event Audit', 'Privilege Rights', 'Registry Values', nil, '')
    desc 'Local Security Policy Type. Section of the config INF the setting is in.'
    defaultto do
      begin
        policy_hash = SecurityPolicy.find_mapping_from_policy_desc(resource[:name])
      rescue KeyError => e
        raise(e.message)
      end
      policy_hash[:policy_type]
    end
    # uses the resource name to perform a lookup of the defined policy and returns the policy type
    munge do |_value|
      begin
        policy_hash = SecurityPolicy.find_mapping_from_policy_desc(resource[:name])
      rescue KeyError => e
        raise(e.message)
      end
      policy_hash[:policy_type]
    end
  end

  newproperty(:policy_setting) do
    desc 'Local Security Policy Machine Name.  What OS knows it by.'
    defaultto do
      begin
        policy_hash = SecurityPolicy.find_mapping_from_policy_desc(resource[:name])
      rescue KeyError => e
        raise(e.message)
      end
      policy_hash[:name]
    end
    munge do |_value|
      begin
        policy_hash = SecurityPolicy.find_mapping_from_policy_desc(resource[:name])
      rescue KeyError => e
        raise(e.message)
      end
      policy_hash[:name]
    end
  end

  newproperty(:policy_value) do
    desc 'Local Security Policy Setting Value'
    validate do |value|
      if resource[:policy_type].nil?
        begin
          cur_policy_hash = SecurityPolicy.find_mapping_from_policy_desc(resource[:name])
        rescue KeyError => e
          raise(e.message)
        end
        cur_policy_type = cur_policy_hash[:policy_type]
      else
        cur_policy_type = resource[:policy_type].to_s
      end

      case cur_policy_type
      when 'Privilege Rights' # rubocop:disable Lint/EmptyWhen
        # maybe validate some sort of user?
      when 'Event Audit'
        raise ArgumentError, "Invalid Event type: #{value} for #{resource[:policy_value]}" unless SecurityPolicy::EVENT_TYPES.include?(value)
      when 'Registry Values'
        cur_converted_value = SecurityPolicy.convert_registry_value(resource[:name], value)
        cur_value_type = cur_converted_value.split(',')[0]
        case cur_value_type
        # maybe validate the value based on the datatype?
        # REG_NONE 0
        # REG_SZ 1
        when '1'
          raise ArgumentError, "Invalid value for type: #{value} for REG_SZ" unless value.is_a?(String)
        # REG_EXPAND_SZ 2
        # REG_BINARY 3
        # REG_DWORD 4
        when '4'
          test_val = value.to_i
          if test_val < -2_147_483_648 || test_val > 2_147_483_647
            raise ArgumentError, "Invalid value for type: #{test_val} for REG_DWORD"
          end
        # REG_DWORD_LITTLE_ENDIAN 4
        # REG_DWORD_BIG_ENDIAN 5
        # REG_LINK 6
        # REG_MULTI_SZ 7
        when '7'
          raise ArgumentError, "Invalid value for type: #{value} for REG_MULTI_SZ" unless value.is_a?(String)
        # REG_RESOURCE_LIST 8
        # REG_FULL_RESOURCE_DESCRIPTOR 9
        # REG_RESOURCE_REQUIREMENTS_LIST 10
        # REG_QWORD 11
        when '11'
          test_val = value.to_i
          if test_val < -9_223_372_036_854_775_808 || test_val > 9_223_372_036_854_775_807
            raise ArgumentError, "Invalid value for type: #{test_val} for REG_QWORD"
          end
          # REG_QWORD_LITTLE_ENDIAN 11
        end
      when 'System Access' # rubocop:disable Lint/EmptyWhen
        # Multiple data types are valid.  Need to define a clever validation...
      end
    end

    munge do |value|
      # need to convert policy values to designated types
      case resource[:policy_type].to_s
      when 'Registry Values' # rubocop:disable Lint/EmptyWhen
        # secedit values sometimes look like : "1,\"4\""
      end
      SecurityPolicy.convert_policy_value(resource.to_hash, value)
    end
  end
end
