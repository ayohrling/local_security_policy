#!/usr/bin/env ruby
# frozen_string_literal: true

begin
  require 'puppet_x/lsp/security_policy'
rescue LoadError => e
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

  newparam(:name, :namevar => true) do
    desc 'Local Security Setting Name. What you see it the GUI.'
    validate do |value|
      raise ArgumentError, "Invalid Policy name: #{value}" unless SecurityPolicy.valid_lsp?(value)
    end
  end

  newproperty(:policy_type) do
    newvalues('System Access', 'Event Audit', 'Privilege Rights', 'Registry Values', nil, '')
    desc 'Local Security Policy Machine Name.  What OS knows it by.'
    defaultto do
      begin
        policy_hash = SecurityPolicy.find_mapping_from_policy_desc(resource[:name])
      rescue KeyError => e
        fail(e.message)
      end
      policy_hash[:policy_type]
    end
    # uses the resource name to perform a lookup of the defined policy and returns the policy type
    munge do |value|
      begin
        policy_hash = SecurityPolicy.find_mapping_from_policy_desc(resource[:name])
      rescue KeyError => e
        fail(e.message)
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
        fail(e.message)
      end
      policy_hash[:name]
    end
    munge do |value|
      begin
        policy_hash = SecurityPolicy.find_mapping_from_policy_desc(resource[:name])
      rescue KeyError => e
        fail(e.message)
      end
      policy_hash[:name]
    end
  end

  newproperty(:policy_value) do
    desc 'Local Security Policy Setting Value'
    validate do |value|
      case resource[:policy_type].to_s
        when 'Privilege Rights'
          if value.nil? || value.empty?
            raise ArgumentError, "Value cannot be nil or empty.  Use \'Ensure: absent\' instead")
          end
          # maybe validate some sort of user?
        when 'Event Audit'
          raise ArgumentError, "Invalid Event type: #{value} for #{resource[:policy_value]}" unless SecurityPolicy::EVENT_TYPES.include?(value)
        when 'Registry Values'
          # maybe validate the value based on the datatype?

      case resource[:policy_type].to_s
      when 'Privilege Rights'
        # maybe validate some sort of user?
      when 'Event Audit'
        raise ArgumentError, "Invalid Event type: #{value} for #{resource[:policy_value]}" unless SecurityPolicy::EVENT_TYPES.include?(value)
      when 'Registry Values'
        # maybe validate the value based on the datatype?
        # REG_NONE 0
        # REG_SZ 1
        # REG_EXPAND_SZ 2
        # REG_BINARY 3
        # REG_DWORD 4
        # REG_DWORD_LITTLE_ENDIAN 4
        # REG_DWORD_BIG_ENDIAN 5
        # REG_LINK 6
        # REG_MULTI_SZ 7
        # REG_RESOURCE_LIST 8
        # REG_FULL_RESOURCE_DESCRIPTOR 9
        # REG_RESOURCE_REQUIREMENTS_LIST 10
        # REG_QWORD 11
        # REG_QWORD_LITTLE_ENDIAN 11
      end
    end

    munge do |value|
      # need to convert policy values to designated types
      case resource[:policy_type].to_s
      when 'Registry Values'
        # secedit values sometimes look like : "1,\"4\""
      end
      SecurityPolicy.convert_policy_value(resource.to_hash, value)
    end
  end
end
