# frozen_string_literal: true

require 'spec_helper_acceptance'

describe 'local_security_policy' do
  [10, 20].each do |n|
    context "set system access policy (PasswordHistorySize=#{n})" do
      let(:manifest) do
        <<~END
          local_security_policy { 'Enforce password history':
            ensure       => present,
            policy_value => '#{n}',
          }
        END
      end

      it 'is expected to apply with no errors' do
        # Run twice to test idempotency
        apply_manifest(manifest, 'catch_failures' => true)
        apply_manifest(manifest, 'catch_changes' => true)
      end

      it 'sets the value correctly' do
        on hosts, 'Secedit /Export /Areas SecurityPolicy /CFG C:\secedit.txt'
        hosts.each do |host|
          value = on(host, 'type C:\secedit.txt')
          expect(value.output).to match(%r{^PasswordHistorySize\s*=\s*#{n}$})
        end
      end
    end
  end

  context 'rename guest account' do
    let(:manifest) do
      <<~END
        local_security_policy { 'Accounts: Rename guest account':
          ensure       => present,
          policy_value => '"lsp_guest"',
        }
      END
    end

    it 'is expected to apply with no errors' do
      # Run twice to test idempotency
      apply_manifest(manifest, 'catch_failures' => true)
      apply_manifest(manifest, 'catch_changes' => true)
    end
  end

  context 'rename administrator account' do
    let(:manifest) do
      <<~END
        local_security_policy { 'Accounts: Rename administrator account':
          ensure       => present,
          policy_value => '"lsp_admin"',
        }
      END
    end

    it 'is expected to apply with no errors' do
      # Run twice to test idempotency
      apply_manifest(manifest, 'catch_failures' => true)
      apply_manifest(manifest, 'catch_changes' => true)
    end
  end

  # Windows requires ResetLockoutCount <= LockoutDuration, so these three policies can
  # only be set to the same value when they are applied together in one secedit call.
  # Whether the duration or the reset counter has to move first depends on the values the
  # host starts with, so no ordering between the resources can make this pass.
  context 'interdependent account lockout policies' do
    let(:manifest) do
      <<~END
        local_security_policy { 'Account lockout threshold':
          ensure       => present,
          policy_value => '5',
        }
        local_security_policy { 'Account lockout duration':
          ensure       => present,
          policy_value => '15',
        }
        local_security_policy { 'Reset account lockout counter after':
          ensure       => present,
          policy_value => '15',
        }
      END
    end

    it 'is expected to apply with no errors' do
      # Run twice to test idempotency
      apply_manifest(manifest, 'catch_failures' => true)
      apply_manifest(manifest, 'catch_changes' => true)
    end

    it 'sets the values correctly' do
      on hosts, 'Secedit /Export /Areas SecurityPolicy /CFG C:\secedit.txt'
      hosts.each do |host|
        value = on(host, 'type C:\secedit.txt')
        expect(value.output).to match(%r{^LockoutBadCount\s*=\s*5$})
        expect(value.output).to match(%r{^LockoutDuration\s*=\s*15$})
        expect(value.output).to match(%r{^ResetLockoutCount\s*=\s*15$})
      end
    end
  end

  # A policy is written on another resource's behalf only when puppet is going to
  # change it anyway, so a noop resource in the same catalog must be left alone even
  # though its neighbour triggers the combined secedit call.
  context 'noop policies in a batched write' do
    let(:baseline) do
      <<~END
        local_security_policy { 'Enforce password history':
          ensure       => present,
          policy_value => '10',
        }
        local_security_policy { 'Minimum password length':
          ensure       => present,
          policy_value => '8',
        }
      END
    end
    let(:manifest) do
      <<~END
        local_security_policy { 'Enforce password history':
          ensure       => present,
          policy_value => '20',
        }
        local_security_policy { 'Minimum password length':
          ensure       => present,
          policy_value => '14',
          noop         => true,
        }
      END
    end

    it 'only changes the policy that is not running under noop' do
      apply_manifest(baseline, 'catch_failures' => true)
      apply_manifest(manifest, 'catch_failures' => true)

      on hosts, 'Secedit /Export /Areas SecurityPolicy /CFG C:\secedit.txt'
      hosts.each do |host|
        value = on(host, 'type C:\secedit.txt')
        expect(value.output).to match(%r{^PasswordHistorySize\s*=\s*20$})
        expect(value.output).to match(%r{^MinimumPasswordLength\s*=\s*8$})
      end
    end
  end
end
