# frozen_string_literal: true

require 'spec_helper_acceptance'

describe 'local_security_policy' do
  ['lsp_admin,*S-1-5-32-544,*S-1-5-9', '*S-1-5-11,*S-1-5-32-544,*S-1-5-9'].each do |policy_value|
    context "set privilege rights policy (SeNetworkLogonRight = '#{policy_value}')" do
      let(:manifest) do
        <<~END
          local_security_policy { 'Access this computer from the network':
            ensure       => present,
            policy_value => '#{policy_value}',
          }
        END
      end

      it 'is expected to apply with no errors' do
        # Run twice to test idempotency
        apply_manifest(manifest, 'catch_failures' => true)
        apply_manifest(manifest, 'catch_changes' => true)
      end

      it 'sets the value correctly' do
        on hosts, 'Secedit /Export /Areas User_Rights /CFG C:\secedit.txt'
        hosts.each do |host|
          value = on(host, 'type C:\secedit.txt')
          expect(value.output).to match(%r{^SeNetworkLogonRight\s*=\s*#{Regexp.escape(policy_value)}$})
        end
      end
    end
  end
end
