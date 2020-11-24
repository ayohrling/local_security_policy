# frozen_string_literal: true

require 'spec_helper_acceptance'
require 'json'

def get_reg_key_on(host, key)
  powershell = 'powershell.exe -noprofile -nologo -noninteractive -command'
  ps = on host, %(#{powershell} "Get-ItemProperty -Path \\\"#{key}\\\" | ConvertTo-Json")
  JSON.parse(ps.stdout)
end

describe 'local_security_policy' do
  context 'enable registry value policy' do
    let(:manifest) do
      <<~END
      local_security_policy { 'Network access: Restrict clients allowed to make remote calls to SAM':
        ensure => present,
        policy_value => '1,"O:BAG:BAD:(A;;RC;;;BA)"',
      }
      END
    end

    it 'applies with no errors' do
      # Run twice to test idempotency
      apply_manifest(manifest, 'catch_failures' => true)
      apply_manifest(manifest, 'catch_changes' => true)
    end

    it 'sets the value correctly' do
      hosts.each do |host|
        value = get_reg_key_on(host, 'HKLM:\System\CurrentControlSet\Control\Lsa')
        expect(value['restrictremotesam']).to eq('O:BAG:BAD:(A;;RC;;;BA)')
      end
    end
  end

  context 'disable registry value policy' do
    let(:manifest) do
      <<~END
      local_security_policy { 'Network access: Restrict clients allowed to make remote calls to SAM':
        ensure => present,
        policy_value => '',
      }
      END
    end

    it 'applies with no errors' do
      # Run twice to test idempotency
      apply_manifest(manifest, 'catch_failures' => true)
      apply_manifest(manifest, 'catch_changes' => true)
    end

    it 'sets the value correctly' do
      hosts.each do |host|
        value = get_reg_key_on(host, 'HKLM:\System\CurrentControlSet\Control\Lsa')
        expect(value['restrictremotesam']).to eq('')
      end
    end
  end
end
