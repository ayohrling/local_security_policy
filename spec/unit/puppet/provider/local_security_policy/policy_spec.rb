# frozen_string_literal: true

require 'spec_helper'
require 'awesome_print'

# rubocop:disable RSpec/SubjectStub
describe Puppet::Type.type(:local_security_policy).provider(:policy) do
  include PuppetlabsSpec::Fixtures

  subject { described_class }

  before(:each) do
    allow(Puppet::Util).to receive(:which).with('secedit').and_return('c:\\tools\\secedit')

    infout = StringIO.new
    sdbout = StringIO.new
    allow(described_class).to receive(:read_policy_settings).and_return(inf_data)
    allow(Tempfile).to receive(:new).with('infimport').and_return(infout)
    allow(Tempfile).to receive(:new).with('sdbimport').and_return(sdbout)
    allow(File).to receive(:file?).with(secdata).and_return(true)
    # the below mock seems to be required or rspec complains
    allow(File).to receive(:file?).with(%r{facter|lsb_release}).and_return(true)
    allow(subject).to receive_messages(read_policy_settings: inf_data, temp_file: secdata)
    allow(subject).to receive(:secedit).with(['/configure', '/db', 'sdbout', '/cfg', 'infout', '/quiet']).and_return(true)
    allow(subject).to receive(:secedit).with(['/export', '/cfg', secdata, '/quiet']).and_return(true)
  end

  let(:facts) { os_facts }

  let(:security_policy) do
    SecurityPolicy.new
  end

  let(:inf_data) do
    inffile_content = File.read(secdata).encode('utf-8', universal_newline: true).delete("\xEF\xBB\xBF")
    PuppetX::IniFile.new(content: inffile_content)
  end
  # mock up the data which was gathered on a real windows system
  let(:secdata) do
    my_fixture(File.join('..', 'secedit.inf'))
  end

  let(:resource) do
    Puppet::Type.type(:local_security_policy).new(
      name: 'Network access: Let Everyone permissions apply to anonymous users',
      ensure: 'present',
      policy_setting: 'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous',
      policy_type: 'Registry Values',
      policy_value: '0',
    )
  end
  let(:provider) do
    described_class.new(resource)
  end

  it 'creates instances without error' do
    instances = described_class.instances
    expect(instances.class).to eq(Array)
    expect(instances.count).to be >= 114
  end

  # if you get this error, your are missing a entry in the lsp_mapping under puppet_x/security_policy
  # either its a type, case, or missing entry
  it 'lsp_mapping contains all the entries in secdata file' do
    inffile = subject.read_policy_settings
    missing_policies = {}

    inffile.sections.each do |section|
      next if section == 'Unicode'
      next if section == 'Version'

      inffile[section].each do |name, value|
        SecurityPolicy.find_mapping_from_policy_name(name)
      rescue KeyError => e
        puts e.message # rubocop:disable RSpec/Output -- diagnostic output for maintainers when this test fails, see comment above
        if value && section == 'Registry Values'
          reg_type = value.split(',').first
          missing_policies[name] = { name: name, policy_type: section, reg_type: reg_type }
        else
          missing_policies[name] = { name: name, policy_type: section }
        end
      end
    end
    ap missing_policies # rubocop:disable RSpec/Output -- diagnostic output for maintainers when this test fails, see comment above

    expect(missing_policies.count).to eq(0), 'Missing policy, check the lsp mapping'
  end

  it 'ensure instances works', skip: 'Puppet::Type.type(...).instances goes through provider suitability confinement (confine operatingsystem: :windows), so it returns 0 instances on this non-Windows test host' do
    instances = Puppet::Type.type(:local_security_policy).instances
    expect(instances.count).to be > 1
  end

  describe 'write output' do
    let(:resource) do
      Puppet::Type.type(:local_security_policy).new(
        name: 'Recovery console: Allow automatic administrative logon',
        ensure: 'present',
        policy_setting: 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SecurityLevel',
        policy_type: 'Registry Values',
        policy_value: '0',
      )
    end

    it 'writes out the file correctly' do
      provider.create
    end
  end

  describe 'resource is removed' do
    let(:resource) do
      Puppet::Type.type(:local_security_policy).new(
        name: 'Network access: Let Everyone permissions apply to anonymous users',
        ensure: 'absent',
        policy_setting: 'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous',
        policy_type: 'Registry Values',
        policy_value: '0',
      )
    end

    it 'exists? is true' do
      expect(provider.exists?).to be(false)
      # until we can implement the destroy functionality this test is useless
      # expect(provider).to receive(:destroy).exactly(1).times
    end
  end

  describe 'resource is present' do
    let(:secdata) do
      my_fixture(File.join('..', 'short_secedit.inf'))
    end
    let(:resource) do
      Puppet::Type.type(:local_security_policy).new(
        name: 'Recovery console: Allow automatic administrative logon',
        ensure: 'present',
        policy_setting: 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SecurityLevel',
        policy_type: 'Registry Values',
        policy_value: '0',
      )
    end

    it 'exists? is true' do
      expect(provider).to receive(:create).exactly(0).times
    end
  end

  describe 'resource is absent' do
    let(:resource) do
      Puppet::Type.type(:local_security_policy).new(
        name: 'Recovery console: Allow automatic administrative logon',
        ensure: 'present',
        policy_setting: '1MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SecurityLevel',
        policy_type: 'Registry Values',
        policy_value: '76',
      )
    end

    it 'exists? is false' do
      expect(provider.exists?).to be(false)
      allow(provider).to receive(:create).once
    end
  end

  # rubocop:disable RSpec/MultipleMemoizedHelpers -- the outer group already defines six helpers
  describe 'batched writes' do
    # the fixture reports LockoutDuration = 15, ResetLockoutCount = 15 and
    # LockoutBadCount = 5, so a value of 30 is out of sync and 5 is in sync
    let(:lockout_duration) { lsp_resource('Account lockout duration', '30') }
    let(:lockout_reset) { lsp_resource('Reset account lockout counter after', '30') }
    let(:lockout_threshold) { lsp_resource('Account lockout threshold', '5') }
    let(:written_inf) { PuppetX::IniFile.new }
    let(:written_batches) { [] }

    def lsp_resource(title, value, params = {})
      params = { name: title, ensure: 'present', policy_value: value }.merge(params)
      params.delete(:policy_value) if value.nil?
      Puppet::Type.type(:local_security_policy).new(params)
    end

    # puts the resources in a catalog, the way the transaction would, and hands each
    # of them the provider prefetch found for it
    def prepare(*resources)
      catalog = Puppet::Resource::Catalog.new
      resources.each { |res| catalog.add_resource(res) }
      lsp = resources.grep(Puppet::Type.type(:local_security_policy))
      described_class.prefetch(lsp.to_h { |res| [res[:name], res] })
      catalog
    end

    # records what each secedit call would have been asked to write
    def record_writes
      allow(described_class).to receive(:write_policies_to_system) do |policy_hashes|
        written_batches << policy_hashes.map { |policy_hash| policy_hash[:name] }
      end
    end

    # the batched write is rejected, every write after it is recorded
    def reject_first_write
      calls = 0
      allow(described_class).to receive(:write_policies_to_system) do |policy_hashes|
        calls += 1
        raise Puppet::ExecutionFailure, 'secedit returned 1' if calls == 1

        written_batches << policy_hashes.map { |policy_hash| policy_hash[:name] }
      end
    end

    # what the system reports once the rejected batch has been partly applied
    def system_reports(values)
      allow(described_class).to receive(:instances).and_return(
        values.map { |title, value| described_class.new(name: title, policy_value: value) },
      )
    end

    before(:each) do
      described_class.reset_run_state
      allow(described_class).to receive(:secedit)
      allow(FileUtils).to receive(:rm_f)
      allow(PuppetX::IniFile).to receive(:new).and_call_original
      allow(PuppetX::IniFile).to receive(:new).with(no_args).and_return(written_inf)
      allow(written_inf).to receive(:write)
    end

    after(:each) do
      described_class.reset_run_state
    end

    it 'writes every out of sync policy in the catalog with a single secedit call' do
      expect(described_class).to receive(:secedit).once

      prepare(lockout_duration, lockout_reset)
      lockout_duration.provider.flush

      expect(written_inf['System Access']).to eq('LockoutDuration' => '30', 'ResetLockoutCount' => '30')
    end

    it 'does not write again for a policy the batch already covered' do
      record_writes
      prepare(lockout_duration, lockout_reset)
      lockout_duration.provider.flush
      lockout_reset.provider.flush

      expect(written_batches).to eq([['Account lockout duration', 'Reset account lockout counter after']])
    end

    it 'leaves policies that are already in sync out of the batch' do
      record_writes
      prepare(lockout_duration, lockout_threshold)
      lockout_duration.provider.flush

      expect(written_batches).to eq([['Account lockout duration']])
    end

    # a policy is only written on another resource's behalf when the transaction is
    # definitely going to change it, so every one of these has to stay out of the batch
    {
      'noop' => { noop: true },
      'ensure => absent' => { ensure: 'absent' },
      'a schedule' => { schedule: 'maintenance' },
      'a require' => { require: 'Notify[prep]' },
      'a subscribe' => { subscribe: 'Notify[prep]' },
    }.each do |description, params|
      it "leaves a policy with #{description} out of the batch" do
        record_writes
        prepare(lockout_duration, lsp_resource('Reset account lockout counter after', '30', params))
        lockout_duration.provider.flush

        expect(written_batches).to eq([['Account lockout duration']])
      end
    end

    # a policy with nothing to set would be written into the inf as a bare `Setting =`
    # line, which secedit can reject, taking the whole batch down with it
    it 'leaves a policy with no value to set out of the batch' do
      record_writes
      valueless = lsp_resource('Reset account lockout counter after', nil)
      prepare(lockout_duration, valueless)
      # the policy is not on the system, so it is out of sync on ensure alone
      valueless.provider = described_class.new(name: valueless[:name])
      lockout_duration.provider.flush

      expect(written_batches).to eq([['Account lockout duration']])
    end

    it 'leaves a virtual policy out of the batch' do
      record_writes
      virtual_reset = lockout_reset
      virtual_reset.virtual = true
      prepare(lockout_duration, virtual_reset)
      lockout_duration.provider.flush

      expect(written_batches).to eq([['Account lockout duration']])
    end

    it 'leaves a policy whose value is still deferred out of the batch' do
      record_writes
      deferred_reset = lsp_resource('Reset account lockout counter after',
                                    Puppet::Pops::Evaluator::DeferredValue.new(-> { '30' }))
      prepare(lockout_duration, deferred_reset)
      lockout_duration.provider.flush

      expect(written_batches).to eq([['Account lockout duration']])
    end

    it 'leaves a policy filtered out by --tags out of the batch' do
      record_writes
      Puppet[:tags] = 'other'
      prepare(lockout_duration, lockout_reset)
      lockout_duration.provider.flush

      expect(written_batches).to eq([['Account lockout duration']])
    end

    it 'leaves a policy matched by --skip_tags out of the batch' do
      record_writes
      Puppet[:skip_tags] = 'skipme'
      prepare(lockout_duration, lsp_resource('Reset account lockout counter after', '30', tag: 'skipme'))
      lockout_duration.provider.flush

      expect(written_batches).to eq([['Account lockout duration']])
    end

    # `Notify['prep'] -> Local_security_policy['x']` stores the edge on the notify, so
    # the policy's own parameters show nothing; only the relationship graph does
    it 'leaves a policy another resource is ordered before out of the batch' do
      record_writes
      prep = Puppet::Type.type(:notify).new(name: 'prep', before: 'Local_security_policy[Reset account lockout counter after]')
      prepare(lockout_duration, lockout_reset, prep)
      lockout_duration.provider.flush

      expect(written_batches).to eq([['Account lockout duration']])
    end

    # both of these titles map to the ScForceOption registry value and an inf file only
    # holds one value per setting, so the second one has to be written on its own
    it 'leaves a policy that writes an already batched secedit setting out of the batch' do
      record_writes
      smart_card = lsp_resource('Interactive logon: Require smart card', '1')
      hello = lsp_resource('Interactive logon: Require Windows Hello for Business or smart card', '1')
      prepare(smart_card, hello)
      # only the first title is found by the reverse mapping, so the second never gets a
      # provider from prefetch, exactly as on a real system
      hello.provider = described_class.new(name: hello[:name])
      smart_card.provider.flush
      hello.provider.flush

      expect(written_batches).to eq([['Interactive logon: Require smart card'],
                                     ['Interactive logon: Require Windows Hello for Business or smart card']])
    end

    it 'writes nothing when the policy being flushed is noop' do
      record_writes
      noop_duration = lsp_resource('Account lockout duration', '30', noop: true)
      prepare(noop_duration, lockout_reset)
      noop_duration.provider.flush

      expect(written_batches).to be_empty
    end

    it 'writes nothing at all when the whole run is noop' do
      record_writes
      Puppet[:noop] = true
      prepare(lockout_duration, lockout_reset)
      [lockout_duration, lockout_reset].each { |res| res.provider.flush }

      expect(written_batches).to be_empty
    end

    it 'does not rewrite the policies a rejected batch did apply' do
      prepare(lockout_duration, lockout_reset)
      # secedit applied the duration before rejecting the file
      system_reports('Account lockout duration' => '30')
      reject_first_write

      lockout_duration.provider.flush
      lockout_reset.provider.flush

      expect(written_batches).to eq([['Reset account lockout counter after']])
    end

    it 'writes the policies a rejected batch did not apply as they are flushed' do
      prepare(lockout_duration, lockout_reset)
      system_reports({})
      reject_first_write

      lockout_duration.provider.flush
      lockout_reset.provider.flush

      expect(written_batches).to eq([['Account lockout duration'], ['Reset account lockout counter after']])
    end

    it 'raises out of flush when the policy itself cannot be written' do
      prepare(lockout_duration)
      system_reports({})
      allow(described_class).to receive(:write_policies_to_system).and_raise(Puppet::ExecutionFailure, 'secedit returned 1')

      expect { lockout_duration.provider.flush }.to raise_error(Puppet::ExecutionFailure, %r{secedit returned 1})
    end
  end
  # rubocop:enable RSpec/MultipleMemoizedHelpers

  it 'is an instance of Puppet::Type::Local_security_policy::ProviderPolicy' do
    expect(provider).to be_an_instance_of Puppet::Type::Local_security_policy::ProviderPolicy
  end
end
# rubocop:enable RSpec/SubjectStub
