require 'spec_helper'
require "awesome_print"

provider_class = Puppet::Type.type(:local_security_policy).provider(:policy)

describe provider_class do
  subject { provider_class }
  before :all do
    Puppet::Util.stubs(:which).with("wmic").returns("c:\\tools\\wmic")
    Puppet::Util.stubs(:which).with("secedit").returns("c:\\tools\\secedit")
  end
  before :each do
    infout = StringIO.new
    sdbout = StringIO.new
    allow(provider_class).to receive(:read_policy_settings).and_return(inf_data)
    allow(Tempfile).to receive(:new).with('infimport').and_return(infout)
    allow(Tempfile).to receive(:new).with('sdbimport').and_return(sdbout)
    allow(File).to receive(:file?).with(secdata).and_return(true)
    # the below mock seems to be required or rspec complains
    allow(File).to receive(:file?).with(/facter/).and_return(true)
    allow(subject).to receive(:temp_file).and_return(secdata)
    subject.stubs(:secedit).with(['/configure', '/db', 'sdbout', '/cfg', 'infout', '/quiet'])
    subject.stubs(:secedit).with(['/export', '/cfg', secdata, '/quiet'])
    allow_any_instance_of(SecurityPolicy).to receive(:wmic).with([ "useraccount", "get", "name,sid", "/format:csv"]).and_return(userdata)
    allow_any_instance_of(SecurityPolicy).to receive(:wmic).with([ "group", "get", "name,sid", "/format:csv"]).and_return(groupdata)

  end

  let(:security_policy){
    SecurityPolicy.new
  }

  let(:inf_data) do
    inffile_content = File.read(secdata).encode('utf-8', :universal_newline => true).gsub("\xEF\xBB\xBF", '')
    PuppetX::IniFile.new(:content => inffile_content)
  end
  # mock up the data which was gathered on a real windows system
  let(:secdata) do
    File.join(fixtures_path, 'unit', 'secedit.inf')
  end

  let(:groupdata) do
    file = File.join(fixtures_path, 'unit', 'group.txt')
    File.open(file, 'r') {|f| f.read.encode('utf-8', :universal_newline => true).gsub("\xEF\xBB\xBF", '')}
  end

  let(:userdata) do
    file = File.join(fixtures_path, 'unit', 'useraccount.txt')
    File.open(file, 'r') {|f| f.read.encode('utf-8', :universal_newline => true).gsub("\xEF\xBB\xBF", '')}
  end

  let(:facts)do {:is_virtual => 'false', :operatingsystem => 'windows'} end

  let(:resource) {
    Puppet::Type.type(:local_security_policy).new(
        :name => 'Network access: Let Everyone permissions apply to anonymous users',
        :ensure => 'present',
        :policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous',
        :policy_type    => 'Registry Values',
        :policy_value   => '0')
  }
  let(:provider) {
    provider_class.new(resource)
  }

  it 'should create instances without error' do
    instances = provider_class.instances
    expect(instances.class).to eq(Array)
    expect(instances.count).to be >= 115
  end

  # if you get this error, your are missing a entry in the lsp_mapping under puppet_x/security_policy
  # either its a type, case, or missing entry
  it 'lsp_mapping should contain all the entries in secdata file' do
    inffile = subject.read_policy_settings
    missing_policies = {}
    message = lambda {"Missing policy check the lsp mapping for something like:\n"}

    inffile.sections.each do |section|
      next if section == 'Unicode'
      next if section == 'Version'
      inffile[section].each do |name, value|
        begin
          SecurityPolicy.find_mapping_from_policy_name(name)
        rescue KeyError => e
          puts e.message
          if value and section == 'Registry Values'
            reg_type = value.split(',').first
            missing_policies[name] = {:name => name, :policy_type => section, :reg_type => reg_type}
          else
            missing_policies[name] = {:name => name, :policy_type => section}
          end
        end
      end
    end
    ap missing_policies
    expect(missing_policies.count).to eq(0), message
  end

  xit 'ensure instances works' do
    instances = Puppet::Type.type(:local_security_policy).instances
    expect(instances.count).to be > 1
  end

  describe 'write output' do
    let(:resource) {
      Puppet::Type.type(:local_security_policy).new(
          :name => 'Recovery console: Allow automatic adminstrative logon',
        :ensure => 'present',
        :policy_setting => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SecurityLevel',
        :policy_type    => 'Registry Values',
        :policy_value   => '0')
    }
    xit 'should write out the file correctly' do

      provider.create

    end
  end


  describe 'resource is removed' do
    let(:resource) {
      Puppet::Type.type(:local_security_policy).new(
          :name => 'Network access: Let Everyone permissions apply to anonymous users',
          :ensure => 'absent',
          :policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous',
          :policy_type    => 'Registry Values',
          :policy_value   => '0')
    }
    it 'exists? should be true' do
      expect(provider.exists?).to eq(false)
      # until we can implement the destroy functionality this test is useless
      #expect(provider).to receive(:destroy).exactly(1).times
    end
  end

  describe 'resource is present' do
    let(:secdata) do
      File.join(fixtures_path, 'unit', 'short_secedit.inf')
    end
    let(:resource) {
      Puppet::Type.type(:local_security_policy).new(
          :name => 'Recovery console: Allow automatic adminstrative logon',
          :ensure => 'present',
          :policy_setting => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SecurityLevel',
          :policy_type    => 'Registry Values',
          :policy_value   => '0')
    }
    it 'exists? should be true' do
      expect(provider.exists?).to eq(true)
      expect(provider).to receive(:create).exactly(0).times
    end
  end

  describe 'resource is absent' do
    let(:resource) {
      Puppet::Type.type(:local_security_policy).new(
          :name => 'Recovery console: Allow automatic adminstrative logon',
          :ensure => 'present',
          :policy_setting => '1MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SecurityLevel',
          :policy_type    => 'Registry Values',
          :policy_value   => '76')
    }
    it 'exists? should be false' do
      expect(provider.exists?).to eq(false)
      allow(provider).to receive(:create).exactly(1).times

    end
  end

  it "should be an instance of Puppet::Type::Local_security_policy::ProviderPolicy" do
    expect(provider).to be_an_instance_of Puppet::Type::Local_security_policy::ProviderPolicy
  end
end
