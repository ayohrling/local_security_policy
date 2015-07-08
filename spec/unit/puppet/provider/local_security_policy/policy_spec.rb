require 'spec_helper'
provider_class = Puppet::Type.type(:local_security_policy).provider(:policy)

describe provider_class do
  subject { provider_class }

  let(:facts)do {:is_virtual => 'false', :osfamily => 'Windows'} end

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
    expect(provider_class.instances.class).to eq(Array)
  end

  it "should be an instance of Puppet::Type::Local_security_policy::ProviderPolicy" do
    expect(provider).to be_an_instance_of Puppet::Type::Local_security_policy::ProviderPolicy
  end

end
