require 'spec_helper'

describe Puppet::Type.type(:local_security_policy) do
  [:name].each do |param|
    it "should have a #{param} parameter" do
      expect(Puppet::Type.type(:local_security_policy).attrtype(param)).to eq(:param)
    end
  end

  [:policy_type,:ensure, :ensure, :policy_setting, :policy_value].each do |param|
    it "should have an #{param} property" do
      expect(Puppet::Type.type(:local_security_policy).attrtype(param)).to eq(:property)
    end
  end

  describe 'test validation' do
    it 'can create a registry value' do
      resource = Puppet::Type.type(:local_security_policy).new(
          :name => 'Network access: Let Everyone permissions apply to anonymous users',
          :ensure => 'present',
          :policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous',
          :policy_type    => 'Registry Values',
          :policy_value   => '0')
      expect(resource[:policy_value]).to eq('4,0')
    end

    it 'raises an error with bad policy event audit value' do
      expect{
        Puppet::Type.type(:local_security_policy).new(
              :name => 'Audit account logon events',
              :ensure         => 'present',
              :policy_setting => "AuditAccountLogon",
              :policy_type    => "Event Audit",
              :policy_value   => 'xuccess,Failure',
          )}.to raise_error(Puppet::ResourceError)
    end
  end
end