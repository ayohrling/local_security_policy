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

end