require 'puppetlabs_spec_helper/module_spec_helper'
require 'rspec-puppet-utils'

def fixtures_path
    proj_root = File.expand_path(File.join(File.dirname(__FILE__), '..'))
    fixtures_path = File.join(proj_root, 'spec', 'fixtures')
end


# Uncomment this to show coverage report, also useful for debugging
#at_exit { RSpec::Puppet::Coverage.report! }

RSpec.configure do |c|
    c.formatter = 'documentation'
    c.mock_with :rspec
end
