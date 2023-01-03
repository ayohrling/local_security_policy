local_security_policy { 'Allow log on locally':
  ensure       => 'present',
  policy_value => 'Administrators, Users',
}

local_security_policy { 'Maximum password age':
  ensure       => 'present',
  policy_value => '90',
}
