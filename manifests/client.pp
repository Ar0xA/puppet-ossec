# Setup for ossec client
class ossec::client(
  $ossec_active_response   = true,
  $ossec_server_ip         = undef,
  $ossec_emailnotification = 'yes',
  $ossec_scanpaths         = [ {'path' => '/etc,/usr/bin,/usr/sbin', 'report_changes' => 'no', 'realtime' => 'no'}, {'path' => '/bin,/sbin', 'report_changes' => 'no', 'realtime' => 'no'} ],
  $ossec_ip_fact           = '::ipaddress',
  $ossec_package_status    = 'installed',
) {
  include ossec::common

  $client_ip = getvar($ossec_ip_fact)

  case $::osfamily {
    'Debian' : {
	  if $ossec::common::ossec_use_own_repo == false {
          package { $ossec::common::hidsagentpackage:
            ensure  => $ossec_package_status,
                require => Apt::Source['alienvault-ossec'],
		  }
      } else {
	      package { $ossec::common::hidsagentpackage:
            ensure  => $ossec_package_status,
		  }
	  }
    }
	
    'RedHat' : {
	  if $ossec::common::ossec_use_own_repo == false {
          package { $ossec::common::hidsagentpackage:
            ensure  => $ossec_package_status,
                require => Yumrepo['ossec'],
		  }
		  package { $ossec::common::hidsagentpackage:
            ensure  => $ossec_package_status,
              require => [
                Yumrepo['ossec'],
                Package['ossec-hids']
              ]
          }
      } else {
          package { $ossec::common::hidsagentpackage:
            ensure  => $ossec_package_status,
		  }
		  package { $ossec::common::hidsagentpackage:
            ensure  => $ossec_package_status,
              require => [
                Package['ossec-hids']
              ]
          }	  
	  }
	}
	'windows' : {
	    package {$ossec::common::hidsagentpackage:
		    ensure  => $ossec_package_status,
		    provider => 'chocolatey',
			require => Package['ossec-agent'],
		}
	}

    default: { fail('OS family not supported') }
  }

  if $::osfamily == ('Debian'|'RedHat') {
	  service { $ossec::common::hidsagentservice:
		ensure    => running,
		enable    => true,
		hasstatus => $ossec::common::servicehasstatus,
		pattern   => $ossec::common::hidsagentservice,
		require   => Package[$ossec::common::hidsagentpackage],
	  }

	  concat { '/var/ossec/etc/ossec.conf':
		owner   => 'root',
		group   => 'ossec',
		mode    => '0440',
		require => Package[$ossec::common::hidsagentpackage],
		notify  => Service[$ossec::common::hidsagentservice]
	  }
	  concat::fragment { 'ossec.conf_10' :
		target  => '/var/ossec/etc/ossec.conf',
		content => template('ossec/10_ossec_agent.conf.erb'),
		order   => 10,
		notify  => Service[$ossec::common::hidsagentservice]
	  }
	  concat::fragment { 'ossec.conf_99' :
		target  => '/var/ossec/etc/ossec.conf',
		content => template('ossec/99_ossec_agent.conf.erb'),
		order   => 99,
		notify  => Service[$ossec::common::hidsagentservice]
	  }

	  if $::uniqueid {
		concat { '/var/ossec/etc/client.keys':
		  owner   => 'root',
		  group   => 'ossec',
		  mode    => '0640',
		  notify  => Service[$ossec::common::hidsagentservice],
		  require => Package[$ossec::common::hidsagentpackage]
		}
		ossec::agentkey{ "ossec_agent_${::fqdn}_client":
		  agent_id         => $::uniqueid,
		  agent_name       => $::fqdn,
		  agent_ip_address => $client_ip,
		}
		@@ossec::agentkey{ "ossec_agent_${::fqdn}_server":
		  agent_id         => $::uniqueid,
		  agent_name       => $::fqdn,
		  agent_ip_address => $client_ip
		}
	  } else {
		exec { 'agent-auth':
		  command => "/var/ossec/bin/agent-auth -m ${ossec_server_ip} -A ${::fqdn} -D /var/ossec/",
		  creates => '/var/ossec/etc/client.keys',
		  require => Package[$ossec::common::hidsagentpackage]
		}
	  }

	  # Set log permissions properly to fix
	  # https://github.com/djjudas21/puppet-ossec/issues/20
	  file { '/var/ossec/logs':
		ensure  => directory,
		require => Package[$ossec::common::hidsagentpackage],
		owner   => 'ossec',
		group   => 'ossec',
		mode    => '0755',
		seltype => 'var_log_t',
	  }

	  # Fix up the logrotate file with sensible defaults
		file { '/etc/logrotate.d/ossec-hids':
		ensure  => file,
		source => 'puppet:///modules/ossec/ossec-hids',
		require => Package[$ossec::common::hidsagentpackage],
		owner   => 'root',
		group   => 'root',
		mode    => '0644',
	  }
  } elsif $::osfamily == 'windows' {
  #TODO
  } else {
      fail('OS family not supported')
  }
}

