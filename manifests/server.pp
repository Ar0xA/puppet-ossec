# Main ossec server config
class ossec::server (
  $mailserver_ip                       = undef,
  $ossec_emailto                       = undef,
  $ossec_emailfrom                     = "ossec@${::domain}",
  $ossec_active_response               = true,
  $ossec_global_host_information_level = 8,
  $ossec_global_stat_level             = 8,
  $ossec_email_alert_level             = 7,
  $ossec_ignorepaths                   = [],
  $ossec_scanpaths                     = [ {'path' => '/etc,/usr/bin,/usr/sbin', 'report_changes' => 'no', 'realtime' => 'no'}, {'path' => '/bin,/sbin', 'report_changes' => 'no', 'realtime' => 'no'} ],
  $ossec_white_list                    = [],
  $ossec_emailnotification             = 'yes',
  $ossec_package_status                = 'installed',
  $ossec_database                      = false,
  $ossec_database_hostname             = undef,
  $ossec_database_name                 = undef,
  $ossec_database_password             = undef,
  $ossec_database_type                 = undef,
  $ossec_database_username             = undef,
) {
  include ossec::common
  include mysql::client

  # install package
  case $::osfamily {
    'Debian' : {
	  if  $ossec::common::ossec_use_own_repo == false {
          package { $ossec::common::hidsserverpackage:
            ensure  => $ossec_package_status,
            require => Apt::Source['alienvault-ossec'],
		  }
      } else {
	      package { $ossec::common::hidsserverpackage:
            ensure  => $ossec_package_status,
		  }
	  }
    }
    'RedHat' : {
      case $::operatingsystem {
        'CentOS', 'RedHat' : {
		  if  $ossec::common::ossec_use_own_repo == false {
              package { 'ossec-hids':
                ensure   => $ossec_package_status,
                require => Yumrepo['ossec']
              }
              package { $ossec::common::hidsserverpackage:
                ensure  => $ossec_package_status,
                require => [
                  Class['mysql::client'],
                      Yumrepo['ossec']
                ]
			  }
			  if $ossec_database {
                package { $ossec::common::hidsmysqlpackage:
                  ensure  => $ossec_package_status,
                  require => [
                    Class['mysql::client'],
                        Yumrepo['ossec']
                  ],
                  notify  => Service[$ossec::common::hidsserverservice]
				}
             }
           } else {
                  package { 'ossec-hids':
                    ensure   => $ossec_package_status,
                  }
                 package { $ossec::common::hidsserverpackage:
                   ensure  => $ossec_package_status,
                    require => [
                      Class['mysql::client'],
                    ]				  
			     }
				 if $ossec_database {
                    package { $ossec::common::hidsmysqlpackage:
                      ensure  => $ossec_package_status,
                      require => [
                        Class['mysql::client'],
                      ],
                      notify  => Service[$ossec::common::hidsserverservice]
                    }
                 }
		   }
		}

        default: {
          fail("Operating system not supported: ${::operatingsystem}")
        }
      }
    }
    default: { fail("OS family not supported: ${::osfamily}") }
  }

  service { $ossec::common::hidsserverservice:
    ensure    => running,
    enable    => true,
    hasstatus => $ossec::common::servicehasstatus,
    pattern   => $ossec::common::hidsserverservice,
    require   => Package[$ossec::common::hidsserverpackage],
  }

  # configure ossec process list
  concat { '/var/ossec/bin/.process_list':
    owner   => 'root',
    group   => 'ossec',
    mode    => '0440',
    require => Package[$ossec::common::hidsserverpackage],
    notify  => Service[$ossec::common::hidsserverservice]
  }
  concat::fragment { 'ossec_process_list_10' :
    target  => '/var/ossec/bin/.process_list',
    content => template('ossec/10_process_list.erb'),
    order   => 10,
    notify  => Service[$ossec::common::hidsserverservice]
  }

  # configure ossec
  concat { '/var/ossec/etc/ossec.conf':
    owner   => 'root',
    group   => 'ossec',
    mode    => '0440',
    require => Package[$ossec::common::hidsserverpackage],
    notify  => Service[$ossec::common::hidsserverservice]
  }
  concat::fragment { 'ossec.conf_10' :
    target  => '/var/ossec/etc/ossec.conf',
    content => template('ossec/10_ossec.conf.erb'),
    order   => 10,
    notify  => Service[$ossec::common::hidsserverservice]
  }

  if $ossec_database {
    validate_string($ossec_database_hostname)
    validate_string($ossec_database_name)
    validate_string($ossec_database_password)
    validate_string($ossec_database_type)
    validate_string($ossec_database_username)

    # Enable the database in the config
    concat::fragment { 'ossec.conf_80' :
      target  => '/var/ossec/etc/ossec.conf',
      content => template('ossec/80_ossec.conf.erb'),
      order   => 80,
      notify  => Service[$ossec::common::hidsserverservice]
    }

    # Enable the database daemon in the .process_list
    concat::fragment { 'ossec_process_list_20' :
      target  => '/var/ossec/bin/.process_list',
      content => template('ossec/20_process_list.erb'),
      order   => 20,
      notify  => Service[$ossec::common::hidsserverservice]
    }
  }

  concat::fragment { 'ossec.conf_90' :
    target  => '/var/ossec/etc/ossec.conf',
    content => template('ossec/90_ossec.conf.erb'),
    order   => 90,
    notify  => Service[$ossec::common::hidsserverservice]
  }
  
  if $ossec::common::ossec_override_keyfile == false {
      concat { '/var/ossec/etc/client.keys':
        owner   => 'root',
        group   => 'ossec',
        mode    => '0640',
        notify  => Service[$ossec::common::hidsserverservice],
        require => Package[$ossec::common::hidsserverpackage],
      }
      concat::fragment { 'var_ossec_etc_client.keys_end' :
        target  => '/var/ossec/etc/client.keys',
        order   => 99,
        content => "\n",
        notify  => Service[$ossec::common::hidsserverservice]
      }
      Ossec::Agentkey<<| |>>
  } else {
       exec {"fill_client_key":
        command => '/bin/echo "127.0.0.1,default" > /var/ossec/dftagent &&  /var/ossec/bin/manage_agents -f /dftagent',
         onlyif => "/bin/test -n `/bin/cat /var/ossec/etc/client.keys | /bin/grep 001`",
     }->
     file { '/var/ossec/client.key':
       ensure => 'present',
       notify  => Service[$ossec::common::hidsserverservice],
     }
  }

}
