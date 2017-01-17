# Setup for ossec client
class ossec::client(
  $ossec_active_response   = false,
  $ossec_server_ip         = undef,
  $ossec_emailnotification = 'yes',
  $ossec_scanpaths         = [ {'path' => '/etc,/usr/bin,/usr/sbin', 'report_changes' => 'no', 'realtime' => 'no'}, {'path' => '/bin,/sbin', 'report_changes' => 'no', 'realtime' => 'no'} ],
  $ossec_client_ip         = $::ipaddress,
  $ossec_client_hostname   = $::fqdn,
  $ossec_package_status    = 'installed',
  $ossec_use_zookeeper     = true,
) {
  include ossec::common


  $client_ip = getvar($ossec_ip_fact)
  if ($ossec_server_ip == undef ) {
      fail('must pass either $ossec_server_ip Class[\'ossec::client\'].')
  }

  #Package install
  case $::osfamily {
    'RedHat' : {
        package { 'ossec-hids':
            ensure  => $ossec_package_status,
        }
        package { $ossec::common::hidsagentpackage:
            ensure  => $ossec_package_status,
            require => [
                Package['ossec-hids']
            ]
        }
    }
    'windows' : {

        file {
            'C:/ossec-agent-win32-2.8.3.exe':
            owner              => 'Administrators',
            group              => 'Administrators',
            mode               => '0774',
            source             => 'puppet:///modules/ossec/ossec-agent-win32-2.8.3.exe',
            source_permissions => ignore
        }

        package { $ossec::common::hidsagentservice:
            ensure          => installed,
            source          => 'C:/ossec-agent-win32-2.8.3.exe',
            install_options => [ '/S' ],  # Nullsoft installer silent installation
            require         => File['C:/ossec-agent-win32-2.8.3.exe'],
        }
    }

    default: { fail('OS family not supported') }
  }


  #Configuration
  if ($::osfamily == 'RedHat') {
    service { $ossec::common::hidsagentservice:
        ensure    => running,
        enable    => true,
        hasstatus => $ossec::common::servicehasstatus,
        pattern   => $ossec::common::hidsagentservice,
        provider  => $ossec::common::serviceprovider, #workaround. See bug https://tickets.puppetlabs.com/browse/PUP-5296
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

    ossec::create_store_agentkey{ "ossec_agent_${ossec_client_hostname}_client":
        agent_use_zookeeper => $ossec_use_zookeeper,
        agent_name          => $ossec_client_hostname,
        agent_ip_address    => $ossec_client_ip,
        ossec_server_ip     =>$ossec_server_ip,
    }


    # Set log permissions properly to fix
    # https://github.com/djjudas21/puppet-ossec/issues/20
    #logrotate fix centos 7
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
        source  => 'puppet:///modules/ossec/ossec-hids',
        require => Package[$ossec::common::hidsagentpackage],
        owner   => 'root',
        group   => 'root',
        mode    => '0644',
    }

  } elsif $::osfamily == 'windows' {
    service { 'OssecSvc':
      ensure    => running,
      enable    => true,
      pattern   => 'OssecSvc',
      hasstatus => true,
      require   => Package[$ossec::common::hidsagentservice],
    }
    concat { 'C:/Program Files (x86)/ossec-agent/ossec.conf':
      owner   => 'Administrator',
      group   => 'Administrators',
      mode    => '0440',
      notify  => Service['OssecSvc'],
      require => Package[$ossec::common::hidsagentservice],
    }
    concat::fragment { 'ossec.conf_10' :
      target  => 'C:/Program Files (x86)/ossec-agent/ossec.conf',
      content => template('ossec/10_ossec_agent.conf.erb'),
      order   => 10,
      notify  => Service['OssecSvc'],
    }
    concat::fragment { 'ossec.conf_99' :
      target  => 'C:/Program Files (x86)/ossec-agent/ossec.conf',
      content => template('ossec/99_ossec_agent.conf.erb'),
      order   => 99,
      notify  => Service['OssecSvc'],
    }
    ossec::create_store_agentkey{ "ossec_agent_${ossec_client_hostname}_client":
      agent_use_zookeeper => $ossec_use_zookeeper,
      agent_name          => $ossec_client_hostname,
      agent_ip_address    => $ossec_client_ip,
      ossec_server_ip     =>$ossec_server_ip,
    }

  } else {
      fail('OS family not supported')
  }
}
