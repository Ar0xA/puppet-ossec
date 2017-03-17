# Main ossec server config
class ossec::server (
  $mailserver_ip                       = undef,
  $ossec_emailto                       = undef,
  $ossec_emailfrom                     = "ossec@${::domain}",
  $ossec_active_response               = false,
  $ossec_global_host_information_level = 8,
  $ossec_global_stat_level             = 8,
  $ossec_email_alert_level             = 7,
  $ossec_ignorepaths                   = [],
  $ossec_scanpaths                     = [{ 'path' => '/etc,/usr/bin,/usr/sbin',
                                            'report_changes' => 'no',
                                            'realtime' => 'no'
                                          },
                                          { 'path' => '/bin,/sbin',
                                            'report_changes' => 'no',
                                            'realtime' => 'no'
                                          } ],
  $ossec_white_list                    = [],
  $ossec_emailnotification             = 'yes',
  $ossec_package_status                = 'installed',
  $ossec_database                      = false,
  $ossec_database_hostname             = undef,
  $ossec_database_name                 = undef,
  $ossec_database_password             = undef,
  $ossec_database_type                 = undef,
  $ossec_database_username             = undef,
  $ossec_enable_authd                  = false,
  $ossec_enable_zookeeper              = true,
  $ossec_log_to_json                   = false,
) {
  include ossec::common
  include mysql::client

  # install package
  case $::osfamily {
    'RedHat' : {
      if $ossec_database {
        package { $ossec::common::hidsmysqlpackage:
          ensure  => $ossec_package_status,
          require => Class['mysql::client'],
          notify  => Service[$ossec::common::hidsserverservice]
        }
      }
      package { 'ossec-hids':
        ensure   => $ossec_package_status,
      }
      package { $ossec::common::hidsserverpackage:
        ensure  => $ossec_package_status,
      }
    }
    default: {
      fail("Operating system not supported: ${::operatingsystem}")
    }
  }

  #we can only continue using redhat anyway
  service { $ossec::common::hidsserverservice:
    ensure    => running,
    enable    => true,
    hasstatus => $ossec::common::servicehasstatus,
    pattern   => $ossec::common::hidsserverservice,
    provider  => $ossec::common::serviceprovider, #workaround. See bug https://tickets.puppetlabs.com/browse/PUP-5296
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

  # Set log permissions properly to fix
  # https://github.com/djjudas21/puppet-ossec/issues/20
  #logrotate fix centos 7
  file { '/var/ossec/logs':
    ensure  => directory,
    #require => Package[$ossec::common::hidsagentpackage],
    owner   => 'ossec',
    group   => 'ossec',
    mode    => '0755',
    seltype => 'var_log_t',
  }

  # Fix up the logrotate file with sensible defaults
  file { '/etc/logrotate.d/ossec-hids':
    ensure => file,
    source => 'puppet:///modules/ossec/ossec-hids',
    #require => Package[$ossec::common::hidsagentpackage],
    owner  => 'root',
    group  => 'root',
    mode   => '0644',
  }

  #if using database
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
  #do we want to run authd?
  #TODO: use client signed certificates
  if $ossec_enable_authd {
    exec { 'make_authd_key_file':
      command => '/bin/openssl genrsa -out /var/ossec/etc/sslmanager.key 2048',
      unless  => '/bin/test -f /var/ossec/etc/sslmanager.key'
    } ->
    exec { 'make_authd_cert_file':
      command => "/bin/openssl req -new -x509 -key /var/ossec/etc/sslmanager.key -out /var/ossec/etc/sslmanager.cert -days 365 -subj \"/C=NL/ST=Utrecht/L=Utrecht/O=CMC/CN=${::domain}\"",
      unless  => '/bin/test -f /var/ossec/etc/sslmanager.cert'
    } ->
    service {'ossec-authd':
      ensure  => running,
      start   => '/var/ossec/bin/ossec-authd -p 1515 >/dev/null 2>&1 &',
      stop    => "/bin/kill $(/bin/ps aux | /bin/grep '/var/ossec/bin/ossec-authd' | /bin/awk '{print ${2}}')",
      pattern => '/var/ossec/bin/ossec-authd',
      require => Package[$ossec::common::hidsserverpackage],
    }
  }
  #TODO: rewrite to zookeeper data storage and fill on rerun?
  if $ossec::common::ossec_override_keyfile == false {
    #here we make the client.keys file with data from zookeeper

    concat { '/var/ossec/etc/client.keys':
      owner   => 'root',
      group   => 'ossec',
      mode    => '0640',
      notify  => Service[$ossec::common::hidsserverservice],
      require => Package[$ossec::common::hidsserverpackage],
    }
    #iterate through all data from zookeeper
    #get client info
    #generate client key
    #add key to file
    $ossec_server_ip = $::fqdn
    #TODO: check of alle keys er zijn
    $resultsetzk = zkget("/puppet/production/nodes/${ossec_server_ip}/client-keys",0,'children')
    $resultsetzk.each |String $peer| {
      $agent_ip_address = zkget("/puppet/production/nodes/${ossec_server_ip}/client-keys/${peer}/ip",1)[0]
      $agent_id = zkget("/puppet/production/nodes/${ossec_server_ip}/client-keys/${peer}/id",1)[0]
      $agent_key = zkget("/puppet/production/nodes/${ossec_server_ip}/client-keys/${peer}/key",1)[0]
      $agent_name= $peer
      ossec::agentkey{ "ossec_agent_${agent_name}_client":
        agent_id         => $agent_id,
        agent_name       => $agent_name,
        agent_ip_address => $agent_ip_address,
        agent_key        => $agent_key,
      }
    }
    concat::fragment { 'var_ossec_etc_client.keys_end' :
      target  => '/var/ossec/etc/client.keys',
      order   => 99,
      content => "\n",
      notify  => Service[$ossec::common::hidsserverservice]
    }
  } else {
    #TODO: ugly hack, cant we use agentkey function? or perhaps just let it fill with the agent registration and restart of the service then
    exec {'fill_client_key':
      command => '/bin/echo "127.0.0.1,default" > /var/ossec/dftagent &&  /var/ossec/bin/manage_agents -f /dftagent && rm -f /var/ossec/dftagent',
      onlyif  => '/bin/test -n `/bin/cat /var/ossec/etc/client.keys | /bin/grep 001`',
    }->
    file { '/var/ossec/etc/client.keys':
      ensure => 'file',
      owner  => 'root',
      group  => 'ossec',
      mode   => '0640',
      notify => Service[$ossec::common::hidsserverservice],
    }
  }
}
