# Creates the keystore on the client used by the agent
define ossec::create_store_agentkey (
  $agent_use_hiera,
  $agent_name,
  $agent_ip_address,
  $ossec_server_ip,
  $agent_id = undef,
  $agent_key = undef,
) {
  if ($agent_use_hiera) {
    if $agent_id {
      concat { '/var/ossec/etc/client.keys':
        owner   => 'root',
        group   => 'ossec',
        mode    => '0640',
        notify  => Service[$ossec::common::hidsagentservice],
        require => Package[$ossec::common::hidsagentpackage]
      }
      ossec::agentkey{ "ossec_agent_${agent_name}_client":
        agent_id         => $agent_id,
        agent_name       => $agent_name,
        agent_ip_address => $agent_ip_address,
        agent_key        => $agent_key,
      }
    }
  } else {
    exec { 'agent-auth':
      command => "/var/ossec/bin/agent-auth -m ${ossec_server_ip} -A ${::fqdn} -D /var/ossec/",
      creates => '/var/ossec/etc/client.keys',
      require => Package[$ossec::common::hidsagentpackage]
    }
  }
}
