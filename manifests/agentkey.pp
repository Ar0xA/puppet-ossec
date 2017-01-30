# utility function to fill up /var/ossec/etc/client.keys
define ossec::agentkey(
  $agent_name,
  $agent_ip_address,
  $agent_id = undef,
  $agent_key = undef
) {
  if $agent_id {
    if $agent_key {
      concat::fragment { "var_ossec_etc_client.keys_${agent_name}_part":
        target  => '/var/ossec/etc/client.keys',
        order   => $agent_id,
        content => "${agent_id} ${agent_name} ${agent_ip_address} ${agent_key}\n",
      }
    } else {
      fail('No value present for the ossec agent_key (ossec::agentkey::agent_key)')
    }
  } else {
    notify{ "ossec::agentkey: ${agent_id} is missing": }
  }
}
