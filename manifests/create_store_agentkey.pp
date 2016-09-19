define ossec::create_store_agentkey(
    $agent_name,
    $agent_ip_address,
    $ossec_server_ip,
) {
    include ossec::common
    
    if ($ossec::common::ossec_use_zookeeper) {

        include zk_puppet
        #does entry already exist? if so, why bother?

        $zkexist = zkget("${ossec::common::zookeeper_base_path}${ossec_server_ip}/client-keys/${agent_name}/id",1)
        if ($zkexist[0].empty) {

            $zkagent_num = zkget("${ossec::common::zookeeper_base_path}${ossec_server_ip}/client-num",1)

            #does not exist, so add it with value 1 (first agent)
            if ($zkagent_num[0].empty) {
                $zkagent_id = 1
            } else {
                $zkagent_id =$zkagent_num[0] + 1
            }


            #this info is used by both the client and master to generate the keys
            zkput("${ossec::common::zookeeper_base_path}${ossec_server_ip}/client-keys/${agent_name}/ip",$agent_ip_address)
            #so, whats our number then?
            zkput("${ossec::common::zookeeper_base_path}${ossec_server_ip}/client-keys/${agent_name}/id",$zkagent_id)
            zkput("${ossec::common::zookeeper_base_path}${ossec_server_ip}/client-num",$zkagent_id)

            if $zkagent_id {
                concat { '/var/ossec/etc/client.keys':
                  owner   => 'root',
                  group   => 'ossec',
                  mode    => '0640',
                  notify  => Service[$ossec::common::hidsagentservice],
                  require => Package[$ossec::common::hidsagentpackage]
                }
                ossec::agentkey{ "ossec_agent_${agent_name}_client":
                  agent_id         => $zkagent_id,
                  agent_name       => $agent_name,
                  agent_ip_address => $agent_ip_address,
                }
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
