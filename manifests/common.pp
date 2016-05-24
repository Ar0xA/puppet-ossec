# Package installation
class ossec::common ( $ossec_override_keyfile       = false, ) {
  case $::osfamily {
    'Redhat' : {
      $hidsagentservice  = 'ossec-hids'
      $hidsagentpackage  = 'ossec-hids-client'
      $hidsserverservice = 'ossec-hids'
      $hidsserverpackage = 'ossec-hids-server'
      $hidsmysqlpackage  = 'ossec-hids-mysql'
      $servicehasstatus  = true
      case $::operatingsystemrelease {
        /^5/:    {$redhatversion='el5'}
        /^6/:    {$redhatversion='el6'}
        /^7/:    {
          $redhatversion='el7'
          $serviceprovider = 'redhat' #workaround. See bug https://tickets.puppetlabs.com/browse/PUP-5296
        }
        default: { }
      }
      package { 'inotify-tools':
          ensure  => present,
      }
    }
#	  'windows' : {
#	    $hidsagentservice  = 'ossec-agent'
#      $hidsagentpackage  = 'ossec-hids-agent'
#	  }
    default: { fail('This ossec module has not been tested on your distribution') }
  }
}
