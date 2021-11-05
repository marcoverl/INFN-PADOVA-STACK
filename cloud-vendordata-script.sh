#!/bin/bash
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export instance_id="`cat /var/lib/cloud/data/instance-id`"
export SSH_CONFIG=/etc/ssh/sshd_config
export CIPHERS="Ciphers aes128-ctr,aes128-gcm@openssh.com,aes192-ctr,aes256-ctr,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com"
export KEX="KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1"

logger "Vendor data: configure sshd"

if [ -e /etc/redhat-release ] && ! grep -q "6\." /etc/redhat-release ;
then
  export LINUX_DISTRIBUTION=RedHat
else
  export LINUX_DISTRIBUTION=`lsb_release -si`
fi

case $LINUX_DISTRIBUTION in
     Ubuntu|Debian)
          logger "Vendor data injected on $LINUX_DISTRIBUTION host"
          ;;
     Scientific)
          ;;
     RedHat)
          # Disable weak ssh ciphers on RedHat systems and restart ssh if needed
          if ! grep -q "${CIPHERS}" ${SSH_CONFIG}
          then
              sed -i 's/^Ciphers/#Ciphers/' ${SSH_CONFIG}
              echo "${CIPHERS}" >> ${SSH_CONFIG}
              echo "" >> ${SSH_CONFIG}
              pidof sshd && service sshd restart
          fi
          if ! grep -q "${KEX}" ${SSH_CONFIG}
          then
              sed -i 's/^KexAlgorithms/#KexAlgorithms/' ${SSH_CONFIG}
              echo "${KEK}" >> ${SSH_CONFIG}
              echo "" >> ${SSH_CONFIG}
              pidof sshd && service sshd restart
          fi
          
          logger "Vendor data injected on $LINUX_DISTRIBUTION host"
          ;;
     *)
          logger "$LINUX_DISTRIBUTION not managed by this script"
          ;;
esac
