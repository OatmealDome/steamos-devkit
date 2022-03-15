#!/bin/bash
# executed as root via interactive shell and sudo

set -u
set -e

if [ "${EUID}" -ne 0 ] ; then
  echo "Please run as root"
  exit -1
fi

# just a quick backup
set +e
ls -1 /var/lib/overlays/etc/upper/{passwd,group,gpasswd,shadow,gshadow} 2>/dev/null | xargs tar cvf /var/lib/overlays/etc/upper/dayone-backup.tar 2>/dev/null
set -e

rm -rf /var/lib/overlays/etc/upper/{passwd,group,gpasswd,shadow,gshadow}
mount -o remount /etc

echo
echo === Device is now ready for OS update, please proceed with OS update from the Deck interface ===
echo