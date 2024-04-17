
sudo cp ./* /p4app/
rm -f /tmp/p4app-logs/*
mkdir /tmp/p4app-logs

# Clear IP LINKS
ip link | grep -P 's\d+-eth\d+' -o | while read line ; do sudo ip link delete $line ; done


CURRENT=$(pwd)
sudo rm -r $CURRENT/logs/*
cd /home/whyalex/p4app/docker/scripts
sudo -s ./run.sh

sudo cp -r /tmp/p4app-logs/* $CURRENT/logs

