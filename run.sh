
sudo cp ./* /p4app/
mkdir /tmp/p4app-logs



CURRENT=$(pwd)
sudo rm -r $CURRENT/logs/*
cd /home/whyalex/p4app/docker/scripts
sudo -s ./run.sh

sudo cp -r /tmp/p4app-logs/* $CURRENT/logs