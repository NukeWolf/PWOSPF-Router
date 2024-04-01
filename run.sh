
sudo cp ./* /p4app/
mkdir /tmp/p4app-logs

CURRENT=$(pwd)

cd /home/whyalex/p4app/docker/scripts
sudo -s ./run.sh

sudo rm -r $CURRENT/logs/*
sudo cp -r /tmp/p4app-logs/* $CURRENT/logs