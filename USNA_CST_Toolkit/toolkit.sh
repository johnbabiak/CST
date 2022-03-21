#!/bin/bash
# toolkit.sh
# United States Naval Academy Cyber Security Team Common Toolkit
# install script for tools commonly used by the team in practice and competition

#make sure system is up to date, this step may take a while
sudo apt update
sudo apt full-upgrade

#create toolkit directory
mkdir ~/USNA_CST_Toolkit
mv ../resource.zip ~/USNA_CST_Toolkit
cd ~/USNA_CST_Toolkit
unzip resource.zip

#set up key for MongoDB install
wget -qO - https://www.mongodb.org/static/pgp/server-5.0.asc | sudo apt-key add -
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/5.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-5.0.list
sudo apt-get update

#install following from apt:
# pip
# nmap
# dirb
# tcpdump
# sqlmap
# mongodb
# sqlite3
# johntheripper
# hashcat
# aircrack-ng
# nasm
# openjdk-11-jdk
# wireshark
# tshark
# scalpel
# binwalk
# hashdeep
# exiftool
# toilet
# lolcat
sudo apt -y install python3-pip nmap dirb tcpdump sqlmap mongodb-org sqlite3 john p7zip aircrack-ng nasm openjdk-11-jdk wireshark tshark scalpel binwalk hashdeep exiftool toilet lolcat

#set up anna generator
chmod 700 USNA_CST_Toolkit_src/anna_generator
chmod 755 USNA_CST_Toolkit_src/g_words.txt
sudo mv USNA_CST_Toolkit_src/anna_generator /usr/bin
sudo mv USNA_CST_Toolkit_src/g_words.txt /usr/bin

#fix mongodb permissions
chown -R mongodb:mongodb /var/lib/mongodb
chown mongodb:mongodb /tmp/mongodb-27017.sock

#start burpsuite installer
chmod 755 USNA_CST_Toolkit_src/burpsuite_community_linux_v2022_1_1.sh
./USNA_CST_Toolkit_src/burpsuite_community_linux_v2022_1_1.sh

#RSACtfTool
git clone https://github.com/Ganapati/RsaCtfTool.git

#Ghidra
git clone https://github.com/NationalSecurityAgency/ghidra.git

#pwndbg
git clone https://github.com/pwndbg/pwndbg
./pwndbg/setup.sh

#ciphey
python3 -m pip install ciphey --upgrade

#metasploit
sudo apt-get install -y curl gpgv2 autoconf bison build-essential git-corelibapr1 postgresql libaprutil1 libcurl4openssl-dev libgmp3-dev libpcap-dev openssl libpq-dev libreadline6-dev libsqlite3-dev libssl-dev locate libsvn1 libtool libxml2 libxml2-dev libxslt-dev wget libyaml-dev ncurses-dev  postgresql-contrib xsel zlib1g zlib1g-dev

curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall

chmod 755 msfinstall

./msfinstall

sudo service postgresql start

#pwntools
python3 -m pip install --upgrade pwntools

#ROPGadget
python3 -m pip install --upgrade ROPGadget

#angr
virtualenv --python=$(which python3) angr && python -m pip install angr

#ropper
sudo pip install capstone
sudo pip install filebytes
sudo pip install keystone-engine
sudo pip install ropper

# Handle the aliases
file=~/.zshrc
if [[ -f "$file" ]]
then
	echo 'alias RsaCtfTool="python3 ~/USNA_CST_Toolkit/RsaCtfTool/RsaCtfTool.py"' >> ~/.zshrc
	echo 'alias ciphey="python -m ciphey"' >> ~/.zshrc
	echo 'alias ghidra="~/USNA_CST_Toolkit/ghidra_10.1.2_PUBLIC/ghidraRun"' >> ~/.zshrc
else
	echo 'alias RsaCtfTool="python3 ~/USNA_CST_Toolkit/RsaCtfTool/RsaCtfTool.py"' >> ~/.bashrc
	echo 'alias ciphey="python -m ciphey"' >> ~/.bashrc
	echo 'alias ghidra="~/USNA_CST_Toolkit/ghidra_10.1.2_PUBLIC/ghidraRun"' >> ~/.bashrc
fi
sleep 5

