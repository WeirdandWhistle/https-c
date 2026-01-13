set -e

sh compile.sh

openssl s_client -connect 192.168.2.65:2000 -keylogfile /home/wnj/keys.txt -trace >/dev/null &
./main

cat /home/wnj/keys.txt
rm /home/wnj/keys.txt
touch /home/wnj/keys.txt
