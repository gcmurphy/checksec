checksec
========

This is a port of the checksec.sh script from coredump.cx 
to Go. It ain't pretty but works ok. I wrote this because 
readelf doesn't seem to like receiving binary files via 
stdin. Without this it would mean that I have to install 
every single package of Fedora for example to extract the 
binary hardening information. (Use with script + *.iso 
or reposync).


