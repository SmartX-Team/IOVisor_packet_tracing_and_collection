# Files for the IO Visor packet tracing and collection

## List of files

packet_tracing.c : Core program for IO Visor packet tracing

packet_tracing.py : Core program for IO Visor packet tracing

result.txt : Collected results of IO Visor packet tracing

list.txt : White-list of IP addresses (examples)

## Name of each NIC in each machine

Type S : eth0

Type C : ens2f0

Type O : eth0


## How to execute

Download packet_tracing.c, packet_tracing.py, result.txt, and list.txt (optional) in one folder.

Then use follwing command to execute it

$ sudo python packet_tracing.py



Result will be collected in "result.txt"


