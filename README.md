# networking-syn_flooding_and_detection
networking-syn_flooding_and_detection

setup VMs using docker compose file to create 4 machine Attacker, Vitcim, HostA, HostB

Do SYN flooding attack from attacker, HostA or HostB to victim using syn_flooding_attacker.py, syn_flooding_hostA.py or syn_flooding_hostB.py respectively (change IPs accordingly)

On victim machine use "tcpdump -i eth0" to capture TCP packets and see the attack happening.

For detection, on victim machine run syn_flooding_detection.py, it will create "traffic_analysis.log" file which will show if attack is happening or everthing is fine.
