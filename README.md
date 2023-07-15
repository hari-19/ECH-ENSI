# ECH-ENSI
This project contains a script that would sniff the network and get following information for each flow.

1. Time
1. TLS version
1. SNI
1. Source IP address
1. Destination IP address
1. Source port
1. Destination Port
1. Protocol
1. Downloaded Data size (bytes)
1. TLS session duration (s)
1. Foreground/Background (WIP)
1. SSL Certificate information (WIP)
1. Flow ID (A unique identifier for each flow)

## Usage :

|Short      |Long           |   Description                                                                 |
|-          |-              |-                                                                              |
|-c         | --command     | Command a - Analyse, s - Sniff, b - Both                                      |
|-t         | --time        | Time to sniff in second                                                       |
|-sf        | --snifffile   | File Name of sniff file. Will be Placed inside ./Input_data/ directory        |
|-of        | --outputfile  | File Name of output file. Default is sni.csv. Inside ./Output_data directory  |
