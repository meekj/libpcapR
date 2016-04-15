# libpcapR
R interface to libpcap packet capture files

Load packet header data directly into a data frame

To install: 

 library(devtools)
 devtools::install_github("meekj/libpcapR")

Test:

 File <- '/data/iperf/20100916/t2-192.168.1.1-snd.tcpd'
 pkt_df <- read_pcap(File, '')

With filter:

 pkt_df <- read_pcap(File, 'dst port 3000')

This is an alpha release, more documentation and tests coming...
