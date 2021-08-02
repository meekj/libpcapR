# libpcapR
R interface to libpcap packet capture files

Load packet header data directly into a data frame

This has been tested on Linux and MacOS. libpcap-dev (Debian, Ubuntu), or equivalent, is required

To install: 

    library(devtools)
 
    devtools::install_github("meekj/libpcapR")
 
Alternatively:

    Sys.setenv(PKG_LIBS = '-lpcap') # Required
	
    Sys.setenv(CC = 'clang')        # Optionally set
    Sys.setenv(CXX = 'clang++')     # compilers

    library(devtools)
    library(Rcpp)

    sourceCpp('/path/to/libpcapR/src/libpcap.cpp', rebuild = TRUE)


Test:

 Capture some traffic

    : rz9:~/tcpd ; sudo tcpdump -i enp4s0 -s 256 -w audio-stream-1.tcpd

 Look at the traffic

    tcpdFile <- '/home/meekj/tcpd/audio-stream-1.tcpd' # Full path is required

    pkt_df <- read_pcap(tcpdFile, '')

    str(pkt_df)
    'data.frame':   4930 obs. of  17 variables:
    $ Time         : num  1.63e+09 1.63e+09 1.63e+09 1.63e+09 1.63e+09 ...
    $ SrcMAC       : chr  "e8:f7:24:27:b:53" "e8:f7:24:27:b:53" "e8:f7:24:27:b:53" "18:c0:4d:6:43:aa" ...
    $ DstMAC       : chr  "1:80:c2:0:0:0" "1:80:c2:0:0:0" "1:80:c2:0:0:0" "64:d1:54:19:d5:97" ...
    $ Protocol     : chr  "802.3" "802.3" "802.3" "UDP" ...
    $ SrcAddr      : chr  "" "" "" "192.168.15.49" ...
    $ SrcPort      : int  0 0 0 40276 34588 53 50454 53 56006 53 ...
    $ DstAddr      : chr  "" "" "" "8.8.4.4" ...
    $ DstPort      : int  0 0 0 53 53 34588 53 50454 53 40276 ...
    $ IPid         : int  0 0 0 33072 33073 3063 33074 5842 33080 39445 ...
    $ FrameLength  : int  60 60 60 84 84 229 89 206 93 172 ...
    $ TCPflags     : chr  "" "" "" "" ...
    $ TCPseq       : num  0 0 0 0 0 0 0 0 0 0 ...
    $ TCPack       : num  0 0 0 0 0 0 0 0 0 0 ...
    $ PayloadLength: int  0 0 0 42 42 187 47 164 51 130 ...
    $ TOS          : int  0 0 0 0 0 0 0 0 0 0 ...
    $ TTL          : int  0 0 0 64 64 122 64 123 64 123 ...
    $ Payload      : chr  "" "" "" "\x8c\023\001" ...

    pkt_df %>% group_by(SrcAddr, Protocol) %>% summarise(Packets = n())

    # A tibble: 40 x 3
    # Groups:   SrcAddr [36]
    SrcAddr           Protocol Packets
    <chr>            <chr>      <int>
     1 ""                802.3        151
     2 ""                ARP           68
     3 ""                UNK           15
     4 "104.17.113.66"   TCP           10
     5 "104.244.42.130"  TCP           23
     6 "104.244.42.193"  TCP           19
     7 "104.72.3.21"     TCP            9
     8 "140.82.113.26"   TCP           15
     9 "142.250.188.195" UDP           20
    10 "142.250.188.35"  UDP            7
    # … with 30 more rows

    ## We care only about TCP & UDP, so re-read with a filter

    pkt_df <- read_pcap(tcpdFile, 'tcp or udp')

    pkt_df %>% group_by(SrcAddr, Protocol) %>% summarise(Packets = n())

    # A tibble: 37 x 3
    # Groups:   SrcAddr [35]
    SrcAddr         Protocol Packets
    <chr>           <chr>      <int>
     1 104.17.113.66   TCP           10
     2 104.244.42.130  TCP           23
     3 104.244.42.193  TCP           19
     4 104.72.3.21     TCP            9
     5 140.82.113.26   TCP           15
     6 142.250.188.195 UDP           20
     7 142.250.188.35  UDP            7
     8 142.250.188.42  UDP           15
     9 142.250.65.67   UDP           14
    10 148.168.32.77   TCP           29
    # … with 27 more rows

    clientIPaddress <- '192.168.5.49'

    pkt_df %>% filter(SrcAddr != clientIPaddress)  %>% group_by(SrcAddr, Protocol) %>%
         summarise(Packets = n(), bytesIn = sum(FrameLength)) %>% arrange(desc(bytesIn))

    # A tibble: 35 x 4
    # Groups:   SrcAddr [34]
    SrcAddr         Protocol Packets bytesIn
    <chr>           <chr>      <int>   <int>
     1 50.31.140.12    TCP         1798 3669756
     2 54.205.206.74   TCP           40   31334
     3 172.217.2.110   UDP           27   10545
     4 172.217.164.170 UDP           24    9742
     5 148.168.32.77   TCP           29    8398
     6 172.217.164.142 UDP           17    7642
     7 162.144.114.31  TCP           12    7441
     8 172.217.2.106   UDP            8    6141
     9 142.250.188.42  UDP           15    6041
    10 142.250.65.67   UDP           14    5798
    # … with 25 more rows

