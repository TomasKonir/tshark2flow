# tshark2flow

Simple tool for compute flow from pcap using qt library and tshark with no aim to be fast.  
  
Compilation: qmake;make  
  
Usage: tshark2flow config.json data.pcap ... output will be lines with flows (each single line is one json object, representing single flow/biflow)  
  
Field operations:  
* sum - get value as number and add ... val = old_val + new_val
* first - get and print first found value ... if (old_val is blank) val = new_val
* last - get and print last found value ... val = new_val
* array - add each different value and print as array if(array not contains new_val) array.add new_val
* or - do OR with value val = oldval | newval

Sample config:  
```
{  
    "queueLimit":100000, //maximum parallel flow  
    "queueInactiveInterval":30000, //inactive interval for flows  
    "optimize":true, //run tshark with only specified decoders  
    "pretty":false, //print pretty json  
    "printUnknown":true, //print unknown fields at program end  
    "ident" : [ //fields used as flow identifier  
        "eth_eth_type",  
        "ip_ip_proto",  
        "ip_ip_src",  
        "ip_ip_dst",  
        "ipv6_ipv6_next",  
        "ipv6_ipv6_src",  
        "ipv6_ipv6_dst",  
        "tcp_tcp_srcport",  
        "tcp_tcp_dstport",  
        "udp_udp_srcport",  
        "udp_udp_dstport"  
    ],  
    "fields" : { //fields used in output  
        "ip_ip_len":"sum",  
        "ip_ip_proto":"first",  
        "ip_ip_src":"first",  
        "ip_ip_dst":"first",  
        "ipv6_ipv6_plen":"sum",  
        "ipv6_ipv6_nxt":"first",  
        "ipv6_ipv6_src":"first",  
        "ipv6_ipv6_dst":"first",  
        "icmp_icmp_type":"array",  
        "icmp_icmp_code":"array",  
        "tcp_tcp_srcport":"first",  
        "tcp_tcp_dstport":"first",  
        "tcp_tcp_flags":"or",  
        "udp_udp_srcport":"first",  
        "udp_udp_dstport":"first",  
        "dns_dns_qry_name":"array",  
        "dns_dns_resp_name":"array",  
        "dns_dns_cname":"array",  
        "dns_dns_a":"array",  
        "http_http_request_uri":"array",  
        "http_http_host":"first"  
    },  
    "transform":{ //change field names to ...  
        "ip_ip_len":"bytes",  
        "ip_ip_proto":"ip_proto",  
        "ip_ip_src":"ip_src",  
        "ip_ip_dst":"ip_dst",  
        "ipv6_ipv6_plen":"bytes",  
        "ipv6_ipv6_next":"ipv6_next",  
        "ipv6_ipv6_src":"ipv6_src",  
        "ipv6_ipv6_dst":"ipv6_dst",  
        "icmp_icmp_type":"icmp_type",  
        "icmp_icmp_code":"icmp_code",  
        "tcp_tcp_srcport":"port_src",  
        "tcp_tcp_dstport":"port_dst",  
        "tcp_tcp_flags":"tcp_flags",  
        "udp_udp_srcport":"port_src",  
        "udp_udp_dstport":"port_dst",  
        "dns_dns_qry_name":"dns_qry_name",  
        "dns_dns_cname":"dns_cname",  
        "dns_dns_resp_name":"dns_resp_name",  
        "dns_dns_a":"dns_a",  
        "http_http_request_uri":"http_uri",  
        "http_http_host":"http_host"  
    },  
    "hexa":[ //fields with hexa output  
        "eth_eth_type",  
        "tcp_tcp_flags"  
    ],  
    "biflow" : { //biflow fields  
        "tests" : [ //check fields for biflow   
            ["ip_ip_src","ip_ip_dst"], 
            ["ipv6_ipv6_src","ipv6_ipv6_dst"]  
        ],  
        "flips" : [ //flip fields if biflow is detected  
            ["ip_ip_src","ip_ip_dst"],  
            ["ipv6_ipv6_src","ipv6_ipv6_dst"],  
            ["tcp_tcp_srcport","tcp_tcp_dstport"],  
            ["udp_udp_srcport","udp_udp_dstport"]  
        ],  
        "bi_fields" : [ //biflow dual fields  
            "ip_ip_len","ipv6_ipv6_plen","frame_frame_len","tcp_tcp_flags"  
        ]  
    },  
    "skip" : [ //skip this fields and don't report them at end as unknown  
        "_ws_expert" ,  
        "cflow_cflow_count" ,  
        "cflow_cflow_exporttime" ,  
        "cflow_cflow_flowset_id" ,  
        "cflow_cflow_flowset_length" ,  
        "cflow_cflow_len" ,  
        "cflow_cflow_od_id" ,  
        "cflow_cflow_sequence" ,  
        "cflow_cflow_source_id" ,  
        "cflow_cflow_sysuptime" ,  
        "cflow_cflow_timestamp" ,  
        "cflow_cflow_unix_secs" ,  
    ]  
}
```  
  
