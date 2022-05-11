# tshark2flow

Simple tool for compute flow from pcap using qt library and tshark with no aim to be fast.  
skip fields was taken from tshark using: 'tshark -G | cut -f3 | sort'
  
Compilation: qmake;make  
  
Usage: tshark2flow config.json data.pcap ... output will be lines with flows (each single line is one json object, representing single flow/biflow)  
  
Field operations:  
* sum - get value as number and add ... val = old_val + new_val
* first - get and print first found value ... if (old_val is blank) val = new_val
* last - get and print last found value ... val = new_val
* array - add each different value and print as array if(array not contains new_val) array.add new_val
* or - do OR with value val = oldval | newval

Sample config:  
```json
{  
    "queueLimit":100000, //maximum parallel flow  
    "queueInactiveInterval":30000, //inactive interval for flows in ms
    "queueActiveInterval":30000, //active interval for flows in ms (max flow duration)
    "pretty":false, //print pretty json  
    "printUnknown":true, //print unknown fields at program end  
    "ident" : [ //fields used as flow identifier  
        "eth.type",
        "ip.proto",
        "ip.src",
        "ip.dst",
        "ipv6.next",
        "ipv6.src",
        "ipv6.dst",
        "tcp.srcport",
        "tcp.dstport",
        "udp.srcport",
        "udp.dstport"
    ],  
    "fields" : { //fields used in output  
        "ip.len":"sum",
        "ip.proto":"first",
        "ip.src":"first",
        "ip.dst":"first",
        "ipv6.plen":"sum",
        "ipv6.nxt":"first",
        "ipv6.src":"first",
        "ipv6.dst":"first",
        "icmp.type":"array",
        "icmp.code":"array",
        "tcp.srcport":"first",
        "tcp.dstport":"first",
        "tcp.flags":"or",
        "udp.srcport":"first",
        "udp.dstport":"first",
        "dns.qry.name":"array",
        "dns.resp.name":"array",
        "dns.cname":"array",
        "dns.a":"array",
        "http.request.uri":"array",
        "http.host":"first"
    },  
    "transform":{ //change field names to ...  
        "ip.len":"bytes",
        "ip.proto":"ip.proto",
        "ip.src":"ip.src",
        "ip.dst":"ip.dst",
        "ipv6.plen":"bytes",
        "ipv6.next":"ipv6.next",
        "ipv6.src":"ipv6.src",
        "ipv6.dst":"ipv6.dst",
        "icmp.type":"icmp.type",
        "icmp.code":"icmp.code",
        "tcp.srcport":"port.src",
        "tcp.dstport":"port.dst",
        "tcp.flags":"tcp.flags",
        "udp.srcport":"port.src",
        "udp.dstport":"port.dst",
        "dns.qry.name":"dns.qry.name",
        "dns.cname":"dns.cname",
        "dns.resp.name":"dns.resp.name",
        "dns.a":"dns.a",
        "http.request.uri":"http.uri",
        "http.host":"http.host"
    },  
    "hexa":[ //fields with hexa output  
        "eth.type",
        "tcp.flags"
    ],  
    "biflow" : { //biflow fields  
        "tests" : [ //check fields for biflow   
            ["ip.src","ip.dst"],
            ["ipv6.src","ipv6.dst"]
        ],  
        "flips" : [ //flip fields if biflow is detected  
            ["ip.src","ip.dst"],
            ["ipv6.src","ipv6.dst"],
            ["tcp.srcport","tcp.dstport"],
            ["udp.srcport","udp.dstport"]
        ],  
        "bi_fields" : [ //biflow dual fields  
            "ip.len","ipv6.plen","frame.len","tcp.flags"
         ]  
    },  
    "skip" : [ //skip this fields and don't report them at end as unknown  
        "timestamp",
        "29west",
        "2dparityfec",
        "2dparityfec.d",
        "2dparityfec.e",
        "2dparityfec.index",
        "2dparityfec.lr",
        "2dparityfec.mask",
        "2dparityfec.na",
        "2dparityfec.offset",
        "2dparityfec.payload",
        "2dparityfec.ptr",
        "2dparityfec.snbase_ext",
        "2dparityfec.snbase_low",
        "2dparityfec.tsr",
        "2dparityfec.type",
        "2dparityfec.x",
        "3comxns",
        "3comxns.type",
        "3gpp",
        "3gpp.tmsi",
        "5gli",
        "6lowpan",
        "6lowpan.6loRH.bitF",
        "6lowpan.6loRH.bitI",
        "6lowpan.6loRH.bitK",
        "6lowpan.6loRH.bitO",
        "6lowpan.6loRH.bitR",
        "6lowpan.bad_ext_header_length",
        "6lowpan.bad_ipv6_header_length",
        "6lowpan.bcast.seqnum",
        "6lowpan.bitmap",
        "6lowpan.class",
        "6lowpan.dscp",
        "6lowpan.dst",
        "6lowpan.ecn",
        "6lowpan.flow",
        "..."
    ]  
}
```  
  
