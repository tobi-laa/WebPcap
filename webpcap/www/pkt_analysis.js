var ws = null;  
var conn_button = document.getElementById("connect");
var output = document.getElementById("otable");
var output_div = document.getElementById("output");
var pcap_file = document.getElementById("pcap_file");

// 24 bytes for the global pcap header
var pcap_global_header = new ArrayBuffer(24);
// we need to fill it with integers and shorts
var shortView = new Uint16Array(pcap_global_header);
var intView   = new Uint32Array(pcap_global_header);

intView[0]   = 0xa1b2c3d4; // magic number
shortView[2] = 2;
shortView[3] = 4;
intView[2] = 0;
intView[3] = 0;
intView[4] = 65535; // snaplen
intView[5] = 1; // Ethernet

var cache = "data:application/x-download;base64,"+base64ArrayBuffer(pcap_global_header);

var counter = 0;

function ntohl(num) {
    return ((num >> 24) & 0x000000FF) |
           ((num >> 16) & 0x0000FF00) |
           ((num >>  8) & 0x00FF0000) |
           ((num >>  0) & 0xFF000000);
}

function ntohs(num) {
    return ((num >>  8) & 0x00FF) |
           ((num <<  8) & 0xFF00);
}

function saveCapture() {
    var link = document.createElement("a");
    link.download = "log.pcap";
    link.href = cache;
    link.click();
}

function onWSMessage(msg) {
    // append to cache
    cache += base64ArrayBuffer(msg.data);
    
    var offset = 0;
    var ph = new Pcaph(msg.data, offset);
    offset += Pcaph.HLEN;
    var ll = new Ethh(msg.data, offset);
    offset += Ethh.HLEN;
    var nl;
    var tl;
    var tr_class = "eth";
    
    var prot = "Ethernet";
    var src, dst, info;
    src = Ethh.printMAC(ll.src);
    dst = Ethh.printMAC(ll.dst);
    
    switch(ll.prot) {
        case 0x0800:
            tr_class = "ipv4";
            nl = new IPv4h(msg.data, offset);
            offset += nl.getHeaderLength();
            prot = "IPv4";
            src = IPv4h.printIP(nl.src);
            dst = IPv4h.printIP(nl.dst);
            
            // FIXME FIXME ugly!!!
            if(nl.prot == 6) { // TCP
                tr_class = "tcp";
                tl = new TCPh(msg.data, offset);
                offset += tl.getHeaderLength();
                prot = "TCP";
                info = tl;
/*                if (offset < ph.incl_len) {
                    var buff = new Uint8Array(msg.data, offset);
                    buff = String.fromCharCode.apply(String, buff);
                    info += buff;
                }
                if (tl.sport == 6600 || tl.dport == 6600) {
                    prot = "MPD";
                    info += buff;
                }
                else if(buff == "GET " || buff =="HTTP") {
                    prot = "HTTP";
                    tr_class = "http";
                }            */    
            }     
            else if(nl.prot == 17) { // UDP
                tr_class = "udp";
                tl = new UDPh(msg.data, offset);
                prot = "UDP";
                info = tl;
            }
            else if(nl.prot == 1) { // ICMP
                tr_class = "icmp";
                prot = "ICMP";
                info = tl;
            }
            break;
        case 0x86DD:
            prot = "IPv6";
            break;
        case 0x0806:            
            tr_class = "arp";
            nl = new ARPh(msg.data, offset);
            prot = "ARP";
            info = nl;
            break;
        case 0x8035:
            prot = "RARP";
            break;
         default:
             info = "Unknown Ethtype "+ll.prot.toString(16);
             break;
    }  

    var row = document.createElement("tr");
    row.setAttribute("class",tr_class);
    row.innerHTML = "<td>"+src+"</td>"+
                    "<td>"+dst+"</td>"+
                    "<td>"+prot+"</td>"+
                    "<td>"+info+"</td>";
                
    output.appendChild(row);
    output_div.scrollTop = output_div.scrollHeight;
}       

function clearOutputTable() {
    output.innerHTML = '<colgroup><col width="400"><col width="400"><col width="100"><col width="800"></colgroup>';
}

function switchConnection() {
    if(ws == null) {
        ws = new WebSocket("ws://sparrowprince.chickenkiller.com:8080/binary");
        ws.binaryType = "arraybuffer";
        ws.onopen = onWSOpen;
        ws.onclose = onWSClose;
        ws.onmessage = onWSMessage;        
    }
    else
        ws.close();         
}

function onWSOpen() {
    conn_button.setAttribute("title","Stop the running live capture");
    conn_button.setAttribute("class","disconn");
    ws.send("none\0");
}

function onWSClose() {
    ws = null;
    conn_button.setAttribute("title","Start a new live capture");
    conn_button.setAttribute("class","conn");
}