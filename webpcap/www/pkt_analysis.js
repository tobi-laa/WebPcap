var ws = null;  
var conn_button = document.getElementById("connect");
var output = document.getElementById("otable");
var output_div = document.getElementById("output");

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


function bin2String(array) {
    return String.fromCharCode.apply(String, array);
}

function onWSMessage(msg) {
    var ll = new Ethh(msg.data, 0);
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
            nl = new IPv4h(msg.data, Ethh.HLEN);
            prot = "IPv4";
            src = IPv4h.printIP(nl.src);
            dst = IPv4h.printIP(nl.dst);
            
            // FIXME FIXME ugly!!!
            if(nl.prot == 6) { // TCP
                tr_class = "tcp";
                tl = new TCPh(msg.data, Ethh.HLEN + nl.getHeaderLength());
                prot = "TCP";
                info = tl;
                var buff = bin2String(new Uint8Array(msg.data, Ethh.HLEN + nl.getHeaderLength() + tl.getHeaderLength(), 16));
                if (tl.sport == 6600 || tl.dport == 6600) {
                    prot = "MPD";
                    info += buff;
                }
                else if(buff == "GET " || buff =="HTTP") {
                    prot = "HTTP";
                    tr_class = "http";
                }                
            }     
            else if(nl.prot == 17) { // UDP
                tr_class = "udp";
                tl = new UDPh(msg.data, Ethh.HLEN + nl.getHeaderLength());
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
            nl = new ARPh(msg.data, Ethh.HLEN);
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
        ws = new WebSocket("ws://sparrowprince.dyndns-remote.com:8080/binary");
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
    conn_button.innerHTML = '<img src="img/stop_cap.png" alt="Stop capture">';
}

function onWSClose() {
    ws = null;
    conn_button.setAttribute("title","Start a new live capture");
    conn_button.setAttribute("class","conn");
    conn_button.innerHTML = '<img src="img/start_cap.png" alt="Start capture">';
}