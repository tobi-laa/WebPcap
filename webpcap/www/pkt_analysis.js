var ws_url = "ws://"+window.location.host+"/binary";
var ws = null;  
var conn_button = document.getElementById("connect");
var output = document.getElementById("output");
var otable = document.getElementById("otable");
var payload_div = document.getElementById("payload");
var details_div = document.getElementById("details");
var counter = 1;
var oldPacket = null;
var selectedRow = null;
var packets = new Array();
var rawPackets = new Array();
var months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];

function ntohl(num) {
    return ((num & 0x000000FF) >>> 0) |
           ((num & 0x0000FF00) >>> 8) |
           ((num & 0x00FF0000) >>> 16) |
           ((num & 0xFF000000) >>> 24);
}

function ntohs(num) {
    return ((num >>  8) & 0x00FF) |
           ((num <<  8) & 0xFF00);
}

function onWSMessage(msg) {    
    appendToDataUrl(msg.data);
    
    dissect(msg.data);
}   

function dissect(packet) {
    if (oldPacket != null) {
        packet = appendBuffer(oldPacket, packet);
        oldPacket = null;
    }
    if (packet.byteLength < 16) { // i.e. not enough for pcap header
        oldPacket = packet;
        return;
    }
    
    var ph = new Pcaph(packet, 0);
    packets[counter] = ph;
    rawPackets[counter] = packet.slice(0, ph.incl_len + 16);
    
    if (packet.byteLength < (ph.incl_len + 16)) { // i.e. packet not complete
        oldPacket = packet;
        return;
    }
    
    infos = new Array();
    ph.next_header = dissectLinkLayer(packet, Pcaph.HLEN, infos);    

    var row = document.createElement("div");
    row.setAttribute("class","row "+infos[2]);
    row.setAttribute("onclick","processClick(this, "+counter+")");
    row.innerHTML = '<div class="col 10p">'+(counter++)+"</div>"+
                    '<div class="col 30p">'+infos[0]+"</div>"+
                    '<div class="col 30p">'+infos[1]+"</div>"+
                    '<div class="col 10p">'+infos[3]+"</div>"+
                    '<div class="col 10p">'+ph.orig_len+"</div>";
                
    otable.appendChild(row);
    output.scrollTop = output.scrollHeight;
    
    if (packet.byteLength > (ph.incl_len + 16) && ph.incl_len > 0)
        dissect(packet.slice(ph.incl_len + 16));
}

function dissectLinkLayer(packet, offset, infos) {
    // FIXME probably should be variable
    var toReturn = new Ethh(packet, offset);   
    
    infos[0] = Ethh.printMAC(toReturn.src);
    infos[1] = Ethh.printMAC(toReturn.dst);
    infos[2] = "eth";
    infos[3] = "Ethernet";
    infos[4] = toReturn.toString();
    
    toReturn.next_header = dissectNetworkLayer(packet, offset + Ethh.HLEN, toReturn.prot, infos);
    
    return toReturn;
}

function dissectNetworkLayer(packet, offset, prot, infos) {
    var toReturn;
    switch(prot) {
        case 0x0800: // IPv4
            toReturn = new IPv4h(packet, offset);
            
            infos[0] = IPv4h.printIP(toReturn.src);
            infos[1] = IPv4h.printIP(toReturn.dst);
            infos[2] = "ipv4";
            infos[3] = "IPv4";
            infos[4] = toReturn.toString();
            
            toReturn.next_header = dissectTransportLayer(packet, offset + toReturn.getHeaderLength(), toReturn.prot, infos);
               
            break;
        case 0x86DD: // IPv6
            toReturn = new IPv6h(packet, offset);           
            
            infos[0] = IPv6h.printIP(toReturn.src);
            infos[1] = IPv6h.printIP(toReturn.dst);
            infos[2] = "ipv6";
            infos[3] = "IPv6";
            infos[4] = toReturn.toString();
            
            toReturn.next_header = dissectTransportLayer(packet, offset + IPv6h.HLEN, toReturn.nh, infos);
    
            break;
        case 0x0806: // ARP    
            toReturn = new ARPh(packet, offset);
            
            infos[2] = "arp";
            infos[3] = "ARP";
            infos[4] = toReturn.toString();
            
            break;
        case 0x8035: // RARP
            toReturn = null;
                        
            infos[2] = "arp"; // FIXME
            infos[3] = "RARP";
                       
            break;
        default: // "unknown" ethtype
            toReturn = null;
            
            infos[4] = "unknown ethtype";
            
            break;
    }
    return toReturn;
}

function dissectTransportLayer(packet, offset, prot, infos) {
    var toReturn;
    switch(prot) {
        case 1: // ICMP
            toReturn = null;
            
            infos[2] = "icmp";
            infos[3] = "ICMP";
            
            break;
        case 6: // TCP
            toReturn = new TCPh(packet, offset);            
            
            infos[2] = "tcp";
            infos[3] = "TCP";
            infos[4] = toReturn.toString();
            
            toReturn.next_header = dissectApplicationLayer(packet, offset + toReturn.getHeaderLength(), infos);
            
            break;
        case 17: // UDP
            toReturn = new UDPh(packet, offset);
                        
            infos[2] = "udp";
            infos[3] = "UDP";
            infos[4] = toReturn.toString();
            
            toReturn.next_header = dissectApplicationLayer(packet, offset + toReturn.getHeaderLength(), infos);
            
            break;
        default:
            toReturn = null;
            break;
    }  
    return toReturn;
}

function dissectApplicationLayer(packet, offset, infos) {
    return null;
/*  if (offset < ph.incl_len) {
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
    }*/    
}

function processClick(row, pkt_num) {
    selectRow(row);
    printPacketDetails(pkt_num);
    printPayload(pkt_num);
}

function selectRow(row) {
    deselectRow(selectedRow);
    row.className += "active";
    selectedRow = row;
}

function deselectRow(row) {
    if (row != null)
        row.className = row.className.replace("active","");
}

function printPacketDetails(pkt_num) {
    var packet = packets[pkt_num];
    
    details_div.innerHTML = "";
    
    while (packet != null) { // go to payload
        details_div.appendChild(packet.printDetails());
        packet = packet.next_header;        
    }
}

function printPayload(pkt_num) {
//     var offset = 0;
//     var packet = packets[pkt_num];
//     
//     while (packet != null) { // go to payload
//         offset += packet.getHeaderLength();
//         packet = packet.next_header;        
//     }
//     
//     var payload = new Uint8Array(rawPackets[pkt_num].slice(offset));
    
    var payload = new Uint8Array(rawPackets[pkt_num]);
    
    var output = "<pre>";
        
    var remainder = payload.byteLength % 16;
    
    var i, j;
    
    for (i = 0; i < payload.byteLength - 16; i += 16) {
        output += printNum(i, 16, 4)+"  ";
        for (j = 0; j < 16; j++) {
            output += printNum(payload[i + j], 16, 2) + " ";
            if (j == 7)
                output += " ";
        }
        output += " ";
        for (j = 0; j < 16; j++) {
            if (payload[i + j] >= 32 && payload[i + j] <= 126)
                output += String.fromCharCode(payload[i + j]);
            else
                output += ".";
        }
        output += "</br>";
    }
    
    output += printNum(i, 16, 4)+"  ";
    for (j = 0; j < remainder; j++) {
        output += printNum(payload[i + j], 16, 2) + " ";
        if (j == 7)
            output += " ";
    }
    
    for (j = 0; j < (16 - remainder); j++) {
        output += "   ";
        if (j == 7)
            output += " ";
    }
    output += " ";
    
    for (j = 0; j < remainder; j++) {
        if (payload[i + j] >= 32 && payload[i + j] <= 126)
            output += String.fromCharCode(payload[i + j]);
        else
            output += ".";
    }
    
    output += "</pre>";
    
    payload_div.innerHTML = output;
}

function printNum(num, base, len) {
    if(num == null)
        return "%";
    var hex = num.toString(base);
    var toReturn = "";
    for (var i = 0; i < (len - hex.length); i++)
        toReturn += "0";
    return toReturn + hex;
}

function clearOutputTable() {
    otable.innerHTML = "";
}

function switchConnection() {
    if(ws == null) {
        ws = new WebSocket(ws_url);
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

function printDate(date) {
    return months[date.getMonth()]+" "+date.getDate()+", "+date.getFullYear()+" "+date.getHours()+":"+date.getMinutes()+":"+date.getSeconds();
}