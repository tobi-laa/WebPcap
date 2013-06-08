var doc = document;
var output = doc.getElementById("output");
var table = output.getElementsByTagName("div")[0];
var payload_div = doc.getElementById("payload");
var details_div = doc.getElementById("details");
var selectedRow = new Object();




var ws_url = "ws://" + window.location.host + "/binary";
var ws = null;  
var conn_button = document.getElementById("conn");
var conn_light = conn.getElementsByTagName("input")[0];

function onWSMessage(msg) {    
    appendPacketData(msg.data);
    
    dissect(msg.data, printRow);
}  

function onWSOpen() {
    ws.send("none\0"); // default filter
    conn_light.checked = true;
    conn_button.setAttribute('title', 'Stop the running live capture');
}

function onWSClose() {
    ws = null;
    conn_light.checked = false;
    conn_button.setAttribute('title', 'Start a new live capture');
}





var tmpLink = document.createElement("a");
tmpLink.download = "log.pcap";

// will be used to click on the link
var mc = document.createEvent("MouseEvents");
mc.initEvent("click", true, false);

function saveCapture() {
    tmpLink.href = getURL();
    tmpLink.dispatchEvent(mc);
} 



function clickOnFileInput() {
    fi.click();
}







function printRow(packet) {
    if (tcp_filter && packet.tcp_id !== tcp_filter)
        return;
    
    var row = doc.createElement("div");
    row.setAttribute('onclick','processClick(this, ' + packet.num + ')');
    row.setAttribute('class','row ' + packet.prot);
    
    var num   = doc.createElement("div");
    num.setAttribute('class', 'col 5p');
    var src  = doc.createElement("div");
    src.setAttribute('class', 'col 25p');
    var dst  = doc.createElement("div");
    dst.setAttribute('class', 'col 25p');
    var prot = doc.createElement("div");
    prot.setAttribute('class', 'col 5p');
    var len  = doc.createElement("div");
    len.setAttribute('class', 'col 5p');
    var info = doc.createElement("div");
    info.setAttribute('class', 'col 30p');
    
    num.innerHTML  = packet.num;
    len.innerHTML  = packet.orig_len;
    src.innerHTML  = packet.src;
    dst.innerHTML  = packet.dst;
    prot.innerHTML = packet.prot;
    
    while(packet.next_header) packet = packet.next_header;
    
    info.innerHTML = packet;
    
    row.appendChild(num);
    row.appendChild(src);
    row.appendChild(dst);
    row.appendChild(prot);
    row.appendChild(len);
    row.appendChild(info);
                    
    table.appendChild(row);    
    
    return row;
}

// FIXME
setInterval(function() { if(ws) output.scrollTop = output.scrollHeight;}, 500);

function processClick(row, pkt_num) {
    selectRow(row, pkt_num);
    printPacketDetails(pkt_num);
    printPayload(pkt_num);
}

function selectRow(row, pkt_num) {
    deselectRow(selectedRow.row);
    
    selectedRow.class = row.className;    
    selectedRow.row = row;
    selectedRow.num = pkt_num;
    
    row.setAttribute('class','row selected');
}

function deselectRow(row) {
    if (!row) return;
    
    row.setAttribute('class', selectedRow.class);
}

function printPacketDetails(pkt_num) {
    var packet = getPacket(pkt_num);
    if(!packet) return;
    
    details_div.innerHTML = "";
    
    while (packet !== null) { // go to payload
        details_div.appendChild(packet.printDetails(pkt_num));
        packet = packet.next_header;        
    }
}

function printPayload(pkt_num) { 
    payload_div.innerHTML = "";
    
    var payload = getRawPacket(pkt_num);
    if (!payload) return;
    payload = new Uint8Array(payload);
    
    var output = '';
        
    var remainder = payload.byteLength % 16;
    
    var i, j;
    
    for (i = 0; i < payload.byteLength - 16; i += 16) {
        output += printNum(i, 16, 4)+"  ";
        for (j = 0; j < 16; j++) {
            output += printNum(payload[i + j], 16, 2) + " ";
            if (j === 7)
                output += " ";
        }
        output += " ";
        for (j = 0; j < 16; j++) {
            if (payload[i + j] >= 32 && payload[i + j] <= 126)
                output += String.fromCharCode(payload[i + j]);
            else
                output += ".";
        }
        output += "\n";
    }
    
    output += printNum(i, 16, 4)+"  ";
    for (j = 0; j < remainder; j++) {
        output += printNum(payload[i + j], 16, 2) + " ";
        if (j === 7)
            output += " ";
    }
    
    for (j = 0; j < (16 - remainder); j++) {
        output += "   ";
        if (j === 7)
            output += " ";
    }
    output += " ";
    
    for (j = 0; j < remainder; j++) {
        if (payload[i + j] >= 32 && payload[i + j] <= 126)
            output += String.fromCharCode(payload[i + j]);
        else
            output += ".";
    }
    
    var pre = document.createElement('pre');
    pre.appendChild(document.createTextNode(output))
    payload_div.appendChild(pre);
}

function clearScreen() {
    table.innerHTML = "";
    details.innerHTML = "";
    payload.innerHTML = "";
}

function switchConnection() {
    if(ws) {
        ws.close();
        ws = null;
        return;
    }
    ws = new WebSocket(ws_url);
    ws.binaryType = "arraybuffer";
    ws.onopen = onWSOpen;
    ws.onclose = onWSClose;
    ws.onmessage = onWSMessage;        
}








var tcp_filter = false;

function filterTCPConn(tcp_id) {
    clearScreen(); // redraw the table
    if (tcp_filter) {
        tcp_filter = false;
        printPackets(getPackets());
    }
    else {
        tcp_filter = tcp_id;
        printPackets(getTCPConn(tcp_id));
    }
}

function printPackets(packets) {
    if (!packets) return;
    
    for (var i = 1; i < packets.length; i++) {
        if (packets[i].num === selectedRow.num) {
            selectRow(printRow(packets[i]), i);
            printPacketDetails(i);
            printPayload(i);
        }
        else
            printRow(packets[i]);
    }
}