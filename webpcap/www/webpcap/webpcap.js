var doc = document;
var pktview = doc.getElementById('pktview');
var connview = doc.getElementById('connview');
var pktoutput = pktview.getElementsByClassName('output')[0];
var connoutput = connview.getElementsByClassName('output')[0];
var pkttable  = pktoutput.getElementsByTagName('div')[0];
var conntable = connoutput.getElementsByTagName('div')[0];
var payload_div = doc.getElementById('payload');
var details_div = doc.getElementById('details');
var selectedPacketRow = new Object();
var selectedConnectionRow = new Object();

var ws_url = 'ws://' + window.location.host + '/binary';
var ws = null;  
var conn_button = doc.getElementById('conn');
var conn_light = conn.getElementsByTagName('input')[0];

function onWSMessage(msg) {    
    appendPacketData(msg.data);
    
    dissect(msg.data, print);
}  

function onWSOpen() {
    ws.send('none\0'); // default filter
    conn_light.checked = true;
    conn_button.setAttribute('title', 'Stop the running live capture');
}

function onWSClose() {
    ws = null;
    conn_light.checked = false;
    conn_button.setAttribute('title', 'Start a new live capture');
}



var packetView = true;
var connRows = {};

function switchView() {
    packetView = !packetView;
    if (packetView) {
        connview.setAttribute('class', 'hidden');
        pktview.removeAttribute('class');
    }
    else {
        pktview.setAttribute('class', 'hidden');
        connview.removeAttribute('class');
    }
}





var tmpLink = document.createElement('a');
tmpLink.download = 'log.pcap';

// will be used to click on the link
var mc = document.createEvent('MouseEvents');
mc.initEvent('click', true, false);

function saveCapture() {
    tmpLink.href = getURL();
    tmpLink.dispatchEvent(mc);
} 



function clickOnFileInput() {
    fi.click();
}



function print(packet) {
    printRow(packet);
    printConnection(packet);
}

function printRow(packet) {
    if (tcp_filter && packet.tcp_id !== tcp_filter)
        return;
    
    var row = doc.createElement('div');
    var num   = doc.createElement('div');
    var src  = doc.createElement('div');
    var dst  = doc.createElement('div');
    var prot = doc.createElement('div');
    var len  = doc.createElement('div');
    var info = doc.createElement('div');
        
    row.setAttribute('onclick','processClick(this, ' + packet.num + ')');
    row.setAttribute('class','row ' + packet.prot);
    
    
    num.setAttribute('class', 'col 5p');    
    src.setAttribute('class', 'col 25p');    
    dst.setAttribute('class', 'col 25p');    
    prot.setAttribute('class', 'col 10p');    
    len.setAttribute('class', 'col 5p');    
    info.setAttribute('class', 'col 30p');
    
    num.innerHTML  = packet.num;
    len.innerHTML  = packet.orig_len;
    src.innerHTML  = packet.src;
    dst.innerHTML  = packet.dst;
    prot.innerHTML = packet.prot;
    
    while (packet.next_header) packet = packet.next_header;
    
    info.innerHTML = packet;
    
    row.appendChild(num);
    row.appendChild(src);
    row.appendChild(dst);
    row.appendChild(prot);
    row.appendChild(len);
    row.appendChild(info);
                    
    pkttable.appendChild(row);    
    
    return row;
}

function printConnection(packet) {
    if (!packet.tcp_id)
        return;
    
    var conn = getTCPConn(packet.tcp_id);
    
    var row = connRows[packet.tcp_id];
    if (!row) {
        row = connRows[packet.tcp_id] = doc.createElement('div');
        row.setAttribute('onclick','processClick(this, ' + packet.tcp_id + ')');
        row.setAttribute('class','row ' + packet.prot);
        conntable.appendChild(row);
    }
        
    var num   = doc.createElement('div');
    var src  = doc.createElement('div');
    var sport  = doc.createElement('div');
    var dst  = doc.createElement('div');
    var dport = doc.createElement('div');
    var prot = doc.createElement('div');
    var len  = doc.createElement('div');
    var info = doc.createElement('div');
        
    num.setAttribute('class', 'col 5p');    
    src.setAttribute('class', 'col 25p'); 
    sport.setAttribute('class', 'col 5p');
    dst.setAttribute('class', 'col 25p'); 
    dport.setAttribute('class', 'col 5p');    
    prot.setAttribute('class', 'col 10p');    
    len.setAttribute('class', 'col 5p tr');    
    info.setAttribute('class', 'col 20p');
    
    num.innerHTML   = conn.num;
    src.innerHTML   = conn.src;
    sport.innerHTML = conn.sport;
    dst.innerHTML   = conn.dst;
    dport.innerHTML = conn.dport;
    prot.innerHTML  = packet.prot;
    if (conn.len < 1024)
        len.innerHTML = conn.len + ' B';
    else if (conn.len < 1024 * 1024)
        len.innerHTML = (conn.len/1024 >> 0) + ' KiB';
    else if (conn.len < 1024 * 1024 * 1024)
        len.innerHTML = (conn.len/(1024 * 1024) >> 0) + ' MiB';
    else
        len.innerHTML = (conn.len/(1024 * 1024 * 1024) >> 0) + ' GiB';
    // info.innerHTML  = 'lol';
    
    row.innerHTML = '';
    row.appendChild(num);
    row.appendChild(src);
    row.appendChild(sport);
    row.appendChild(dst);
    row.appendChild(dport);
    row.appendChild(prot);
    row.appendChild(len);
    row.appendChild(info);
    
    return row;
}

function printConnections() {
    var tcpConns = getTCPConns();
    
    for (id in tcpConns) 
        printConnection(tcpConns[id].packets[0]);
}

// FIXME
setInterval(function() { if(ws) pktoutput.scrollTop = pktoutput.scrollHeight;}, 500);

function processClick(row, num) {
    selectRow(row, num);
    if (!packetView)
        return;
    printPacketDetails(num);
    printPayload(num);
}

function selectRow(row, num) {
    var selectedRow;
    if (packetView)
        selectedRow = selectedPacketRow;
    else
        selectedRow = selectedConnectionRow;
    
    if (selectedRow.row)
        selectedRow.row.setAttribute('class', selectedRow.class);
    selectedRow.class = row.className;    
    selectedRow.row = row;
    selectedRow.num = num;
    
    row.setAttribute('class','row selected');
}

function printPacketDetails(pkt_num) {
    var packet = getPacket(pkt_num);
    if(!packet) return;
    
    details_div.innerHTML = '';
    
    while (packet !== null) { // go to payload
        details_div.appendChild(packet.printDetails(pkt_num));
        packet = packet.next_header;        
    }
}

function printPayload(pkt_num) { 
    payload_div.innerHTML = '';
    
    var payload = getRawPacket(pkt_num);
    if (!payload) return;
    payload = new Uint8Array(payload);
    
    var output = '';
        
    var remainder = payload.byteLength % 16;
    
    var i, j;
    
    for (i = 0; i < payload.byteLength - 16; i += 16) {
        output += printNum(i, 16, 4)+'  ';
        for (j = 0; j < 16; j++) {
            output += printNum(payload[i + j], 16, 2) + ' ';
            if (j === 7)
                output += ' ';
        }
        output += ' ';
        for (j = 0; j < 16; j++) {
            if (payload[i + j] >= 32 && payload[i + j] <= 126)
                output += String.fromCharCode(payload[i + j]);
            else
                output += '.';
        }
        output += '\n';
    }
    
    output += printNum(i, 16, 4)+'  ';
    for (j = 0; j < remainder; j++) {
        output += printNum(payload[i + j], 16, 2) + ' ';
        if (j === 7)
            output += ' ';
    }
    
    for (j = 0; j < (16 - remainder); j++) {
        output += '   ';
        if (j === 7)
            output += ' ';
    }
    output += ' ';
    
    for (j = 0; j < remainder; j++) {
        if (payload[i + j] >= 32 && payload[i + j] <= 126)
            output += String.fromCharCode(payload[i + j]);
        else
            output += '.';
    }
    
    var pre = document.createElement('pre');
    pre.appendChild(document.createTextNode(output))
    payload_div.appendChild(pre);
}

function clearScreen() {
    pkttable.innerHTML = '';
    details.innerHTML = '';
    payload.innerHTML = '';
}

function switchConnection() {
    if(ws) {
        ws.close();
        ws = null;
        return;
    }
    ws = new WebSocket(ws_url);
    ws.binaryType = 'arraybuffer';
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
        printPackets(getTCPConn(tcp_id).packets);
    }
}

function printPackets(packets) {
    if (!packets) return;
    
    for (var i = 0; i < packets.length; i++) {
        if (packets[i].num === selectedPacketRow.num) {
            selectRow(printRow(packets[i]), packets[i].num);
            printPacketDetails(packets[i].num);
            printPayload(packets[i].num);
        }
        else
            printRow(packets[i]);
    }
}