var scrollanchor = 0;
var pkts = getDissectedPackets();

function printPacketDetails(packetNum) {
    var packet = getDissectedPacket(packetNum);
    if (!packet) return;

    
    detailsOutput.innerHTML = '';
    
    while (packet !== null) { // print details for each header
        detailsOutput.appendChild(packet.printDetails(packetNum));
        packet = packet.next_header;        
    }
}

function printPayload(packetNum) {   
    var bytes = getRawPacket(packetNum);
    if (!bytes) return;
    
    bytes = new Uint8Array(bytes);
                
    var output = '';
    
    var i, j;
    
    for (i = 0; i < bytes.length; i += 16) { // each line -> 16 bytes
        output += printNum(i, 16, 4) + '  '; // enumerate the lines
        
        for (j = 0; j < 16; j++) { // print bytes as hex
            if (i + j >= bytes.length)
                output += '   '; // keep correct indentation for acii printing
            else
                output += printNum(bytes[i + j], 16, 2) + ' ';
            if (j === 7)
                output += ' '; // double space in the middle
        }
        
        output += ' ';
        
        for (j = 0; j < 16; j++) {// print bytes as ascii
            if (i + j >= bytes.length)
                break;
            output += printASCIINoLF(bytes[i + j]);            
        }
        
        output += '\n';
    }
    
    bytesOutput.innerHTML = '';
    bytesOutput.appendChild(document.createTextNode(output));
} 

function printRow(packet, customClass) {
    var row  = document.createElement('div');
    var num  = document.createElement('div');
    var src  = document.createElement('div');
    var dst  = document.createElement('div');
    var prot = document.createElement('div');
    var len  = document.createElement('div');
    var info = document.createElement('div');
        
    row.setAttribute('onclick','processClick(this, ' + packet.num + ')');
    if (packet.id)
        row.setAttribute('oncontextmenu','processRightClick(this, ' + packet.num + ', event, "' + packet.id + '")');
    else
        row.setAttribute('oncontextmenu','processRightClick(this, ' + packet.num + ', event)');
    row.setAttribute('class','row ' + (customClass || '') + ' ' + (packet.class || packet.prot));
        
    num.setAttribute('class', 'col 10p tr');    
    src.setAttribute('class', 'col 20p'); 
    dst.setAttribute('class', 'col 20p'); 
    prot.setAttribute('class', 'col 10p');    
    len.setAttribute('class', 'col 10p tr mono');    
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
    
    return row;
}

function renderPacketView() {    
    if (pkts.length === 0 || !renderNextTime)
        return;
    
    doubleBuffer.innerHTML = '';
    
    for (var i = scrollanchor; i <= scrollanchor + maxPackets; i++) {
        if (i >= pkts.length)
            break;
        row = printRow(pkts[i]);
        doubleBuffer.appendChild(row);
        if (pkts[i].num === selectedPacketRow.num)
            selectRow(row, pkts[i].num);
    }
    
    mainOutputTable.innerHTML = '';
    mainOutputTable.appendChild(doubleBuffer);
    
    if (autoscroll)
        mainOutput.scrollTop = mainOutput.scrollHeight;
    else
        mainOutput.scrollTop = 0;
    
    renderNextTime = false;
}