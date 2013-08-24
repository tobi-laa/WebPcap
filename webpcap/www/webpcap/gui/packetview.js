'use strict';
var packets = [];
var packetViewAnchor = 0;

function printPacketDetails(packetNum) {
    var packet = dissector.getDissectedPacket(packetNum);
    if (!packet) return;

    doubleBuffer.innerHTML = '';
    
    while (packet) { // print details for each header
        doubleBuffer.appendChild(packet.printDetails(packetNum));
        packet = packet.next_header;        
    }
    
    detailsOutput.innerHTML = '';
    detailsOutput.appendChild(doubleBuffer);
}

function printBytes(packetNum) {
    var bytes = dissector.getRawPacket(packetNum);
    var output = '';
    
    if (!bytes) {
        throw 'No packet data available for number ' + packetNum;
    }
    
    bytes = new Uint8Array(bytes);
    
    // show the bytes in lines of 16 bytes
    for (var line = 0; line < bytes.length; line += 16) {
        output += printNum(line, 16, 4) + '  '; // enumerate the lines
        
        // print bytes as hex
        for (var lineOff = 0; lineOff < 16; lineOff++) { 
            if (line + lineOff >= bytes.length) {
                output += '   '; // keep correct indentation for acii printing                
            }
            else {
                output += printNum(bytes[line + lineOff], 16, 2) + ' ';
            }
            
            if (lineOff === 7) {
                output += ' '; // double space in the middle, looks nicer                
            }
        }
        
        output += ' '; // separator between hex and ascii
        
        // print bytes as ascii
        for (var lineOff = 0; lineOff < 16; lineOff++) {
            if (line + lineOff >= bytes.length) { // we're done
                break;                
            }
            output += printASCIINoLF(bytes[line + lineOff]);            
        }
        
        output += '\n';
    }
    
    bytesOutput.innerHTML = '';
    bytesOutput.appendChild(document.createTextNode(output));
} 

function printRow(packet, customClass) { // customClass is additional
    var row  = document.createElement('div');
    var num  = document.createElement('div');
    var src  = document.createElement('div');
    var dst  = document.createElement('div');
    var prot = document.createElement('div');
    var len  = document.createElement('div');
    var info = document.createElement('div');
        
    row.addEventListener('click', function () {
        processClick(packet.num);        
    });
    if (packet.id) {
        row.addEventListener('contextmenu', function (event) {
            processRightClick(packet.num, event, packet.id);            
        });        
    }
    else {
        row.addEventListener('contextmenu', function (event) {
            processRightClick(packet.num, event);            
        });        
    }
    row.setAttribute('class','row ' + (customClass || '') + ' ' + packet.class);
        
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
    info.innerHTML = packet.info;
    
    row.appendChild(num);
    row.appendChild(src);
    row.appendChild(dst);
    row.appendChild(prot);
    row.appendChild(len);
    row.appendChild(info);                     
    
    return row;
}

function renderPacketView() {    
    if (packets.length === 0 || !renderNextTime)
        return;
    
    var row;
    
    doubleBuffer.innerHTML = '';
    
    for (var i = packetViewAnchor; i <= packetViewAnchor + maxRows; i++) {
        if (i >= packets.length)
            break;
        
        if (packets[i].num === selectedPacketRow)
            row = printRow(packets[i], 'selected');
        else
            row = printRow(packets[i]);
        doubleBuffer.appendChild(row);
    }
    
    mainOutputTable.innerHTML = '';
    mainOutputTable.appendChild(doubleBuffer);
    
    if (autoscroll)
        mainOutput.scrollTop = mainOutput.scrollHeight;
    else
        mainOutput.scrollTop = 0;
    
    renderNextTime = false;
}

function scrollPacketView(direction) {
    if (packets.length === 0)
        return;
    
    autoscroll = false;
    renderNextTime = true;
    
    packetViewAnchor += direction;
    
    if (packetViewAnchor < 0) {
        packetViewAnchor = 0;
    }
    else if (packetViewAnchor >= packets.length - maxRows) {
        // we don't want a negative anchor (happens when main output not 'full')
        packetViewAnchor = Math.max(packets.length - maxRows, 0);
        autoscroll = true;
    }
}