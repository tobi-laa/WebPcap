'use strict';

if (typeof require !== 'undefined') {
    var readCSVFile = require('../fileio').readCSVFile;  
    var IPv4 = require('./ipv4').IPv4;
    var IPv6 = require('./ipv6').IPv6;
    IPv4.printIP = require('./ipv4').printIP;
    IPv6.printIP = require('./ipv6').printIP;
    var Ethernet = require('./ethernet').Ethernet;
    Ethernet.TYPES = require('./ethernet').TYPES;
    Ethernet.printMAC = require('./ethernet').printMAC;
}

function ARP(littleEndian, packet, dataView, offset) {
    this.htype = dataView.getUint16(offset, littleEndian);
    this.ptype = dataView.getUint16(offset + 2, littleEndian);
    this.hlen  = dataView.getUint8(offset + 4);
    this.plen  = dataView.getUint8(offset + 5);
    this.op    = dataView.getUint16(offset + 6, littleEndian);
    
    offset += ARP.MIN_HEADER_LENGTH;
    if (dataView.byteLength < offset) {// bogus value
        packet.val = false;
        packet.class = 'malformed';
        return;
    }
    this.sha = new DataView(dataView.buffer, offset, this.hlen);
    
    offset += this.hlen;
    if (dataView.byteLength < offset) {// bogus value
        packet.val = false;
        packet.class = 'malformed';
        return;
    }
    this.spa = new DataView(dataView.buffer, offset, this.plen);
    
    offset += this.plen;
    if (dataView.byteLength < offset) {// bogus value
        packet.val = false;
        packet.class = 'malformed';
        return;
    }
    this.tha = new DataView(dataView.buffer, offset, this.hlen);
    
    offset += this.hlen;
    if (dataView.byteLength < offset) {// bogus value
        packet.val = false;
        packet.class = 'malformed';
        return;
    }
    this.tpa = new DataView(dataView.buffer, offset, this.plen);    
    
    // set general information
    packet.prot = packet.class = 'ARP';
    packet.info = this.toString;
}

ARP.prototype.getHeaderLength = function () {
    return ARP.MIN_HEADER_LENGTH + 2 * this.hlen + 2 * this.plen;
}

ARP.prototype.toString = function () {
    switch (this.op) {        
    case 1: // ARP query
        if (this.ptype === 0x0800)
            return 'Who has ' + printIPv4(this.tpa)+'? Tell ' 
                + printIPv4(this.spa);
        if (this.ptype === 0x86DD)
            return 'Who has ' + printIPv6(this.tpa)+'? Tell ' 
                + printIPv6(this.spa);
        break;
    case 2: // ARP reply
        if (this.htype == 1) {
            if (this.ptype === 0x0800) {
                return printIPv4(this.spa) + ' is at ' + 
                    Ethernet.printMAC(this.sha);                
            }
            if (this.ptype === 0x86DD) {
                return printIPv6(this.spa) + ' is at ' + 
                    Ethernet.printMAC(this.sha);                
            }
        }
        break;
    }
    // something is not supported yet
    return ARP.OPCODES[this.op];
}

ARP.prototype.printDetails = function () {
    var title = 'Address Resolution Protocol';
    var nodes = [];
    var textFragments;
    
    textFragments =
    [        
        'Hardware type: ' + ARP.HARDWARE_TYPES[this.htype] + ' (' + this.htype +
            ')',
        'Protocol type: ' + Ethernet.TYPES[this.ptype] + 
            ' (0x' + printNum(this.ptype, 16, 4) + ')',
        'Hardware size: ' + this.hlen,
        'Protocol size: ' + this.plen,
        'Opcode: ' + ARP.OPCODES[this.op] + ' (' + this.op + ')'
    ];
    
    if (this.htype === 1) {
        textFragments.push('Sender MAC address: ' +Ethernet.printMAC(this.sha));
        textFragments.push('Target MAC address: ' +Ethernet.printMAC(this.tha));
    }
    
    if (this.ptype === 0x0800) {
        textFragments.push('Sender IP address: ' + IPv4.printIP(this.spa));
        textFragments.push('Target IP address: ' + IPv4.printIP(this.tpa));
    }
    else if (this.ptype === 0x86DD) {
        textFragments.push('Sender IP address: ' + IPv6.printIP(this.spa));
        textFragments.push('Target IP address: ' + IPv6.printIP(this.tpa));
    }
    
    nodes.push(document.createTextNode(textFragments.join('\n')));
    
    return createDetails(title, nodes);
}

ARP.MIN_HEADER_LENGTH = 8; // beginning (!) of ARP header length in bytes
ARP.HARDWARE_TYPES = readCSVFile('webpcap/dissection/resources/arp-parameters-2.csv', 0, 1);
ARP.OPCODES = readCSVFile('webpcap/dissection/resources/arp-parameters-1.csv', 0, 1);

if (typeof module !== 'undefined') {
    module.exports.ARP = ARP;
    module.exports.MIN_HEADER_LENGTH = ARP.MIN_HEADER_LENGTH;
}