'use strict';

if (typeof require !== 'undefined') {
    var printMAC = require('./ethernet').printMAC;
    var printIPv4 = require('./ipv4').printIPv4;
    var printIPv6 = require('./ipv6').printIPv6;
    var Ethernet = require('./ethernet').Ethernet;
    Ethernet.TYPES = require('./ethernet').TYPES;
}
/*
 ******************************************************************
 ************************** ARP HEADER ****************************
 ******************************************************************
 */

function ARP(littleEndian, dataView, offset) {
    this.htype = dataView.getUint16(offset, littleEndian);
    this.ptype = dataView.getUint16(offset + 2, littleEndian);
    this.hlen  = dataView.getUint8(offset + 4);
    this.plen  = dataView.getUint8(offset + 5);
    this.op    = dataView.getUint16(offset + 6, littleEndian);

    this.next_header = null; // not used
    
    offset  += ARP.HLEN;
    if (dataView.byteLength < offset) {// bogus value
        // packet.val = false;
        return;
    }
    this.sha = new DataView(dataView.buffer, offset, this.hlen);
    
    offset  += this.hlen;
    if (dataView.byteLength < offset) {// bogus value
        // packet.val = false;
        return;
    }
    this.spa = new DataView(dataView.buffer, offset, this.plen);
    
    offset  += this.plen;
    if (dataView.byteLength < offset) {// bogus value
        // packet.val = false;
        return;
    }
    this.tha = new DataView(dataView.buffer, offset, this.hlen);
    
    offset  += this.hlen;
    if (dataView.byteLength < offset) {// bogus value
        // packet.val = false;
        return;
    }
    this.tpa = new DataView(dataView.buffer, offset, this.plen);    
}

ARP.prototype = {
    getHeaderLength: function () {
        return ARP.MIN_HEADER_LENGTH + 2 * this.hlen + 2 * this.plen;
    },    
    toString: function () {
        if (this.op == 1) { // ARP query
            if (this.ptype == 0x0800)
                return 'Who has ' + printIPv4(this.tpa)+'? Tell ' + printIPv4(this.spa);
            else
                return 'ARP Query';
        }
        if (this.op == 2) {// ARP reply
            if (this.ptype == 0x0800 && this.htype == 1)
                return printIPv4(this.spa) + ' is at ' + printMAC(this.sha);
            else
                return 'ARP Reply';
        }
    }
}

ARP.prototype.printDetails = function () {
    var title = 'Address Resolution Protocol';
    var nodes = []
    
    nodes.push(document.createTextNode(
        [        
        'Hardware type: ' + ARP.HARDWARE_TYPES[this.htype] + '(' + this.htype +
            ')',
        'Protocol type: ' + Ethernet.TYPES[this.ptype] + 
            ' (0x' + printNum(this.ptype, 16, 4) + ')',
        'Hardware size: ' + this.hlen,
        'Protocol size: ' + this.plen,
        'Opcode: ' + ARP.OPCODES[this.op] + '(' + this.op + ')',
        // FIXME FIXME obviously not always IP & MAC... also show whether query or reply etc
        'Sender MAC address: ' + printMAC(this.sha),                         
        'Sender IP address: ' + printIPv4(this.spa),
        'Target MAC address: ' + printMAC(this.tha),                         
        'Target IP address: ' + printIPv4(this.tpa)
        ].join('\n')
    ));
    
    return createDetails(title, nodes);
}

ARP.MIN_HEADER_LENGTH = 8; // beginning (!) of ARP header length in bytes
ARP.HARDWARE_TYPES = [];
ARP.OPCODES = [];

if (typeof module !== 'undefined') {
    module.exports.ARP = ARP;
    module.exports.MIN_HEADER_LENGTH = ARP.MIN_HEADER_LENGTH;
}