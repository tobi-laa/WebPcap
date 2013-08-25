'use strict';

/*
 *******************************************************************************
 * This is the root object for any dissected packet. In includes the value of  *
 * the pcap header, but also general information that will be used for the     *
 * the rows in packet or connection view.                                      *
 *******************************************************************************
 */

function Packet(littleEndian, dataView, offset, num, nanoSecondAccuracy) {    
    // libpcap packet header
    
    // timestamp seconds
    this.ts_sec   = dataView.getUint32(offset, littleEndian);
    // timestamp offset in microseconds or nanoseconds
    this.ts_usec  = dataView.getUint32(offset + 4, littleEndian);  
    // number of octets of packet saved in file
    this.incl_len = dataView.getUint32(offset + 8, littleEndian); 
    // actual length of packet
    this.orig_len = dataView.getUint32(offset + 12, littleEndian);
    
    this.nanoSecondAccuracy = nanoSecondAccuracy;
    
    // some general information about the packet (not part of pcap header)
    this.num = num;
    this.src = '';
    this.dst = '';
    this.prot = '';
    // length is above
    this.info = '';
    
    this.class = ''; // color of the row...
    
    this.val = true; // packet is valid... for now!
    // this.id; // might be specified by TCP or UDP
    
    this.next_header = null;
}

Packet.prototype = {
    getHeaderLength: function () {
        return Packet.HEADER_LEN;
    },
    printTime: function () {
        return printDate(new Date(this.ts_sec * 1000)) + '.' + 
               printNum(this.ts_usec, 10, this.nanoSecondAccuracy ? 9 : 6);
    },
    toString: function () {
        return '';
    }
};

Packet.prototype.printDetails = function () {
    var title = 'General Information';
    var nodes = []
    
    nodes.push(document.createTextNode(
        [
        'Arrival Time: ' + this.printTime(),
        'Frame Length: ' + this.orig_len + ' bytes (' + (this.orig_len * 8) + 
            ' bits)',
        'Captured Length: ' + this.incl_len + ' bytes (' + (this.incl_len * 8) +
            ' bits)'
        ].join('\n')
    ));
    
    return createDetails(title, nodes);
}

Packet.HEADER_LENGTH = 16; // pcap header length in bytes 

if (typeof module !== 'undefined') {
    module.exports.Packet = Packet;
    module.exports.HEADER_LENGTH = Packet.HEADER_LENGTH;
}