'use strict';
if (typeof require !== 'undefined') {
    var createID = require('./TCPh').createID;
    var buildPseudoHeader = require('./TCPh').buildPseudoHeader;
    var validateChecksum = require('./IPv4h').validateChecksum;
}
/*
 ******************************************************************
 ************************** UDP HEADER ****************************
 ******************************************************************
 */
function UDPh(littleEndian, dataView, offset, parent) {    
    this.sport = dataView.getUint16(offset, littleEndian); // source port
    this.dport = dataView.getUint16(offset + 2, littleEndian); // destination port
    this.len   = dataView.getUint16(offset + 4, littleEndian); // length of payload incl. UDP header
    this.csum  = dataView.getUint16(offset + 6, littleEndian); // header checksum
      
    this.id = createID(parent.src, this.sport, parent.dst, this.dport, 'u');
    
//     if (offset + this.getHeaderLength() > dataView.length)
//         this.val = false;
//     else if (!this.csum) // UDP checksum is optional...
//         this.val = true;
//     else {
//         var ph = buildPseudoHeader(littleEndian, dataView.buffer, offset, parent);
//         this.val = validateChecksum(ph);
//     }
        
    this.next_header = null;
}

UDPh.prototype = {
    getHeaderLength: function () {
        return UDPh.HLEN;
    },
    printDetails: function (pkt_num) {
        var details = document.createElement('div');
        details.setAttribute('class','udp');
        var check = document.createElement('input');
        check.setAttribute('type','checkbox');  
        check.setAttribute('id', 'ud');
        var hidden = document.createElement('div');
        var label = document.createElement('label');
        var icon = document.createElement('span');
        icon.setAttribute('class', 'dropdown glow');
        label.setAttribute('for', 'ud');
        label.appendChild(icon);
        label.innerHTML += 'User Datagram Protocol';
        details.appendChild(check);
        details.appendChild(label);   
         
        hidden.innerHTML = 'Source port: ' + this.sport + '</br>'
                         + 'Destination port: ' + this.dport + '</br>'
                         + 'Length: ' + this.len + '</br>'                    
                         + 'Checksum: 0x' + printNum(this.csum, 16, 4) + ' [' + (this.val ? 'correct' : 'incorrect') + ']</br>';
        
        details.appendChild(hidden);
        
        return details;
    },
    printPorts: function() {
        return (UDP_PORTS[this.sport] || this.sport) + ' ⊳ ' +
               (UDP_PORTS[this.dport] || this.dport);
    },
    toString: function () {
        return this.printPorts();
    }
};

UDPh.HLEN = 8; // UDP header length in bytes  
UDPh.PORTS = []; // well-known ports

if (typeof module !== 'undefined')
    module.exports = UDPh;
