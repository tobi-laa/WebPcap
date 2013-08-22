'use strict';
if (typeof require !== 'undefined') 
    var printNum = require('../formattedOutput').printNum;

/*
 ******************************************************************
 ************************ ETHERNET HEADER *************************
 ******************************************************************
 */

function Ethh(littleEndian, dataView, offset) {   
    this.dst  = new DataView(dataView.buffer, offset, Ethh.ALEN);  // destination MAC address
    this.src  = new DataView(dataView.buffer, offset + 6, Ethh.ALEN); // source MAC address    
    this.prot = dataView.getUint16(offset + 12, littleEndian); // protocol (i.e. IPv4)
    
    this.next_header = null;
}

Ethh.prototype = {
    getHeaderLength: function () {
        return Ethh.HLEN;
    },
    printDetails: function (pkt_num) {
        var details = document.createElement('div');
        details.setAttribute('class','eth');
        var check = document.createElement('input');
        check.setAttribute('type','checkbox');  
        check.setAttribute('id', 'ed');
        var hidden = document.createElement('div');
        var label = document.createElement('label');
        var icon = document.createElement('span');
        icon.setAttribute('class', 'dropdown glow');
        label.setAttribute('for', 'ed');
        label.appendChild(icon);
        label.innerHTML += 'Ethernet II';
        details.appendChild(check);
        details.appendChild(label);   
                
        hidden.innerHTML  = 'Destination: ' + printMAC(this.dst) + '</br>';
        hidden.innerHTML += 'Source: ' + printMAC(this.src) + '</br>';
        hidden.innerHTML += 'Type: ' + printEtherType(this.prot) + ' (0x' + printNum(this.prot, 16, 4) + ')</br>';
        
        details.appendChild(hidden);
        
        return details;
    },
    toString: function () {
        return 'From: ' + printMAC(this.src)+
               ' To: '  + printMAC(this.dst);
    }
};

Ethh.HLEN = 14; // Ethernet frame length in bytes
Ethh.ALEN = 6;  // MAC address length in bytes

function printIPv4(ip) {
    // check param for consistency
    if (!ip.getUint8)
        throw 'IPv4 address param has to be a DataView object.';
    if (ip.byteLength !== IPv4h.ALEN)
        console.log('Warning: Incorrect IPv4 address length.');
    
    var ipFragments = [];
    for (var i = 0; i < ip.byteLength; i++)
        ipFragments[i] = ip.getUint8(i);
    return ipFragments.join('.');
}
function printMAC(mac) {
    // check param for consistency
    if (!mac.getUint8)
        throw 'MAC address param has to be a DataView object.';
    if (mac.byteLength !== Ethh.ALEN)
        console.log('Warning: Incorrect MAC address length.');
    
    var macFragments = [];
    for (var i = 0; i < mac.byteLength; i++)
        macFragments[i] = printNum(mac.getUint8(i), 16, 2);
    return macFragments.join(':');
}

function printEtherType(type) {
    switch(type) {
    case 0x0800: return 'IPv4';
    case 0x0806: return 'ARP';
    case 0x0842: return 'Wake-on-LAN';
    case 0x8035: return 'RARP';
    case 0x8137: return 'IPX';
    case 0x8138: return 'IPX';
    case 0x86DD: return 'IPv6';
    case 0x8808: return 'Ethernet flow control';
    default:     return 'Unknown';
    }
}

if (typeof module !== 'undefined') {
    module.exports.Ethh = Ethh;
    module.exports.printMAC = printMAC;
    module.exports.printEtherType = printEtherType;
}