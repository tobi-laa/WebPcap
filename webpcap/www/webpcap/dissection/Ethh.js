if (typeof require !== 'undefined') 
    var printNum = require('../formattedOutput').printNum;

/*
 ******************************************************************
 ************************ ETHERNET HEADER *************************
 ******************************************************************
 */

function Ethh(data, offset) {    
    var byteView  = new  Uint8Array(data, offset, Ethh.HLEN);
    var shortView = new Uint16Array(data, offset + 2 * Ethh.ALEN, 1);
    
    this.dst  = byteView.subarray(0, 6);  // destination MAC address
    this.src  = byteView.subarray(6, 12); // source MAC address    
    this.prot = ntohs(shortView[0]);      // protocol (i.e. IPv4)
    
    this.next_header = null;
    byteView = shortView = null;
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

// FIXME: check params for consistency
function printMAC(mac) {
    var output = printNum(mac[0], 16, 2);
    for (i = 1; i < mac.length; i++)
        output += ':' + printNum(mac[i], 16, 2);
    return output;
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