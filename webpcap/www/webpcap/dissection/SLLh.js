if (typeof require !== 'undefined') {
    var printNum = require('../formattedOutput').printNum;
    var printMAC = require('./Etth').printMAC;
    var printEtherType = require('./Etth').printEtherType;
}

/*
 ******************************************************************
 ******************* LINUX 'COOKED' CAPTURE ***********************
 ******************************************************************
 */

function SLLh(data, offset) {
    var byteView  = new  Uint8Array(data, offset, SLLh.HLEN);
    var shortView = new Uint16Array(data, offset, SLLh.HLEN / 2);
    
    this.type    = ntohs(shortView[0]);                 // packet type
    this.llat    = ntohs(shortView[1]);                 // link-layer address type
    this.llal    = ntohs(shortView[2]);                 // link-layer address length
    this.src     = byteView.subarray(6, 6 + this.llal); // source (MAC) address    
    this.prot    = ntohs(shortView[7]);                 // protocol (i.e. IPv4)
    
    this.next_header = null;    
}

SLLh.prototype = {
    getHeaderLength: function () {
        return SLLh.HLEN;
    },
    printDetails: function (pkt_num) {
        var details = document.createElement('div');
        details.setAttribute('class','eth');
        var check = document.createElement('input');
        check.setAttribute('type','checkbox');  
        check.setAttribute('id','ed');
        var hidden = document.createElement('div');
        var label = document.createElement('label');
        var icon = document.createElement('span');
        icon.setAttribute('class', 'dropdown');
        label.setAttribute('for','ed');
        label.appendChild(icon);
        label.innerHTML += 'Linux cooked capture';
        details.appendChild(check);
        details.appendChild(label);   
        
        hidden.innerHTML += 'Packet type: ' + printPacketType(this.type) + ' (' + this.type + ')</br>';
        hidden.innerHTML += 'Link-layer address type: ' + this.llat + '</br>';
        hidden.innerHTML += 'Link-layer address length: ' + this.llal + '</br>';
        hidden.innerHTML += 'Source: ' + printMAC(this.src) + '</br>';
        hidden.innerHTML += 'Protocol: ' + printEtherType(this.prot) + ' (0x' + printNum(this.prot, 16, 4) + ')</br>';
        
        details.appendChild(hidden);
        
        return details;
    },
    toString: function () {
        return 'From: '+printMAC(this.src);
    }
};

function printPacketType(type) {
    switch(type) {
    case 0:  return 'Unicast to us';
    case 1:  return 'Broadcast';
    case 2:  return 'Multicast';
    case 3:  return 'Unicast to another host';
    case 4:  return 'Sent by us';
    default: return 'Unknown';
    }
}

SLLh.HLEN = 16; // SLL header length in bytes

if (typeof module !== 'undefined')
    module.exports.SLLh = SLLh;
