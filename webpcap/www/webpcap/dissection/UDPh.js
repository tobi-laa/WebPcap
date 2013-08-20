/*
 ******************************************************************
 ************************** UDP HEADER ****************************
 ******************************************************************
 */

function UDPh(data, offset, parent) {
    var shortView = new Uint16Array(data, offset, UDPh.HLEN / 2);
    
    this.sport = ntohs(shortView[0]); // source port
    this.dport = ntohs(shortView[1]); // destination port
    this.len   = ntohs(shortView[2]); // length of payload incl. UDP header
    this.csum  = ntohs(shortView[3]); // header checksum
      
    this.id = createID(parent.src, this.sport, parent.dst, this.dport, 'u');
    
    if (offset + this.getHeaderLength() > data.byteLength)
        this.val = false;
    else if (!this.csum) // UDP checksum is optional...
        this.val = true;
    else {
        var ph = buildPseudoHeader(parent, data, offset);
        this.val = validateChecksum(ph);
    }
        
    this.next_header = null;
    shortView = null;
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

if (typeof module !== 'undefined')
    module.exports = UDPh;
