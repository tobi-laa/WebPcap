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
        
    this.next_header = null;
}

UDPh.prototype = {
    getHeaderLength: function () {
        return UDPh.HLEN;
    },
    printDetails: function (pkt_num, prefix) {
        var details = document.createElement('div');
        details.setAttribute('class','udp');
        var check = document.createElement('input');
        check.setAttribute('type','checkbox');  
        check.setAttribute('id', prefix + 'ud');
        var hidden = document.createElement('div');
        var label = document.createElement('label');
        var icon = document.createElement('span');
        icon.setAttribute('class', 'dropdown');
        label.setAttribute('for', prefix + 'ud');
        label.appendChild(icon);
        label.innerHTML += 'User Datagram Protocol';
        details.appendChild(check);
        details.appendChild(label);   
         
        hidden.innerHTML = 'Source port: ' + this.sport + '</br>'
                         + 'Destination port: ' + this.dport + '</br>'
                         + 'Length: ' + this.len + '</br>'                    
                         + 'Checksum: 0x' + printNum(this.csum, 16, 4) + '</br>';
        
        details.appendChild(hidden);
        
        return details;
    },
    toString: function () {
        return 'SRC Port: '+this.sport+
              ' DST Port: '+this.dport;
    }
};

UDPh.HLEN = 8; // UDP header length in bytes  

if (typeof module !== 'undefined')
    module.exports = UDPh;
