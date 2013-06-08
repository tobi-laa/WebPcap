/*
 ******************************************************************
 ************************** UDP HEADER ****************************
 ******************************************************************
 */

function UDPh(data, offset) {
    data = data.slice(offset);
    var shortView = new Uint16Array(data, 0, UDPh.HLEN / 2);
    
    this.sport = ntohs(shortView[0]); // source port
    this.dport = ntohs(shortView[1]); // destination port
    this.len   = ntohs(shortView[2]); // length of payload incl. UDP header
    this.csum  = ntohs(shortView[3]); // header checksum
        
    this.next_header = null;
}

UDPh.prototype = {
    getHeaderLength: function () {
        return UDPh.HLEN;
    },
    printDetails: function (pkt_num) {
        var details = document.createElement("div");
        details.setAttribute("class","udp");
        var check = document.createElement("input");
        check.setAttribute("type","checkbox");  
        check.setAttribute("id","ud");
        var hidden = document.createElement("div");
        var label = document.createElement("label");
        var icon = document.createElement("span");
        label.setAttribute("for","ud");
        label.appendChild(icon);
        label.innerHTML += "User Datagram Protocol";
        details.appendChild(check);
        details.appendChild(label);   
         
        hidden.innerHTML = "Source port: " + this.sport + "</br>"
                         + "Destination port: " + this.dport + "</br>"
                         + "Length: " + this.len + "</br>"                    
                         + "Checksum: 0x" + printNum(this.csum, 16, 4) + "</br>";
        
        details.appendChild(hidden);
        
        return details;
    },
    toString: function () {
        return "SRC Port: "+this.sport+
              " DST Port: "+this.dport;
    }
};

UDPh.HLEN = 8; // UDP header length in bytes  