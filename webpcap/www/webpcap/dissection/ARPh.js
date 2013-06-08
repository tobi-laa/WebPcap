/*
 ******************************************************************
 ************************** ARP HEADER ****************************
 ******************************************************************
 */

function ARPh(data, offset) {
    data = data.slice(offset);
    var byteView  = new  Uint8Array(data, 0, ARPh.HLEN);
    var shortView = new Uint16Array(data, 0, ARPh.HLEN / 2);
    
    this.htype = ntohs(shortView[0]);
    this.ptype = ntohs(shortView[1]);
    this.hlen  = byteView[4];
    this.plen  = byteView[5];
    this.op    = ntohs(shortView[3]);
    
    offset   = ARPh.HLEN;
    this.sha = new Uint8Array(data, offset, this.hlen);
    offset  += this.hlen;
    this.spa = new Uint8Array(data, offset, this.plen);
    offset  += this.plen;
    this.tha = new Uint8Array(data, offset, this.hlen);
    offset  += this.hlen;
    this.tpa = new Uint8Array(data, offset, this.plen);
        
    this.next_header = null;
}

ARPh.prototype = {
    getHeaderLength: function () {
        return ARPh.HLEN + 2*this.hlen + 2*this.plen;
    },
    printDetails: function (pkt_num) {
        var details = document.createElement("div");
        details.setAttribute("class","arp");
        var check = document.createElement("input");
        check.setAttribute("type","checkbox");  
        check.setAttribute("id","ad");
        var hidden = document.createElement("div");
        var label = document.createElement("label");
        var icon = document.createElement("span");
        label.setAttribute("for","ad");
        label.appendChild(icon);
        label.innerHTML += "Address Resolution Protocol";
        details.appendChild(check);
        details.appendChild(label);   
         
        // FIXME FIXME obviously not always IP & MAC... also show whether query or reply etc
        hidden.innerHTML = "Hardware type: " + this.htype + "</br>"
                         + "Protocol type: " + Ethh.printEtherType(this.ptype) + " (0x" + printNum(this.ptype, 16, 4) + ")</br>"
                         + "Hardware size: " + this.hlen + "</br>"
                         + "Protocol size: " + this.plen + "</br>"
                         + "Opcode: " + this.op + "</br>"
                         + "Sender MAC address: " + Ethh.printMAC(this.sha) + "</br>"                         
                         + "Sender IP address: " + IPv4h.printIP(this.spa) + "</br>"
                         + "Target MAC address: " + Ethh.printMAC(this.tha) + "</br>"                         
                         + "Target IP address: " + IPv4h.printIP(this.tpa) + "</br>";

        details.appendChild(hidden);
        
        return details;
    },
    toString: function () {
        if (this.op == 1) { // ARP query
            if (this.ptype == 0x0800)
                return "Who has "+IPv4h.printIP(this.tpa)+"? Tell "+IPv4h.printIP(this.spa);
            else
                return "ARP Query";
        }
        if (this.op == 2) {// ARP reply
            if (this.ptype == 0x0800 && this.htype == 1)
                return IPv4h.printIP(this.spa)+" is at "+Ethh.printMAC(this.sha);
            else
                return "ARP Reply";
        }
    }
}

ARPh.HLEN = 8; // beginning (!) of ARP header length in bytes