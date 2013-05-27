/*
 ******************************************************************
 ************************* PCAP HEADER ****************************
 ******************************************************************
 */

//note: this is basically copied over from the wireshark wiki
function Pcaph(data, offset) {
    data = data.slice(offset);
    var intView  = new Uint32Array(data, 0, Pcaph.HLEN / 4);
    
    this.ts_sec   = intView[0];  // timestamp seconds
    this.ts_usec  = intView[1];  // timestamp microseconds
    this.incl_len = intView[2];  // number of octets of packet saved in file
    this.orig_len = intView[3];  // actual length of packet
    
    this.next_header = null;
}

Pcaph.prototype = {
    getHeaderLength: function() {
        return Pcaph.HLEN;
    },
    printDetails: function(pkt_num) {
        var details = document.createElement("div");
        details.setAttribute("class","pcap");
        var check = document.createElement("input");
        check.setAttribute("type","checkbox");  
        check.setAttribute("id","pd");
        var hidden = document.createElement("div");
        var label = document.createElement("label");
        var icon = document.createElement("span");
        label.setAttribute("for","pd");
        label.appendChild(icon);
        label.innerHTML += "General Information";
        details.appendChild(check);
        details.appendChild(label);        
        
        hidden.innerHTML += "Arrival Time: " + printDate(new Date(this.ts_sec * 1000)) + "." + printNum(this.ts_usec, 10, 6) + "</br>";
        hidden.innerHTML += "Frame Length: " + this.incl_len + " bytes (" + (this.incl_len * 8) + " bits)</br>";
        hidden.innerHTML += "Captured Length: " + this.orig_len + " bytes (" + (this.orig_len * 8) + " bits)</br>";
        
        details.appendChild(hidden);
        
        return details;
    },
    toString: function() {
        return "";
    }
};

Pcaph.HLEN = 16; // pcap header length in bytes
/*
 ******************************************************************
 ****************** LINK-LAYER HEADER TYPES ***********************
 ******************************************************************
 */

function Ethh(data, offset) {
    data = data.slice(offset);
    var byteView  = new  Uint8Array(data, 0, Ethh.HLEN);
    var shortView = new Uint16Array(data, 2 * Ethh.ALEN, 1);
    
    this.dst  = byteView.subarray(0, 6);  // destination MAC address
    this.src  = byteView.subarray(6, 12); // source MAC address    
    this.prot = ntohs(shortView[0]);      // protocol (i.e. IPv4)
    
    this.next_header = null;    
}

Ethh.prototype = {
    getHeaderLength: function() {
        return Ethh.HLEN;
    },
    printDetails: function(pkt_num) {
        var details = document.createElement("div");
        details.setAttribute("class","eth");
        var check = document.createElement("input");
        check.setAttribute("type","checkbox");  
        check.setAttribute("id","ed");
        var hidden = document.createElement("div");
        var label = document.createElement("label");
        var icon = document.createElement("span");
        label.setAttribute("for","ed");
        label.appendChild(icon);
        label.innerHTML += "Ethernet II";
        details.appendChild(check);
        details.appendChild(label);   
                
        hidden.innerHTML  = "Destination: " + Ethh.printMAC(this.dst) + "</br>";
        hidden.innerHTML += "Source: " + Ethh.printMAC(this.src) + "</br>";
        hidden.innerHTML += "Type: " + Ethh.printEtherType(this.prot) + " (0x" + printNum(this.prot, 16, 4) + ")</br>";
        
        details.appendChild(hidden);
        
        return details;
    },
    toString: function() {
        return "From: "+Ethh.printMAC(this.src)+
               " To: " +Ethh.printMAC(this.dst);
    }
};

Ethh.HLEN = 14; // Ethernet frame length in bytes
Ethh.ALEN = 6;  // MAC address length in bytes

// FIXME: check params for consistency
Ethh.printMAC = function(mac) {
    var output = printNum(mac[0], 16, 2);
    for (i = 1; i < mac.length; i++)
        output += ":" + printNum(mac[i], 16, 2);
    return output;
};
Ethh.printEtherType = function(type) {
    switch(type) {
        case 0x0800: return "IPv4";
        case 0x0806: return "ARP";
        case 0x0842: return "Wake-on-LAN";
        case 0x8035: return "RARP";
        case 0x8137: return "IPX";
        case 0x8138: return "IPX";
        case 0x86DD: return "IPv6";
        case 0x8808: return "Ethernet flow control";
        default:     return "Unknown";
    }
}

// FIXME: add 802.11 support

/*
 ******************************************************************
 ***************** NETWORK LAYER HEADER TYPES *********************
 ******************************************************************
 */

function IPv4h(data, offset) {
    data = data.slice(offset);
    var byteView  = new  Uint8Array(data, 0, IPv4h.HLEN);
    var shortView = new Uint16Array(data, 0, IPv4h.HLEN / 2);
    
    this.v    = byteView[0] >> 4;             // version
    this.hl   = byteView[0] & 0x0F;           // IP header length
    this.tos  = byteView[1];                  // type of service
    this.tlen = ntohs(shortView[1]);          // total length
    this.id   = ntohs(shortView[2]);          // identification
    this.frag = ntohs(shortView[3]);          // fragmentation flags & offset
    this.off  = ntohs(shortView[3]) & 0x1FFF; // fragmentation offset
    this.ttl  = byteView[8];                  // time to live
    this.prot = byteView[9];                  // protocol (i.e. TCP)
    this.csum = ntohs(shortView[5]);          // header checksum
    this.src  = byteView.subarray(12, 16);    // source IPv4 address
    this.dst  = byteView.subarray(16, 20);    // destination IPv4 address
    /* various options may follow; it is virtually impossible
     * though to specify them within this struct */
        
    this.next_header = null;
}

IPv4h.prototype = {
    getHeaderLength: function() {
        return 4 * this.hl;
    },
    printDetails: function(pkt_num) {
        var details = document.createElement("div");
        details.setAttribute("class","ip");
        var check = document.createElement("input");
        check.setAttribute("type","checkbox");  
        check.setAttribute("id","i4d");
        var hidden = document.createElement("div");
        var label = document.createElement("label");
        var icon = document.createElement("span");
        label.setAttribute("for","i4d");
        label.appendChild(icon);
        label.innerHTML += "Internet Protocol Version 4";
        details.appendChild(check);
        details.appendChild(label);   
         
        hidden.innerHTML = "Version: " + this.v + "</br>"
                         + "Header length: " + this.getHeaderLength() + "</br>"
                         + "Differentiated Services Field: 0x" + printNum(this.tos, 16, 2) + "</br>"
                         + "Total Length: " + this.tlen + "</br>"
                         + "Identification: 0x" + printNum(this.id, 16, 4) + " (" + this.id + ")</br>"
                         // FIXME
        //                  += "Flags: " +  + "</br>"
                         + "Fragment offset: " + this.off + "</br>"
                         + "Time to live: " + this.ttl + "</br>"
                         + "Protocol: " + this.prot + "</br>"
                         + "Header checksum: 0x" + printNum(this.csum, 16, 4) + "</br>"
                         + "Source: " + IPv4h.printIP(this.src) + "</br>"
                         + "Destination: " + IPv4h.printIP(this.dst) + "</br>";

        details.appendChild(hidden);
        
        return details;
    },
    toString: function() {
        return "";
    }
};

IPv4h.HLEN = 20; // IPv4 minimum header length in bytes 
IPv4h.ALEN = 4;  // IPv4 address length in bytes

// FIXME: check params for consistency
IPv4h.printIP = function(ip) {
    var output = ip[0];
    for (i = 1; i < ip.length; i++)
        output += "."+ip[i];
    return output;    
}

function IPv6h(data, offset) {
    data = data.slice(offset);
    var byteView  = new  Uint8Array(data, 0, IPv6h.HLEN);
    var shortView = new Uint16Array(data, 0, IPv6h.HLEN / 2);
    
    this.v = (byteView[0] & 0xF0) >> 4;     // version
    this.v_tc_fl = byteView.subarray(0, 4); // version, traffic class, flow label
    this.plen = ntohs(shortView[2]);        // payload length
    this.nh = byteView[6];                  // next header; same as protocol for ipv4h
    this.hlim = byteView[7];                // hop limit
    this.src = shortView.subarray(4, 12);   // source IPv6 address
    this.dst = shortView.subarray(12, 20);  // destination IPv6 address
        
    this.next_header = null;
}

IPv6h.prototype = {
    getHeaderLength: function() {
        return IPv6.HLEN;
    },
    printDetails: function(pkt_num) {
        var details = document.createElement("div");
        details.setAttribute("class","ip");
        var check = document.createElement("input");
        check.setAttribute("type","checkbox");  
        check.setAttribute("id","i6d");
        var hidden = document.createElement("div");
        var label = document.createElement("label");
        var icon = document.createElement("span");
        label.setAttribute("for","i6d");
        label.appendChild(icon);
        label.innerHTML += "Internet Protocol Version 6";
        details.appendChild(check);
        details.appendChild(label);   
         
        hidden.innerHTML = "Version: " + this.v + "</br>"
                         // FIXME traffic class & flow label
                         + "Payload length: " + this.plen + "</br>"
                         + "Next header: " + this.nh + "</br>"
                         + "Hop limit " + this.hlim + "</br>"
                         + "Source: " + IPv6h.printIP(this.src) + "</br>"
                         + "Destination: " + IPv6h.printIP(this.dst) + "</br>";

        details.appendChild(hidden);
        
        return details;
    },
    toString: function() {
        return "";
    }
};

IPv6h.HLEN = 40; // IPv6 header length in bytes
IPv6h.ALEN = 8;  // IPv6 address length in shorts

// FIXME: check params for consistency
IPv6h.printIP = function(ip) {
    var output = printNum(ip[0], 16, 2);
    for (i = 1; i < ip.length; i++)
        output += ":" + printNum(ip[i], 16, 2);
    return output;
};

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
    getHeaderLength: function() {
        return ARPh.HLEN + 2*this.hlen + 2*this.plen;
    },
    printDetails: function(pkt_num) {
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
    toString: function() {
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

// FIXME: add RARP support (amongst others)

/*
 ******************************************************************
 *************** TRANSPORT LAYER HEADER TYPES *********************
 ******************************************************************
 */

function TCPh(data, offset) {
    data = data.slice(offset);
    var shortView = new Uint16Array(data, 0, TCPh.HLEN / 2);
    var intView   = new Uint32Array(data, 0, TCPh.HLEN / 4);
    
    this.sport    = ntohs(shortView[0]); // source port
    this.dport    = ntohs(shortView[1]); // destination port
    this.seqn     = ntohl(intView[1]);   // sequence number
    this.ackn     = ntohl(intView[2]);   // ACK number
    // FIXME: maybe split the following in two chars?
    this.off_flag = shortView[6]; // data offset, reserved portion, flags
    this.wsize    = ntohs(shortView[7]); // window size
    this.csum     = ntohs(shortView[8]); // header checksum
    this.urg      = ntohs(shortView[9]); // urgent pointer
    /* various options may follow; it is virtually impossible
     * though to specify them within this struct */
        
    this.next_header = null;
}

TCPh.prototype = {
    getHeaderLength: function() {
        return 4 * ((ntohs(this.off_flag)) >> 12);
    },
    printDetails: function(pkt_num) {
        var details = document.createElement("div");
        details.setAttribute("class","tcp");
        var check = document.createElement("input");
        check.setAttribute("type","checkbox");  
        check.setAttribute("id","td");
        var hidden = document.createElement("div");
        var label = document.createElement("label");
        var icon = document.createElement("span");
        label.setAttribute("for","td");
        label.appendChild(icon);
        label.innerHTML += "Transmission Control Protocol";
        details.appendChild(check);
        details.appendChild(label);   
         
        hidden.innerHTML = "Source port: " + this.sport + "</br>"
                         + "Destination port: " + this.dport + "</br>"
                         + "Sequence number: " + this.seqn + "</br>"
                         + "Acknowledgment number: " + this.ackn + "</br>"
                         + "Header length: " + this.getHeaderLength() + "</br>"
                         // FIXME
                         // + "Flags: " +  + "</br>"
                         + "Window size value: " + this.wsize + "</br>"                         
                         + "Checksum: 0x" + printNum(this.csum, 16, 4) + "</br>";
                         // FIXME options
                         
        var follow = document.createElement("a");
        follow.setAttribute("onclick","filterTCPConn(" + pkt_num + ")");
        if (tcp_filter)
            follow.innerHTML = "Unfollow";
        else
            follow.innerHTML = "Follow";
        hidden.appendChild(follow);
        
        details.appendChild(hidden);
        
        return details;
    },
    toString: function() {
        return "SRC Port: "+this.sport+
              " DST Port: "+this.dport;
    }
};

TCPh.HLEN = 20; // TCP minimum header length in bytes

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
    getHeaderLength: function() {
        return UDPh.HLEN;
    },
    printDetails: function(pkt_num) {
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
    toString: function() {
        return "SRC Port: "+this.sport+
              " DST Port: "+this.dport;
    }
};

UDPh.HLEN = 8; // UDP header length in bytes

// FIXME: add ICMP support (amongst others)

/*
 ******************************************************************
 *************** APPLICATION LAYER HEADER TYPES *******************
 ******************************************************************
 */
// FIXME: There's nothing as of yet