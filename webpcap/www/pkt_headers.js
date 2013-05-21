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
}

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
}

Ethh.prototype = {
    toString: function() {
        return "From: "+this.dst[0].toString(16)+":"+this.dst[1].toString(16)
        +":"+this.dst[2].toString(16)+":"+this.dst[3].toString(16)+":"
        +this.dst[4].toString(16)+":"+this.dst[5].toString(16)+" To: ";
    }
};

Ethh.HLEN = 14; // Ethernet frame length in bytes
Ethh.ALEN = 6;  // MAC address length in bytes

// FIXME: check params for consistency
Ethh.printMAC = function(mac) {
    var output = mac[0].toString(16);
    for (i = 1; i < mac.length; i++)
        output += ":"+mac[i].toString(16);
    return output;
};

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
    
    this.v_hl = byteView[0];               // version & IP header length
    this.tos  = byteView[1];               // type of service
    this.tlen = ntohs(shortView[1]);       // total length
    this.id   = ntohs(shortView[2]);       // identification
    this.frag = ntohs(shortView[3]);       // fragmentation flags & offset
    this.ttl  = byteView[8];               // time to live
    this.prot = byteView[9];               // protocol (i.e. TCP)
    this.csum = ntohs(shortView[5]);       // header checksum
    this.src  = byteView.subarray(12, 16); // source IPv4 address
    this.dst  = byteView.subarray(16, 20); // destination IPv4 address
    /* various options may follow; it is virtually impossible
     * though to specify them within this struct */
}

IPv4h.prototype = {
    getHeaderLength: function() {
        return 4 * (this.v_hl & 0x0F);
    },
    toString: function() {
        return "From: "+this.src[0]+"."+this.src[1]+"."+this.src[2]+"."+this.src[3]+"  "+
               "To: "+this.dst[0]+"."+this.dst[1]+"."+this.dst[2]+"."+this.dst[3];
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
    
    this.v_tc_fl = byteView.subarray(0, 4); // version, traffic class, flow label
    this.plen = shortView[2];               // payload length
    this.nh = byteView[6];                  // next header; same as protocol for ipv4h
    this.hlim = byteView[7];                // hop limit
    this.src = shortView.subarray(4, 12);   // source IPv6 address
    this.dst = shortView.subarray(12, 20);  // destination IPv6 address
}

IPv6h.HLEN = 40; // IPv6 header length in bytes
IPv6h.ALEN = 8;  // IPv6 address length in shorts

function ARPh(data, offset) {
    data = data.slice(offset);
    var byteView  = new  Uint8Array(data, 0, ARPh.HLEN);
    var shortView = new Uint16Array(data, 0, ARPh.HLEN / 2);
    
    this.htype = ntohs(shortView[0]);
    this.ptype = ntohs(shortView[1]);
    this.hlen  = byteView[4];
    this.plen  = byteView[5];
    this.op    = ntohs(shortView[3]);
    
    offset =  ARPh.HLEN;
    this.sha   = new Uint8Array(data, offset, this.hlen);
    offset += this.hlen;
    this.spa   = new Uint8Array(data, offset, this.plen);
    offset += this.plen;
    this.tha   = new Uint8Array(data, offset, this.hlen);
    offset += this.hlen;
    this.tpa   = new Uint8Array(data, offset, this.plen);
}

ARPh.prototype = {
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
    this.seqn     = intView[1];   // sequence number
    this.ackn     = intView[2];   // ACK number
    // FIXME: maybe split the following in two chars?
    this.off_flag = shortView[6]; // data offset, reserved portion, flags
    this.wsize    = shortView[7]; // window size
    this.csum     = shortView[8]; // header checksum
    this.urg      = shortView[9]; // urgent pointer
    /* various options may follow; it is virtually impossible
     * though to specify them within this struct */
}

TCPh.prototype = {
    getHeaderLength: function() {
        return 4 * ((ntohs(this.off_flag)) >> 12);
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
}

UDPh.prototype = {
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