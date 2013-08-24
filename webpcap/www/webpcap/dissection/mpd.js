'use strict';

/*
 ******************************************************************
 * this dissector was added 'just for fun', it's not a popular    *
 * protocol                                                       *
 ******************************************************************
 */

function MPD(littleEndian, packet, data, offset, parent) {
    data = data.buffer;
    this.success = true; // indicator for successful dissection
    
    if (data.byteLength - offset < 2)
        return;
    
    var cmds = String.fromCharCode.apply(null, new Uint8Array(data, offset));

    if ((cmds.indexOf('OK', cmds.length - 3) === cmds.length - 3) ||
        (cmds.indexOf('ACK', cmds.length - 4) === cmds.length - 4)) {
        this.type = 'Response';     
        this.processHeaders(cmds);
    }
    else if ((cmds.indexOf('status', cmds.length - 7) === cmds.length - 7) ||
             (cmds.indexOf('idle', cmds.length - 5) === cmds.length - 5)) {
        this.type = 'Command';
        this.processHeaders(cmds);
    }
    else {
        this.success = false;
        return; // stop right here
    }
    
    // set general information
    packet.prot = packet.class = 'MPD';
    packet.info = this.toString();
    
    this.next_header = null;
}

MPD.prototype = {
    processHeaders: function (cmds) {
        var tokens = cmds.split('\n');
        
        this.headers = [];
        
        var i;
        for (i = 0; i < tokens.length - 1; i++) // skip the empty string
            this.headers.push(tokens[i]);
        
        this.type += ': ' + this.headers[--i];
    },
    printDetails: function (pkt_num) {
        var details = document.createElement('div');
        details.setAttribute('class','http');
        var check = document.createElement('input');
        check.setAttribute('type','checkbox');  
        check.setAttribute('id', 'mpd');
        var hidden = document.createElement('div');
        var label = document.createElement('label');
        var icon = document.createElement('span');
        icon.setAttribute('class', 'dropdown glow');
        label.setAttribute('for', 'mpd');
        label.appendChild(icon);
        label.innerHTML += 'Music Player Daemon Protocol';
        details.appendChild(check);
        details.appendChild(label);
        
        hidden.innerHTML = this.type + '</br>';
        
        for (var i = 0; i < this.headers.length - 1; i++)
            hidden.innerHTML += this.headers[i] + '</br>';
                                 
        details.appendChild(hidden);
        
        return details;
    },
    toString: function () {
        return this.type;
    }
};

if (typeof module !== 'undefined') {
    module.exports.MPD = MPD;
}