/*
 ******************************************************************
 ************************* HTTP HEADER ****************************
 ******************************************************************
 */

function HTTPh(data, offset, parent) {
    if (data.byteLength - offset < 4)
        return;
    
    var byteView = new Uint8Array(data, offset, 4);

    switch(String.fromCharCode.apply(null, byteView)) {
    case 'GET ':
    case 'HEAD':
    case 'POST':
        this.type = 'Request';
        processHeaders(this, new Uint8Array(data, offset));
        break;
    case 'HTTP':
        this.type = 'Response';
        processHeaders(this, new Uint8Array(data, offset));
        break;
    }
    
    this.next_header = null;
}

HTTPh.prototype = {
    getHeaderLength: function () {
        return this.hlen;
    },
    printDetails: function (pkt_num, prefix) {
        var details = document.createElement('div');
        details.setAttribute('class','http');
        var check = document.createElement('input');
        check.setAttribute('type','checkbox');  
        check.setAttribute('id', prefix + 'hd');
        var hidden = document.createElement('div');
        var label = document.createElement('label');
        var icon = document.createElement('span');
        icon.setAttribute('class', 'dropdown glow');
        label.setAttribute('for', prefix + 'hd');
        label.appendChild(icon);
        label.innerHTML += 'Hypertext Transfer Protocol';
        details.appendChild(check);
        details.appendChild(label);   
         
        hidden.innerHTML = 'Header length: ' + this.hlen + '</br>';
        
        for (var i = 0; i < this.headers.length; i++)
            hidden.innerHTML += this.headers[i] + '</br>';
                                 
        details.appendChild(hidden);
        
        return details;
    },
    toString: function () {
        return this.headers[0];
    }
};

function processHeaders(httph, byteView) {
    var tokens = String.fromCharCode.apply(null, byteView).split('\r\n');
    
    httph.hlen = 0
    httph.headers = [];
    
    for (var i = 0; i < tokens.length; i++) {
        if (tokens[i].length === 0) {
            httph.hlen += 2;
            return;
        }
        httph.hlen += tokens[i].length + 2;
        httph.headers.push(tokens[i]);
    }
}