'use strict';

if (typeof require !== 'undefined') {
    var printMAC = require('./ethernet').printMAC;
    var printIPv4 = require('./ipv4').printIPv4;
    var printIPv6 = require('./ipv6').printIPv6;
}
/*
 ******************************************************************
 ************************** DNS HEADER ****************************
 ******************************************************************
 */

function DNS(littleEndian, dataView, offset, parent) {
    this.id = dataView.getUint16(offset, littleEndian);
    this.flags = dataView.getUint16(offset + 2, littleEndian);
    this.questionCount = dataView.getUint16(offset + 4, littleEndian);
    this.answerCount = dataView.getUint16(offset + 6, littleEndian);
    this.authorityCount = dataView.getUint16(offset + 8, littleEndian);
    this.additionalCount = dataView.getUint16(offset + 10, littleEndian);
    
    if (this.questionCount === 0)
        alert('there is your what the fuck situation')
    
    this.QR     = this.flags & 0x8000 && 1;
    this.opcode = this.flags & 0x7800 >>> 11;
    this.AA     = this.flags & 0x0400 && 1;
    this.TC     = this.flags & 0x0200 && 1;
    this.RD     = this.flags & 0x0100 && 1;
    this.RA     = this.flags & 0x0080 && 1;
    this.Z      = this.flags & 0x0040 && 1;
    this.AD     = this.flags & 0x0020 && 1;
    this.CD     = this.flags & 0x0010 && 1;
    this.rCode  = this.flags & 0x000F;
    
    this.offset = offset; // for pointers
    
    this.dissectResourceRecords(littleEndian, dataView, 
                                offset + DNS.MIN_HEADER_LENGTH);
    
    this.next_header = null;
}

DNS.prototype = {
    getHeaderLength: function () {
        return DNS.MIN_HEADER_LENGTH;
    },
    printDetails: function (pkt_num) {
        var details = document.createElement('div');
        var check = document.createElement('input');
        check.setAttribute('type','checkbox');  
        check.setAttribute('id', 'dnsd');
        var hidden = document.createElement('div');
        var label = document.createElement('label');
        var icon = document.createElement('span');
        icon.setAttribute('class', 'dropdown glow');
        label.setAttribute('for', 'dnsd');
        label.appendChild(icon);
        label.innerHTML += 'Domain Name System';
        details.appendChild(check);
        details.appendChild(label);   
         
        hidden.innerHTML = 'Transaction ID: 0x' + printNum(this.id, 16, 4) + '</br>'
                         // FIXME
        //                  += 'Flags: ' +  + '</br>'
                         + 'Questions: ' + this.questionCount + '</br>' 
                         + 'Answer RRs: ' + this.answerCount + '</br>'
                         + 'Authority RRs: ' + this.authorityCount + '</br>'
                         + 'Additional RRs: ' + this.additionalCount + '</br>';
            
        if (this.questionCount) {
            for (var i = 0; i < this.questionCount; i++) {
                hidden.innerHTML += this.questions[i].name + '</br>'
                                 + this.questions[i].type + '</br>'
                                 + this.questions[i].class+ '</br>';
            }
        }
        if (this.answerCount) {
            for (var i = 0; i < this.answerCount; i++) {
                hidden.innerHTML += this.answers[i].name + '</br>'
                                 + this.answers[i].type + '</br>'
                                 + this.answers[i].class+ '</br>'
                                 + printTime(this.answers[i].ttl)+ '</br>'
                                 + this.answers[i].rdLength+ '</br>'
                                 + this.answers[i].rData+ '</br>';
            }
        }
                if (this.authorityCount) {
            for (var i = 0; i < this.authorityCount; i++) {
                hidden.innerHTML += this.authorities[i].name + '</br>'
                                 + this.authorities[i].type + '</br>'
                                 + this.authorities[i].class+ '</br>';
            }
        }
                if (this.additionalCount) {
            for (var i = 0; i < this.additionalCount; i++) {
                hidden.innerHTML += this.additions[i].name + '</br>'
                                 + this.additions[i].type + '</br>'
                                 + this.additions[i].class+ '</br>';
            }
        }

        details.appendChild(hidden);
        
        return details;
    }
};

DNS.prototype.toString = function () {
    var resourceRecordStrings = ''; // suffix of the string, either add ...
    
    // ... all answers
    if (this.QR && this.answers) {
        for (var i = 0; i < this.answers.length; i++) {
            resourceRecordStrings += DNS.TYPES[this.answers[i].type] + ' '
            + this.answers[i].rData;                
        }
    }
    // ... or all questions
    else if (this.questions) {
        for (var i = 0; i < this.questions.length; i++) {
            resourceRecordStrings += DNS.TYPES[this.questions[i].type] + ' '
                                    + this.questions[i].name;                
        }
    }
    
    return (DNS.OPCODES[this.opcode] || '') + (this.QR ? 'response ' : '') +
            printNum(this.id, 16, 4) + '  ' + resourceRecordStrings;
}

DNS.prototype.dissectResourceRecords = function (littleEndian, dataView, offset) 
{
    var tuple;
    
    if (this.questionCount)
        this.questions = [];
    if (this.answerCount)
        this.answers = [];
    if (this.authorityCount)
        this.authorities = [];
    if (this.additionalCount)
        this.additions = [];
        
    for (var i = 0; i < this.questionCount; i++) {
        tuple = this.nextResourceRecord(littleEndian, dataView, offset, true);
        this.questions.push(tuple.resourceRecord);
        offset = tuple.offset;
    }
    for (var i = 0; i < this.answerCount; i++) {
        tuple = this.nextResourceRecord(littleEndian, dataView, offset);
        this.answers.push(tuple.resourceRecord);
        offset = tuple.offset;
    }
    for (var i = 0; i < this.authorityCount; i++) {
        tuple = this.nextResourceRecord(littleEndian, dataView, offset);
        this.authorities.push(tuple.resourceRecord);
        offset = tuple.offset;
    }
    for (var i = 0; i < this.additionalCount; i++) {
        tuple = this.nextResourceRecord(littleEndian, dataView, offset);
        this.additions.push(tuple.resourceRecord);
        offset = tuple.offset;
    }
}

DNS.prototype.nextResourceRecord = function (littleEndian, dataView, offset, 
                                             question) 
{
    var resourceRecord = {};
    var tuple
    
    // get NAME value
    tuple = this.getName(littleEndian, dataView, offset);
    resourceRecord.name = tuple.name;
    offset = tuple.offset; // offset calculated by getName
    
    // get TYPE value
    resourceRecord.type = dataView.getUint16(offset, littleEndian);
    offset += 2;
    
    // get CLASS value
    resourceRecord.class = dataView.getUint16(offset, littleEndian);
    offset += 2;
    
    if (question) // no more data when this is a question
        return {resourceRecord: resourceRecord, offset: offset};
    
    // get TTL 
    resourceRecord.ttl = dataView.getUint32(offset, littleEndian);
    offset += 4;
    
    // get RDLENGTH
    resourceRecord.rdLength = dataView.getUint16(offset, littleEndian);
    offset += 2;
    
    // FIXME: only A, AAAA and CNAME supported as yet
    switch (resourceRecord.type) {
    case DNS.A:
        resourceRecord.rData = printIPv4(new DataView(dataView.buffer, offset, 4));
        break;
    case DNS.AAAA:
        resourceRecord.rData = printIPv6(new DataView(dataView.buffer, offset, 16));
        break;
    case DNS.CNAME:
        resourceRecord.rData = this.getName(littleEndian, dataView, offset).name;
        break;
    default:
        resourceRecord.rData = '';
        break;        
    }
    offset += resourceRecord.rdLength;
    
    return {resourceRecord: resourceRecord, offset: offset};
}

DNS.prototype.getName = function (littleEndian, dataView, offset) {
    var name = [];
    var namePart = '';
    var currentByte;

    while ((currentByte = dataView.getUint8(offset)) !== 0x00) {
        if ((currentByte & 0xc0) === 0xc0) { // pointer
            // get name pointed at...
            name.push(this.getName(littleEndian, dataView, this.offset 
                + (dataView.getUint16(offset, littleEndian) & ~0xc000)).name);
            
            offset += 2;
            // and then immediately return
            return {name: name.join('.'), offset: offset};
        }
        for (var i = 1; i <= currentByte; i++)
            namePart += String.fromCharCode(dataView.getUint8(offset + i));
        
        offset += currentByte + 1; // add length of namePart to offset
        name.push(namePart);
        namePart = '';
    }
    offset++; // skip the 0x00 byte
    
    return {name: name.join('.'), offset: offset};
}

DNS.MIN_HEADER_LENGTH = 12; // initial dns header size in bytes
DNS.A    = 0x0001;
DNS.AAAA = 0x001c;
DNS.OPCODES = ['Standard Query ', 'Inverse Query ', 'Status ', '', 'Notify ',
               'Update '];
DNS.TYPES = [];

if (typeof module !== 'undefined') {
    module.exports.DNS = DNS;
} 
