'use strict';

if (typeof require !== 'undefined') {
    var readCSVFile = require('../fileio').readCSVFile;
    var IPv4 = require('./ipv4').IPv4;
    var IPv6 = require('./ipv6').IPv6;
    IPv4.printIP = require('./ipv4').printIP;
    IPv6.printIP = require('./ipv6').printIP;
    var Ethernet = require('./ethernet').Ethernet;
    Ethernet.TYPES = require('./ethernet').TYPES;
    Ethernet.printMAC = require('./ethernet').printMAC;
}

function DNS(littleEndian, packet, dataView, offset, parent) {
    this.success = true; // indicator for successful dissection
    
    this.id = dataView.getUint16(offset, littleEndian);
    this.flags = dataView.getUint16(offset + 2, littleEndian);
    this.questionCount = dataView.getUint16(offset + 4, littleEndian);
    this.answerCount = dataView.getUint16(offset + 6, littleEndian);
    this.authorityCount = dataView.getUint16(offset + 8, littleEndian);
    this.additionalCount = dataView.getUint16(offset + 10, littleEndian);
    
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
    
    // initialize objects for rr dissection    
    this.offset = offset; // for pointers
    this.questions = [];
    this.otherRecords = [[], [], []]; // answers, authorities, additions
    this.otherRecordsLen = [this.answerCount, this.authorityCount, 
                            this.additionalCount];
    
    this.dissectResourceRecords(littleEndian, dataView, 
                                offset + DNS.MIN_HEADER_LENGTH);
    
    // set general information
    packet.class = packet.prot = 'DNS';
    packet.info = this.toString();
    
    this.next_header = null;
}

DNS.prototype.getHeaderLength = function () {
    return DNS.MIN_HEADER_LENGTH;
}

DNS.prototype.printDetails = function () {
    var title = 'Domain Name System';
    var nodes = [];
    // for nested entries
    var nestedNodes = [];
    var nestedNode;
    
    // put the general information first to the beginning
    nodes.push(document.createTextNode(
        [
            'Transaction ID: 0x' + printNum(this.id, 16, 4),
            // NOTE show flags as well
            'Questions: ' + this.questionCount,
            'Answer RRs: ' + this.answerCount,
            'Authority RRs: ' + this.authorityCount,
            'Additional RRs: ' + this.additionalCount
        ].join('\n')
    ));
    
    // now create nested entries for resource records
    for (var i = 0; i < this.questionCount; i++) {
        nestedNode = document.createTextNode(
            [
                'Name: ' + this.questions[i].name,
                'Type: ' + DNS.TYPES[this.questions[i].type],
                'Class: ' + DNS.CLASSES[this.questions[i].class]
            ].join('\n'));
        
        nestedNodes.push(createDetails(this.questions[i].name, 
                                        [nestedNode]));
    }
    
    nodes.push(createDetails('Queries', nestedNodes));
    
    for (var j = 0; j < this.otherRecords.length; j++) {
        if (!this.otherRecordsLen[j]) // skip empty arrays
            continue;
        
        nestedNodes = [];
        
        for (var i = 0; i < this.otherRecordsLen[j]; i++) {            
            nestedNode = document.createTextNode(
                [
                    'Name: ' + this.otherRecords[j][i].name,
                    'Type: ' + DNS.TYPES[this.otherRecords[j][i].type],
                    'Class: ' + DNS.CLASSES[this.otherRecords[j][i].class],
                    'Time to live: ' + printTime(this.otherRecords[j][i].ttl),
                    'Data length: ' + this.otherRecords[j][i].rdLength,
                    // NOTE empty string when unsupported
                    'Data: ' + this.otherRecords[j][i].rData
                ].join('\n'));
            
            nestedNodes.push(createDetails(this.questions[i].name, 
                                            [nestedNode]));
        }
        
        nodes.push(createDetails(DNS.OTHER_RECORD_NAMES[j], nestedNodes));
    }
    
    return createDetails(title, nodes);
}

DNS.prototype.toString = function () {
    var resourceRecordStrings = ''; // suffix of the string, either add ...
    
    // ... all answers
    if (this.QR) {
        for (var i = 0; i < this.otherRecords[0].length; i++) {
            resourceRecordStrings += DNS.TYPES[this.otherRecords[0][i].type] + 
            ' ' + this.otherRecords[0][i].rData;                
        }
    }
    // ... or all questions
    else if (this.questions) {
        for (var i = 0; i < this.questions.length; i++) {
            resourceRecordStrings += DNS.TYPES[this.questions[i].type] + ' '
                                    + this.questions[i].name;                
        }
    }
    
    return DNS.OPCODES[this.opcode] + (this.QR ? ' response ' : ' ') +
            '0x' + printNum(this.id, 16, 4) + '  ' + resourceRecordStrings;
}

DNS.prototype.dissectResourceRecords = function (littleEndian, dataView, offset) 
{
    var tuple;
        
    for (var i = 0; i < this.questionCount; i++) {
        tuple = this.nextResourceRecord(littleEndian, dataView, offset, true);
        this.questions.push(tuple.resourceRecord);
        offset = tuple.offset;
    }
    
    for (var j = 0; j < this.otherRecords.length; j++) {
        for (var i = 0; i < this.otherRecordsLen[j]; i++) {
            tuple = this.nextResourceRecord(littleEndian, dataView, offset);
            this.otherRecords[j].push(tuple.resourceRecord);
            offset = tuple.offset;
        }
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
        resourceRecord.rData = IPv4.printIP(new DataView(dataView.buffer, 
                                                         offset, 4));
        break;
    case DNS.AAAA:
        resourceRecord.rData = IPv6.printIP(new DataView(dataView.buffer, 
                                                         offset, 16));
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
DNS.A     = 0x0001;
DNS.AAAA  = 0x001c;
DNS.CNAME = 0x0005;
DNS.OPCODES = readCSVFile('webpcap/dissection/resources/dns-parameters-5.csv', 0, 1);
DNS.TYPES = readCSVFile('webpcap/dissection/resources/dns-parameters-4.csv', 1, 0);
DNS.CLASSES = readCSVFile('webpcap/dissection/resources/dns-parameters-2.csv', 0, 2);
DNS.OTHER_RECORD_NAMES = ['Answers', 'Authorities', 'Additions'];

if (typeof module !== 'undefined') {
    module.exports.DNS = DNS;
} 
