var assert = require('assert');
var fs = require('fs');
var dissectPcapFile = require('../fileIO').dissectPcapFile;
var getTCPConns = require('../dissection/dissection').getTCPConns;

var PATH = './test/dissection/test.pcap';
var PKTNUM = 67;
var TCPNUM = 60;
var UDPNUM = 4;
var ARPNUM = 3;
var CONNNUM = 3;

test('number of read packets from test.pcap is correct', function () {
    var count = 0;    
    var data = fs.readFileSync(PATH);
    
    dissectPcapFile(toArrayBuffer(data), function() {count++;});
    
    assert.strictEqual(count, PKTNUM);
});

test('number of read TCP/UDP/... packets from test.pcap is correct', function () {
    var tcpCount = udpCount = arpCount = 0;
    var data = fs.readFileSync(PATH);
    
    dissectPcapFile(toArrayBuffer(data), function(packet) {
        switch(packet.prot) {
        case 'ARP':
            arpCount++;
            break;
        case 'TCP':
        case 'MPD':
        case 'HTTP':
            tcpCount++;
            break;
        case 'UDP':
            udpCount++;
            break;
        }});
    
    assert.strictEqual(tcpCount, TCPNUM);
    assert.strictEqual(arpCount, ARPNUM);
    assert.strictEqual(udpCount, UDPNUM);
});

test('number of TCP connections from test.pcap is correct', function () {
    var connCount = 0;
    var data = fs.readFileSync(PATH);
    
    dissectPcapFile(toArrayBuffer(data));
    
    for (conn in getTCPConns())
        connCount++;
    
    assert.strictEqual(connCount, CONNNUM);
});

function toArrayBuffer(buff, read) {
    if (!read)
        read = buff.length;
    var newBuff = new ArrayBuffer(read);
    var byteView = new Uint8Array(newBuff);
    for (var i = 0; i < read; ++i) {
        byteView[i] = buff[i];
    }
    return newBuff;
} 
