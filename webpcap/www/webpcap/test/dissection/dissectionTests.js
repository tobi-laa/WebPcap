var assert = require('assert');
var fs = require('fs');
var Dissector = require('../../dissection/dissector').Dissector;
var readPcapGlobalHeader = require('../../fileio').readPcapGlobalHeader;
var bufferToArrayBuffer = require('../../arraybuffers').bufferToArrayBuffer;
var arrayBufferToBuffer = require('../../arraybuffers').arrayBufferToBuffer;

var PATH = './test/dissection/test.pcap';
var PKTNUM = 67;
var TCPNUM = 60;
var UDPNUM = 4;
var ARPNUM = 3;
var CONNNUM = 4; // 3 TCP, 1 UDP

test('number of read packets from test.pcap is correct', function () {
    var dissector = new Dissector();
    var count = 0;    
    var data = fs.readFileSync(PATH);
    data = bufferToArrayBuffer(data);
    
    readPcapGlobalHeader(data.slice(0, 24), dissector);
    dissector.dissect(data.slice(24));
    
    assert.strictEqual(dissector.getRawPackets().length, PKTNUM);
});

test('number of read TCP/UDP/... packets from test.pcap is correct', function () {
    var dissector = new Dissector();
    var tcpCount = udpCount = arpCount = 0;
    var data = fs.readFileSync(PATH);
    data = bufferToArrayBuffer(data);
    
    readPcapGlobalHeader(data.slice(0, 24), dissector);
    dissector.dissect(data.slice(24));
    
    for (var i = 0; i < dissector.getDissectedPackets().length; i++) {
        switch (dissector.getDissectedPackets()[i].prot) {
        case 'ARP':
            arpCount++;
            break;
        case 'TCP':
        case 'MPD':
        case 'HTTP':
            tcpCount++;
            break;
        case 'UDP':
        case 'DNS':
            udpCount++;
            break;
        }
    }
    
    assert.strictEqual(tcpCount, TCPNUM);
    assert.strictEqual(arpCount, ARPNUM);
    assert.strictEqual(udpCount, UDPNUM);
});

test('number of TCP connections from test.pcap is correct', function () {
    var dissector = new Dissector();
    var connCount = 0;
    var data = fs.readFileSync(PATH);
    data = bufferToArrayBuffer(data);
    
    readPcapGlobalHeader(data.slice(0, 24), dissector);
    dissector.dissect(data.slice(24));
    
    assert.strictEqual(dissector.getConnectionsByArrival().length, CONNNUM);
});