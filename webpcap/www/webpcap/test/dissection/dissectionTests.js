var assert = require('assert');
var fs = require('fs');

var dissect = require('../../dissection/dissection').dissect;

test('number of read packets from test.pcap is correct', function () {
    var count = 0;
    var buff = new Buffer(1024);
    var fd = fs.openSync('./test/dissection/test.pcap', 'r');
    fs.readSync(fd, buff, 0, 24); // FIXME
    var read;
    while ((read = fs.readSync(fd, buff, 0, 1024)) > 0)
        dissect(toArrayBuffer(buff, read), function() {count++;});
    
    assert.strictEqual(count, 37);
});

test('number of read TCP/UDP/... packets from test.pcap is correct', function () {
    var tcpCount = udpCount = arpCount = 0;
    var buff = new Buffer(1024);
    var fd = fs.openSync('./test/dissection/test.pcap', 'r');
    fs.readSync(fd, buff, 0, 24); // FIXME
    var read;
    while ((read = fs.readSync(fd, buff, 0, 1024)) > 0)
        dissect(toArrayBuffer(buff, read), function(packet) {
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
    
    assert.strictEqual(tcpCount, 35);
    assert.strictEqual(arpCount, 2);
    assert.strictEqual(udpCount, 0);
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