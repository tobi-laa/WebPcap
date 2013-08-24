var assert = require('assert');
var IPv6 = require('../../dissection/ipv6').IPv6;
IPv6.printIP = require('../../dissection/ipv6').printIP;
IPv6.ADDRESS_LENGTH = require('../../dissection/ipv6').ADDRESS_LENGTH;

var littleEndian = true;

var ips = 
[
    [0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000],
    [0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001],
    [0x0001, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000],
    [0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008],
    [0xaaaa, 0xbbbb, 0xcccc, 0xdddd, 0xeeee, 0xffff, 0x0000, 0x1001],
    [0xaaaa, 0x0000, 0x0000, 0xdddd, 0xeeee, 0xffff, 0x0000, 0x1001],
    [0xaaaa, 0x0000, 0x0000, 0xdddd, 0xeeee, 0x0000, 0x0000, 0x0000]
]

var shortIps =
[
    '::',
    '::1',
    '1::',
    '1:2:3:4:5:6:7:8',
    'aaaa:bbbb:cccc:dddd:eeee:ffff::1001',
    'aaaa::dddd:eeee:ffff:0:1001',
    'aaaa:0:0:dddd:eeee::'
]

test('shortening of IPv6 addresses is correct', function () {
    var dataView;
    
    for (var i = 0; i < ips.length; i++) {
        dataView = new DataView(new ArrayBuffer(IPv6.ADDRESS_LENGTH));
        for (var j = 0; j < ips[i].length; j++) {
            dataView.setUint16(j * 2, ips[i][j], littleEndian);
        }
        assert.strictEqual(IPv6.printIP(dataView, littleEndian), shortIps[i]);
    }
});