'use strict';

function mergeBuffers(buffers) {
    var byteLength = 0;
    var currentPos = 0;
    var mergedBuffer;
    var byteView;
    
    for (var i = 0; i < buffers.length; i++) {
        if (buffers[i]) // handle null or undefined as empty buffers
            byteLength += buffers[i].byteLength;
    }
    
    mergedBuffer = new ArrayBuffer(byteLength);
    byteView = new Uint8Array(mergedBuffer);
    
    if (byteLength === 0)
        return mergedBuffer;
    
    for (var i = 0; i < buffers.length; i++) {
        if (buffers[i]) {
            byteView.set(new Uint8Array(buffers[i]), currentPos);
            currentPos += buffers[i].byteLength;
        }
    }
    
    return mergedBuffer;
}

// deprecated method
function appendBuffer(fstBuff, sndBuff) {
    return mergeBuffers([fstBuff, sndBuff]);
} 

function base64ArrayBuffer(arrayBuffer) {
    var base64 = '';
    var i = 0;
    
    for (i = 0; i < arrayBuffer.byteLength - 3; i += 3) {
        base64 += window.btoa(
            String.fromCharCode.apply(null, new Uint8Array(arrayBuffer, i, 3)));
    }
    base64 += window.btoa(
            String.fromCharCode.apply(null, new Uint8Array(arrayBuffer, i)));
    
    return base64;
}

// convert between nodejs's buffers and arrayBuffers

function bufferToArrayBuffer(buff) {
    var newBuff = new ArrayBuffer(buff.length);
    var byteView = new Uint8Array(newBuff);
    
    for (var i = 0; i < buff.length; i++) {
        byteView[i] = buff[i];
    }
    return newBuff;
} 

function arrayBufferToBuffer(arrBuff) {
    var newBuff = new Buffer(arrBuff.byteLength);
    var byteView = new Uint8Array(arrBuff);
    
    for (var i = 0; i < arrBuff.byteLength; i++) {
        newBuff[i] = byteView[i];
    }
    return newBuff;
}

if (typeof module !== 'undefined') {
    module.exports.appendBuffer = appendBuffer;
    module.exports.mergeBuffers = mergeBuffers;
    module.exports.base64ArrayBuffer = base64ArrayBuffer;
    module.exports.bufferToArrayBuffer = bufferToArrayBuffer;
    module.exports.arrayBufferToBuffer = arrayBufferToBuffer;
}