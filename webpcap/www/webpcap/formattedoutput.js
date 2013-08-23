'use strict';

var MONTHS = ['Jan','Feb','Mar','Apr','May','Jun', 'Jul','Aug','Sep','Oct',
              'Nov','Dec'];

var TIME_UNITS=[' seconds', ' minutes', ' hours', ' days', ' years'];
              
var IEC_UNITS = [' Bit', ' KiB', ' MiB', ' GiB', ' TiB', ' PiB', ' EiB', ' ZiB',
                 ' YiB'];

                 
function printASCII(charCode) {    
    if (charCode === 10 || charCode === 13 || // LF and CR
       (charCode >= 32 && charCode <= 126)) // ascii range
        return String.fromCharCode(charCode);
    else
        return '.';
}

function printASCIINoLF(charCode) { // NoLF ~> no linefeed
    if (charCode >= 32 && charCode <= 126)
        return String.fromCharCode(charCode);
    else
        return '.';
}

function printTime(time) {
    for (var i = 0; i < 2; i++) {
        if (time < 60)
            return time + TIME_UNITS[i];
        time = time / 60 | 0;
    }
    if (time < 24)
        return time + TIME_UNITS[2];
    
    time = time / 24 | 0;
    
    if (time < 365)
        return time + TIME_UNITS[3];
    
    return (time / 365 | 0) + TIME_UNITS[4] + ' and ' + 
            time % 365 + TIME_UNITS[3];    
}
                
function printNum(num, base, minLen) {
    if(num === null)
        return '%';
    var hex = num.toString(base);
    var toReturn = '';
    for (var i = 0; i < (minLen - hex.length); i++)
        toReturn += '0';
    return toReturn + hex;
}

function printSize(bytes) {
    var i = 0;
    while (bytes >= 1024 && i < IEC_UNITS.length - 1) {
        bytes /= 1024;
        i++;
    }
    return (bytes | 0) + IEC_UNITS[i];
}

function printDate(date) {
    return MONTHS[date.getMonth()] + ' ' + date.getDate() + ', ' + 
           date.getFullYear() + ' ' + date.getHours() + ':' + 
           printNum(date.getMinutes(), 10, 2) + ':' + 
           printNum(date.getSeconds(), 10, 2);
} 

if (typeof module !== 'undefined')
    module.exports.printNum = printNum;