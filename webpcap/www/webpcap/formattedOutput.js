var months = ['Jan','Feb','Mar','Apr','May','Jun',
              'Jul','Aug','Sep','Oct','Nov','Dec'];
              
var iecUnits = [' Bit', ' KiB', ' MiB', ' GiB', ' TiB',
                ' PiB', ' EiB', ' ZiB', ' YiB'];
          
function printASCII(charCode) {    
    if (charCode === 10 || charCode === 13 || // LF and CR
       (charCode >= 32 && charCode <= 126))
        return String.fromCharCode(charCode);
    else
        return '.';
}

function printASCIINoLF(charCode) {    
    if (charCode >= 32 && charCode <= 126)
        return String.fromCharCode(charCode);
    else
        return '.';
}

                
function printNum(num, base, len) {
    if(num === null)
        return '%';
    var hex = num.toString(base);
    var toReturn = '';
    for (var i = 0; i < (len - hex.length); i++)
        toReturn += '0';
    return toReturn + hex;
}

function printSize(bytes) {
    var i = 0;
    while (bytes >= 1024 && i < iecUnits.length - 1) {
        bytes /= 1024;
        i++;
    }
    return (bytes | 0) + iecUnits[i];
}

function printDate(date) {
    return months[date.getMonth()] + ' ' + date.getDate() + ', ' + 
           date.getFullYear() + ' ' + date.getHours() + ':' + 
           printNum(date.getMinutes(), 10, 2) + ':' + 
           printNum(date.getSeconds(), 10, 2);
} 

if (typeof module !== 'undefined')
    module.exports.printNum = printNum;