'use strict';

var conns = [];
var connAnchor = 0;
var pktAnchor = -1;

function seekConnectionView(direction) {
    var cV = connectionViewLength();
    var currentConnection = conns[connAnchor];
    
    // seeking down to the very bottom
    if (direction > 0 && direction + cV.anchor >= cV.length - maxRows) {
        autoscroll = true;
        // may be negative when main output is not full.. dont want that
        direction = Math.max(cV.length - cV.anchor - maxRows, 0);
        // we dont know the connAnchor/pktAnchor of the last row, so continue
    }
    // seeking to the top
    else if (direction + cV.anchor < 0) {
        connAnchor = 0;
        pktAnchor = -1;
        return;
    }
    
    // nothing to do
    if (direction === 0)
        return;
    
    while (direction !== 0) {
        pktAnchor += direction;
        
        if (pktAnchor < -1) { // scrolling up
            direction = (pktAnchor + 2);
            connAnchor--;            
            currentConnection = conns[connAnchor];
            pktAnchor = currentConnection.getEffectiveLength() - 1;
        }
        // scrolling down
        else if (pktAnchor >= currentConnection.getEffectiveLength()) {
            direction = (pktAnchor - currentConnection.getEffectiveLength());
            connAnchor++;
            currentConnection = conns[connAnchor];
            pktAnchor = -1;
        }
        else // changing the pktAnchor was sufficient
            direction = 0;
    }
}

function scrollConnectionView(direction) {
    if (conns.length === 0)
        return;
    
    autoscroll = false;
    renderNextTime = true;
    
    seekConnectionView(direction);
}

function updateConnectionView() {        
    var connNum = connAnchor;
    var packetNum = pktAnchor;
    
    var rows = mainOutputTable.getElementsByClassName('row');
    
    for (var rowNum = 0; rowNum < rows.length; rowNum++) {
        if (packetNum === -1)
            updateConnectionHeader(connNum, rows[rowNum]);
        if (++packetNum >= conns[connNum].getEffectiveLength()) {
            connNum++;
            packetNum = -1;
        }
    }
}

function renderConnectionView() {
    if (conns.length === 0)
        return;
    
    if (selectedConnectionRow)
        printConnectionDetails(selectedConnectionRow);
    
    if (!renderNextTime) {
        updateConnectionView();
        return;
    }
    
    var c = connAnchor;
    var p = pktAnchor;
   
    doubleBuffer.innerHTML = '';
        
    var row;
    
    for (var i = 0; i <= maxRows; i++) {
        if (p === -1) {
            if (conns[c].id === selectedConnectionRow)
                row = printConnectionHeader(c, 'selected');
            else
                row = printConnectionHeader(c);
        }
        else {
            if (conns[c].packets[p].num === selectedConnectionRow)
                row = printRow(conns[c].packets[p], 'selected');
            else
                row = printRow(conns[c].packets[p], 'gray');
        }
        doubleBuffer.appendChild(row);        
        p++;
        
        if (p >= conns[c].getEffectiveLength()) {
            p = -1;
            c++;
            if (c >= conns.length)
                break;
        }
    }
    
    mainOutputTable.innerHTML = '';
    mainOutputTable.appendChild(doubleBuffer);
    
    if (autoscroll)
        mainOutput.scrollTop = mainOutput.scrollHeight;
    else
        mainOutput.scrollTop = 0;
    
    renderNextTime = false;
}

function printConnectionHeader(connectionNumber, customClass) {
    var connection = conns[connectionNumber];
    var row;
    var drop, num, src, dst, prot, len, info; // columns
    var icon;
    
    if (!connection)
        throw 'Connection ' + connectionNumber + ' does not exist.';
    
    row = document.createElement('div');
    drop = document.createElement('div');
    num  = document.createElement('div');
    src  = document.createElement('div');
    dst  = document.createElement('div');
    prot = document.createElement('div');
    len  = document.createElement('div');
    info = document.createElement('div');
    
    row.addEventListener('click', function () {
        processClick(connection.id);        
    });
    row.addEventListener('contextmenu', function (event) {
        processRightClick(connection.id, event, connection.id);        
    });
    row.className = 'row ' + (customClass || '') + ' ' + connection.class;
       
    drop.setAttribute('class', 'col 2p');
    num.setAttribute('class', 'col 8p tr');    
    src.setAttribute('class', 'col 20p'); 
    dst.setAttribute('class', 'col 20p'); 
    prot.setAttribute('class', 'col 10p');    
    len.setAttribute('class', 'col 10p tr mono');    
    info.setAttribute('class', 'col 30p');
    
    icon = document.createElement('span');
    if (connection.visible)
        icon.setAttribute('class', 'dropdown glow clicked');
    else
        icon.setAttribute('class', 'dropdown glow');
    icon.addEventListener('click', function () {
        switchVisibility(this, connectionNumber);
    });
    drop.appendChild(icon);    
    
    num.innerHTML  = connection.num;
    src.innerHTML  = connection.src;
    dst.innerHTML  = connection.dst;
    prot.innerHTML = connection.prot;
    len.innerHTML  = printSize(connection.len);
    info.innerHTML = ((followID === connection.id) && '[Following] ' || '')
                   + connection.info + ' [' + connection.packets.length + ' packets]';
    
    row.appendChild(drop);
    row.appendChild(num);
    row.appendChild(src);
    row.appendChild(dst);
    row.appendChild(prot);
    row.appendChild(len);
    row.appendChild(info);
    
    return row;
}

function updateConnectionHeader(connectionNumber, row) {
    var connection = conns[connectionNumber];
    
    if (!connection || !row) 
        return;
    
    if (selectedConnectionRow !== connection.id)
        row.className = 'row ' + connection.class;
    
    var cols = row.getElementsByTagName('div');
    
    cols[1].innerHTML = connection.num;
    cols[2].innerHTML = connection.src;
    cols[3].innerHTML = connection.dst;
    cols[4].innerHTML = connection.prot;
    cols[5].innerHTML = printSize(connection.len);
    cols[6].innerHTML = ((followID === connection.id) && '[Following] ' || '')
                      + connection.info + ' [' + connection.packets.length + ' packets]';
}

function printConnectionDetails(id) {
    var conn = dissector.getConnectionById(id);
    
    if (!conn)
        return;
    
    var lastPacket = conn.packets[conn.packets.length - 1];    
    
    detailsOutput.innerHTML = '';
        
    detailsOutput.innerHTML  = 'Last packet arrival: ' + lastPacket.printTime() + '<br/>';
    detailsOutput.innerHTML += 'Number of pkts: ' + conn.num + '<br/>';
    detailsOutput.innerHTML += 'Amount of data: ' + printSize(conn.len) + '<br/>';
}

function connectionViewLength() {
    var length = 0;
    var anchor = 0;
    
    for (var i = 0; i < conns.length; i ++) {
        if (i === connAnchor)
            anchor = connAnchor + length + pktAnchor + 1;
        length += conns[i].packets.length * conns[i].visible;            
    } 
    length += conns.length;
    
    return {length: length, anchor: anchor};
}

function switchVisibility(dropdown, connectionNumber) {
    var connection = conns[connectionNumber];
    
    if (!connection) 
        return;
    
    autoscroll = false;
    
    if (connection.visible) {
        connection.visible = 0;
        dropdown.className = 'dropdown glow';
    }
    else {
        connection.visible = 1;
        dropdown.className = 'dropdown glow clicked';
    }
    
    renderNextTime = true; // show the changes
}
