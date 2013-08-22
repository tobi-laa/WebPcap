'use strict';
var conns = [];
var connAnchor = 0;
var pktAnchor = -1;

function connectionViewSeek(direction) {
    var tuple = connectionViewLength();
    var length = tuple[0];
    var anchor = tuple[1];   
    
    if (direction > 0 && direction >= length - anchor - maxRows) {
        autoscroll = true;
        direction = length - anchor - maxRows;
    }
    if (direction === 0)
        return;
    
    var currentConnection;
    
    while (direction !== 0) {
        pktAnchor += direction;
        
        currentConnection = conns[connAnchor];
        
        if (pktAnchor < -1) {
            direction = (pktAnchor + 2);
            connAnchor--;
            
            if (connAnchor < 0) {
                connAnchor = 0;
                pktAnchor = -1;
                break;
            }
            
            currentConnection = conns[connAnchor];
            pktAnchor = (currentConnection.packets.length * currentConnection.visible) - 1;
        }
        else if (pktAnchor >= currentConnection.packets.length * currentConnection.visible) {
            direction = (pktAnchor - currentConnection.packets.length * currentConnection.visible);
            connAnchor++;
            
            if (connAnchor >= conns.length) {
                alert('BUG!')
                connAnchor = conns.length - 1;
                currentConnection = conns[connAnchor];
                pktAnchor = (currentConnection.packets.length * currentConnection.visible) - 1;
                direction = 0;
            }            
            pktAnchor = -1;
        }
        else
            direction = 0;
    }
}

function scrollConnectionView(direction) {
    if (conns.length === 0)
        return;
    
    autoscroll = false;
    renderNextTime = true;
    
    connectionViewSeek(direction);
    
    
}

function updateConnectionView() {        
    var i = connAnchor;
    var j = pktAnchor;
    
    var rows = mainOutputTable.getElementsByClassName('row');
    
    for (var k = 0; k < rows.length; k++) {
        if (j === -1) updateConnectionHeader(i, rows[k]);
        if (++j >= conns[i].packets.length * conns[i].visible) {
            i++;
            j = -1;
        }
    }
}

function renderConnectionView() {
    if (conns.length === 0)
        return;
    
    if (selectedConnectionRow.num)
        printConnectionDetails(selectedConnectionRow.num);
    
    if (!renderNextTime) {
        updateConnectionView();
        return;
    }
    
    var c = connAnchor;
    var p = pktAnchor;
   
    doubleBuffer.innerHTML = '';
        
    var row, num;
    
    for (var i = 0; i <= maxRows; i++) {
        if (p === -1) {
            row = printConnectionHeader(c);
            num = conns[c].id;            
        }
        else {
            row = printRow(conns[c].packets[p], 'gray');
            num = conns[c].packets[p].num;
        }
        doubleBuffer.appendChild(row);
        if (num === selectedConnectionRow.num)
            selectRow(row, num);
        
        p++;
        
        if (p >= conns[c].packets.length * conns[c].visible) {
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

function printConnectionHeader(connectionNumber) {
    var connection = conns[connectionNumber];
    var row;
    
    if (!connection) {
        return;
        alert(connectionNumber)
    }
    
    row = document.createElement('div');    

    row.setAttribute('onclick','processClick(this, "' + connection.id + '")');
    row.setAttribute('oncontextmenu','processRightClick(this, "' + connection.id + '", event, "' + connection.id + '")');
    row.className = 'row ' + (connection.class || connection.prot);
    
    var drop = document.createElement('div');
    var num  = document.createElement('div');
    var src  = document.createElement('div');
    var dst  = document.createElement('div');
    var prot = document.createElement('div');
    var len  = document.createElement('div');
    var info = document.createElement('div');
       
    drop.setAttribute('class', 'col 2p');
    num.setAttribute('class', 'col 8p tr');    
    src.setAttribute('class', 'col 20p'); 
    dst.setAttribute('class', 'col 20p'); 
    prot.setAttribute('class', 'col 10p');    
    len.setAttribute('class', 'col 10p tr mono');    
    info.setAttribute('class', 'col 30p');
    
    var icon = document.createElement('span');
    if (connection.visible)
        icon.setAttribute('class', 'dropdown glow clicked');
    else
        icon.setAttribute('class', 'dropdown glow');
    icon.setAttribute('onclick', 'switchVisibility(this,' + connectionNumber + ')');
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
    
    if (selectedConnectionRow.num !== connection.id)
        row.className = 'row ' + (connection.class || connection.prot);
    
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
        
    detailsOutput.innerHTML  = 'Last packet arrival: ' + lastPacket.printTime() + '</br>';
    detailsOutput.innerHTML += 'Number of pkts: ' + conn.num + '</br>';
    detailsOutput.innerHTML += 'Amount of data: ' + printSize(conn.len) + '</br>';
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
    
    return [length, anchor];
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
