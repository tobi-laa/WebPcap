var mainOutput = document.getElementById('output');
var mainOutputTable  = document.getElementById('table');
var detailsOutput = document.getElementById('details');
var bytesOutput = document.getElementById('raw');
var html = document.getElementById('html');

var packetView = false; // makes connection view the default
var contextMenu = document.getElementById('contextmenu');

var renderThread;
var renderNextTime = false;

var autoscroll = true;

var maxPackets = 0;

var doubleBuffer = document.createDocumentFragment();

var followID = false;

function initGUI() {
    // some cross-browser related stuff
    window.requestAnimationFrame = window.requestAnimationFrame || 
                                   window.mozRequestAnimationFrame || 
                                   window.oRequestAnimationFrame ||
                                   window.webkitRequestAnimationFrame;
                                   
    window.cancelAnimationFrame =  window.cancelAnimationFrame ||
                                   window.cancelTimeout;

    if (!window.requestAnimationFrame) {
        // create a pseudo-requestAnimationFrame method
        window.requestAnimationFrame = 
            function (callback) {
                return setTimeout(callback, 40); // roundabout 25 FPS
            }
            
        alert('Hi there!\n' +
            'Your browser does not support the nifty method ' +
            'requestAnimationFrame, so I will render your session ' +
            'via setTimeout.');
    }
}

function stopRendering() {
    window.cancelAnimationFrame(renderThread);
}

function startRendering() {
    renderThread = window.requestAnimationFrame(render);
}

function closeContextMenu() {
    contextMenu.className = 'hidden';
}

function selectRow(row, num) {
    var selectedRow;
    if (packetView)
        selectedRow = selectedPacketRow;
    else
        selectedRow = selectedConnectionRow;
    
    if (selectedRow.row)
        selectedRow.row.setAttribute('class', selectedRow.class);
    selectedRow.class = row.className;    
    selectedRow.row = row;
    selectedRow.num = num;
    
    row.setAttribute('class','row selected');
}

function processClick(row, num) {
    selectRow(row, num);
    
    if (packetView) {
        printPacketDetails(num);
        printPayload(num);
        return;
    }
    
    if (getConnectionById(num)) {
        printConnectionDetails(num);
        bytesOutput.innerHTML = '';
        return;
    }
    
    printPacketDetails(num);
    printPayload(num);
}

function processRightClick(row, num, event, id) {
    processClick(row, num);
    
    // skip non-UDP, non-TCP packets
    if (!id || !connectionsById[id])
        return false;
    
    var follow, showContent, downloadSrcContent, downloadDstContent;
    

    
    follow = document.createElement('div');
    follow.setAttribute('onclick','followStream("' + id + '")');
    follow.setAttribute('class', 'contextentry');
    
    if (followID === id)
        follow.innerHTML = 'Unfollow';
    else
        follow.innerHTML = 'Follow this stream';
    
    doubleBuffer.innerHTML = '';
    doubleBuffer.appendChild(follow);
    
    if (connectionsById[id].contents) {
        showContent = document.createElement('div');
        
        showContent.setAttribute('onclick','showContent("' + id + '")');
        showContent.setAttribute('class', 'contextentry');
        showContent.innerHTML = 'Show content';
        
        doubleBuffer.appendChild(showContent);
        
        if (connectionsById[id].contents[0].length) {
            downloadSrcContent = document.createElement('div');
            
            downloadSrcContent.setAttribute('onclick','downloadContent("' + id + '", 0)');
            downloadSrcContent.setAttribute('class', 'contextentry');
            downloadSrcContent.innerHTML = 'Download source content';
                    
            doubleBuffer.appendChild(downloadSrcContent);
        }
        
        if (connectionsById[id].contents[1].length) {
            downloadDstContent = document.createElement('div');
            
            downloadDstContent.setAttribute('onclick','downloadContent("' + id + '", 1)');
            downloadDstContent.setAttribute('class', 'contextentry');
            downloadDstContent.innerHTML = 'Download destination content';
            
            doubleBuffer.appendChild(downloadDstContent);            
        }
    }

    contextMenu.className = '';
    contextMenu.innerHTML = '';
    contextMenu.style.left = event.pageX + 'px';
    contextMenu.style.top = event.pageY + 'px';
    contextMenu.appendChild(doubleBuffer);
    
    return false;
}

function downloadContent(id, srcOrDst) {
    var contents = connectionsById[id].contents[srcOrDst];
    
    if (contents.length === 0)
        return;
    
    var data = [];
    
    for (var i = 0; i < contents.length; i++)
        data[i] = contents[i].data.slice(contents[i].offset);
        
    downloadFileFromURI(createURI('application/x-download', data), id);
}

function showContent(id) {
    var contents = connectionsById[id].mergeContent();
    
    if (contents.length === 0)
        return;
    
    var data = [];
    var srcOrDst = contents[0].srcOrDst;
        
    var box = document.createElement('div');
    box.className = 'contentbox';
    
    for (var i = 0; i < contents.length; i++) {
        if (srcOrDst !== contents[i].srcOrDst) {
            data = new Uint8Array(mergeBuffers(data));
            
            var text = '';
            for (var j = 0; j < data.length; j++)
                text += printASCII(data[j]);

            var span = document.createElement('span');
            span.className = ((srcOrDst && 'src') || 'dst') + 'content';
            span.appendChild(document.createTextNode(text));
            
            box.appendChild(span);
            
            data = [];
            srcOrDst = contents[i].srcOrDst;
        }
        data.push(contents[i].data.slice(contents[i].offset));
    }
    data = new Uint8Array(mergeBuffers(data));
    
    var text = '';
    for (var j = 0; j < data.length; j++)
        text += printASCII(data[j]);

    var span = document.createElement('span');
    span.className = ((srcOrDst && 'src') || 'dst') + 'content';
    span.appendChild(document.createTextNode(text));
    
    box.appendChild(span);
    
    var w = window.open('tcpcontent.html', 'content', 'width=640, height=480, status=yes, resizable=yes');
    w.onload = function() {w.document.body.appendChild(box); w.connection = connectionsById[id]};
}

function render() {    
    if (packetView)
        renderPacketView();
    else {
        renderConnectionView();        
    }
    calculateScrollbarSize();
    
    window.requestAnimationFrame(render);
}

function followStream(id) {  
    if (followID === id) {
        followID = false;
        pkts = getDissectedPackets();
    }
    else {
        packetView = true;
        followID = id;
        pkts = getConnectionById(id).packets;
    }
    // we don't want a negative anchor
    scrollanchor = Math.max(0, pkts.length - maxPackets);
    autoscroll = true;
    renderNextTime = true;
}