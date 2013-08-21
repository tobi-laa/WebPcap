var selectedPacketRow = {};
var selectedConnectionRow = {};

var webSocketURL = 'ws://' + window.location.host + '/binary';
var webSocket = null;  

var startCapture = document.getElementById('startcap');

var serverFilter;

var cache = null;

var dissector = null;

var JSEVENTS = 
[
    ['html', 'onclick', 'closeContextMenu()'],
    ['html', 'onmouseup', 'processMouseUp()'],
    ['html', 'onmousemove', 'processMouseMove(event)'],
    ['html', 'onresize', 'processResize()'],
    ['startcap', 'onclick', 'switchConnection()'],
    ['clearscr', 'onclick', 'clearScreen()'],
    ['savecap', 'onclick', 'saveCapture()'],
    ['loadcap', 'onclick', 'fileInput.click()'],
    ['fileInput', 'onchange', 'readPcapFile(this.files[0], dissector)'],
    ['switchview', 'onclick', 'switchView()'],
    ['filterForm', 'onsubmit', 'return processFilter()'],
    ['output', 'oncontextmenu', 'return false'],
    ['output', 'onmousewheel', 'processMouseWheel(event)'],
    ['output', 'onwheel', 'processMouseWheel(event)'],
    ['table', 'oncontextmenu', 'return false'],    
    ['scrollbar-track', 'onmousedown', 'startTrackScrolling(true)'],
    ['scroll-thumb', 'onmousedown', 'selectScrollThumb(event)'],
    ['scrollbar-button-up', 'onmousedown', 'startScrolling(-1)'],
    ['scrollbar-button-down', 'onmousedown', 'startScrolling(1)']
];

initWebPcapJS();

function initWebPcapJS () {
    dissector = new Dissector();
    pkts = dissector.getDissectedPackets();
    conns = dissector.getConnectionsByArrival();
    initWellKnownPorts();
    initGUI();
    initJSEvents();
    processResize();
    startRendering();
    switchConnection();    
}

function initWellKnownPorts() {
    var portNumbersReq = new XMLHttpRequest();    
    portNumbersReq.open("get", "webpcap/dissection/service-names-port-numbers.txt", true);
    portNumbersReq.send();    
    portNumbersReq.onload = function () {
        var lines = this.responseText.split('\n');
        var tokens, index;
        for (var i = 0; i < lines.length; i++) {
            tokens = lines[i].split(/\s* \s*/, 3);
            if (tokens[0] === '' || tokens[1] === '' || tokens[2] === '')
                continue;
            
            index = Number(tokens[1]);
            
            switch (tokens[2]) {
            case 'tcp':
                TCP_PORTS[index] = TCP_PORTS[index] || tokens[0];
                break;
            case 'udp':
                UDP_PORTS[index] = UDP_PORTS[index] || tokens[0];
                break;
            }
        }
    }
}

function initJSEvents() {
    for (var i = 0; i < JSEVENTS.length; i++)
        document.getElementById(JSEVENTS[i][0])
           .setAttribute(JSEVENTS[i][1], JSEVENTS[i][2]);
}

function onFirstMessage(msg) {
    switch (String.fromCharCode(new Uint8Array(msg.data, 0, 1)[0])) {
    case 'O':  
        if (serverFilter)
            filterField.style.backgroundColor = '#afffaf';
        webSocket.onmessage = onSecondMessage;
        onSecondMessage({data: msg.data.slice(1)});
        return;
    case 'E':
    default:
        if (serverFilter)
            filterField.style.backgroundColor = '#ffafaf';
        switchConnection();
        return;
    }
}

function onSecondMessage(msg) {    
    cache = appendBuffer(cache, msg.data);
    if (cache.byteLength < 24)
        return;
    
    readPcapGlobalHeader(cache, dissector);
    webSocket.onmessage = onWebSocketMessage;
    dissectMessage(cache.slice(24));
}

function onWebSocketMessage(msg) {
    dissectMessage(msg.data);
}

function dissectMessage(data) {
    var oldLength, oldAnchor, length, anchor;
    
    if (packetView) oldLength = pkts.length;
    else {
        var tuple = connectionViewLength();
        oldLength = tuple[0];
        oldAnchor = tuple[1];
    }
    
    dissector.dissect(data);
    // simpleDissect(msg.data, simplePrint);
    
    if (packetView)
        length = pkts.length;
    else {
        var tuple = connectionViewLength();
        length = tuple[0];
        anchor = tuple[1];
    }
    
    if (oldLength === length)
        return;
    if (autoscroll) {
        if (packetView) {
            // we don't want a negative scrollanchor     
            scrollanchor = Math.max(0, pkts.length - maxPackets);
            renderNextTime = true;
        }
        else {
            connectionViewSeek(Math.max(0, length - anchor - maxPackets));
            renderNextTime = true;
        }
    }
    else if (!packetView) {
        // FIXME: what happens if connection is extended BELOW anchor...
        if (oldAnchor === anchor && oldLength - oldAnchor >= maxPackets)
            return;
        renderNextTime = true;
    }
}  

function onWebSocketOpen() {
    webSocket.send(serverFilter || 'none\0');
    startCapture.setAttribute('title', 'Stop the running live capture');
    startCapture.innerHTML = '<img class="glow buttonicon" src="img/media-' + 
                             'playback-stop.svgz" alt="Stop capture">';
}
    
function onWebSocketClose() {
    webSocket = null;
    startCapture.setAttribute('title', 'Start a new live capture');
    startCapture.innerHTML = '<img class="glow buttonicon" src="img/media-' +
                             'record.svgz" alt="Start capture">';
    cache = null;
}

function processResize() {
    document.body.style.fontSize = '0.9vw';
    
    mainOutput.style.width = '100%';
    tableheader.style.width = '100%';
    
    tableheader.style.width = (tableheader.offsetWidth - 15) + 'px';
    mainOutput.style.width = (mainOutput.offsetWidth - 15) + 'px';
    
    scrollbar.style.height = mainOutput.offsetHeight + 'px';
    scrollbar.style.top =  mainOutput.offsetTop + 'px';
    scrollbar.style.left = mainOutput.offsetLeft + mainOutput.offsetWidth + 'px';
        
    scrollbarTrack.style.height = '100%';
    
    scrollbarTrack.style.height = (scrollbarTrack.offsetHeight - 30) + 'px';
    
    MAX_SCROLLTHUMB_OFFSET = scrollbarTrack.offsetHeight - MIN_SCROLLTHUMB_SIZE;
    
    maxPackets = 0;
    mainOutputTable.innerHTML = '';
    
    while (mainOutput.scrollHeight <= mainOutput.clientHeight) {
        var row = document.createElement('div');
        var col = document.createElement('div');
        row.setAttribute('class','row');        
        col.setAttribute('class', 'col 5p');
        col.innerHTML = 'test';
        row.appendChild(col);
        mainOutputTable.appendChild(row);
        maxPackets++;
    }
    
    mainOutputTable.innerHTML = '';
    renderNextTime = true;    
}

function processFilter() {
    serverFilter = filterField.value + '\0';
    return false;
}

function switchView() {
    packetView = !packetView;
    renderNextTime = true;
}

function saveCapture() {
    downloadFileFromURI(getPcapURI(dissector), 'log.pcap');
} 

function downloadFileFromURI(resource, filename) {
    if (!resource || !resource.URI)
        return;
    
    var tmpLink = document.createElement('a'); // link to be 'clicked' on
    var mc = document.createEvent('MouseEvents'); // event to 'click' on it
    
    mc.initEvent('click', true, false);
    
    if (filename)
        tmpLink.download = filename;    
    tmpLink.href = resource.URI;
    
    tmpLink.dispatchEvent(mc); //'click' on the link
    
    if (resource.blob) // if we're using blobs, close the blob
        delete blob;
}

function switchConnection() {
    if(webSocket) {
        webSocket.close();
        webSocket = null;
        return;
    }
    webSocket = new WebSocket(webSocketURL);
    webSocket.binaryType = 'arraybuffer';
    webSocket.onopen = onWebSocketOpen;
    webSocket.onclose = onWebSocketClose;
    webSocket.onerror = onWebSocketClose;
    webSocket.onmessage = onFirstMessage;        
}