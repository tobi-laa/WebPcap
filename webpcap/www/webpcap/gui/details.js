var detailsCounter = 0;

function createDetails(title, nodes) {
    // this method makes creating nested details a lot easier!
    var container;
    var checkBox;
    var label;
    var dropdown;
    var hiddenContainer;
    
    // initialize all DOM nodes needed
    container = document.createElement('div');
    checkBox = document.createElement('input');
    label = document.createElement('label');
    dropdown = document.createElement('span');
    hiddenContainer = document.createElement('div');
    
    // set their attributes
    checkBox.setAttribute('type','checkbox');  
    checkBox.setAttribute('id', 'details' + detailsCounter);
    
    dropdown.setAttribute('class', 'dropdown glow');
    
    label.setAttribute('for', 'details' + detailsCounter++);
    label.appendChild(dropdown);
    label.appendChild(document.createTextNode(title));
    
    // append all specified nodes to the inner element
    for (var i = 0; i < nodes.length; i++) {
        hiddenContainer.appendChild(nodes[i]);
    }
    
    // create and return the container
    container.appendChild(checkBox);
    container.appendChild(label);
    container.appendChild(hiddenContainer);
    
    return container;
}