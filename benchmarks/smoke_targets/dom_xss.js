// Classic DOM XSS
function showMessage(msg) {
    var output = document.getElementById('output');
    
    // RULE: innerHTML assignment
    output.innerHTML = msg; 
    
    // RULE: document.write
    document.write("Debug: " + msg);
}

// Another sink
function updateStatus(status) {
    // RULE: outerHTML assignment
    document.body.outerHTML = "<div>" + status + "</div>";
}
