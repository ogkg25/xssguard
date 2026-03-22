// False Positives Trap
// These patterns often trick simple regex scanners

function safeOperations() {
    var element = document.getElementById('test');
    
    // Safe: Constant string
    element.innerHTML = "<b>Safe Static Content</b>";
    
    // Safe: textContent is safe
    element.textContent = "User Input: " + getParam('q');
    
    // Safe: innerText is safe
    element.innerText = "Hello " + username;
    
    // Safe: Variable naming confusion (should not flag just because variable is named 'innerHTML')
    var innerHTML = "some value";
    console.log(innerHTML);
}
