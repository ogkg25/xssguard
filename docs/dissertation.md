# Dissertation: Advanced XSS Detection and Prevention Tool

**Abstract**
(To be written: Summary of the project, the dual-approach tool, and key findings.)

---

## Chapter 1: Introduction

### 1.1 Background
The evolution of web applications has shifted significant logic to the client-side, increasing the attack surface for Cross-Site Scripting (XSS). Despite the maturity of web standards, XSS remains a top vulnerability (OWASP Top 10). Modern frameworks (React, Vue) offer some protection, but complex DOM interactions and legacy code integration continue to introduce risks.

### 1.2 Problem Statement
Existing tools often fall short in two areas:
1.  **Context Awareness**: Standard WAFs and simple regex-based scanners often miss DOM-based XSS where the payload is executed client-side without hitting the server in a recognizable form.
2.  **False Positives/Negatives**: Static analyzers (SAST) often flag safe code, while dynamic scanners (DAST) may miss deep application states.
There is a need for a tool that combines or offers both approaches with a focus on modern application structures.

### 1.3 Aims and Objectives
The primary aim is to develop a comprehensive XSS detection and prevention suite.
*   **Objective 1**: Develop a standalone "White-box" scanner capable of analyzing source code (initially focusing on Python/JavaScript) for insecure patterns.
*   **Objective 2**: Develop a standalone "Black-box" scanner capable of crawling a target URL and injecting polyglot payloads to detect reflected and stored XSS.
*   **Objective 3**: Evaluate the effectiveness of these tools against vulnerable-by-design applications (e.g., DVWA).

### 1.4 Scope and Limitations
*   **Scope**: The project covers Reflected, Stored, and DOM-based XSS. It provides both scanning (detection) and suggested sanitization (prevention) mechanisms.
*   **Limitations**: The tool may not bypass advanced WAFs or solve logical vulnerabilities that are not strictly XSS. Verification of DOM-based XSS in the black-box scanner relies on headless browser capabilities which can be resource-intensive.

---

## Chapter 2: Literature Review & Fundamentals

### 2.1 Understanding XSS
*   **Reflected XSS**: Malicious script is reflected off the web server, such as in an error message or search result.
*   **Stored XSS**: Malicious script is permanently stored on the target server (e.g., in a database).
*   **DOM-based XSS**: The vulnerability exists in the client-side code rather than the server-side code. The attack payload is executed as a result of modifying the DOM environment in the victim's browser.

### 2.2 Current Detection Techniques
*   **SAST (Static Application Security Testing)**: Analyzes source code without executing it. Good for coverage, prone to false positives.
*   **DAST (Dynamic Application Security Testing)**: Interacts with the running application. Lower false positives, but coverage depends on the crawler.
*   **IAST (Interactive Application Security Testing)**: Combines both, instrumenting the application to watch execution flow.

### 2.3 State-of-the-Art Tools
*   **Burp Suite**: The industry standard for manual and automated testing. Powerful but complex and expensive (Pro version).
*   **OWASP ZAP**: Open-source alternative, robust but can be slower.
*   **AI-based Filters**: Emerging tools using ML to classify payloads, though often vulnerable to adversarial examples.

### 2.4 The Gap in Literature
While many tools exist, there is often a high barrier to entry or a lack of modularity. This project aims to provide a lightweight, modular solution that allows developers to choose specifically between white-box inspection and black-box scanning without the overhead of a full enterprise suite, with a specific focus on ease of integration into CI/CD pipelines (future work).

---

## Chapter 3: Requirements and System Design

### 3.1 Functional Requirements
*   **FR1**: The system shall accept a target URL for black-box scanning.
*   **FR2**: The system shall accept a file path or directory for white-box scanning.
*   **FR3**: The black-box scanner shall crawl the target to identify input vectors (forms, URL parameters).
*   **FR4**: The white-box scanner shall parse code to identify dangerous sinks (e.g., `innerHTML`, `eval`, `exec`).
*   **FR5**: The system shall generate a report detailing found vulnerabilities.

### 3.2 Non-Functional Requirements
*   **NFR1 - Performance**: The white-box scan should complete within 60 seconds for a medium-sized project (<10k LOC).
*   **NFR2 - Usability**: The CLI should be intuitive with clear help messages.
*   **NFR3 - Modularity**: The two scanning engines must operate independently.

### 3.3 System Architecture
*   **Overview**: Two distinct packages (`whitebox_scanner`, `blackbox_scanner`) that can be invoked via a unified CLI or independently.
*   **Data Flow (Black-box)**: User Input -> Crawler -> Injection Engine -> Headless Browser (Verification) -> Report.
*   **Data Flow (White-box)**: User Input (File) -> Parser/Lexer -> Pattern Matcher/Taint Analysis -> Report.

### 3.4 Detection Logic/Algorithm

#### Detection (Finding the Hole)
*   **White-box**: Uses Abstract Syntax Tree (AST) parsing to find flows from "Sources" (user input) to "Sinks" (dangerous functions) without sanitization.
    *   *Algorithm*: Taint Analysis. Mark variables from inputs as "tainted". If a tainted variable reaches a sink, flag as vulnerability.
*   **Black-box**: Uses a payload list (fuzzing) including polyglots.
    *   *Algorithm*:
        1.  Crawl page for inputs.
        2.  Inject unique token (canary).
        3.  Check response for canary.
        4.  If reflected, inject XSS payload.
        5.  Use headless browser to detect execution (e.g., `alert()` hook).

#### Prevention (Plugging the Hole)
*   **Input Validation**: Rejecting bad characters (allow-listing is preferred).
*   **Output Encoding**: Converting special characters to HTML entities (e.g., `<` to `&lt;`).
*   **Content Security Policy (CSP)**: HTTP headers to restrict script sources.

---

## Chapter 4: Implementation

### 4.1 Technology Stack
*   **Language**: Python 3.10+ (Selected for rich library ecosystem: `requests`, `beautifulsoup4`, `ast` module).
*   **Black-box**: `selenium` or `playwright` for DOM verification, `requests` for injection.
*   **White-box**: Python's built-in `ast` module for Python code, regex/specialized parsers for other languages.

### 4.2 Module Development

#### The White-box Scanner
*   **Core**: `Scanner` class that walks the directory.
*   **Analyzer**: Parses files. For Python, uses `ast.NodeVisitor`. For generic files, uses regex signatures for common sinks like `document.write()`.

#### The Black-box Scanner
*   **Crawler**: Spiders the target to find links and forms.
*   **Injector**: Fuzzer that iterates through a payload wordlist.
*   **Detector**: Checks HTTP responses and renders pages to confirm execution.

### 4.3 Challenges Overcome
*   **Handling Asynchronous JS**: Black-box scanning requires waiting for DOM to settle. Solved using explicit waits in Selenium/Playwright.
*   **Context-Sensitive Encoding**: Ensuring the white-box scanner differentiates between data in HTML context vs Attribute context.

---

## Chapter 5: Evaluation and Testing

### 5.1 Experimental Setup
*   **Target**: DVWA (Damn Vulnerable Web App) running in a Docker container.
*   **Environment**: MacBook Pro M1/M2/M3 (Darwin Kernel), Python 3.11.

### 5.2 Performance Metrics
*   **Precision/Recall**:
    *   *White-box*: Tested against a known vulnerable codebase. Counted True Positives vs False Positives (e.g., flagged safe string concatenation).
    *   *Black-box*: Tested against DVWA "Low", "Medium", "High" security levels.
*   **Execution Time**: Measured time to scan vs depth of crawl.

### 5.3 Comparative Analysis
*   Compared findings with a baseline scan from OWASP ZAP.
*   (Results placeholder: e.g., "Our tool was faster but missed reflected XSS in JSON responses compared to ZAP").

---

## Chapter 6: Discussion and Conclusion

### 6.1 Discussion
*   The dual approach proved effective. White-box is instant but noisy. Black-box is slow but accurate for reflection.
*   DOM-based XSS remains the hardest to detect statically due to the dynamic nature of JS.

### 6.2 Future Work
*   Integration with LLMs to generate context-specific payloads.
*   Automated patch generation (e.g., suggesting specific encoding functions).

### 6.3 Conclusion
This project demonstrates a viable, modular framework for XSS defense, providing developers with accessible tools to secure applications throughout the SDLC.
