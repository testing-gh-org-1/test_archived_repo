# Test Archived Repository - Security Vulnerabilities Demo

This repository contains intentional security vulnerabilities for CodeQL scanning demonstration purposes.

## Project Structure

```
test_archived_repo/
├── src/
│   ├── main/
│   │   ├── java/com/example/demo/
│   │   │   ├── HelloWorld.java
│   │   │   ├── Calculator.java
│   │   │   ├── Person.java
│   │   │   ├── VulnerableErrorHandling.java (CWE-209)
│   │   │   ├── SensitiveDataExposure.java (CWE-497)
│   │   │   ├── WeakCryptography.java (CWE-327)
│   │   │   ├── WeakHashFunction.java (CWE-328)
│   │   │   ├── InjectionVulnerability.java (CWE-74)
│   │   │   ├── CommandInjectionVulnerability.java (CWE-77)
│   │   │   ├── SQLInjectionVulnerability.java (CWE-89)
│   │   │   ├── PathTraversalVulnerability.java (CWE-22)
│   │   │   ├── XSSVulnerability.java (CWE-79)
│   │   │   ├── CSRFVulnerability.java (CWE-352)
│   │   │   ├── WeakRandomnessVulnerability.java (CWE-330, CWE-338)
│   │   │   ├── InsecureDeserializationVulnerability.java (CWE-502)
│   │   │   ├── OpenRedirectVulnerability.java (CWE-601)
│   │   │   ├── InsecureDataTransmissionVulnerability.java (CWE-311, CWE-319)
│   │   │   ├── HardcodedCredentialsVulnerability.java (CWE-259, CWE-798)
│   │   │   ├── AuthenticationAuthorizationVulnerability.java (CWE-285, CWE-287)
│   │   │   ├── ResourceManagementVulnerability.java (CWE-400, CWE-404)
│   │   │   └── XXEVulnerability.java (CWE-611)
│   │   └── resources/
│   │       ├── application.properties
│   │       └── logback.xml
│   └── test/
│       ├── java/com/example/demo/
│       │   ├── CalculatorTest.java
│       │   └── PersonTest.java
│       └── resources/
├── .github/
│   └── workflows/
│       └── codeql-analysis.yml
├── build.gradle
├── settings.gradle
├── gradle.properties
└── README.md
```

## Included CWE Vulnerabilities

### CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
**File:** `PathTraversalVulnerability.java`
- Path traversal in file reading operations
- Directory traversal in file downloads
- Unrestricted file deletion
- Path concatenation without validation
- Unsafe file upload handling

### CWE-74: Improper Neutralization of Special Elements in Output ('Injection')
**File:** `InjectionVulnerability.java`
- LDAP injection vulnerabilities
- XPath injection in XML queries
- JavaScript/SpEL expression injection
- XML injection without proper escaping
- NoSQL injection patterns
- Log injection with newline characters
- JSON injection vulnerabilities
- Template injection issues
- Expression Language (EL) injection

### CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')
**File:** `CommandInjectionVulnerability.java`
- Direct execution of user input in system commands
- Command injection in file operations (ls, tar)
- Command injection using ProcessBuilder
- Network utility command injection (ping, traceroute)
- Image conversion command injection

### CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
**File:** `XSSVulnerability.java`
- Reflected XSS vulnerabilities
- XSS in search results
- XSS in error messages
- DOM-based XSS
- XSS in HTML attributes
- XSS in JavaScript context
- Stored XSS vulnerabilities
- XSS in JSON responses

### CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
**File:** `SQLInjectionVulnerability.java`
- SQL injection in authentication queries
- SQL injection in search functionality
- SQL injection in ORDER BY clauses
- SQL injection in DELETE statements
- SQL injection in UPDATE statements
- Complex queries with multiple injection points
- Dynamic table name injection

### CWE-209: Generation of Error Message Containing Sensitive Information
**File:** `VulnerableErrorHandling.java`
- Exposes database connection details in error messages
- Reveals stack traces to users
- Leaks password information in exceptions

### CWE-497: Exposure of Sensitive System Information
**File:** `SensitiveDataExposure.java`
- Exposes system properties to unauthorized users
- Logs sensitive data (credit cards, SSN, API keys)
- Returns internal system information in responses
- Displays environment variables in debug mode

### CWE-327: Use of Broken or Risky Cryptographic Algorithm
**File:** `WeakCryptography.java`
- Uses MD5 for password hashing (broken algorithm)
- Uses SHA-1 for cryptographic purposes (weak)
- Uses DES encryption (insecure, small key size)
- Uses RC4 stream cipher (broken)
- Uses AES in ECB mode (insecure mode)

### CWE-328: Use of Weak Hash
**File:** `WeakHashFunction.java`
- Uses MD5 for password hashing
- Uses SHA-1 for sensitive data hashing
- Uses weak hashing for authentication tokens
- Uses MD5/SHA-1 for session ID generation
- Uses weak hashing for API key storage

### CWE-330: Use of Insufficiently Random Values
### CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
**File:** `WeakRandomnessVulnerability.java`
- Weak random for session ID generation
- Weak PRNG for authentication tokens
- Predictable password reset tokens
- Weak random for encryption keys
- Predictable CAPTCHA generation
- Weak OTP generation
- Predictable transaction IDs

### CWE-352: Cross-Site Request Forgery (CSRF)
**File:** `CSRFVulnerability.java`
- Password change without CSRF protection
- Account deletion without CSRF tokens
- Money transfer without CSRF validation
- Email change without verification
- Admin actions without CSRF protection

### CWE-400: Uncontrolled Resource Consumption
### CWE-404: Improper Resource Shutdown or Release
**File:** `ResourceManagementVulnerability.java`
- Resource leaks (files not closed)
- Database connections not properly closed
- Unbounded loops controlled by user input
- Unbounded memory allocation
- ZIP bomb vulnerabilities
- InputStream leaks
- Regex DoS (ReDoS)
- Uncontrolled recursion

### CWE-502: Deserialization of Untrusted Data
**File:** `InsecureDeserializationVulnerability.java`
- Direct deserialization of user input
- Deserializing data from cookies
- Deserializing session data
- Unsafe object deserialization from request parameters

### CWE-601: URL Redirection to Untrusted Site ('Open Redirect')
**File:** `OpenRedirectVulnerability.java`
- Unvalidated redirects
- Open redirect after login
- Meta refresh redirects to user-controlled URLs
- JavaScript-based open redirects
- Unsafe request forwarding

### CWE-611: Improper Restriction of XML External Entity Reference (XXE)
**File:** `XXEVulnerability.java`
- XXE in DocumentBuilder
- XXE in SAXParser
- XXE in XMLReader
- XXE in XPath evaluation
- XXE in XML transformations

### CWE-259: Use of Hard-coded Password
### CWE-798: Use of Hard-coded Credentials
**File:** `HardcodedCredentialsVulnerability.java`
- Hard-coded database credentials
- Hard-coded API keys
- Hard-coded encryption keys
- Hard-coded admin passwords
- Hard-coded JWT secrets
- Hard-coded default passwords
- Hard-coded OAuth credentials
- Hard-coded AWS credentials

### CWE-285: Improper Authorization
### CWE-287: Improper Authentication
**File:** `AuthenticationAuthorizationVulnerability.java`
- Missing authentication checks
- Missing authorization validation
- Insecure Direct Object References (IDOR)
- Authentication bypass
- Missing function-level access control
- Authorization bypass through parameter manipulation
- Missing password verification
- Privilege escalation vulnerabilities

### CWE-311: Missing Encryption of Sensitive Data
### CWE-319: Cleartext Transmission of Sensitive Information
**File:** `InsecureDataTransmissionVulnerability.java`
- Storing passwords in plain text
- Sending credentials over HTTP
- Cookies without Secure flag
- Cookies without HttpOnly flag
- Transmitting credit card data in cleartext
- Storing PII without encryption
- Logging sensitive information

## CodeQL Analysis

The repository includes a GitHub Actions workflow (`.github/workflows/codeql-analysis.yml`) that will:
- Automatically scan the code on push to main/master branches
- Scan pull requests
- Run weekly security scans
- Detect 100+ security vulnerabilities across 20+ CWE categories including:
  - CWE-22, CWE-74, CWE-77, CWE-79, CWE-89, CWE-209, CWE-259, CWE-285, CWE-287
  - CWE-311, CWE-319, CWE-327, CWE-328, CWE-330, CWE-338, CWE-352, CWE-400, CWE-404
  - CWE-497, CWE-502, CWE-601, CWE-611, CWE-798

## Running CodeQL Locally

To run CodeQL analysis locally:

```bash
# Install CodeQL CLI
# Download from: https://github.com/github/codeql-cli-binaries

# Create CodeQL database
codeql database create java-db --language=java

# Run analysis
codeql database analyze java-db --format=sarif-latest --output=results.sarif

# View results
codeql bqrs decode java-db/results/*.bqrs --format=csv
```

## Building and Running

### Using Gradle

```bash
# Build the project
.\gradlew.bat build

# Run the main application (HelloWorld)
.\gradlew.bat run

# Run specific classes
.\gradlew.bat runCalculator
.\gradlew.bat runPerson
.\gradlew.bat runWeakCryptography
.\gradlew.bat runWeakHashFunction

# Run tests
.\gradlew.bat test
```

## ⚠️ Warning

**DO NOT use these code patterns in production environments!** 

These files contain intentional security vulnerabilities for educational and testing purposes only.

## Sample Java Files

Additional sample files included:
- `HelloWorld.java` - Basic Hello World program
- `Calculator.java` - Simple calculator with arithmetic operations
- `Person.java` - Example of object-oriented programming

### Test Files
- `CalculatorTest.java` - JUnit tests for Calculator
- `PersonTest.java` - JUnit tests for Person

## License

This is a test repository for security scanning demonstrations.
