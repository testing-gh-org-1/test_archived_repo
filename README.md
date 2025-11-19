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
│   │   │   ├── XXEVulnerability.java (CWE-611)
│   │   │   ├── AdvancedInjectionVulnerabilities.java (CWE-91, CWE-93, CWE-95, CWE-113)
│   │   │   ├── ImproperEncodingVulnerabilities.java (CWE-116, CWE-117)
│   │   │   ├── NumericVulnerabilities.java (CWE-129, CWE-190, CWE-191, CWE-197)
│   │   │   ├── InformationExposureVulnerabilities.java (CWE-200, CWE-203, CWE-208)
│   │   │   ├── APIAndValidationVulnerabilities.java (CWE-185, CWE-221, CWE-227, CWE-248, CWE-252)
│   │   │   ├── PrivilegeAndPasswordVulnerabilities.java (CWE-256, CWE-260, CWE-266, CWE-271, CWE-273)
│   │   │   ├── AccessControlVulnerabilities.java (CWE-284)
│   │   │   ├── AuthenticationBypassVulnerabilities.java (CWE-287, CWE-290)
│   │   │   ├── CertificateValidationVulnerabilities.java (CWE-295, CWE-297)
│   │   │   ├── CryptographicStorageVulnerabilities.java (CWE-311, CWE-312, CWE-315, CWE-319, CWE-326)
│   │   │   └── AdditionalAuthorizationVulnerabilities.java (CWE-285)
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
- Unclosed file resources
- Database connections not closed
- Unbounded loops controlled by user input
- Memory exhaustion through large allocations
- ZIP bomb vulnerabilities
- Regular expression denial of service (ReDoS)
- Thread exhaustion
- Disk space exhaustion

### CWE-91: XML Injection (aka Blind XPath Injection)
**File:** `AdvancedInjectionVulnerabilities.java`
- XML injection without escaping special characters
- Blind XPath injection in XML queries

### CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection')
**File:** `AdvancedInjectionVulnerabilities.java`
- CRLF injection in log messages
- CRLF injection in file writing operations

### CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')
**File:** `AdvancedInjectionVulnerabilities.java`
- JavaScript eval injection using ScriptEngine
- Dynamic code evaluation with user input
- Groovy code execution vulnerabilities

### CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')
**File:** `AdvancedInjectionVulnerabilities.java`
- CRLF injection in HTTP headers
- Response splitting in Set-Cookie header
- HTTP header injection in Location header

### CWE-116: Improper Encoding or Escaping of Output
**File:** `ImproperEncodingVulnerabilities.java`
- Missing HTML encoding in user output
- Missing URL encoding in query parameters
- Missing JavaScript escaping in script context
- Missing attribute encoding in HTML attributes
- Missing SQL escaping in queries
- Missing JSON encoding in responses

### CWE-117: Improper Output Neutralization for Logs
**File:** `ImproperEncodingVulnerabilities.java`
- Log injection/forging with user-controlled data
- Multiline log injection vulnerabilities
- Stack trace exposure in logs
- Failed login attempts with unsanitized input

### CWE-129: Improper Validation of Array Index
**File:** `NumericVulnerabilities.java`
- Unchecked array index access
- Array index from user input without bounds checking
- Negative array index vulnerabilities
- Buffer access with unvalidated size and offset

### CWE-185: Incorrect Regular Expression
**File:** `APIAndValidationVulnerabilities.java`
- Weak regex for email validation
- Incomplete URL validation patterns
- Overly permissive phone number regex

### CWE-190: Integer Overflow or Wraparound
**File:** `NumericVulnerabilities.java`
- Integer overflow in addition operations
- Integer overflow in multiplication
- Integer overflow in buffer size calculation
- Unchecked cast from long to int

### CWE-191: Integer Underflow (Wrap or Wraparound)
**File:** `NumericVulnerabilities.java`
- Integer underflow in subtraction operations
- Underflow in loop counter calculations

### CWE-197: Numeric Truncation Error
**File:** `NumericVulnerabilities.java`
- Truncation from long to int
- Truncation from double to int with loss of precision
- Value exceeding short range cast

### CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
**File:** `InformationExposureVulnerabilities.java`
- Exposing internal file system paths
- Exposing database structure and error details
- Exposing system configuration and properties
- Exposing internal network information (IPs, hostnames)
- Exposing software version information
- Full stack trace disclosure to users

### CWE-203: Observable Discrepancy
**File:** `InformationExposureVulnerabilities.java`
- Observable response discrepancy in authentication (user enumeration)
- Different error messages revealing user existence
- Username enumeration vulnerabilities

### CWE-208: Observable Timing Discrepancy
**File:** `InformationExposureVulnerabilities.java`
- Timing attack in password comparison
- Timing discrepancy in authentication revealing valid users

### CWE-221: Information Loss or Omission
**File:** `APIAndValidationVulnerabilities.java`
- Information loss in exception handling
- Truncating error details in conversion operations

### CWE-227: API Abuse
**File:** `APIAndValidationVulnerabilities.java`
- Incorrect use of equals() with arrays
- Misuse of String.replace() for sanitization
- Incorrect thread synchronization

### CWE-248: Uncaught Exception
**File:** `APIAndValidationVulnerabilities.java`
- Uncaught IOException in file operations
- Unhandled NullPointerException
- RuntimeException propagation

### CWE-252: Unchecked Return Value
**File:** `APIAndValidationVulnerabilities.java`
- Ignoring return value of file.delete()
- Ignoring return value of mkdir()
- Ignoring bytes read from InputStream
- Ignoring database connection errors

### CWE-256: Plaintext Storage of a Password
**File:** `PrivilegeAndPasswordVulnerabilities.java`
- Storing passwords in plain text files
- Plain text passwords in database
- Password strings remaining in memory without clearing
- Passwords visible in logs

### CWE-260: Password in Configuration File
**File:** `PrivilegeAndPasswordVulnerabilities.java`
- Hard-coded passwords in source code
- Passwords in properties files
- API keys stored in configuration
- Database credentials in config files

### CWE-266: Incorrect Privilege Assignment
**File:** `PrivilegeAndPasswordVulnerabilities.java`
- Files created with overly permissive permissions
- Granting excessive privileges without proper checks
- Improper permission validation

### CWE-271: Privilege Dropping / Lowering Errors
**File:** `PrivilegeAndPasswordVulnerabilities.java`
- Failing to drop privileges after elevated operations
- Running with unnecessary elevated privileges

### CWE-273: Improper Check for Dropped Privileges
**File:** `PrivilegeAndPasswordVulnerabilities.java`
- Not verifying privilege drop succeeded
- Continuing sensitive operations without privilege verification

### CWE-284: Improper Access Control
**File:** `AccessControlVulnerabilities.java`
- Missing access control checks before sensitive operations
- Insecure direct object references (IDOR)
- Missing function-level access control
- Trusting client-side access control flags
- Missing authorization in API endpoints
- Horizontal privilege escalation vulnerabilities
- Vertical privilege escalation (any user can grant admin)
- File access without permission checks
- Resource access without authentication
- Missing ownership verification before modifications
- Weak session-based access control
- Unrestricted file upload vulnerabilities
- Missing rate limiting on sensitive operations

### CWE-285: Improper Authorization
**Files:** `AuthenticationAuthorizationVulnerability.java`, `AdditionalAuthorizationVulnerabilities.java`
- Missing role-based access control checks
- Insufficient authorization validation
- Authorization based on client-provided input
- Missing authorization for dangerous API endpoints
- Weak authorization logic patterns
- Path-based authorization bypass vulnerabilities
- Time-based authorization flaws
- Missing ownership checks in document modifications
- Group-based authorization bypass
- State-based authorization flaws
- Authorization via HTTP method confusion
- Missing re-authorization for privilege escalation
- Authorization check performed after data access
- Trusting client-side authorization flags

### CWE-287: Improper Authentication
**Files:** `AuthenticationAuthorizationVulnerability.java`, `AuthenticationBypassVulnerabilities.java`
- Authentication bypass with weak credential checks
- No password verification in login
- Hard-coded credential bypass
- Predictable session token generation
- Session fixation vulnerabilities
- Accepting default credentials
- Empty password authentication bypass
- Username-only authentication

### CWE-290: Authentication Bypass by Spoofing
**File:** `AuthenticationBypassVulnerabilities.java`
- Trusting client-provided authentication tokens without verification
- IP-based authentication using spoofable X-Forwarded-For header
- User-Agent based authentication
- Trusting Referer header for authentication
- Cookie-based authentication bypass (isAdmin cookie)
- Client-side authentication control spoofing

### CWE-295: Improper Certificate Validation
**File:** `CertificateValidationVulnerabilities.java`
- Disabling all SSL certificate verification
- Trust all certificates vulnerability
- Accepting self-signed certificates without validation
- Ignoring certificate validation errors
- Not checking certificate expiration dates
- Missing certificate chain validation
- Trust manager that logs but doesn't validate
- Accepting expired certificates

### CWE-297: Improper Validation of Certificate with Host Mismatch
**File:** `CertificateValidationVulnerabilities.java`
- Disabling hostname verification completely
- Custom hostname verifier that always returns true
- Weak hostname verification with substring matching
- Accepting any hostname in SSL connections

### CWE-311: Missing Encryption of Sensitive Data
**Files:** `InsecureDataTransmissionVulnerability.java`, `CryptographicStorageVulnerabilities.java`
- Missing encryption for database passwords in connection strings
- Storing API keys without encryption
- No encryption for sensitive configuration data
- Unencrypted sensitive data at rest

### CWE-312: Cleartext Storage of Sensitive Information
**File:** `CryptographicStorageVulnerabilities.java`
- Storing credit card numbers in cleartext files
- Cleartext storage of CVV and card expiry dates
- Storing Social Security Numbers without encryption
- Storing personal information (SSN, DOB) in plaintext
- Logging sensitive user credentials and credit cards
- Cleartext API key storage in files

### CWE-315: Cleartext Storage of Sensitive Information in a Cookie
**File:** `CryptographicStorageVulnerabilities.java`
- Storing userId and account balance in cleartext cookies
- Credit card numbers stored in cookies without encryption
- Session tokens in cookies without Secure flag
- Sensitive data in cookies without HttpOnly flag

### CWE-319: Cleartext Transmission of Sensitive Information
**Files:** `InsecureDataTransmissionVulnerability.java`, `CryptographicStorageVulnerabilities.java`
- Transmitting passwords over HTTP (unencrypted)
- Sending API keys over unencrypted connections
- Transmitting health data (PHI) over HTTP
- Credit card data transmission without TLS
- Unencrypted transmission of authentication credentials

### CWE-326: Inadequate Encryption Strength
**File:** `CryptographicStorageVulnerabilities.java`
- Using 56-bit DES encryption (inadequate key strength)
- Using 128-bit AES instead of 256-bit for sensitive data
- Using broken RC4 cipher
- Short encryption keys insufficient for security requirements

### CWE-259: Use of Hard-coded Password
### CWE-287: Improper Authentication
- Missing authorization in API endpoints
- Horizontal privilege escalation vulnerabilities
- Vertical privilege escalation (any user can grant admin)
- File access without permission checks
- Resource access without authentication
- Missing ownership verification before modifications
- Weak session-based access control
- Unrestricted file upload vulnerabilities
- Missing rate limiting on sensitive operations

### CWE-259: Use of Hard-coded Password
### CWE-285: Improper Authorization
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
- Detect 250+ security vulnerabilities across 50+ CWE categories including:
  - CWE-22, CWE-74, CWE-77, CWE-79, CWE-89, CWE-91, CWE-93, CWE-95, CWE-113, CWE-116, CWE-117
  - CWE-129, CWE-185, CWE-190, CWE-191, CWE-197, CWE-200, CWE-203, CWE-208, CWE-209
  - CWE-221, CWE-227, CWE-248, CWE-252, CWE-256, CWE-259, CWE-260, CWE-266, CWE-271, CWE-273
  - CWE-284, CWE-285, CWE-287, CWE-290, CWE-295, CWE-297, CWE-311, CWE-312, CWE-315, CWE-319
  - CWE-326, CWE-327, CWE-328, CWE-330, CWE-338, CWE-352, CWE-400, CWE-404, CWE-497, CWE-502
  - CWE-601, CWE-611, CWE-798

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
