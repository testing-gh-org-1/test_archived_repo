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
│   │   │   └── SQLInjectionVulnerability.java (CWE-89)
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

## CodeQL Analysis

The repository includes a GitHub Actions workflow (`.github/workflows/codeql-analysis.yml`) that will:
- Automatically scan the code on push to main/master branches
- Scan pull requests
- Run weekly security scans
- Detect security vulnerabilities including CWE-74, CWE-77, CWE-89, CWE-209, CWE-497, CWE-327, and CWE-328

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
