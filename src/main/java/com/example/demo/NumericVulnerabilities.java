package com.example.demo;

import javax.servlet.http.HttpServletRequest;

// CWE-129: Improper Validation of Array Index
// CWE-190: Integer Overflow or Wraparound
// CWE-191: Integer Underflow (Wrap or Wraparound)
// CWE-197: Numeric Truncation Error
public class NumericVulnerabilities {
    
    private String[] usernames = new String[100];
    private int[] balances = new int[100];
    
    // CWE-129: Unchecked array index
    public String getUserByIndex(int index) {
        // Vulnerable: no bounds checking
        return usernames[index];
    }
    
    // CWE-129: Array index from user input
    public String getUserData(HttpServletRequest request) {
        String indexStr = request.getParameter("index");
        int index = Integer.parseInt(indexStr);
        // Vulnerable: user-controlled array index
        return usernames[index];
    }
    
    // CWE-129: Negative array index
    public void setUserData(int index, String username) {
        // Vulnerable: no validation for negative index
        usernames[index] = username;
    }
    
    // CWE-190: Integer overflow in addition
    public int addBalance(int currentBalance, int amount) {
        // Vulnerable: integer overflow
        return currentBalance + amount;
    }
    
    // CWE-190: Integer overflow in multiplication
    public int calculateTotal(int quantity, int price) {
        // Vulnerable: overflow possible
        return quantity * price;
    }
    
    // CWE-190: Integer overflow in buffer size calculation
    public byte[] allocateBuffer(int size, int multiplier) {
        // Vulnerable: size * multiplier may overflow
        return new byte[size * multiplier];
    }
    
    // CWE-191: Integer underflow
    public int subtractAmount(int balance, int withdrawal) {
        // Vulnerable: underflow possible
        return balance - withdrawal;
    }
    
    // CWE-191: Underflow in loop counter
    public void processItems(int count) {
        // Vulnerable: count - 1 may underflow
        for (int i = count - 1; i >= 0; i--) {
            // Process item
        }
    }
    
    // CWE-197: Truncation from long to int
    public int convertLongToInt(long value) {
        // Vulnerable: numeric truncation
        return (int) value;
    }
    
    // CWE-197: Truncation from double to int
    public int calculateDiscount(double price, double discountPercent) {
        // Vulnerable: loss of precision
        return (int) (price * (discountPercent / 100));
    }
    
    // CWE-190: Unchecked cast
    public short convertToShort(int value) {
        // Vulnerable: value may exceed short range
        return (short) value;
    }
    
    // CWE-129: Buffer access with unvalidated size
    public void readBuffer(byte[] buffer, int offset, int length) {
        // Vulnerable: no validation of offset + length
        for (int i = offset; i < offset + length; i++) {
            byte b = buffer[i];
        }
    }
}
