package com.example.demo;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

// CWE-287: Improper Authentication
// CWE-290: Authentication Bypass by Spoofing
public class AuthenticationBypassVulnerabilities {
    
    // CWE-287: Authentication bypass with weak credential check
    public boolean authenticateUser(String username, String password) {
        // Vulnerable: allows empty password
        if (username != null && !username.isEmpty()) {
            return true;
        }
        return false;
    }
    
    // CWE-287: No password verification
    public boolean loginUser(String username) {
        // Vulnerable: authenticates without checking password
        if (username.equals("admin") || username.equals("user")) {
            return true;
        }
        return false;
    }
    
    // CWE-287: Hard-coded credential bypass
    public boolean adminLogin(String username, String password) {
        // Vulnerable: hard-coded bypass credentials
        if (username.equals("admin") && password.equals("admin123")) {
            return true;
        }
        // Also vulnerable: no rate limiting
        return checkDatabase(username, password);
    }
    
    // CWE-290: Trust client-provided authentication token
    public void authenticateByToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String token = request.getHeader("X-Auth-Token");
        // Vulnerable: trusting client-provided token without verification
        if (token != null && !token.isEmpty()) {
            response.getWriter().println("Authenticated successfully");
        }
    }
    
    // CWE-290: IP-based authentication spoofing
    public boolean authenticateByIP(HttpServletRequest request) {
        String clientIP = request.getHeader("X-Forwarded-For");
        // Vulnerable: trusting X-Forwarded-For header (can be spoofed)
        if ("192.168.1.100".equals(clientIP)) {
            return true;
        }
        return false;
    }
    
    // CWE-290: User-Agent based authentication
    public boolean authenticateByUserAgent(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        // Vulnerable: authenticating based on spoofable User-Agent
        if (userAgent != null && userAgent.contains("TrustedClient")) {
            return true;
        }
        return false;
    }
    
    // CWE-287: Session fixation vulnerability
    public void login(HttpServletRequest request, String username, String password) {
        // Vulnerable: not regenerating session ID after login
        HttpSession session = request.getSession();
        session.setAttribute("username", username);
        session.setAttribute("authenticated", true);
    }
    
    // CWE-290: Trusting Referer header
    public boolean verifyRequest(HttpServletRequest request) {
        String referer = request.getHeader("Referer");
        // Vulnerable: trusting Referer header for authentication
        if (referer != null && referer.contains("trusted-domain.com")) {
            return true;
        }
        return false;
    }
    
    // CWE-287: Predictable session tokens
    public String generateSessionToken(String username) {
        // Vulnerable: predictable session token generation
        return username + "_" + System.currentTimeMillis();
    }
    
    // CWE-290: Cookie-based authentication bypass
    public boolean authenticateByCookie(HttpServletRequest request) {
        javax.servlet.http.Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (javax.servlet.http.Cookie cookie : cookies) {
                // Vulnerable: trusting client-side cookie without verification
                if ("isAdmin".equals(cookie.getName()) && "true".equals(cookie.getValue())) {
                    return true;
                }
            }
        }
        return false;
    }
    
    // CWE-287: Default credentials
    public boolean checkDefaultCredentials(String username, String password) {
        // Vulnerable: accepting default credentials
        if ("admin".equals(username) && "password".equals(password)) {
            return true;
        }
        if ("root".equals(username) && "toor".equals(password)) {
            return true;
        }
        return false;
    }
    
    private boolean checkDatabase(String username, String password) {
        // Simulated database check
        return username != null && password != null;
    }
}
