package com.example.demo;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

// CWE-295: Improper Certificate Validation
// CWE-297: Improper Validation of Certificate with Host Mismatch
public class CertificateValidationVulnerabilities {
    
    // CWE-295: Trust all certificates
    public void disableSSLVerification() throws NoSuchAlgorithmException, KeyManagementException {
        // Vulnerable: disabling all SSL certificate verification
        TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
                
                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                    // Vulnerable: no validation
                }
                
                public void checkServerTrusted(X509Certificate[] certs, String authType) {
                    // Vulnerable: no validation
                }
            }
        };
        
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
    }
    
    // CWE-297: Disable hostname verification
    public void disableHostnameVerification() {
        // Vulnerable: accepting all hostnames
        HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                return true; // Accepts any hostname
            }
        });
    }
    
    // CWE-295: Accept self-signed certificates
    public HttpsURLConnection connectWithoutValidation(String urlString) throws IOException, NoSuchAlgorithmException, KeyManagementException {
        // Vulnerable: creating connection without certificate validation
        TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                public void checkServerTrusted(X509Certificate[] certs, String authType) {}
            }
        };
        
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustAllCerts, new SecureRandom());
        
        URL url = new URL(urlString);
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.setSSLSocketFactory(sslContext.getSocketFactory());
        connection.setHostnameVerifier((hostname, session) -> true);
        
        return connection;
    }
    
    // CWE-295: Ignoring certificate validation errors
    public void connectIgnoringErrors(String urlString) {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[] { new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {}
                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {}
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }}, null);
            
            SSLSocketFactory factory = ctx.getSocketFactory();
            HttpsURLConnection.setDefaultSSLSocketFactory(factory);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // CWE-297: Custom hostname verifier that always returns true
    public static class InsecureHostnameVerifier implements HostnameVerifier {
        public boolean verify(String hostname, SSLSession session) {
            // Vulnerable: no hostname verification
            return true;
        }
    }
    
    // CWE-295: Accepting expired certificates
    public boolean validateCertificate(X509Certificate cert) {
        // Vulnerable: not checking certificate expiration
        return cert != null;
    }
    
    // CWE-295: Not checking certificate chain
    public void connectWithoutChainValidation(String urlString) throws Exception {
        TrustManager tm = new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
                // Vulnerable: no chain validation
            }
            
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
                // Vulnerable: accepting any certificate chain
            }
            
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }
        };
        
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[] { tm }, null);
        
        URL url = new URL(urlString);
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setSSLSocketFactory(sslContext.getSocketFactory());
    }
    
    // CWE-297: Partial hostname verification
    public boolean weakHostnameCheck(String hostname, String expectedHost) {
        // Vulnerable: weak substring matching
        return hostname.contains(expectedHost);
    }
    
    // CWE-295: Trust manager that logs but doesn't validate
    public static class LoggingTrustManager implements X509TrustManager {
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            // Vulnerable: just logging, not validating
            System.out.println("Client certificate: " + (chain.length > 0 ? chain[0].getSubjectDN() : "none"));
        }
        
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            // Vulnerable: just logging, not validating
            System.out.println("Server certificate: " + (chain.length > 0 ? chain[0].getSubjectDN() : "none"));
        }
        
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
