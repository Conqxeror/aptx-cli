# 🛡️ Penetration Testing Checklist
**Title:** *This Is What Should AI Do When AI Hunt*

---

## 🔍 Reconnaissance
1. Find Subdomains  
2. Check CNAME Records of Subdomains (for Subdomain Takeover)  
3. Use WaybackURLs for historical URL discovery  
4. Use MassScan for port scanning  
5. Perform GitHub Recon  

---

## 🌐 Web Application Testing
6. On WebApp  
7. Check for CORS Misconfiguration  
8. Test Email Header Injection (especially in password reset)  
9. Check for SMTP and Host Header Injection  
10. Test for IFRAME vulnerabilities (Clickjacking)  
11. Check for Improper Access Control & Parameter Tampering  
12. Review Burp Suite history for endpoints  
13. Use Arjun to find hidden endpoints  
14. Check for CSRF  
15. Test for SSRF parameters  
16. Check for XSS and SSTI  
17. Analyze cryptography in reset password tokens  
18. Test for Unicode Injection in email parameters  
19. Attempt to bypass rate limits  

---

## 📁 Advanced Exploits & Edge Cases
20. Directory brute-force  
21. Check for HTTP Request Smuggling  
22. Test for Open Redirects via WaybackURLs  
23. Check for Social Sign-on Bypass  
24. Inspect State Parameter in Social Sign-in  
    - Test for DoS via multiple cookie injection  
25. File Upload Vulnerabilities:  
    - CSRF, XSS, SSRF, RCE, LFI, XXE  
26. Buffer Overflow  

---

## 📦 IP Header Injection Targets
Used for spoofing or bypassing IP-based restrictions:

| Header Name         | Description  |
|---------------------|--------------|
| X-Originating-IP     | IP Address   |
| X-Forwarded-For      | IP Address   |
| X-Remote-IP          | IP Address   |
| X-Remote-Addr        | IP Address   |
| X-Client-IP          | IP Address   |
| X-Forwarded-Host     | IP Address   |

---

> ✅ Use this checklist as a guide during bug bounty hunting or penetration testing engagements. 