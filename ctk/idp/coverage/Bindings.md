# Bindings Specification
This file tracks the testing coverage of the SAML Bindings specification.

### Legend
```diff
+ Fully tested
- Ignored
Unmarked sections need attention
```

### Table of Contents
```diff
- 1 Introduction
-	1.1 Protocol Binding Concepts
-	1.2 Notation
- 2 Guidelines for Specifying Additional Protocol Bindings
3 Protocol Bindings
-	3.1 General Considerations
+		3.1.1 Use of RelayState
-		3.1.2 Security
			3.1.2.1 Use of SSL 3.0 or TLS 1.0
-			3.1.2.2 Data Origin Authentication
-			3.1.2.3 Message Integrity
-			3.1.2.4 Message Confidentiality
-			3.1.2.5 Security Considerations
	3.2 SAML SOAP Binding
		3.2.1 Required Information
		3.2.2 Protocol-Independent Aspects of the SAML SOAP Binding
			3.2.2.1 Basic Operation
			3.2.2.2 SOAP Headers
		3.2.3 Use of SOAP over HTTP
			3.2.3.1 HTTP Headers
			3.2.3.2 Caching
			3.2.3.3 Error Reporting
			3.2.3.4 Metadata Considerations
			3.2.3.5 Example SAML Message Exchange Using SOAP over HTTP
	3.3 Reverse SOAP (PAOS) Binding
		3.3.1 Required Information
		3.3.2 Overview
		3.3.3 Message Exchange
			3.3.3.1 HTTP Request, SAML Request in SOAP Response
			3.3.3.2 SAML Response in SOAP Request, HTTP Response
		3.3.4 Caching
		3.3.5 Security Considerations
			3.3.5.1 Error Reporting
			3.3.5.2 Metadata Considerations
-	3.4 HTTP Redirect Binding
-		3.4.1 Required Information
-		3.4.2 Overview
+		3.4.3 RelayState
+		3.4.4 Message Encoding
+			3.4.4.1 DEFLATE Encoding
+		3.4.5 Message Exchange
-			3.4.5.1 HTTP and Caching Considerations
+			3.4.5.2 Security Considerations
+		3.4.6 Error Reporting
-		3.4.7 Metadata Considerations
-		3.4.8 Example SAML Message Exchange Using HTTP Redirect
-	3.5 HTTP POST Binding
-		3.5.1 Required Information
-		3.5.2 Overview
+		3.5.3 RelayState
+		3.5.4 Message Encoding
-		3.5.5 Message Exchange
-			3.5.5.1 HTTP and Caching Considerations
+			3.5.5.2 Security Considerations
+		3.5.6 Error Reporting
-		3.5.7 Metadata Considerations
-		3.5.8 Example SAML Message Exchange Using HTTP POST
	3.6 HTTP Artifact Binding
		3.6.1 Required Information
		3.6.2 Overview
		3.6.3 Message Encoding
			3.6.3.1 RelayState
			3.6.3.2 URL Encoding
			3.6.3.3 Form Encoding
		3.6.4 Artifact Format
			3.6.4.1 Required Information
			3.6.4.2 Format Details
		3.6.5 Message Exchange
			3.6.5.1 HTTP and Caching Considerations
			3.6.5.2 Security Considerations
		3.6.6 Error Reporting
		3.6.7 Metadata Considerations
		3.6.8 Example SAML Message Exchange Using HTTP Artifact
	3.7 SAML URI Binding
		3.7.1 Required Information
		3.7.2 Protocol-Independent Aspects of the SAML URI Binding
			3.7.2.1 Basic Operation
		3.7.3 Security Considerations
		3.7.4 MIME Encapsulation
		3.7.5 Use of HTTP URIs
			3.7.5.1 URI Syntax
			3.7.5.2 HTTP and Caching Considerations
			3.7.5.3 Security Considerations
			3.7.5.4 Error Reporting
			3.7.5.5 Metadata Considerations
			3.7.5.6 Example SAML Message Exchange Using an HTTP URI
```