# Core Specification
This file tracks the testing coverage of the SAML Core specification.

### Legend
```diff
+ Fully tested
- Ignored
Unmarked sections need attention
```

### Table of Contents
```diff
 1 Introduction
-	1.1 Notation
-	1.2 Schema Organization and Namespaces
	1.3 Common Data Types
		1.3.1 String Values
+		1.3.2 URI Values
		1.3.3 Time Values
		1.3.4 ID and ID Reference Values
2 SAML Assertions
-	2.1 Schema Header and Namespace Declarations
	2.2 Name Identifiers
-		2.2.1 Element <BaseID>
-		2.2.2 Complex Type NameIDType
-		2.2.3 Element <NameID>
		2.2.4 Element <EncryptedID>
-		2.2.5 Element <Issuer>
	2.3 Assertions
-		2.3.1 Element <AssertionIDRef>
-		2.3.2 Element <AssertionURIRef>
		2.3.3 Element <Assertion>
		2.3.4 Element <EncryptedAssertion>
	2.4 Subjects
		2.4.1 Element <Subject>
+			2.4.1.1 Element <SubjectConfirmation>
			2.4.1.2 Element <SubjectConfirmationData>
			2.4.1.3 Complex Type KeyInfoConfirmationDataType
-			2.4.1.4 Example of a Key-Confirmed <Subject>
	2.5 Conditions
		2.5.1 Element <Conditions>
			2.5.1.1 General Processing Rules
+			2.5.1.2 Attributes NotBefore and NotOnOrAfter
-			2.5.1.3 Element <Condition>
			2.5.1.4 Elements <AudienceRestriction> and <Audience>
			2.5.1.5 Element <OneTimeUse>
			2.5.1.6 Element <ProxyRestriction>
-	2.6 Advice
-		2.6.1 Element <Advice>
	2.7 Statements
-		2.7.1 Element <Statement>
+		2.7.2 Element <AuthnStatement>
-			2.7.2.1 Element <SubjectLocality>
-			2.7.2.2 Element <AuthnContext>
		2.7.3 Element <AttributeStatement>
			2.7.3.1 Element <Attribute>
+				2.7.3.1.1 Element <AttributeValue>
			2.7.3.2 Element <EncryptedAttribute>
		2.7.4 Element <AuthzDecisionStatement>
-			2.7.4.1 Simple Type DecisionType
+			2.7.4.2 Element <Action>
-			2.7.4.3 Element <Evidence>
3 SAML Protocols
-	3.1 Schema Header and Namespace Declarations
	3.2 Requests and Responses
+		3.2.1 Complex Type RequestAbstractType
		3.2.2 Complex Type StatusResponseType
+			3.2.2.1 Element <Status>
+			3.2.2.2 Element <StatusCode>
-			3.2.2.3 Element <StatusMessage>
-			3.2.2.4 Element <StatusDetail>
	3.3 Assertion Query and Request Protocol
-		3.3.1 Element <AssertionIDRequest>
-		3.3.2 Queries
-			3.3.2.1 Element <SubjectQuery>
-			3.3.2.2 Element <AuthnQuery>
-				3.3.2.2.1 Element <RequestedAuthnContext>
-			3.3.2.3 Element <AttributeQuery>
-			3.3.2.4 Element <AuthzDecisionQuery>
-		3.3.3 Element <Response>
		3.3.4 Processing Rules
+	3.4 Authentication Request Protocol
		3.4.1 Element <AuthnRequest>
			3.4.1.1 Element <NameIDPolicy>
-			3.4.1.2 Element <Scoping>
-			3.4.1.3 Element <IDPList>
-				3.4.1.3.1 Element <IDPEntry>
			3.4.1.4 Processing Rules
-			3.4.1.5 Proxying
				3.4.1.5.1 Proxying Processing Rules
-	3.5 Artifact Resolution Protocol
-		3.5.1 Element <ArtifactResolve>
-		3.5.2 Element <ArtifactResponse>
-		3.5.3 Processing Rules
-	3.6 Name Identifier Management Protocol
-		3.6.1 Element <ManageNameIDRequest>
-		3.6.2 Element <ManageNameIDResponse>
-		3.6.3 Processing Rules
-	3.7 Single Logout Protocol
+		3.7.1 Element <LogoutRequest>
-		3.7.2 Element <LogoutResponse>
-		3.7.3 Processing Rules
-			3.7.3.1 Session Participant Rules
-			3.7.3.2 Session Authority Rules
-	3.8 Name Identifier Mapping Protocol
-		3.8.1 Element <NameIDMappingRequest>
-		3.8.2 Element <NameIDMappingResponse>
-		3.8.3 Processing Rules
4 SAML Versioning
	4.1 SAML Specification Set Version
-		4.1.1 Schema Version
		4.1.2 SAML Assertion Version
		4.1.3 SAML Protocol Version
-			4.1.3.1 Request Version
			4.1.3.2 Response Version
			4.1.3.3 Permissible Version Combinations
	4.2 SAML Namespace Version
-		4.2.1 Schema Evolution
5 SAML and XML Signature Syntax and Processing
-	5.1 Signing Assertions
-	5.2 Request/Response Signing
-	5.3 Signature Inheritance
	5.4 XML Signature Profile
+		5.4.1 Signing Formats and Algorithms
+		5.4.2 References
-		5.4.3 Canonicalization Method
		5.4.4 Transforms
-		5.4.5 [E91] Object
-		5.4.6 KeyInfo
-		5.4.7 Example
6 SAML and XML Encryption Syntax and Processing
+	6.1 General Considerations
-	6.2 [E93] Encryption and Integrity Protection
-	6.3 [E43] Key and Data Referencing Guidelines
-	6.4 Examples
- 7 SAML Extensibility
-	7.1 Schema Extension
-		7.1.1 Assertion Schema Extension
-		7.1.2 Protocol Schema Extension
-	7.2 Schema Wildcard Extension Points
-		7.2.1 Assertion Extension Points
-		7.2.2 Protocol Extension Points
-	7.3 Identifier Extension
8 SAML-Defined Identifiers
	8.1 Action Namespace Identifiers
-		8.1.1 Read/Write/Execute/Delete/Control
		8.1.2 Read/Write/Execute/Delete/Control with Negation
-		8.1.3 Get/Head/Put/Post
-		8.1.4 UNIX File Permissions
+	8.2 Attribute Name Format Identifiers
+		8.2.1 Unspecified
+		8.2.2 URI Reference
+		8.2.3 Basic
-	8.3 Name Identifier Format Identifiers
-		8.3.1 Unspecified
-		8.3.2 Email Address
-			8.3.3 X.509 Subject Name
-		8.3.4 Windows Domain Qualified Name
-		8.3.5 Kerberos Principal Name
		8.3.6 Entity Identifier
		8.3.7 Persistent Identifier
		8.3.8 Transient Identifier
-	8.4 Consent Identifiers
-		8.4.1 Unspecified
-		8.4.2 Obtained
-		8.4.3 Prior
-		8.4.4 Implicit
-		8.4.5 Explicit
-		8.4.6 Unavailable
-		8.4.7 Inapplicable
```
