# Profiles Specification
This file tracks the testing coverage of the SAML Profiles specification.

### Legend
```diff
+ Fully tested
- Ignored
Unmarked sections need attention
```

### Table of Contents
```diff
- 1 Introduction
-	1.1 Profile Concepts
-	1.2 Notation
- 2 Specification of Additional Profiles
-	2.1 Guidelines for Specifying Profiles
-	2.2 Guidelines for Specifying Attribute Profiles
- 3 Confirmation Method Identifiers
-	3.1 Holder of Key
-	3.2 Sender Vouches
-	3.3 Bearer
4 SSO Profiles of SAML
-	4.1 Web Browser SSO Profile
-		4.1.1 Required Information
-		4.1.2 Profile Overview
		4.1.3 Profile Description
-			4.1.3.1 HTTP Request to Service Provider
-			4.1.3.2 Service Provider Determines Identity Provider
			4.1.3.3 <AuthnRequest> Is Issued by Service Provider to Identity Provider
			4.1.3.4 Identity Provider Identifies Principal
			4.1.3.5 Identity Provider Issues <Response> to Service Provider
-			4.1.3.6 Service Provider Grants or Denies Access to User Agent
		4.1.4 Use of Authentication Request Protocol
			4.1.4.1 <AuthnRequest> Usage
+			4.1.4.2 <Response> Usage
-			4.1.4.3 <Response> Message Processing Rules
-			4.1.4.4 Artifact-Specific <Response> Message Processing Rules
+			4.1.4.5 POST-Specific Processing Rules
-		4.1.5 Unsolicited Responses
-		4.1.6 [E90] Use of Relay State
-		4.1.7 Use of Metadata
	4.2 Enhanced Client or Proxy (ECP) Profile
		4.2.1 Required Information
		4.2.2 Profile Overview
		4.2.3 Profile Description
			4.2.3.1 ECP issues HTTP Request to Service Provider
			4.2.3.2 Service Provider Issues <AuthnRequest> to ECP
			4.2.3.3 ECP Determines Identity Provider
			4.2.3.4 ECP issues <AuthnRequest> to Identity Provider
			4.2.3.5 Identity Provider Identifies Principal
			4.2.3.6 Identity Provider issues <Response> to ECP, targeted at service provider
			4.2.3.7 ECP Conveys <Response> Message to Service Provider
			4.2.3.8 Service Provider Grants or Denies Access to Principal
		4.2.4 ECP Profile Schema Usage
			4.2.4.1 PAOS Request Header Block: SP to ECP
			4.2.4.2 ECP Request Header Block: SP to ECP
			4.2.4.3 ECP RelayState Header Block: SP to ECP
			4.2.4.4 ECP Response Header Block: IdP to ECP
			4.2.4.5 PAOS Response Header Block: ECP to SP
		4.2.5 Security Considerations
		4.2.6 [E20]Use of Metadata
	4.3 Identity Provider Discovery Profile
		4.3.1 [E32]Required Information
		4.3.2 Common Domain Cookie
		4.3.3 Setting the Common Domain Cookie
		4.3.4 Obtaining the Common Domain Cookie
	4.4 Single Logout Profile
		4.4.1 Required Information
		4.4.2 Profile Overview
		4.4.3 Profile Description
			4.4.3.1 <LogoutRequest> Issued by Session Participant to Identity Provider
			4.4.3.2 Identity Provider Determines Session Participants
			4.4.3.3 <LogoutRequest> Issued by Identity Provider to Session Participant/Authority
			4.4.3.4 Session Participant/Authority Issues <LogoutResponse> to Identity Provider
			4.4.3.5 Identity Provider Issues <LogoutResponse> to Session Participant
		4.4.4 Use of Single Logout Protocol
			4.4.4.1 <LogoutRequest> Usage
			4.4.4.2 <LogoutResponse> Usage
		4.4.5 Use of Metadata
	4.5 Name Identifier Management Profile
		4.5.1 Required Information
		4.5.2 Profile Overview
		4.5.3 Profile Description
			4.5.3.1 <ManageNameIDRequest> Issued by Requesting Identity/Service Provider
			4.5.3.2 <ManageNameIDResponse> issued by Responding Identity/Service Provider
		4.5.4 Use of Name Identifier Management Protocol
			4.5.4.1 <ManageNameIDRequest> Usage
			4.5.4.2 <ManageNameIDResponse> Usage
		4.5.5 Use of Metadata
5 Artifact Resolution Profile
	5.1 Required Information
	5.2 Profile Overview
	5.3 Profile Description
		5.3.1 <ArtifactResolve> issued by Requesting Entity
		5.3.2 <ArtifactResponse> issued by Responding Entity
	5.4 Use of Artifact Resolution Protocol
		5.4.1 <ArtifactResolve> Usage
		5.4.2 <ArtifactResponse> Usage
	5.5 Use of Metadata
6 Assertion Query/Request Profile
	6.1 Required Information
	6.2 Profile Overview
	6.3 Profile Description
		6.3.1 Query/Request issued by SAML Requester
		6.3.2 <Response> issued by SAML Authority
	6.4 Use of Query/Request Protocol
		6.4.1 Query/Request Usage
		6.4.2 <Response> Usage
	6.5 Use of Metadata
7 Name Identifier Mapping Profile
	7.1 Required Information
	7.2 Profile Overview
	7.3 Profile Description
		7.3.1 <NameIDMappingRequest> issued by Requesting Entity
		7.3.2 <NameIDMappingResponse> issued by Identity Provider
	7.4 Use of Name Identifier Mapping Protocol
		7.4.1 <NameIDMappingRequest> Usage
		7.4.2 <NameIDMappingResponse> Usage
			7.4.2.1 Limiting Use of Mapped Identifier
	7.5 Use of Metadata
8 SAML Attribute Profiles
	8.1 Basic Attribute Profile
		8.1.1 Required Information
		8.1.2 SAML Attribute Naming
			8.1.2.1 Attribute Name Comparison
		8.1.3 Profile-Specific XML Attributes
		8.1.4 SAML Attribute Values
		8.1.5 Example
		8.2 X.500/LDAP Attribute Profile [E53] – Deprecated
		8.2.1 Required Information
		8.2.2 SAML Attribute Naming
			8.2.2.1 Attribute Name Comparison
		8.2.3 Profile-Specific XML Attributes
		8.2.4 SAML Attribute Values
		8.2.5 Profile-Specific Schema
		8.2.6 Example
	8.3 UUID Attribute Profile
		8.3.1 Required Information
		8.3.2 UUID and GUID Background
		8.3.3 SAML Attribute Naming
			8.3.3.1 Attribute Name Comparison
		8.3.4 Profile-Specific XML Attributes
		8.3.5 SAML Attribute Values
		8.3.6 Example
	8.4 DCE PAC Attribute Profile
		8.4.1 Required Information
		8.4.2 PAC Description
		8.4.3 SAML Attribute Naming
			8.4.3.1 Attribute Name Comparison
		8.4.4 Profile-Specific XML Attributes
		8.4.5 SAML Attribute Values
		8.4.6 Attribute Definitions
			8.4.6.1 Realm
			8.4.6.2 Principal
			8.4.6.3 Primary Group
			8.4.6.4 Groups
			8.4.6.5 Foreign Groups
		8.4.7 Example
	8.5 XACML Attribute Profile
		8.5.1 Required Information
		8.5.2 SAML Attribute Naming
			8.5.2.1 Attribute Name Comparison
		8.5.3 Profile-Specific XML Attributes
		8.5.4 SAML Attribute Values
		8.5.5 Profile-Specific Schema
		8.5.6 Example
```