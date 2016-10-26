package saml

import "encoding/xml"

type AuthnRequest struct {
	XMLName                        xml.Name
	SAMLP                          string                 `xml:"xmlns:samlp,attr"`
	SAML                           string                 `xml:"xmlns:saml,attr"`
	SAMLSIG                        string                 `xml:"xmlns:samlsig,attr,omitempty"`
	ID                             string                 `xml:"ID,attr"`
	Version                        string                 `xml:"Version,attr"`
	ProtocolBinding                string                 `xml:"ProtocolBinding,attr,omitempty"`
	AssertionConsumerServiceURL    string                 `xml:"AssertionConsumerServiceURL,attr"`
	IssueInstant                   string                 `xml:"IssueInstant,attr"`
	Destination                    string                 `xml:"Destination,attr,omitempty"`
	AssertionConsumerServiceIndex  int                    `xml:"AssertionConsumerServiceIndex,attr,omitempty"`
	AttributeConsumingServiceIndex int                    `xml:"AttributeConsumingServiceIndex,attr,omitempty"`
	ForceAuthn                     string                 `xml:"ForceAuthn,attr,omitempty"`
	Issuer                         Issuer                 `xml:"Issuer"`
	Signature                      []Signature            `xml:"Signature,omitempty"`
	NameIDPolicy                   *NameIDPolicy          `xml:"NameIDPolicy,omitempty"`
	RequestedAuthnContext          *RequestedAuthnContext `xml:"RequestedAuthnContext,omitempty"`
	originalString                 string
}

type Issuer struct {
	XMLName xml.Name
	SAML    string `xml:"xmlns:saml,attr,omitempty"`
	Url     string `xml:",innerxml"`
}

type NameIDPolicy struct {
	XMLName     xml.Name
	AllowCreate bool   `xml:"AllowCreate,attr,omitempty"`
	Format      string `xml:"Format,attr"`
}

type RequestedAuthnContext struct {
	XMLName              xml.Name
	SAMLP                string               `xml:"xmlns:samlp,attr,omitempty"`
	Comparison           string               `xml:"Comparison,attr"`
	AuthnContextClassRef AuthnContextClassRef `xml:"AuthnContextClassRef"`
}

type AuthnContextClassRef struct {
	XMLName   xml.Name
	SAML      string `xml:"xmlns:saml,attr,omitempty"`
	Transport string `xml:",innerxml"`
}

type Signature struct {
	XMLName        xml.Name
	Id             string `xml:"Id,attr"`
	SignedInfo     SignedInfo
	SignatureValue SignatureValue
	KeyInfo        KeyInfo
}

type SignedInfo struct {
	XMLName                xml.Name
	CanonicalizationMethod CanonicalizationMethod `xml:"CanonicalizationMethod"`
	SignatureMethod        SignatureMethod        `xml:"SignatureMethod"`
	SamlsigReference       SamlsigReference       `xml:"Reference"`
}

type SignatureValue struct {
	XMLName xml.Name
	Value   string `xml:",innerxml"`
}

type KeyInfo struct {
	XMLName  xml.Name
	X509Data X509Data `xml:"X509Data"`
}

type CanonicalizationMethod struct {
	XMLName   xml.Name
	Algorithm string `xml:"Algorithm,attr"`
}

type SignatureMethod struct {
	XMLName   xml.Name
	Algorithm string `xml:"Algorithm,attr"`
}

type SamlsigReference struct {
	XMLName      xml.Name
	URI          string       `xml:"URI,attr"`
	Transforms   Transforms   `xml:",innerxml"`
	DigestMethod DigestMethod `xml:",innerxml"`
	DigestValue  DigestValue  `xml:",innerxml"`
}

type X509Data struct {
	XMLName         xml.Name
	X509Certificate X509Certificate `xml:"X509Certificate"`
}

type Transforms struct {
	XMLName    xml.Name
	Transforms []Transform
}

type DigestMethod struct {
	XMLName   xml.Name
	Algorithm string `xml:"Algorithm,attr"`
}

type DigestValue struct {
	XMLName xml.Name
}

type X509Certificate struct {
	XMLName xml.Name
	Cert    string `xml:",innerxml"`
}

type Transform struct {
	XMLName   xml.Name
	Algorithm string `xml:"Algorithm,attr"`
}

type EntityDescriptor struct {
	XMLName  xml.Name
	DS       string `xml:"xmlns:ds,attr"`
	XMLNS    string `xml:"xmlns,attr"`
	MD       string `xml:"xmlns:md,attr"`
	EntityId string `xml:"entityID,attr"`

	Extensions      Extensions      `xml:"Extensions"`
	SPSSODescriptor SPSSODescriptor `xml:"SPSSODescriptor"`
}

type Extensions struct {
	XMLName xml.Name
	Alg     string `xml:"xmlns:alg,attr"`
	MDAttr  string `xml:"xmlns:mdattr,attr"`
	MDRPI   string `xml:"xmlns:mdrpi,attr"`

	EntityAttributes string `xml:"EntityAttributes"`
}

type SSODescriptor struct {
	//ArtifactResolutionServices []ArtifactResolutionServices `xml:"ArtifactResolutionService"`
	SingleLogoutService []SingleLogoutService `xml:"SingleLogoutService"`
	//NameIDFormats              []NameIdFormat               `xml:"NameIDFormat"`
}

type SPSSODescriptor struct {
	XMLName                    xml.Name
	ProtocolSupportEnumeration string `xml:"protocolSupportEnumeration,attr"`
	SSODescriptor
	SigningKeyDescriptor    KeyDescriptor
	EncryptionKeyDescriptor KeyDescriptor
	// SingleLogoutService        SingleLogoutService `xml:"SingleLogoutService"`
	AssertionConsumerServices []AssertionConsumerService
}

type IDPSSODescriptor struct {
	XMLName                    xml.Name
	ProtocolSupportEnumeration string `xml:"protocolSupportEnumeration,attr"`
	SSODescriptor
	KeyDescriptors      []KeyDescriptor
	SingleSignOnService []SingleSignOnService `xml:"SingleSignOnService"`
	Attributes          []Attribute
}

type EntityAttributes struct {
	XMLName xml.Name
	SAML    string `xml:"xmlns:saml,attr"`

	EntityAttributes []Attribute `xml:"Attribute"` // should be array??
}

type KeyDescriptor struct {
	XMLName xml.Name
	Use     string  `xml:"use,attr"`
	KeyInfo KeyInfo `xml:"KeyInfo"`
}

type SingleLogoutService struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

type SingleSignOnService struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

type AssertionConsumerService struct {
	XMLName  xml.Name
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
	Index    string `xml:"index,attr"`
}

type Response struct {
	XMLName      xml.Name
	SAMLP        string `xml:"xmlns:samlp,attr"`
	SAML         string `xml:"xmlns:saml,attr"`
	SAMLSIG      string `xml:"xmlns:samlsig,attr"`
	Destination  string `xml:"Destination,attr"`
	ID           string `xml:"ID,attr"`
	Version      string `xml:"Version,attr"`
	IssueInstant string `xml:"IssueInstant,attr"`
	InResponseTo string `xml:"InResponseTo,attr"`

	Assertion          Assertion          `xml:"Assertion"`
	EncryptedAssertion EncryptedAssertion `xml:"EncryptedAssertion"`
	Signature          Signature          `xml:"Signature"`
	Issuer             Issuer             `xml:"Issuer"`
	Status             Status             `xml:"Status"`
	originalString     string
}

type EncryptedData struct {
	XMLName xml.Name
	Type    string `xml:"Type,attr"`
}

type EncryptedAssertion struct {
	XMLName       xml.Name
	EncryptedData *EncryptedData `xml:"EncryptedData"`

	// "Assertion" nodes are not valid here according to the SAML assertion schema, but they are implied by the
	// XMLEnc standard as an intermediate form, and therefore in the files that 'xmlsec1 --decrypt' returns.
	Assertion *Assertion `xml:"Assertion"`
}

type Assertion struct {
	XMLName            xml.Name
	ID                 string    `xml:"ID,attr"`
	Version            string    `xml:"Version,attr"`
	XS                 string    `xml:"xmlns:xs,attr"`
	XSI                string    `xml:"xmlns:xsi,attr"`
	SAML               string    `xml:"saml,attr"`
	IssueInstant       string    `xml:"IssueInstant,attr"`
	Issuer             Issuer    `xml:"Issuer"`
	Signature          Signature `xml:"Signature"`
	Subject            Subject
	Conditions         Conditions
	AttributeStatement AttributeStatement
	AuthnStatement     AuthnStatement
}

type AuthnStatement struct {
	SessionIndex string `xml:"SessionIndex,attr"`
}

type Conditions struct {
	XMLName      xml.Name
	NotBefore    string `xml:",attr"`
	NotOnOrAfter string `xml:",attr"`
}

type Subject struct {
	XMLName             xml.Name
	NameID              NameID
	SubjectConfirmation SubjectConfirmation
}

type SubjectConfirmation struct {
	XMLName                 xml.Name
	Method                  string `xml:",attr"`
	SubjectConfirmationData SubjectConfirmationData
}

type Status struct {
	XMLName    xml.Name
	StatusCode StatusCode `xml:"StatusCode"`
}

type SubjectConfirmationData struct {
	InResponseTo string `xml:",attr"`
	NotOnOrAfter string `xml:",attr"`
	Recipient    string `xml:",attr"`
}

type NameID struct {
	XMLName xml.Name
	Format  string `xml:",attr,omitempty"`
	Value   string `xml:",innerxml"`
}

type StatusCode struct {
	XMLName xml.Name
	Value   string `xml:",attr"`
}

type AttributeValue struct {
	XMLName xml.Name
	Type    string `xml:"xsi:type,attr"`
	Value   string `xml:",innerxml"`
}

type Attribute struct {
	XMLName         xml.Name
	Name            string           `xml:",attr"`
	FriendlyName    string           `xml:",attr"`
	NameFormat      string           `xml:",attr"`
	AttributeValues []AttributeValue `xml:"AttributeValue"`
}

type AttributeStatement struct {
	XMLName    xml.Name
	Attributes []Attribute `xml:"Attribute"`
}

type LogoutRequest struct {
	XMLName      xml.Name
	SAMLP        string         `xml:"xmlns:samlp,attr"`
	SAML         string         `xml:"xmlns:saml,attr"`
	SAMLSIG      string         `xml:"xmlns:samlsig,attr,omitempty"`
	ID           string         `xml:"ID,attr"`
	Version      string         `xml:"Version,attr"`
	IssueInstant string         `xml:"IssueInstant,attr"`
	Destination  string         `xml:"Destination,attr,omitempty"`
	Issuer       Issuer         `xml:"Issuer"`
	Signature    *Signature     `xml:"Signature,omitempty"`
	NameID       NameID         `xml:"NameID"`
	SessionIndex []SessionIndex `xml:"SessionIndex"`
}

type SessionIndex struct {
	XMLName xml.Name
	Value   string `xml:",innerxml"`
}

type RoleDescriptor struct {
	ValidUntil                 string          `xml:"validUntil,attr,omitempty"`
	CacheDuration              string          `xml:"cacheDuration,attr,omitempty"`
	ProtocolSupportEnumeration string          `xml:"protocolSupportEnumeration,attr"`
	Signature                  *Signature      `xml:"Signature,omitempty"`
	KeyDescriptors             []KeyDescriptor `xml:"KeyDescriptor,omitempty"`
}

type Metadata struct {
	XMLName       xml.Name   // urn:oasis:names:tc:SAML:2.0:metadata:EntityDescriptor
	ID            string     `xml:"ID,attr,omitempty"`
	EntityId      string     `xml:"entityID,attr"`
	ValidUntil    string     `xml:"validUntil,attr,omitempty"`
	CacheDuration string     `xml:"cacheDuration,attr,omitempty"`
	Signature     *Signature `xml:"Signature,omitempty"`

	// note: the schema permits these elements to appear in any order an unlimited number of times
	RoleDescriptor   []RoleDescriptor  `xml:"RoleDescriptor,omitempty"`
	SPSSODescriptor  *SPSSODescriptor  `xml:"SPSSODescriptor,omitempty"`
	IDPSSODescriptor *IDPSSODescriptor `xml:"IDPSSODescriptor,omitempty"`
}
