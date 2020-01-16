package saml

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResponseSignatureOnResponse(t *testing.T) {
	assertion := assert.New(t)
	sp := ServiceProviderSettings{
		PublicCertPath:              "./default.crt",
		PrivateKeyPath:              "./default.key",
		IDPSSOURL:                   "http://www.onelogin.net",
		IDPSSODescriptorURL:         "http://www.onelogin.net",
		IDPPublicCertPath:           "./default.crt",
		AssertionConsumerServiceURL: "http://localhost:8000/auth/saml/name",
		SPSignRequest:               true,
	}

	err := sp.Init()
	assertion.NoError(err)

	// Construct a SignedResponse
	response := NewSignedResponse()

	var sURI strings.Builder
	sURI.WriteString("#")
	sURI.WriteString(response.ID)

	response.Signature.SignedInfo.SamlsigReference.URI = sURI.String()

	sXml, err := response.String()
	assertion.NoError(err)

	fmt.Println("Response (XML as String) : ", sXml)

	signedXml, err := SignResponse(sXml, "./default.key")
	assertion.NoError(err)

	fmt.Println("Signed Response (XML as String) : ", sXml)

	signedResponse, err := ParseDecodedResponse([]byte(signedXml))
	assertion.NoError(err)

	err = signedResponse.VerifySignature("./default.crt")
	assertion.NoError(err)
}

func TestResponseSignatureOnAssertion(t *testing.T) {
	assertion := assert.New(t)
	sp := ServiceProviderSettings{
		PublicCertPath:              "./default.crt",
		PrivateKeyPath:              "./default.key",
		IDPSSOURL:                   "http://www.onelogin.net",
		IDPSSODescriptorURL:         "http://www.onelogin.net",
		IDPPublicCertPath:           "./default.crt",
		AssertionConsumerServiceURL: "http://localhost:8000/auth/saml/name",
		SPSignRequest:               true,
	}

	err := sp.Init()
	assertion.NoError(err)

	// Construct a SignedResponse
	response := NewSignedResponse()

	var sURI strings.Builder
	sURI.WriteString("#")
	sURI.WriteString(response.ID)

	response.Assertion.Signature.SignedInfo.SamlsigReference.URI = sURI.String()

	sXml, err := response.String()
	assertion.NoError(err)

	fmt.Println("Response (XML as String) : ", sXml)

	signedXml, err := SignResponse(sXml, "./default.key")
	assertion.NoError(err)

	fmt.Println("Signed Response (XML as String) : ", sXml)

	signedResponse, err := ParseDecodedResponse([]byte(signedXml))
	assertion.NoError(err)

	err = signedResponse.VerifySignature("./default.crt")
	assertion.NoError(err)
}

func TestLoadedXmlResponse(t *testing.T) {
	assertion := assert.New(t)
	sp := ServiceProviderSettings{
		PublicCertPath:              "./default.crt",
		PrivateKeyPath:              "./default.key",
		IDPSSOURL:                   "http://www.onelogin.net",
		IDPSSODescriptorURL:         "http://www.onelogin.net",
		IDPPublicCertPath:           "./default.crt",
		AssertionConsumerServiceURL: "http://localhost:8000/auth/saml/name",
		SPSignRequest:               true,
	}

	err := sp.Init()
	assertion.NoError(err)

	gpXMLResponse, err := LoadXml("./samlresponse.xml") // Feel free to change the Path to whatever your XML Response is
	assertion.NoError(err)

	err = VerifyResponseSignature(gpXMLResponse, sp.PublicCertPath, "")
	assertion.NoError(err)
}
