package saml

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetSignedRequest(t *testing.T) {
	assert := assert.New(t)
	sp := ServiceProviderSettings{
		PublicCertPath:              "./default.crt",
		PrivateKeyPath:              "./default.key",
		IDPSSOURL:                   "http://www.onelogin.net",
		IDPSSODescriptorURL:         "http://www.onelogin.net",
		IDPPublicCertPath:           "./default.crt",
		AssertionConsumerServiceURL: "http://localhost:8000/auth/saml/name",
	}
	err := sp.Init()
	assert.NoError(err)

	// Construct an AuthnRequest
	authnRequest := sp.GetAuthnRequest()
	signedXML, err := authnRequest.SignedString(sp.PrivateKeyPath)
	assert.NoError(err)
	assert.NotEmpty(signedXML)

	err = VerifyRequestSignature(signedXML, sp.PublicCertPath)
	assert.NoError(err)
}
