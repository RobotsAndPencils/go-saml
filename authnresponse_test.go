package saml

import (
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStatus_Success(t *testing.T) {
	response := NewSignedResponse()
	assert.NotNil(t, response)
	status := response.GetStatusCode()
	assert.Equal(t, "urn:oasis:names:tc:SAML:2.0:status:Success", status)
}

func TestStatus_EmptyStatusCode(t *testing.T) {
	response := NewSignedResponse()
	response.Status = Status{}
	assert.NotNil(t, response)
	status := response.GetStatusCode()
	assert.Equal(t, "", status)
}

func TestStatus_Failure(t *testing.T) {
	response := NewSignedResponse()
	response.Status = Status{
		XMLName: xml.Name{
			Local: "samlp:Status",
		},
		StatusCode: StatusCode{
			XMLName: xml.Name{
				Local: "samlp:StatusCode",
			},
			Value: "urn:oasis:names:tc:SAML:2.0:status:Requester",
			StatusCode: &StatusCode{
				XMLName: xml.Name{
					Local: "samlp:StatusCode",
				},
				Value: "urn:oasis:names:tc:SAML:2.0:status:RequestDenied",
			},
		},
		StatusMessage: StatusMessage{
			XMLName: xml.Name{
				Local: "samlp:StatusMessage",
			},
			Value: "Invalid request, ACS Url in request https://example.com/callback doesn't match configured ACS Url https://test.com/callback.",
		},
	}
	assert.NotNil(t, response)
	status := response.GetStatusCode()
	assert.Equal(t, "urn:oasis:names:tc:SAML:2.0:status:RequestDenied", status)
	assert.Equal(t, "Invalid request, ACS Url in request https://example.com/callback doesn't match configured ACS Url https://test.com/callback.", response.Status.StatusMessage.Value)
}
