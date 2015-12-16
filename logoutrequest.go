// Copyright 2014 Matthew Baird, Andrew Mussey
// Copyright 2015 Wearable Intelligence
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package saml

import (
	"encoding/base64"
	"encoding/xml"
	"time"

	"github.com/wearableintelligence/go-saml/util"
)

// GetSignedAuthnRequest returns a singed XML document that represents a AuthnRequest SAML document
func (s *ServiceProviderSettings) GetLogoutRequest(nameID string, sessionIds... string) *LogoutRequest {
	r := NewLogoutRequest(s.SPSignRequest)
	r.Issuer.Url = s.IDPSSODescriptorURL
	if s.SPSignRequest {
		r.Signature.KeyInfo.X509Data.X509Certificate.Cert = s.PublicCert()
		r.Destination = s.IDPSSOLogoutURL
	}
	r.NameID.Value = nameID
	if len(sessionIds) > 0 {
		r.SessionIndex = make([]SessionIndex, len(sessionIds))
		for idx, sid := range sessionIds {
			r.SessionIndex[idx].Value = sid
			r.SessionIndex[idx].XMLName.Local = "samlp:SessionIndex"
		}
	}

	return r
}

func NewLogoutRequest(sign bool) *LogoutRequest {
	id := util.ID()
	logoutReq := &LogoutRequest{
		XMLName: xml.Name{
			Local: "samlp:LogoutRequest",
		},
		SAMLP:                       "urn:oasis:names:tc:SAML:2.0:protocol",
		SAML:                        "urn:oasis:names:tc:SAML:2.0:assertion",
		ID:                          id,
		Version:                     "2.0",
		Issuer: Issuer{
			XMLName: xml.Name{
				Local: "saml:Issuer",
			},
			Url:  "", // caller must populate ar.AppSettings.Issuer
		},
		IssueInstant: time.Now().UTC().Format(time.RFC3339),
		NameID: NameID {
			XMLName: xml.Name{
				Local: "saml:NameID",
			},
			Value: "", // caller must populate
		},
	}

	if sign {
		logoutReq.SAMLSIG = "http://www.w3.org/2000/09/xmldsig#"
		logoutReq.Signature = &Signature{
			XMLName: xml.Name{
				Local: "samlsig:Signature",
			},
			Id: "Signature1",
			SignedInfo: SignedInfo{
				XMLName: xml.Name{
					Local: "samlsig:SignedInfo",
				},
				CanonicalizationMethod: CanonicalizationMethod{
					XMLName: xml.Name{
						Local: "samlsig:CanonicalizationMethod",
					},
					Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
				},
				SignatureMethod: SignatureMethod{
					XMLName: xml.Name{
						Local: "samlsig:SignatureMethod",
					},
					Algorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
				},
				SamlsigReference: SamlsigReference{
					XMLName: xml.Name{
						Local: "samlsig:Reference",
					},
					URI: "#" + id,
					Transforms: Transforms{
						XMLName: xml.Name{
							Local: "samlsig:Transforms",
						},
						Transforms: []Transform{
							{
								XMLName: xml.Name{
									Local: "samlsig:Transform",
								},
								Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
							},
							{
								XMLName: xml.Name{
									Local: "samlsig:Transform",
								},
								Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
							},
						},
					},
					DigestMethod: DigestMethod{
						XMLName: xml.Name{
							Local: "samlsig:DigestMethod",
						},
						Algorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
					},
					DigestValue: DigestValue{
						XMLName: xml.Name{
							Local: "samlsig:DigestValue",
						},
					},
				},
			},
			SignatureValue: SignatureValue{
				XMLName: xml.Name{
					Local: "samlsig:SignatureValue",
				},
			},
			KeyInfo: KeyInfo{
				XMLName: xml.Name{
					Local: "samlsig:KeyInfo",
				},
				X509Data: X509Data{
					XMLName: xml.Name{
						Local: "samlsig:X509Data",
					},
					X509Certificate: X509Certificate{
						XMLName: xml.Name{
							Local: "samlsig:X509Certificate",
						},
						Cert: "", // caller must populate cert,
					},
				},
			},
		}
	}
	return logoutReq
}

func (r *LogoutRequest) String() (string, error) {
	b, err := xml.Marshal(r)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func (r *LogoutRequest) SignedString(privateKeyPath string) (string, error) {
	s, err := r.String()
	if err != nil {
		return "", err
	}

	return SignLogoutRequest(s, privateKeyPath)
}

// GetAuthnRequestURL generate a URL for the AuthnRequest to the IdP with the SAMLRequst parameter encoded
func (r *LogoutRequest) EncodedSignedString(privateKeyPath string) (string, error) {
	signed, err := r.SignedString(privateKeyPath)
	if err != nil {
		return "", err
	}
	b64XML := base64.StdEncoding.EncodeToString([]byte(signed))
	return b64XML, nil
}

func (r *LogoutRequest) EncodedString() (string, error) {
	saml, err := r.String()
	if err != nil {
		return "", err
	}
	b64XML := base64.StdEncoding.EncodeToString([]byte(saml))
	return b64XML, nil
}
