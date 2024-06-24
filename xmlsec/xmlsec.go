// depends on libxmlsec1 and libxml2
package xmlsec

// #cgo pkg-config: xmlsec1 libxml-2.0
//
// #include <xmlsec/app.h>
// #include <xmlsec/crypto.h>
// #include <xmlsec/xmldsig.h>
// #include <xmlsec/xmlsec.h>
// #include <xmlsec/xmltree.h>
//
// #include <libxml/parser.h>
// #include <libxml/parserInternals.h>
// #include <libxml/xmlmemory.h>
// #include <errno.h>
//
// // Wrapper for xmlFree because cgo cant access it
// static inline void xmlFreeWrapper(void *p) {
//   xmlFree(p);
// }
import "C"

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"unsafe"
)

var (
	initLock    sync.Mutex
	initialized uint32

	ErrVerification = errors.New("verification error")
)

// https://www.aleksey.com/xmlsec/api/xmlsec-xmldsig.html#XMLSECDSIGSTATUS
const (
	xmlSecDSigStatusUnknown = iota
	xmlSecDSigStatusSucceeded
	xmlSecDSigStatusInvalid
)

type Options struct {
	// Equivalent to using xmlsec command line utility with "--id-attr" option"
	// https://www.aleksey.com/xmlsec/faq.html#section_3_2
	IDAttrs []IDAttr
}

type IDAttr struct {
	Name     string
	NodeName string
	NsHref   string
}

// https://www.aleksey.com/xmlsec/api/xmlsec-notes-init-shutdown.html
// call when initialize the library
func Init() {
	if atomic.LoadUint32(&initialized) == 1 {
		return
	}
	C.xmlInitParser()
	initLock.Lock()
	defer initLock.Unlock()
	if initialized == 0 {
		defer atomic.StoreUint32(&initialized, 1)
		if res := C.xmlSecInit(); res < 0 {
			panic("xmlSecInit failed")
		}
		if res := C.xmlSecCryptoAppInit(nil); res < 0 {
			panic("xmlSecCryptoAppInit failed")
		}
		if rv := C.xmlSecCryptoInit(); rv < 0 {
			panic("xmlSecCryptoInit failed")
		}
	}
}

// https://www.aleksey.com/xmlsec/api/xmlsec-notes-init-shutdown.html
// calls when shutting down the binary
func Shutdown() {
	if atomic.LoadUint32(&initialized) == 0 {
		return
	}
	C.xmlSecCryptoShutdown()    // Shutdown xmlsec-crypto library
	C.xmlSecCryptoAppShutdown() // Shutdown crypto library
	C.xmlSecShutdown()          // Shutdown xmlsec library
	C.xmlCleanupParser()        // Shutdown libxml
}

// Verify checks that the document is signed with the public certificate. The
// caller needs to make sure that passed slices will not be mutated elsewhere
func Verify(signedDoc []byte, publicCert []byte, opts Options) error {
	var (
		cert    = (*C.xmlSecByte)(unsafe.Pointer(&publicCert[0]))
		certLen = C.xmlSecSize(len(publicCert))
	)

	// https://www.aleksey.com/xmlsec/api/xmlsec-keysmngr.html#XMLSECKEYSMNGRCREATE
	// https://www.aleksey.com/xmlsec/api/xmlsec-keysmngr.html#XMLSECKEYSMNGRDESTROY
	km := C.xmlSecKeysMngrCreate()
	if km == nil {
		return fmt.Errorf("xmlSecKeysMngrCreate failed")
	}
	defer C.xmlSecKeysMngrDestroy(km)

	// https://www.aleksey.com/xmlsec/api/xmlsec-app.html#XMLSECCRYPTOAPPDEFAULTKEYSMNGRINIT
	if errno := C.xmlSecCryptoAppDefaultKeysMngrInit(km); errno < 0 {
		return fmt.Errorf("xmlSecCryptoAppDefaultKeysMngrInit failed %d", errno)
	}

	// https://www.aleksey.com/xmlsec/api/xmlsec-app.html#XMLSECCRYPTOAPPKEYLOADMEMORY
	key := C.xmlSecCryptoAppKeyLoadMemory(cert, certLen, C.xmlSecKeyDataFormatCertPem, nil, nil, nil)
	if key == nil {
		return errors.New("xmlSecCryptoAppKeyLoadMemory failed")
	}

	// https://www.aleksey.com/xmlsec/api/xmlsec-app.html#XMLSECCRYPTOAPPKEYCERTLOADMEMORY
	if errno, err := C.xmlSecCryptoAppKeyCertLoadMemory(key, cert, certLen, C.xmlSecKeyDataFormatCertPem); errno < 0 {
		C.xmlSecKeyDestroy(key)
		return fmt.Errorf("xmlSecCryptoAppKeyCertLoad failed %d %v", errno, err)
	}

	// https://www.aleksey.com/xmlsec/api/xmlsec-app.html#XMLSECCRYPTOAPPDEFAULTKEYSMNGRADOPTKEY
	if errno := C.xmlSecCryptoAppDefaultKeysMngrAdoptKey(km, key); errno < 0 {
		return fmt.Errorf("xmlSecCryptoAppDefaultKeysMngrAdoptKey failed %d", errno)
	}

	// https://www.aleksey.com/xmlsec/api/xmlsec-xmldsig.html#XMLSECDSIGCTXCREATE
	// https://www.aleksey.com/xmlsec/api/xmlsec-xmldsig.html#XMLSECDSIGCTXDESTROY
	ctx := C.xmlSecDSigCtxCreate(km)
	if ctx == nil {
		return fmt.Errorf("xmlSecDSigCtxCreate failed")
	}
	defer C.xmlSecDSigCtxDestroy(ctx)

	parsedDoc, err := parseXML(signedDoc, opts)
	if err != nil {
		return err
	}
	defer C.xmlFreeDoc(parsedDoc)

	// https://www.aleksey.com/xmlsec/api/xmlsec-xmltree.html#XMLSECFINDNODE
	node := C.xmlSecFindNode(C.xmlDocGetRootElement(parsedDoc),
		(*C.xmlChar)(unsafe.Pointer(&C.xmlSecNodeSignature)),
		(*C.xmlChar)(unsafe.Pointer(&C.xmlSecDSigNs)))
	if node == nil {
		return errors.New("xmlSecFindNode failed")
	}
	if errno := C.xmlSecDSigCtxVerify(ctx, node); errno < 0 || ctx.status != xmlSecDSigStatusSucceeded {
		return ErrVerification
	}
	return nil
}

func parseXML(doc []byte, opts Options) (*C.xmlDoc, error) {
	var (
		docPtr = (*C.char)(unsafe.Pointer(&doc[0]))
		docLen = C.int(len(doc))
	)
	// http://www.xmlsoft.org/html/libxml-parserInternals.html#xmlCreateMemoryParserCtxt
	ctx := C.xmlCreateMemoryParserCtxt(docPtr, docLen)
	if ctx == nil {
		return nil, errors.New("error creating parser")
	}
	// this will not free ctx.myDoc
	defer C.xmlFreeParserCtxt(ctx)

	if C.xmlParseDocument(ctx) == -1 {
		return nil, errors.New("xmlParseDocument failed")
	}
	if ctx.wellFormed != 1 || ctx.valid != 1 || ctx.myDoc == nil {
		return nil, errors.New("xml document is not well formed")
	}
	for _, attr := range opts.IDAttrs {
		err := addIDAttr(C.xmlDocGetRootElement(ctx.myDoc), attr.Name, attr.NodeName, attr.NsHref)
		if err != nil {
			return nil, err
		}
	}
	return ctx.myDoc, nil
}

// https://github.com/GNOME/xmlsec/blob/8f78efe126e579041a07e342fe4dbbc38711a414/apps/xmlsec.c#L2740
// xmlSecAppAddIDAttr(xmlNodePtr node, const xmlChar* attrName, const xmlChar* nodeName, const xmlChar* nsHref))
func addIDAttr(node *C.xmlNode, attrName, nodeName, nsHref string) error {
	var (
		attr, tmpAttr *C.xmlAttr
		cur           *C.xmlNode
		id            *C.xmlChar
	)
	// process children first because it does not matter much but does simplify code
	cur = C.xmlSecGetNextElementNode(node.children)
	for {
		if cur == nil {
			break
		}
		if err := addIDAttr(cur, attrName, nodeName, nsHref); err != nil {
			return err
		}
		cur = C.xmlSecGetNextElementNode(cur.next)
	}
	// node name must match
	if C.GoString((*C.char)(unsafe.Pointer(node.name))) != nodeName {
		return nil
	}
	// if nsHref is set then it also should match
	if nsHref != "" && node.ns != nil && C.GoString((*C.char)(unsafe.Pointer(node.ns.href))) != nsHref {
		return nil
	}
	// the attribute with name equal to attrName should exist
	for attr = node.properties; attr != nil; attr = attr.next {
		if C.GoString((*C.char)(unsafe.Pointer(attr.name))) == attrName {
			break
		}
	}
	if attr == nil {
		return nil
	}
	// if found, the attribute should have some value
	id = C.xmlNodeListGetString(node.doc, attr.children, 1)
	if id == nil {
		return nil
	}
	defer C.xmlFreeWrapper(unsafe.Pointer(id))
	// check that we dont have the same ID already
	tmpAttr = C.xmlGetID(node.doc, id)
	if tmpAttr == nil {
		C.xmlAddID(nil, node.doc, id, attr)
	} else if tmpAttr != attr {
		return fmt.Errorf("duplicate ID attribute %s", id)
	}
	return nil
}
