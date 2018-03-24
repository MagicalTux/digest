package digest

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	digestCookie   []byte
	validKeysMutex sync.Mutex
	validKeys      map[int64]map[uint64]bool
)

func init() {
	digestCookie = make([]byte, 32)
	_, err := rand.Read(digestCookie)
	if err != nil {
		panic(err)
	}

	validKeys = make(map[int64]map[uint64]bool)
	go validNonceKeysCleanupThread()
}

type Digest struct {
	Username string
	Realm    string
	Nonce    []byte

	Response map[string]string
}

func validNonceKeysCleanupThread() {
	t := time.NewTimer(5 * time.Minute)

	for {
		select {
		case <-t.C:
			validNonceKeysCleanupOp()
		}
	}
}

func validNonceKeysCleanupOp() {
	validKeysMutex.Lock()
	defer validKeysMutex.Unlock()

	curK := time.Now().Unix() / 60
	minK := curK - 10

	for i, _ := range validKeys {
		if i < minK {
			delete(validKeys, i)
		}
	}
}

func onceDigestNonce(nonce []byte) error {
	// check values in nonce, return if once or not
	if len(nonce) != 16 {
		return errors.New("nonce should be 16 bytes")
	}

	var onceV int64
	var subK uint64

	buf := bytes.NewReader(nonce)
	binary.Read(buf, binary.BigEndian, &onceV)
	binary.Read(buf, binary.BigEndian, &subK)

	if onceV < (time.Now().Unix() - 300) {
		return errors.New("this nonce has expired")
	}

	onceK := onceV / 60

	validKeysMutex.Lock()
	defer validKeysMutex.Unlock()

	m, ok := validKeys[onceK]
	if !ok {
		m = make(map[uint64]bool)
		m[subK] = true
		validKeys[onceK] = m
		return nil
	}

	_, ok = m[subK]
	if ok {
		return errors.New("duplicate nonce rejected")
	}

	m[subK] = true
	return nil
}

func makeDigestNonce() []byte {
	curV := time.Now().Unix()

	var subK uint64

	subKbin := make([]byte, 8)
	_, err := rand.Read(subKbin)

	// random read failed? use UnixNano as backup, but this is far from enough
	if err != nil {
		subK = uint64(time.Now().UnixNano())
	} else {
		binary.Read(bytes.NewReader(subKbin), binary.BigEndian, &subK)
	}

	// generate key
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.BigEndian, curV)
	binary.Write(buf, binary.BigEndian, subK)
	return buf.Bytes()
}

func AuthDigest(realm string) map[string]string {
	res := make(map[string]string)

	nonce := makeDigestNonce()

	mac := hmac.New(sha256.New, digestCookie)
	mac.Write(nonce)

	res["qop"] = "auth" //,auth-int"
	res["realm"] = realm
	res["nonce"] = hex.EncodeToString(nonce)
	res["opaque"] = hex.EncodeToString(mac.Sum(nil))

	return res
}

func MakeDigestHeader(q map[string]string) string {
	res := "Digest "
	first := true

	for k, v := range q {
		if first {
			first = false
		} else {
			res += ", "
		}

		// TODO escape v if needed
		res += k + "=\"" + v + "\""
	}

	return res
}

func CheckDigestResponse(r map[string]string) (*Digest, error) {
	// first check nonce vs opaque
	nonce, err := hex.DecodeString(r["nonce"])
	if err != nil {
		return nil, err
	}

	opaque, err := hex.DecodeString(r["opaque"])
	if err != nil {
		return nil, err
	}

	mac := hmac.New(sha256.New, digestCookie)
	mac.Write(nonce)

	if !hmac.Equal(opaque, mac.Sum(nil)) {
		return nil, errors.New("invalid nonce value")
	}

	// check nonce
	err = onceDigestNonce(nonce)
	if err != nil {
		return nil, err
	}

	res := new(Digest)
	var ok bool

	res.Nonce = nonce
	res.Response = r

	res.Realm, ok = r["realm"]
	if !ok {
		return nil, errors.New("realm missing from header")
	}

	res.Username, ok = r["username"]
	if !ok {
		return nil, errors.New("username variable missing")
	}

	return res, nil
}

func (d *Digest) CheckPassword(method, password string) error {
	// check password against response
	qop, ok := d.Response["qop"]

	if !ok {
		// RFC 2617 is from 1999, it could have been implemented by now :/
		return errors.New("non-QoP auth not accepted, please at least implement RFC 2617")
	}

	if qop != "auth" {
		return errors.New("unsupportes QoP method, only supported method is \"auth\"")
	}

	// prepare variables
	nonce, ok := d.Response["nonce"]
	if !ok {
		return errors.New("variable missing: nonce")
	}

	cnonce, ok := d.Response["cnonce"]
	if !ok {
		return errors.New("variable missing: cnonce")
	}

	uri, ok := d.Response["uri"]
	if !ok {
		return errors.New("variable missing: uri")
	}

	nc, ok := d.Response["nc"]
	if !ok {
		return errors.New("variable missing: nc")
	}

	clientResponse, err := hex.DecodeString(d.Response["response"])
	if err != nil {
		return fmt.Errorf("Error decoding response: %v", err)
	}

	sum := md5.New()

	sum.Write([]byte(d.Username))
	sum.Write([]byte{':'})
	sum.Write([]byte(d.Realm))
	sum.Write([]byte{':'})
	sum.Write([]byte(password))

	ha1 := hex.EncodeToString(sum.Sum(nil))

	if d.Response["protocol"] == "MD5-sess" {
		sum.Reset()
		sum.Write([]byte(ha1))
		sum.Write([]byte{':'})
		sum.Write([]byte(nonce))
		sum.Write([]byte{':'})
		sum.Write([]byte(cnonce))

		ha1 = hex.EncodeToString(sum.Sum(nil))
	}

	sum.Reset()
	sum.Write([]byte(method))
	sum.Write([]byte{':'})
	sum.Write([]byte(uri))

	ha2 := hex.EncodeToString(sum.Sum(nil))

	sum.Reset()
	sum.Write([]byte(ha1))
	sum.Write([]byte{':'})
	sum.Write([]byte(nonce))
	sum.Write([]byte{':'})
	sum.Write([]byte(nc))
	sum.Write([]byte{':'})
	sum.Write([]byte(cnonce))
	sum.Write([]byte{':'})
	sum.Write([]byte(qop))
	sum.Write([]byte{':'})
	sum.Write([]byte(ha2))

	response := sum.Sum(nil)

	if subtle.ConstantTimeCompare(response, clientResponse) != 1 {
		return errors.New("Invalid password")
	}

	return nil
}

// ParseList parses a comma-separated list of values as described by
// RFC 2068 and returns list elements.
//
// Lifted from https://code.google.com/p/gorilla/source/browse/http/parser/parser.go
// which was ported from urllib2.parse_http_list, from the Python
// standard library.
func ParseList(value string) []string {
	var list []string
	var escape, quote bool
	b := new(bytes.Buffer)
	for _, r := range value {
		switch {
		case escape:
			b.WriteRune(r)
			escape = false
		case quote:
			if r == '\\' {
				escape = true
			} else {
				if r == '"' {
					quote = false
				}
				b.WriteRune(r)
			}
		case r == ',':
			list = append(list, strings.TrimSpace(b.String()))
			b.Reset()
		case r == '"':
			quote = true
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	// Append last part.
	if s := b.String(); s != "" {
		list = append(list, strings.TrimSpace(s))
	}
	return list
}

// ParsePairs extracts key/value pairs from a comma-separated list of
// values as described by RFC 2068 and returns a map[key]value. The
// resulting values are unquoted. If a list element doesn't contain a
// "=", the key is the element itself and the value is an empty
// string.
//
// Lifted from https://code.google.com/p/gorilla/source/browse/http/parser/parser.go
func ParsePairs(value string) map[string]string {
	m := make(map[string]string)
	for _, pair := range ParseList(strings.TrimSpace(value)) {
		if i := strings.Index(pair, "="); i < 0 {
			m[pair] = ""
		} else {
			v := pair[i+1:]
			if v[0] == '"' && v[len(v)-1] == '"' {
				// Unquote it.
				v = v[1 : len(v)-1]
			}
			m[pair[:i]] = v
		}
	}
	return m
}
