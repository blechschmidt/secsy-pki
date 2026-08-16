package yubihsm

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"sync"
)

// fakeDevice is the device half of the protocol: a Transport that terminates
// SCP03 the way a YubiHSM 2 does and answers inner commands from a table.
//
// It exists so the driver's security-relevant behaviour — mutual authentication,
// per-message MAC chaining, the counter-derived IV, rejection of a tampered
// reply — is exercised in CI on machines with no HSM attached. The exact
// derivations it implements were confirmed against a real device by the
// hardware tests in this package, including the one place the YubiHSM departs
// from GlobalPlatform SCP03 (the response is decrypted under the command's ICV).
// Pinning them here means a future change to the client that "still works
// against the fake" cannot silently diverge from the hardware.
type fakeDevice struct {
	mu sync.Mutex

	encKey, macKey []byte
	// cardChallenge is fixed so a session transcript is reproducible.
	cardChallenge []byte
	// expectKeySetID is the only authentication key the fake knows.
	expectKeySetID uint16

	// handlers answers inner commands; a missing command yields ErrInvalidCommand.
	handlers map[byte]func(data []byte) ([]byte, error)

	// tamper, when set, corrupts the response before it is returned.
	tamper func(resp []byte) []byte
	// transactErr, when set, is returned instead of a response, modelling a
	// transport that stopped carrying traffic.
	transactErr error

	session        *scp03Session
	authed         bool
	sessionID      byte
	hostCryptogram []byte

	// Sent records every outer message received, for tests that assert on framing.
	Sent [][]byte
}

func newFakeDevice(password string) *fakeDevice {
	enc, mac, err := DeriveAuthenticationKeys(password)
	if err != nil {
		panic(err)
	}
	return &fakeDevice{
		encKey:         enc,
		macKey:         mac,
		cardChallenge:  []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
		expectKeySetID: 1,
		sessionID:      3,
		handlers:       map[byte]func([]byte) ([]byte, error){},
	}
}

func (d *fakeDevice) Describe() string { return "fake-device" }
func (d *fakeDevice) Close() error     { return nil }

func (d *fakeDevice) Transact(_ context.Context, msg []byte) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.Sent = append(d.Sent, append([]byte(nil), msg...))

	if d.transactErr != nil {
		return nil, d.transactErr
	}
	if len(msg) < 3 {
		return nil, fmt.Errorf("fake device: short message")
	}
	n := int(binary.BigEndian.Uint16(msg[1:3]))
	if len(msg) != 3+n {
		return nil, fmt.Errorf("fake device: length field %d does not match %d payload bytes", n, len(msg)-3)
	}
	body := msg[3:]

	var resp []byte
	var err error
	switch msg[0] {
	case cmdCreateSession:
		resp, err = d.createSession(body)
	case cmdAuthenticateSession:
		resp, err = d.authenticateSession(msg)
	case cmdSessionMessage:
		resp, err = d.sessionMessage(msg)
	default:
		resp = errorFrame(ErrInvalidCommand)
	}
	if err != nil {
		return nil, err
	}
	if d.tamper != nil {
		resp = d.tamper(resp)
	}
	return resp, nil
}

func errorFrame(e DeviceError) []byte {
	f, _ := frame(cmdError, []byte{byte(e)})
	return f
}

func (d *fakeDevice) createSession(body []byte) ([]byte, error) {
	if len(body) != 2+challengeLen {
		return errorFrame(ErrWrongLength), nil
	}
	if binary.BigEndian.Uint16(body[:2]) != d.expectKeySetID {
		return errorFrame(ErrObjectNotFound), nil
	}
	hostChallenge := body[2:]

	kdfContext := append(append([]byte{}, hostChallenge...), d.cardChallenge...)
	encBlock, _ := aes.NewCipher(d.encKey)
	macBlock, _ := aes.NewCipher(d.macKey)
	sEnc := scp03KDF(encBlock, kdfSessionEnc, kdfContext, blockLen)
	sMAC := scp03KDF(macBlock, kdfSessionMAC, kdfContext, blockLen)
	sRMAC := scp03KDF(macBlock, kdfSessionRMAC, kdfContext, blockLen)
	sMACBlock, _ := aes.NewCipher(sMAC)

	sEncBlock, _ := aes.NewCipher(sEnc)
	sRMACBlock, _ := aes.NewCipher(sRMAC)
	d.session = &scp03Session{
		id:      d.sessionID,
		enc:     sEncBlock,
		macKey:  sMACBlock,
		rmacKey: sRMACBlock,
		chain:   make([]byte, blockLen),
	}
	d.authed = false
	d.hostCryptogram = scp03KDF(sMACBlock, kdfHostCryptogram, kdfContext, cryptoLen)

	out := make([]byte, 0, 1+challengeLen+cryptoLen)
	out = append(out, d.sessionID)
	out = append(out, d.cardChallenge...)
	out = append(out, scp03KDF(sMACBlock, kdfCardCryptogram, kdfContext, cryptoLen)...)
	return frame(cmdCreateSession|responseFlag, out)
}

func (d *fakeDevice) authenticateSession(msg []byte) ([]byte, error) {
	if d.session == nil {
		return errorFrame(ErrInvalidSession), nil
	}
	if len(msg) != 3+1+cryptoLen+macLen {
		return errorFrame(ErrWrongLength), nil
	}
	tag, chain := d.session.mac(d.session.macKey, msg[:3+1+cryptoLen])
	if string(tag) != string(msg[3+1+cryptoLen:]) {
		return errorFrame(ErrAuthenticationFailed), nil
	}
	if string(msg[4:4+cryptoLen]) != string(d.hostCryptogram) {
		return errorFrame(ErrAuthenticationFailed), nil
	}
	d.session.chain = chain
	d.authed = true
	return frame(cmdAuthenticateSession|responseFlag, nil)
}

func (d *fakeDevice) sessionMessage(msg []byte) ([]byte, error) {
	if d.session == nil || !d.authed {
		return errorFrame(ErrInvalidSession), nil
	}
	body := msg[3:]
	if len(body) < 1+macLen || body[0] != d.session.id {
		return errorFrame(ErrInvalidSession), nil
	}
	ct := body[1 : len(body)-macLen]

	want, chain := d.session.mac(d.session.macKey, msg[:len(msg)-macLen])
	if string(want) != string(body[len(body)-macLen:]) {
		return errorFrame(ErrAuthenticationFailed), nil
	}
	d.session.chain = chain

	d.session.counter++
	counterBlock := make([]byte, blockLen)
	binary.BigEndian.PutUint32(counterBlock[blockLen-4:], d.session.counter)
	iv := make([]byte, blockLen)
	d.session.enc.Encrypt(iv, counterBlock)

	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(d.session.enc, iv).CryptBlocks(pt, ct)
	inner, err := stripPadding(pt)
	if err != nil {
		// A device answers a malformed command with an error frame rather than
		// dropping the connection, so the decode failure becomes a protocol
		// response here rather than a Go error.
		return errorFrame(ErrInvalidData), nil //nolint:nilerr // modelling the device's error response
	}
	if len(inner) < 3 {
		return errorFrame(ErrInvalidData), nil
	}

	cmd := inner[0]
	data := inner[3 : 3+int(binary.BigEndian.Uint16(inner[1:3]))]

	var respInner []byte
	if h := d.handlers[cmd]; h != nil {
		out, herr := h(data)
		if herr != nil {
			var de DeviceError
			if e, ok := herr.(DeviceError); ok {
				de = e
			} else {
				de = ErrInvalidData
			}
			respInner = errorFrame(de)
		} else {
			respInner, _ = frame(cmd|responseFlag, out)
		}
	} else if cmd == cmdCloseSession {
		respInner, _ = frame(cmdCloseSession|responseFlag, nil)
	} else {
		respInner = errorFrame(ErrInvalidCommand)
	}

	// Encrypt under the *command's* ICV, as the hardware does.
	padded := make([]byte, ((len(respInner)/blockLen)+1)*blockLen)
	copy(padded, respInner)
	padded[len(respInner)] = 0x80
	respCT := make([]byte, len(padded))
	cipher.NewCBCEncrypter(d.session.enc, iv).CryptBlocks(respCT, padded)

	out := make([]byte, 3+1+len(respCT)+macLen)
	out[0] = cmdSessionMessage | responseFlag
	binary.BigEndian.PutUint16(out[1:3], uint16(1+len(respCT)+macLen))
	out[3] = d.session.id
	copy(out[4:], respCT)
	rtag, _ := d.session.mac(d.session.rmacKey, out[:len(out)-macLen])
	copy(out[len(out)-macLen:], rtag)
	return out, nil
}
