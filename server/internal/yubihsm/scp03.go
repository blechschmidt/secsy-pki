package yubihsm

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
)

// GlobalPlatform SCP03 secure channel, as profiled by the YubiHSM 2.
//
// Authentication is mutual and every in-session message is encrypted and MACed,
// so an attacker on the transport (a malicious yubihsm-connector, a USB
// interposer) can deny service but cannot read a signing request, alter an audit
// log response, or replay a command: the MAC chains across the whole session and
// the encryption counter advances per message.
//
// This is the part yubihsm-shell was doing on our behalf. Doing it here is what
// removes the subprocess — and with it a password on a child process's stdin, a
// temporary file for every byte string to be signed, and the need to recognise
// device failures by matching English text on stdout.

// SCP03 key-derivation constants (GlobalPlatform Amendment D, table 4-1).
const (
	kdfCardCryptogram byte = 0x00
	kdfHostCryptogram byte = 0x01
	kdfSessionEnc     byte = 0x04
	kdfSessionMAC     byte = 0x06
	kdfSessionRMAC    byte = 0x07
)

const (
	challengeLen = 8
	cryptoLen    = 8
	macLen       = 8
	blockLen     = 16
)

// DeriveAuthenticationKeys turns an authentication key's password into the pair
// of AES-128 static keys the device stores for it.
//
// The parameters are Yubico's: PBKDF2-HMAC-SHA256 with the fixed salt "Yubico"
// and 10000 iterations, split into a 16-byte ENC key and a 16-byte MAC key. They
// are fixed by the device, not chosen here — a password-derived authentication
// key is only as strong as the password, which is why production deployments
// should provision a key from random bytes instead.
func DeriveAuthenticationKeys(password string) (encKey, macKey []byte, err error) {
	dk, err := pbkdf2.Key(sha256.New, password, []byte("Yubico"), 10000, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("deriving authentication keys: %w", err)
	}
	return dk[:16], dk[16:], nil
}

// scp03Session holds the state of an authenticated secure channel: the three
// session keys, the running MAC chaining value, and the message counter that
// makes each message's encryption unique.
type scp03Session struct {
	id byte
	// The three session keys are held as expanded ciphers: every message needs
	// two of them, so re-deriving a key schedule per MAC would triple the AES
	// setup cost of an exchange for nothing.
	enc     cipher.Block
	macKey  cipher.Block
	rmacKey cipher.Block
	chain   []byte
	counter uint32
}

// openSession performs the two-message SCP03 mutual authentication against the
// device reached through t.
func openSession(ctx context.Context, t Transport, keySetID uint16, encKey, macKey []byte) (*scp03Session, error) {
	hostChallenge := make([]byte, challengeLen)
	if _, err := rand.Read(hostChallenge); err != nil {
		return nil, fmt.Errorf("generating the host challenge: %w", err)
	}

	req := make([]byte, 2+challengeLen)
	binary.BigEndian.PutUint16(req[0:2], keySetID)
	copy(req[2:], hostChallenge)

	body, err := transact(ctx, t, cmdCreateSession, req)
	if err != nil {
		return nil, fmt.Errorf("creating a session with authentication key 0x%04x: %w", keySetID, err)
	}
	if len(body) != 1+challengeLen+cryptoLen {
		return nil, fmt.Errorf("create-session response is %d bytes, want %d", len(body), 1+challengeLen+cryptoLen)
	}
	sessionID := body[0]
	cardChallenge := body[1 : 1+challengeLen]
	cardCryptogram := body[1+challengeLen:]

	// The derivation context is host challenge followed by card challenge; both
	// sides contribute freshness, which is what stops a replayed transcript from
	// re-authenticating.
	kdfContext := make([]byte, 0, 2*challengeLen)
	kdfContext = append(kdfContext, hostChallenge...)
	kdfContext = append(kdfContext, cardChallenge...)

	encBlock, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("session encryption key: %w", err)
	}
	macBlock, err := aes.NewCipher(macKey)
	if err != nil {
		return nil, fmt.Errorf("session MAC key: %w", err)
	}

	sEnc := scp03KDF(encBlock, kdfSessionEnc, kdfContext, blockLen)
	sMAC := scp03KDF(macBlock, kdfSessionMAC, kdfContext, blockLen)
	sRMAC := scp03KDF(macBlock, kdfSessionRMAC, kdfContext, blockLen)

	sMACBlock, err := aes.NewCipher(sMAC)
	if err != nil {
		return nil, err
	}

	// Verifying the card cryptogram authenticates the *device* to us. Skipping it
	// would leave the channel open to anything that can answer on the transport,
	// including a simulator replaying a recorded challenge.
	wantCard := scp03KDF(sMACBlock, kdfCardCryptogram, kdfContext, cryptoLen)
	if subtle.ConstantTimeCompare(wantCard, cardCryptogram) != 1 {
		return nil, fmt.Errorf("device authentication failed: the card cryptogram does not match "+
			"(the device is not the one holding authentication key 0x%04x, or the transport is being tampered with)", keySetID)
	}
	hostCryptogram := scp03KDF(sMACBlock, kdfHostCryptogram, kdfContext, cryptoLen)

	sEncBlock, err := aes.NewCipher(sEnc)
	if err != nil {
		return nil, err
	}
	sRMACBlock, err := aes.NewCipher(sRMAC)
	if err != nil {
		return nil, err
	}
	s := &scp03Session{
		id:      sessionID,
		enc:     sEncBlock,
		macKey:  sMACBlock,
		rmacKey: sRMACBlock,
		chain:   make([]byte, blockLen),
	}

	// Authenticate-session carries its own MAC over the zero chaining value,
	// seeding the chain that every later message extends. The declared length
	// covers the MAC, so it is written before the MAC is computed.
	authMsg := make([]byte, 3+1+cryptoLen+macLen)
	authMsg[0] = cmdAuthenticateSession
	binary.BigEndian.PutUint16(authMsg[1:3], uint16(1+cryptoLen+macLen))
	authMsg[3] = sessionID
	copy(authMsg[4:], hostCryptogram)
	mac, chain := s.mac(s.macKey, authMsg[:4+cryptoLen])
	copy(authMsg[4+cryptoLen:], mac)
	s.chain = chain

	raw, err := t.Transact(ctx, authMsg)
	if err != nil {
		return nil, fmt.Errorf("authenticating session %d: %w", sessionID, err)
	}
	if _, err := parseResponse(cmdAuthenticateSession, raw); err != nil {
		return nil, fmt.Errorf("authenticating session %d: %w", sessionID, err)
	}
	return s, nil
}

// scp03KDF is the NIST SP 800-108 counter-mode KDF with CMAC as the PRF, in the
// single-block form SCP03 uses: an 11-byte zero label, the derivation constant,
// a 0x00 separator, the output length in bits, the counter, then the context.
func scp03KDF(key cipher.Block, constant byte, context []byte, outLen int) []byte {
	input := make([]byte, 0, 16+len(context))
	input = append(input, make([]byte, 11)...)
	input = append(input, constant, 0x00)
	input = append(input, byte(outLen*8>>8), byte(outLen*8))
	input = append(input, 0x01)
	input = append(input, context...)
	return cmacSum(key, input)[:outLen]
}

// mac computes the SCP03 MAC over the current chaining value and the message,
// returning the 8-byte tag to transmit and the new chaining value (the full
// CMAC output).
func (s *scp03Session) mac(key cipher.Block, msg []byte) (tag, chain []byte) {
	full := cmacSum(key, append(append([]byte{}, s.chain...), msg...))
	return full[:macLen], full
}

// wrap encrypts and authenticates an inner command message for transmission,
// returning the SESSION MESSAGE frame and the counter block used, which the
// response decryption needs.
func (s *scp03Session) wrap(inner []byte) (outer, counterBlock []byte) {
	s.counter++
	counterBlock = make([]byte, blockLen)
	binary.BigEndian.PutUint32(counterBlock[blockLen-4:], s.counter)

	// ISO 7816-4 padding: a mandatory 0x80 then zeros. It is always applied, even
	// to an exact multiple of the block size, so unpadding is unambiguous.
	padded := make([]byte, ((len(inner)/blockLen)+1)*blockLen)
	copy(padded, inner)
	padded[len(inner)] = 0x80

	iv := make([]byte, blockLen)
	s.enc.Encrypt(iv, counterBlock)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(s.enc, iv).CryptBlocks(ct, padded)

	// The length field covers the trailing MAC, so it is written before the MAC
	// is computed — the MAC is over the message as it will appear on the wire.
	outer = make([]byte, 3+1+len(ct)+macLen)
	outer[0] = cmdSessionMessage
	binary.BigEndian.PutUint16(outer[1:3], uint16(1+len(ct)+macLen))
	outer[3] = s.id
	copy(outer[4:], ct)

	tag, chain := s.mac(s.macKey, outer[:4+len(ct)])
	copy(outer[4+len(ct):], tag)
	s.chain = chain
	return outer, counterBlock
}

// unwrap verifies and decrypts a SESSION MESSAGE response, returning the inner
// response message.
func (s *scp03Session) unwrap(raw, counterBlock []byte) ([]byte, error) {
	// Only a session-message response may be unwrapped. An error frame is not
	// decoded here even though the framing allows it: outside the secure channel
	// it is unauthenticated, so accepting it would let anything on the transport
	// choose what a command appears to have returned. The one case the device
	// really does answer that way is handled — and checked — by the caller.
	if len(raw) < 3 {
		return nil, fmt.Errorf("truncated session response: %d bytes", len(raw))
	}
	if raw[0] != cmdSessionMessage|responseFlag {
		return nil, fmt.Errorf("unauthenticated frame 0x%02x where an authenticated session response was expected", raw[0])
	}
	n := int(binary.BigEndian.Uint16(raw[1:3]))
	if len(raw) < 3+n {
		return nil, fmt.Errorf("truncated session response: header declares %d payload bytes, got %d", n, len(raw)-3)
	}
	body := raw[3 : 3+n]
	if len(body) < 1+macLen {
		return nil, fmt.Errorf("session response is %d bytes, too short to hold a session id and MAC", len(body))
	}
	if body[0] != s.id {
		return nil, fmt.Errorf("session response is for session %d, expected %d", body[0], s.id)
	}
	ct := body[1 : len(body)-macLen]
	got := body[len(body)-macLen:]

	// The MAC input is the frame as its own length field declares it, not however
	// many bytes the transport happened to hand over: parseResponse tolerates
	// trailing bytes, and those must not become part of what is authenticated.
	//
	// The response MAC chains from the value the *command* left behind, which is
	// what binds a response to the specific request that asked for it.
	want, _ := s.mac(s.rmacKey, raw[:3+len(body)-macLen])
	if subtle.ConstantTimeCompare(want, got) != 1 {
		return nil, fmt.Errorf("session response MAC verification failed (the reply was altered or does not belong to this session)")
	}
	if len(ct) == 0 || len(ct)%blockLen != 0 {
		return nil, fmt.Errorf("session response ciphertext is %d bytes, not a positive multiple of the block size", len(ct))
	}

	// The response is decrypted under the *same* ICV as the command that asked
	// for it — the encrypted counter block, unmodified.
	//
	// This is where the YubiHSM departs from GlobalPlatform SCP03, which sets the
	// counter block's most significant byte to 0x80 for the response direction.
	// The device does not, as the hardware conformance test in scp03_hwtest
	// pins: decrypting with the 0x80 variant corrupts exactly the first
	// plaintext block, which is the CBC signature of a wrong IV and nothing else.
	// Replay is still prevented, because the counter advances per command and the
	// response MAC chains from the command's, and no plaintext equality leaks
	// across directions, because a response's first byte is always the command's
	// with the high bit set.
	iv := make([]byte, blockLen)
	s.enc.Encrypt(iv, counterBlock)

	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(s.enc, iv).CryptBlocks(pt, ct)
	return stripPadding(pt)
}

func stripPadding(b []byte) ([]byte, error) {
	for i := len(b) - 1; i >= 0 && i >= len(b)-blockLen; i-- {
		switch b[i] {
		case 0x00:
			continue
		case 0x80:
			return b[:i], nil
		default:
			return nil, fmt.Errorf("malformed padding in the decrypted session response")
		}
	}
	return nil, fmt.Errorf("no padding marker in the decrypted session response")
}
