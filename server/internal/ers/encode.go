package ers

import (
	"encoding/asn1"
	"errors"
	"fmt"
)

// Marshal encodes an EvidenceRecord to DER. It is the inverse of Parse.
func (er *EvidenceRecord) Marshal() ([]byte, error) {
	return asn1.Marshal(er.wire)
}

// marshalEvidenceRecord DER-encodes the wire structure.
func marshalEvidenceRecord(er *evidenceRecord) ([]byte, error) {
	der, err := asn1.Marshal(*er)
	if err != nil {
		return nil, fmt.Errorf("ers: encoding evidence record: %w", err)
	}
	return der, nil
}

// parseEvidenceRecord decodes a DER EvidenceRecord, rejecting trailing data and
// an unsupported version.
func parseEvidenceRecord(der []byte) (*evidenceRecord, error) {
	var er evidenceRecord
	rest, err := asn1.Unmarshal(der, &er)
	if err != nil {
		return nil, fmt.Errorf("ers: parsing evidence record: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("ers: trailing data after evidence record")
	}
	if er.Version != Version {
		return nil, fmt.Errorf("ers: unsupported evidence-record version %d", er.Version)
	}
	if len(er.ArchiveTimeStampSequence) == 0 {
		return nil, ErrNoTimestamp
	}
	return &er, nil
}

// marshalChain DER-encodes one ArchiveTimeStampChain (a SEQUENCE OF
// ArchiveTimeStamp). Used to build the atsc input for hash-tree renewal, where
// the concatenation of the previous chains' DER is re-hashed under the new
// algorithm (RFC 4998 §5.2).
func marshalChain(chain archiveTimeStampChain) ([]byte, error) {
	der, err := asn1.Marshal(chain)
	if err != nil {
		return nil, fmt.Errorf("ers: encoding archive-timestamp chain: %w", err)
	}
	return der, nil
}

// previousSequenceBytes concatenates the DER encodings of chains[0..n) — the
// atsc(i) input RFC 4998 §5.2 hashes for hash-tree renewal ("the encoded
// ArchiveTimeStampSequence, the concatenation of all previous Archive Timestamp
// Chains ... DER encoded"). The same function is used on the generate and verify
// sides so the two agree byte-for-byte.
func previousSequenceBytes(chains []archiveTimeStampChain) ([]byte, error) {
	var buf []byte
	for _, c := range chains {
		der, err := marshalChain(c)
		if err != nil {
			return nil, err
		}
		buf = append(buf, der...)
	}
	return buf, nil
}
