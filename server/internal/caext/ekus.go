package caext

import "encoding/asn1"

// ExtKeyUsageOIDs is the catalogue of extended-key-usage names an operator may
// write instead of a dotted OID. It is deliberately broad: an issuing CA
// constrained by extKeyUsage is the most effective way to bound what a delegated
// authority can mint, and an operator should not have to look up an OID to use
// it. Anything missing is still reachable — resolveExtKeyUsages falls back to
// parsing the name as a dotted OID.
//
// The id-kp arc (1.3.6.1.5.5.7.3.x) is the IANA "SMI Security for PKIX Extended
// Key Purpose" registry; the rest are the Microsoft, Kerberos, Netscape and
// Adobe purposes that appear in real enterprise and document-signing PKIs.
var ExtKeyUsageOIDs = map[string]asn1.ObjectIdentifier{
	// anyExtendedKeyUsage (RFC 5280 §4.2.1.12): the CA does not restrict purpose.
	"any": {2, 5, 29, 37, 0},

	// --- RFC 5280 / IANA id-kp -------------------------------------------------
	"serverAuth":           {1, 3, 6, 1, 5, 5, 7, 3, 1},
	"clientAuth":           {1, 3, 6, 1, 5, 5, 7, 3, 2},
	"codeSigning":          {1, 3, 6, 1, 5, 5, 7, 3, 3},
	"emailProtection":      {1, 3, 6, 1, 5, 5, 7, 3, 4},
	"ipsecEndSystem":       {1, 3, 6, 1, 5, 5, 7, 3, 5},
	"ipsecTunnel":          {1, 3, 6, 1, 5, 5, 7, 3, 6},
	"ipsecUser":            {1, 3, 6, 1, 5, 5, 7, 3, 7},
	"timeStamping":         {1, 3, 6, 1, 5, 5, 7, 3, 8},
	"ocspSigning":          {1, 3, 6, 1, 5, 5, 7, 3, 9},
	"dvcs":                 {1, 3, 6, 1, 5, 5, 7, 3, 10},
	"sbgpCertAAServerAuth": {1, 3, 6, 1, 5, 5, 7, 3, 11},
	"scvpResponder":        {1, 3, 6, 1, 5, 5, 7, 3, 12},
	"eapOverPPP":           {1, 3, 6, 1, 5, 5, 7, 3, 13},
	"eapOverLAN":           {1, 3, 6, 1, 5, 5, 7, 3, 14},
	"scvpServer":           {1, 3, 6, 1, 5, 5, 7, 3, 15},
	"scvpClient":           {1, 3, 6, 1, 5, 5, 7, 3, 16},
	"ipsecIKE":             {1, 3, 6, 1, 5, 5, 7, 3, 17},
	"capwapAC":             {1, 3, 6, 1, 5, 5, 7, 3, 18},
	"capwapWTP":            {1, 3, 6, 1, 5, 5, 7, 3, 19},
	"sipDomain":            {1, 3, 6, 1, 5, 5, 7, 3, 20},
	"secureShellClient":    {1, 3, 6, 1, 5, 5, 7, 3, 21},
	"secureShellServer":    {1, 3, 6, 1, 5, 5, 7, 3, 22},
	"sendRouter":           {1, 3, 6, 1, 5, 5, 7, 3, 23},
	"sendProxiedRouter":    {1, 3, 6, 1, 5, 5, 7, 3, 24},
	"sendOwner":            {1, 3, 6, 1, 5, 5, 7, 3, 25},
	"sendProxiedOwner":     {1, 3, 6, 1, 5, 5, 7, 3, 26},
	"cmcCA":                {1, 3, 6, 1, 5, 5, 7, 3, 27},
	"cmcRA":                {1, 3, 6, 1, 5, 5, 7, 3, 28},
	"cmcArchive":           {1, 3, 6, 1, 5, 5, 7, 3, 29},
	"bgpsecRouter":         {1, 3, 6, 1, 5, 5, 7, 3, 30},
	// RFC 9118 Brand Indicator for Message Identification (BIMI).
	"bimi": {1, 3, 6, 1, 5, 5, 7, 3, 31},
	// RFC 9480 certificate-management key-generation authority.
	"cmKGA": {1, 3, 6, 1, 5, 5, 7, 3, 32},
	// RFC 9289 RPC-over-TLS.
	"rpcTLSClient": {1, 3, 6, 1, 5, 5, 7, 3, 33},
	"rpcTLSServer": {1, 3, 6, 1, 5, 5, 7, 3, 34},
	// RFC 9174 Bundle Protocol security (DTN).
	"bundleSecurity": {1, 3, 6, 1, 5, 5, 7, 3, 35},
	// RFC 9336 document signing.
	"documentSigning": {1, 3, 6, 1, 5, 5, 7, 3, 36},

	// --- Kerberos / PKINIT -----------------------------------------------------
	"pkinitClientAuth": {1, 3, 6, 1, 5, 2, 3, 4},
	"pkinitKDC":        {1, 3, 6, 1, 5, 2, 3, 5},

	// --- Microsoft -------------------------------------------------------------
	"msSmartcardLogon":       {1, 3, 6, 1, 4, 1, 311, 20, 2, 2},
	"msEnrollmentAgent":      {1, 3, 6, 1, 4, 1, 311, 20, 2, 1},
	"msKDCAuthentication":    {1, 3, 6, 1, 4, 1, 311, 20, 2, 3},
	"msCAExchange":           {1, 3, 6, 1, 4, 1, 311, 21, 5},
	"msKeyRecovery":          {1, 3, 6, 1, 4, 1, 311, 21, 6},
	"msDocumentSigning":      {1, 3, 6, 1, 4, 1, 311, 10, 3, 12},
	"msEncryptingFileSystem": {1, 3, 6, 1, 4, 1, 311, 10, 3, 4},
	"msEFSRecovery":          {1, 3, 6, 1, 4, 1, 311, 10, 3, 4, 1},
	"msTimestampSigning":     {1, 3, 6, 1, 4, 1, 311, 10, 3, 2},
	"msServerGatedCrypto":    {1, 3, 6, 1, 4, 1, 311, 10, 3, 3},
	"msLifetimeSigning":      {1, 3, 6, 1, 4, 1, 311, 10, 3, 13},
	"msKeyRecoveryAgent":     {1, 3, 6, 1, 4, 1, 311, 21, 19},

	// --- Netscape / Adobe ------------------------------------------------------
	"netscapeServerGatedCrypto": {2, 16, 840, 1, 113730, 4, 1},
	"adobePDFSigning":           {1, 2, 840, 113583, 1, 1, 5},
}
