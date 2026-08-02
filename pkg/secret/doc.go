// Package secret encrypts and decrypts werf secrets, either as whole blobs or as the
// individual scalar values of a YAML document.
//
// # Encoded format
//
// An encoded value is the hex encoding of a binary payload that starts with a two-byte
// little-endian format version:
//
//	version 16: [version][16-byte IV][AES-CBC ciphertext, PKCS#7 padded]
//	version  2: [version][12-byte nonce][AES-GCM ciphertext and authentication tag]
//
// Version 16 is the legacy format. Those two bytes originally held the CBC IV size, were
// always written as 16, and were never read back, which is why the field could be
// repurposed as a version without changing the layout of existing data. It is read-only:
// it still decrypts exactly as it always did, but it is never written any more.
//
// Version 2 is AES-GCM and is what Encrypt writes. Any other version is rejected with an
// error rather than being decrypted as CBC.
//
// Both versions are read with the same secret key, so upgrading needs no new key and no
// migration. The key format is unchanged: 16, 24 or 32 random bytes hex-encoded, as
// produced by GenerateAesSecretKey.
//
// # Compatibility
//
// Reading is backward compatible, but writing is not forward compatible: a value written
// in version 2 cannot be read by a werf or nelm release that predates version 2 support,
// because those releases ignore the version field and decrypt everything as CBC. There is
// no way to write the legacy format any more, so a repository whose secrets have been
// re-encrypted needs every consumer, including CI jobs and saved deploy plans, to
// understand version 2. Re-encrypting everything at once is what rotate-secret-key does.
//
// # Authentication
//
// The legacy CBC format has no integrity check, so a corrupted or deliberately modified
// ciphertext could decrypt to garbage instead of failing, and a wrong key was often
// accepted. AES-GCM authenticates, so tampering and wrong keys are reported as errors.
// This protects newly written values only; existing values gain it once re-encrypted.
//
// The version prefix of a version 2 value is authenticated, so it cannot be altered
// within that format. It cannot be bound any tighter than that: rewriting the prefix to
// 16 sends the value to the legacy CBC reader, which by definition does not authenticate.
// Such a value is still rejected unless its length happens to suit the legacy block
// layout and the decrypted tail happens to form valid padding, and what comes out is
// unpredictable garbage rather than anything the attacker chooses, since they do not hold
// the key.
//
// This grants an attacker nothing they did not already have. Anyone able to rewrite those
// two bytes can just as easily replace the whole value with a legacy blob of their own,
// which this package must keep reading, and that succeeds at the same small rate. The
// exposure is not the rewrite but the fact that an unauthenticated format stays readable,
// and that is the price of not breaking existing data. Re-encrypting with
// rotate-secret-key does not change it either, because the legacy reader has to stay for
// as long as any legacy value might exist anywhere.
//
// # YAML scalars
//
// EncryptYamlData and DecryptYamlData encrypt each scalar leaf of a document in place.
// From version 2 on, the YAML tag and the scalar style are stored inside the encrypted
// payload, so a number stays a number and a block scalar keeps its style across a round
// trip. Whole-blob Encrypt and Decrypt never add this framing.
//
// Values encrypted before version 2 did not store a tag, so that information does not
// exist anywhere and cannot be recovered: they keep decrypting as strings. Re-encrypting
// does not help, because by then the original type is already lost. The only way to give
// such a value its intended type is to re-enter it, for example through
// "werf helm secret values edit".
//
// A comment attached to an encrypted value is preserved, which means it stays cleartext in
// the encrypted file, the same way mapping keys already do. Do not put secrets in
// comments.
package secret
