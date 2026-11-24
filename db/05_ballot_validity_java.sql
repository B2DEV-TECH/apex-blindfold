-- APEX Blindfold, Layer 2: ballot validity and ballot signatures, verified in the database.
--
-- The browser proves, without opening anything, that every ciphertext of a ballot encrypts 0 or 1
-- and that the three plaintexts add up to 1 (validity.js). This class checks those proofs and the
-- voter signature. It holds no key and never decrypts.
--
-- It is a second implementation, written apart from the JavaScript one, on java.math.BigInteger.
-- The two must build the same bytes before hashing: the test vectors compare their challenge
-- hashes byte for byte.
--
--   u_k = c * (1 - k*n) mod n^2        an n-th power exactly when c encrypts k
--   a   = z^n * u^-e mod n^2           the commitment that the stored (e, z) stands for
--   bit proof   e0 + e1 = H(label, n, election, ballot, candidate, c, a0, a1)   first 128 bits
--   sum proof   e       = H(label, n, election, ballot, c1, c2, c3, a)          for c1*c2*c3 and k = 1
--
-- Unaudited educational cryptography.
-- (No apostrophes in the comments of the Java source: SQLcl would read one as an open string.)

create or replace and compile java source named "BlindfoldValidity" as
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

public class BlindfoldValidity {

  private static final int CHALLENGE_BYTES = 16;
  private static final int CHALLENGE_HEX = 2 * CHALLENGE_BYTES;
  private static final int MIN_MODULUS_BITS = 512;
  private static final BigInteger CHALLENGE_SPACE = BigInteger.ONE.shiftLeft(8 * CHALLENGE_BYTES);
  private static final String LABEL_BIT = "apex-blindfold/v2/bit";
  private static final String LABEL_SUM = "apex-blindfold/v2/sum";
  private static final String LABEL_BALLOT = "apex-blindfold/v2/ballot";
  private static final String HEX_DIGITS = "0123456789abcdef";

  // Thrown for anything a ballot can get wrong. Its message is the reason of the rejection.
  private static final class Rejected extends Exception {
    Rejected(String reason) {
      super(reason);
    }
  }

  // ---------------------------------------------------------------- encoding

  private static boolean isLowerHex(String text) {
    if (text == null || text.isEmpty()) {
      return false;
    }
    for (int i = 0; i < text.length(); i++) {
      if (HEX_DIGITS.indexOf(text.charAt(i)) < 0) {
        return false;
      }
    }
    return true;
  }

  private static byte[] bytes(String hex) throws Rejected {
    if (!isLowerHex(hex) || hex.length() % 2 != 0) {
      throw new Rejected("expected lower-case hexadecimal, whole bytes");
    }
    byte[] out = new byte[hex.length() / 2];
    for (int i = 0; i < out.length; i++) {
      out[i] = (byte) ((HEX_DIGITS.indexOf(hex.charAt(2 * i)) << 4) | HEX_DIGITS.indexOf(hex.charAt(2 * i + 1)));
    }
    return out;
  }

  private static String hex(byte[] data) {
    StringBuilder sb = new StringBuilder(data.length * 2);
    for (byte b : data) {
      sb.append(HEX_DIGITS.charAt((b >> 4) & 15)).append(HEX_DIGITS.charAt(b & 15));
    }
    return sb.toString();
  }

  // A non-negative integer as exactly width bytes, most significant first.
  private static byte[] fixed(BigInteger value, int width) throws Rejected {
    byte[] raw = value.toByteArray();
    int from = (raw.length > 1 && raw[0] == 0) ? 1 : 0;
    int length = raw.length - from;
    if (value.signum() < 0 || length > width) {
      throw new Rejected("value does not fit the width");
    }
    byte[] out = new byte[width];
    System.arraycopy(raw, from, out, width - length, length);
    return out;
  }

  // Identifiers travel as 8-byte integers.
  private static byte[] id(long value) throws Rejected {
    return fixed(BigInteger.valueOf(value), 8);
  }

  // Every field is a 4-byte length, most significant byte first, followed by its bytes.
  private static byte[] frame(byte[]... fields) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    for (byte[] field : fields) {
      int length = field.length;
      out.write((length >>> 24) & 255);
      out.write((length >>> 16) & 255);
      out.write((length >>> 8) & 255);
      out.write(length & 255);
      out.write(field, 0, length);
    }
    return out.toByteArray();
  }

  private static byte[] text(String value) {
    return value.getBytes(StandardCharsets.UTF_8);
  }

  private static byte[] sha256(byte[] data) throws Exception {
    return MessageDigest.getInstance("SHA-256").digest(data);
  }

  private static BigInteger challengeOf(byte[] digest) {
    byte[] head = new byte[CHALLENGE_BYTES];
    System.arraycopy(digest, 0, head, 0, CHALLENGE_BYTES);
    return new BigInteger(1, head);
  }

  // --------------------------------------------------------------------- key

  private static final class Key {
    final BigInteger n;
    final BigInteger nSquared;
    final int width; // bytes of n; a number modulo n^2 takes twice as many

    Key(String nHex) throws Rejected {
      if (!isLowerHex(nHex)) {
        throw new Rejected("malformed public key");
      }
      n = new BigInteger(nHex, 16);
      if (n.bitLength() < MIN_MODULUS_BITS) {
        throw new Rejected("the proofs need a modulus of at least " + MIN_MODULUS_BITS + " bits");
      }
      nSquared = n.multiply(n);
      width = (n.bitLength() + 7) / 8;
    }

    BigInteger ciphertext(String cHex) throws Rejected {
      if (!isLowerHex(cHex) || cHex.length() != 4 * width) {
        throw new Rejected("malformed ciphertext");
      }
      BigInteger c = new BigInteger(cHex, 16);
      if (c.signum() <= 0 || c.compareTo(nSquared) >= 0 || !c.gcd(n).equals(BigInteger.ONE)) {
        throw new Rejected("ciphertext out of range");
      }
      return c;
    }

    BigInteger commitment(String aHex) throws Rejected {
      if (!isLowerHex(aHex) || aHex.length() != 4 * width) {
        throw new Rejected("malformed commitment");
      }
      return new BigInteger(aHex, 16);
    }

    // u_k = c * (1 - k*n) mod n^2
    BigInteger shifted(BigInteger c, int k) {
      return c.multiply(BigInteger.ONE.subtract(n.multiply(BigInteger.valueOf(k)))).mod(nSquared);
    }

    // a = z^n * u^-e mod n^2
    BigInteger commitmentFor(BigInteger u, BigInteger e, BigInteger z) {
      return z.modPow(n, nSquared).multiply(u.modInverse(nSquared).modPow(e, nSquared)).mod(nSquared);
    }

    BigInteger challenge(String proofHex, int from) throws Rejected {
      return new BigInteger(proofHex.substring(from, from + CHALLENGE_HEX), 16);
    }

    BigInteger response(String proofHex, int from) throws Rejected {
      BigInteger z = new BigInteger(proofHex.substring(from, from + 2 * width), 16);
      if (z.signum() <= 0 || z.compareTo(n) >= 0) {
        throw new Rejected("response out of range");
      }
      return z;
    }
  }

  // ------------------------------------------------------- bytes that are hashed

  private static byte[] bitBytes(Key key, long election, long ballot, int candidate, BigInteger c, BigInteger a0, BigInteger a1) throws Rejected {
    return frame(text(LABEL_BIT), fixed(key.n, key.width), id(election), id(ballot), id(candidate),
        fixed(c, 2 * key.width), fixed(a0, 2 * key.width), fixed(a1, 2 * key.width));
  }

  private static byte[] sumBytes(Key key, long election, long ballot, BigInteger c1, BigInteger c2, BigInteger c3, BigInteger a) throws Rejected {
    return frame(text(LABEL_SUM), fixed(key.n, key.width), id(election), id(ballot),
        fixed(c1, 2 * key.width), fixed(c2, 2 * key.width), fixed(c3, 2 * key.width), fixed(a, 2 * key.width));
  }

  // The bytes a voter signs: the whole ballot.
  private static byte[] ballotBytes(Key key, long election, long ballot, String voter,
      String c1, String c2, String c3, String p1, String p2, String p3, String pSum) throws Rejected {
    return frame(text(LABEL_BALLOT), fixed(key.n, key.width), id(election), id(ballot), text(voter),
        bytes(c1), bytes(p1), bytes(c2), bytes(p2), bytes(c3), bytes(p3), bytes(pSum));
  }

  // ----------------------------------------------------------------- the checks

  // Recomputes both commitments of a bit proof and returns the challenge hash.
  // The proof holds when e0 + e1 equals the first 128 bits of that hash.
  private static byte[] bitDigestOf(Key key, long election, long ballot, int candidate, BigInteger c, String proofHex) throws Exception {
    if (!isLowerHex(proofHex) || proofHex.length() != 2 * CHALLENGE_HEX + 4 * key.width) {
      throw new Rejected("malformed bit proof");
    }
    BigInteger e0 = key.challenge(proofHex, 0);
    BigInteger e1 = key.challenge(proofHex, CHALLENGE_HEX);
    BigInteger z0 = key.response(proofHex, 2 * CHALLENGE_HEX);
    BigInteger z1 = key.response(proofHex, 2 * CHALLENGE_HEX + 2 * key.width);
    BigInteger a0 = key.commitmentFor(key.shifted(c, 0), e0, z0);
    BigInteger a1 = key.commitmentFor(key.shifted(c, 1), e1, z1);
    return sha256(bitBytes(key, election, ballot, candidate, c, a0, a1));
  }

  private static boolean bitHolds(Key key, String proofHex, byte[] digest) throws Rejected {
    BigInteger sum = key.challenge(proofHex, 0).add(key.challenge(proofHex, CHALLENGE_HEX)).mod(CHALLENGE_SPACE);
    return sum.equals(challengeOf(digest));
  }

  private static byte[] sumDigestOf(Key key, long election, long ballot, BigInteger c1, BigInteger c2, BigInteger c3, String proofHex) throws Exception {
    if (!isLowerHex(proofHex) || proofHex.length() != CHALLENGE_HEX + 2 * key.width) {
      throw new Rejected("malformed sum proof");
    }
    BigInteger e = key.challenge(proofHex, 0);
    BigInteger z = key.response(proofHex, CHALLENGE_HEX);
    BigInteger product = c1.multiply(c2).mod(key.nSquared).multiply(c3).mod(key.nSquared);
    BigInteger a = key.commitmentFor(key.shifted(product, 1), e, z);
    return sha256(sumBytes(key, election, ballot, c1, c2, c3, a));
  }

  private static void checkBallot(Key key, long election, long ballot,
      String c1, String c2, String c3, String p1, String p2, String p3, String pSum) throws Exception {
    String[] cHex = { c1, c2, c3 };
    String[] pHex = { p1, p2, p3 };
    BigInteger[] c = new BigInteger[3];
    for (int i = 0; i < 3; i++) {
      try {
        c[i] = key.ciphertext(cHex[i]);
        if (!bitHolds(key, pHex[i], bitDigestOf(key, election, ballot, i + 1, c[i], pHex[i]))) {
          throw new Rejected("the challenges do not add up to the hash");
        }
      } catch (Rejected rejected) {
        throw new Rejected("option " + (i + 1) + ": " + rejected.getMessage());
      }
    }
    try {
      byte[] digest = sumDigestOf(key, election, ballot, c[0], c[1], c[2], pSum);
      if (!key.challenge(pSum, 0).equals(challengeOf(digest))) {
        throw new Rejected("the challenge is not the hash");
      }
    } catch (Rejected rejected) {
      throw new Rejected("sum: " + rejected.getMessage());
    }
  }

  private static String failure(Throwable problem) {
    if (problem instanceof Rejected) {
      return "FAIL " + problem.getMessage();
    }
    return "FAIL " + problem.getClass().getSimpleName() + ": " + problem.getMessage();
  }

  // --------------------------------------------- entry points called from PL/SQL

  // The challenge hash of a bit proof from its commitments, as the prover computes it.
  public static String bitChallenge(String nHex, long election, long ballot, int candidate, String cHex, String a0Hex, String a1Hex) {
    try {
      Key key = new Key(nHex);
      return hex(sha256(bitBytes(key, election, ballot, candidate, key.ciphertext(cHex), key.commitment(a0Hex), key.commitment(a1Hex))));
    } catch (Throwable problem) {
      return failure(problem);
    }
  }

  // The challenge hash of a sum proof from its commitment, as the prover computes it.
  public static String sumChallenge(String nHex, long election, long ballot, String c1, String c2, String c3, String aHex) {
    try {
      Key key = new Key(nHex);
      return hex(sha256(sumBytes(key, election, ballot, key.ciphertext(c1), key.ciphertext(c2), key.ciphertext(c3), key.commitment(aHex))));
    } catch (Throwable problem) {
      return failure(problem);
    }
  }

  // The challenge hash the verifier arrives at, from the stored proof alone.
  public static String bitDigest(String nHex, long election, long ballot, int candidate, String cHex, String proofHex) {
    try {
      Key key = new Key(nHex);
      return hex(bitDigestOf(key, election, ballot, candidate, key.ciphertext(cHex), proofHex));
    } catch (Throwable problem) {
      return failure(problem);
    }
  }

  public static String sumDigest(String nHex, long election, long ballot, String c1, String c2, String c3, String proofHex) {
    try {
      Key key = new Key(nHex);
      return hex(sumDigestOf(key, election, ballot, key.ciphertext(c1), key.ciphertext(c2), key.ciphertext(c3), proofHex));
    } catch (Throwable problem) {
      return failure(problem);
    }
  }

  // OK, or FAIL followed by the reason: which proof failed and why.
  public static String verifyBallot(String nHex, long election, long ballot,
      String c1, String c2, String c3, String p1, String p2, String p3, String pSum) {
    try {
      checkBallot(new Key(nHex), election, ballot, c1, c2, c3, p1, p2, p3, pSum);
      return "OK";
    } catch (Throwable problem) {
      return failure(problem);
    }
  }

  // OK when the text is a P-256 public key in SubjectPublicKeyInfo form.
  public static String checkPublicKey(String publicKeyHex) {
    try {
      PublicKey key;
      try {
        key = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(bytes(publicKeyHex)));
      } catch (Exception malformed) {
        throw new Rejected("malformed voter public key");
      }
      if (((java.security.interfaces.ECPublicKey) key).getParams().getCurve().getField().getFieldSize() != 256) {
        throw new Rejected("the voter public key is not on the curve P-256");
      }
      return "OK";
    } catch (Throwable problem) {
      return failure(problem);
    }
  }

  // SHA-256 of the bytes that the voter signs.
  public static String ballotDigest(String nHex, long election, long ballot, String voter,
      String c1, String c2, String c3, String p1, String p2, String p3, String pSum) {
    try {
      return hex(sha256(ballotBytes(new Key(nHex), election, ballot, voter, c1, c2, c3, p1, p2, p3, pSum)));
    } catch (Throwable problem) {
      return failure(problem);
    }
  }

  // ECDSA P-256 over SHA-256. The browser sends r and s side by side (IEEE P1363), not DER,
  // and its public key as SubjectPublicKeyInfo.
  public static String verifySignature(String publicKeyHex, String signatureHex, String nHex, long election, long ballot, String voter,
      String c1, String c2, String c3, String p1, String p2, String p3, String pSum) {
    try {
      byte[] signed = ballotBytes(new Key(nHex), election, ballot, voter, c1, c2, c3, p1, p2, p3, pSum);
      byte[] signature = bytes(signatureHex);
      if (signature.length != 64) {
        throw new Rejected("malformed signature");
      }
      PublicKey key;
      try {
        key = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(bytes(publicKeyHex)));
      } catch (Exception malformed) {
        throw new Rejected("malformed voter public key");
      }
      Signature verifier = Signature.getInstance("SHA256withECDSAinP1363Format");
      verifier.initVerify(key);
      verifier.update(signed);
      boolean genuine;
      try {
        genuine = verifier.verify(signature);
      } catch (Exception malformed) {
        genuine = false;
      }
      if (!genuine) {
        throw new Rejected("the signature does not match the ballot");
      }
      return "OK";
    } catch (Throwable problem) {
      return failure(problem);
    }
  }
}
/

create or replace function bf_v2_bit_challenge (
  p_n_hex in varchar2, p_election_id in number, p_ballot_id in number, p_candidate_id in number,
  p_enc in varchar2, p_a0 in varchar2, p_a1 in varchar2
) return varchar2
as language java name 'BlindfoldValidity.bitChallenge(java.lang.String, long, long, int, java.lang.String, java.lang.String, java.lang.String) return java.lang.String';
/

create or replace function bf_v2_sum_challenge (
  p_n_hex in varchar2, p_election_id in number, p_ballot_id in number,
  p_enc_1 in varchar2, p_enc_2 in varchar2, p_enc_3 in varchar2, p_a in varchar2
) return varchar2
as language java name 'BlindfoldValidity.sumChallenge(java.lang.String, long, long, java.lang.String, java.lang.String, java.lang.String, java.lang.String) return java.lang.String';
/

create or replace function bf_v2_bit_digest (
  p_n_hex in varchar2, p_election_id in number, p_ballot_id in number, p_candidate_id in number,
  p_enc in varchar2, p_proof in varchar2
) return varchar2
as language java name 'BlindfoldValidity.bitDigest(java.lang.String, long, long, int, java.lang.String, java.lang.String) return java.lang.String';
/

create or replace function bf_v2_sum_digest (
  p_n_hex in varchar2, p_election_id in number, p_ballot_id in number,
  p_enc_1 in varchar2, p_enc_2 in varchar2, p_enc_3 in varchar2, p_proof in varchar2
) return varchar2
as language java name 'BlindfoldValidity.sumDigest(java.lang.String, long, long, java.lang.String, java.lang.String, java.lang.String, java.lang.String) return java.lang.String';
/

create or replace function bf_v2_verify_ballot (
  p_n_hex in varchar2, p_election_id in number, p_ballot_id in number,
  p_enc_1 in varchar2, p_enc_2 in varchar2, p_enc_3 in varchar2,
  p_proof_1 in varchar2, p_proof_2 in varchar2, p_proof_3 in varchar2, p_proof_sum in varchar2
) return varchar2
as language java name 'BlindfoldValidity.verifyBallot(java.lang.String, long, long, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String) return java.lang.String';
/

create or replace function bf_v2_ballot_digest (
  p_n_hex in varchar2, p_election_id in number, p_ballot_id in number, p_voter_id in varchar2,
  p_enc_1 in varchar2, p_enc_2 in varchar2, p_enc_3 in varchar2,
  p_proof_1 in varchar2, p_proof_2 in varchar2, p_proof_3 in varchar2, p_proof_sum in varchar2
) return varchar2
as language java name 'BlindfoldValidity.ballotDigest(java.lang.String, long, long, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String) return java.lang.String';
/

create or replace function bf_v2_verify_signature (
  p_public_key in varchar2, p_signature in varchar2,
  p_n_hex in varchar2, p_election_id in number, p_ballot_id in number, p_voter_id in varchar2,
  p_enc_1 in varchar2, p_enc_2 in varchar2, p_enc_3 in varchar2,
  p_proof_1 in varchar2, p_proof_2 in varchar2, p_proof_3 in varchar2, p_proof_sum in varchar2
) return varchar2
as language java name 'BlindfoldValidity.verifySignature(java.lang.String, java.lang.String, java.lang.String, long, long, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String) return java.lang.String';
/

create or replace function bf_v2_check_public_key (p_public_key in varchar2) return varchar2
as language java name 'BlindfoldValidity.checkPublicKey(java.lang.String) return java.lang.String';
/
