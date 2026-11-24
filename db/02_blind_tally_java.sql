-- APEX Blindfold: the blind tally.
--
-- The lab design asked for an MLE JavaScript module. MLE is not available in
-- Oracle AI Database 26ai Free for Windows (see evidence/00-environment), and
-- PL/SQL has no arbitrary-precision integers, so the tally runs on a Java
-- stored procedure with java.math.BigInteger.
--
-- This class holds no key and never decrypts. For each candidate it multiplies
-- the stored ciphertexts modulo n^2. By the homomorphic property of Paillier,
-- that product is a ciphertext of the number of votes.
--
-- Layer 2: before a ballot is multiplied in, its proofs and its signature are
-- verified again, here, from what the tables hold (class BlindfoldValidity).
-- A row that reached the table by another road than the application is not
-- counted, and the answer says which ballots were left out and why.

create or replace and compile java source named "BlindfoldTally" as
import java.math.BigInteger;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

public class BlindfoldTally {

  // How many rejected ballots the answer lists one by one. All of them are counted.
  private static final int LISTED = 50;

  // Left-pads a hexadecimal number with zeros to a fixed width.
  private static String pad(String hex, int width) {
    StringBuilder padded = new StringBuilder(width);
    for (int i = hex.length(); i < width; i++) {
      padded.append('0');
    }
    return padded.append(hex).toString();
  }

  // n^2 in hexadecimal, at the fixed width of a ciphertext.
  public static String squareHex(String nHex) {
    BigInteger nSquared = new BigInteger(nHex, 16).pow(2);
    return pad(nSquared.toString(16), (nSquared.bitLength() + 3) / 4);
  }

  private static String quote(String text) {
    return "\"" + text.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
  }

  // Returns JSON for the current election: how many ballots were verified,
  // counted and rejected, the rejected ones with the reason, and, for each
  // candidate, the product of the counted ciphertexts modulo n^2.
  public static String tally() throws SQLException {
    // Server-side internal connection: the session that called this method.
    // (No apostrophes in these comments: SQLcl would read one as an open string.)
    Connection conn = DriverManager.getConnection("jdbc:default:connection:");

    long election;
    String nHex;
    try (PreparedStatement ps = conn.prepareStatement("select election_id, n_hex from election_key order by election_id desc fetch first 1 row only");
         ResultSet rs = ps.executeQuery()) {
      if (!rs.next()) {
        throw new SQLException("No public key has been published.");
      }
      election = rs.getLong(1);
      nHex = rs.getString(2);
    }
    BigInteger nSquared = new BigInteger(nHex, 16).pow(2);
    int width = (nSquared.bitLength() + 3) / 4;

    // Every candidate starts at 1, which is a trivial encryption of zero.
    Map<Integer, BigInteger> totals = new TreeMap<>();
    try (PreparedStatement ps = conn.prepareStatement("select candidate_id from candidates order by candidate_id");
         ResultSet rs = ps.executeQuery()) {
      while (rs.next()) {
        totals.put(rs.getInt(1), BigInteger.ONE);
      }
    }

    // The public keys that the voters registered.
    Map<String, String> keys = new HashMap<>();
    try (PreparedStatement ps = conn.prepareStatement("select voter_id, public_key from voter_roll where public_key is not null");
         ResultSet rs = ps.executeQuery()) {
      while (rs.next()) {
        keys.put(rs.getString(1), rs.getString(2));
      }
    }

    long counted = 0;
    long rejected = 0;
    long rows = 0;
    StringBuilder rejections = new StringBuilder();
    Set<String> voted = new HashSet<>();

    try (PreparedStatement seals = conn.prepareStatement(
             "select ballot_id, voter_id, sum_proof, signature from ballot_seals where election_id = ? order by ballot_id");
         PreparedStatement options = conn.prepareStatement(
             "select candidate_id, vote_enc, bit_proof from blind_ballots where election_id = ? and ballot_id = ? order by candidate_id")) {
      seals.setLong(1, election);
      seals.setFetchSize(500);
      options.setLong(1, election);
      try (ResultSet seal = seals.executeQuery()) {
        while (seal.next()) {
          long ballot = seal.getLong(1);
          String voter = seal.getString(2);
          String sumProof = seal.getString(3);
          String signature = seal.getString(4);

          String[] enc = new String[3];
          String[] proof = new String[3];
          int found = 0;
          boolean shape = true;
          options.setLong(2, ballot);
          try (ResultSet option = options.executeQuery()) {
            while (option.next()) {
              int candidate = option.getInt(1);
              if (candidate < 1 || candidate > 3 || enc[candidate - 1] != null) {
                shape = false;
              } else {
                enc[candidate - 1] = option.getString(2);
                proof[candidate - 1] = option.getString(3);
              }
              found++;
            }
          }
          rows += found;

          String reason = null;
          String key = keys.get(voter);
          if (!shape || found != 3) {
            reason = "expected three ciphertext rows, found " + found;
          } else if (key == null) {
            reason = "the voter has no registered public key";
          } else if (voted.contains(voter)) {
            reason = "a second ballot of the same voter";
          } else {
            String verdict = BlindfoldValidity.verifyBallot(nHex, election, ballot, enc[0], enc[1], enc[2], proof[0], proof[1], proof[2], sumProof);
            if (verdict.equals("OK")) {
              verdict = BlindfoldValidity.verifySignature(key, signature, nHex, election, ballot, voter, enc[0], enc[1], enc[2], proof[0], proof[1], proof[2], sumProof);
            }
            if (!verdict.equals("OK")) {
              reason = verdict.startsWith("FAIL ") ? verdict.substring(5) : verdict;
            }
          }

          if (reason == null) {
            voted.add(voter);
            for (int i = 0; i < 3; i++) {
              // Homomorphic addition: Enc(a) * Enc(b) mod n^2 = Enc(a + b).
              totals.put(i + 1, totals.get(i + 1).multiply(new BigInteger(enc[i], 16)).mod(nSquared));
            }
            counted++;
          } else {
            if (rejected < LISTED) {
              if (rejected > 0) {
                rejections.append(',');
              }
              rejections.append("{\"ballot_id\":").append(ballot).append(",\"voter_id\":").append(quote(voter))
                  .append(",\"reason\":").append(quote(reason)).append('}');
            }
            rejected++;
          }
        }
      }
    }

    // Ciphertext rows that belong to no sealed ballot: nobody signed them.
    try (PreparedStatement ps = conn.prepareStatement(
             "select b.ballot_id, count(*) from blind_ballots b where b.election_id = ? and not exists "
             + "(select null from ballot_seals s where s.election_id = b.election_id and s.ballot_id = b.ballot_id) "
             + "group by b.ballot_id order by b.ballot_id")) {
      ps.setLong(1, election);
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          rows += rs.getLong(2);
          if (rejected < LISTED) {
            if (rejected > 0) {
              rejections.append(',');
            }
            rejections.append("{\"ballot_id\":").append(rs.getLong(1)).append(",\"voter_id\":null,\"reason\":")
                .append(quote("ciphertext rows with no voter and no signature")).append('}');
          }
          rejected++;
        }
      }
    }

    StringBuilder json = new StringBuilder(8192);
    json.append("{\"election_id\":").append(election)
        .append(",\"ballot_rows\":").append(rows)
        .append(",\"ballots_counted\":").append(counted)
        .append(",\"ballots_rejected\":").append(rejected)
        .append(",\"rejected\":[").append(rejections).append("]")
        .append(",\"totals\":[");
    boolean first = true;
    for (Map.Entry<Integer, BigInteger> entry : totals.entrySet()) {
      if (!first) {
        json.append(',');
      }
      first = false;
      json.append("{\"candidate_id\":").append(entry.getKey())
          .append(",\"total_enc\":\"").append(pad(entry.getValue().toString(16), width)).append("\"}");
    }
    return json.append("]}").toString();
  }
}
/

create or replace function bf_blind_tally return varchar2
as language java name 'BlindfoldTally.tally() return java.lang.String';
/

create or replace function bf_square_hex (p_n_hex in varchar2) return varchar2
as language java name 'BlindfoldTally.squareHex(java.lang.String) return java.lang.String';
/
