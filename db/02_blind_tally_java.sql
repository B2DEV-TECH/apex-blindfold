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

create or replace and compile java source named "BlindfoldTally" as
import java.math.BigInteger;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Map;
import java.util.TreeMap;

public class BlindfoldTally {

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

  // Returns JSON: the number of ciphertext rows read and, for each candidate,
  // the product of its ciphertexts modulo n^2 (an encrypted total).
  public static String tally() throws SQLException {
    // Server-side internal connection: the session that called this method.
    // (No apostrophes in these comments: SQLcl would read one as an open string.)
    Connection conn = DriverManager.getConnection("jdbc:default:connection:");

    BigInteger nSquared;
    try (PreparedStatement ps = conn.prepareStatement("select n_hex from election_key");
         ResultSet rs = ps.executeQuery()) {
      if (!rs.next()) {
        throw new SQLException("No public key has been published.");
      }
      nSquared = new BigInteger(rs.getString(1), 16).pow(2);
    }
    int width = (nSquared.bitLength() + 3) / 4;

    // Every candidate starts at 1, which is a trivial encryption of zero.
    Map<Integer, BigInteger> totals = new TreeMap<>();
    try (PreparedStatement ps = conn.prepareStatement("select candidate_id from candidates order by candidate_id");
         ResultSet rs = ps.executeQuery()) {
      while (rs.next()) {
        totals.put(rs.getInt(1), BigInteger.ONE);
      }
    }

    long rows = 0;
    try (PreparedStatement ps = conn.prepareStatement("select candidate_id, vote_enc from blind_ballots")) {
      ps.setFetchSize(1000);
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          int candidate = rs.getInt(1);
          BigInteger ciphertext = new BigInteger(rs.getString(2), 16);
          // Homomorphic addition: Enc(a) * Enc(b) mod n^2 = Enc(a + b).
          totals.put(candidate, totals.get(candidate).multiply(ciphertext).mod(nSquared));
          rows++;
        }
      }
    }

    StringBuilder json = new StringBuilder(4096);
    json.append("{\"ballot_rows\":").append(rows).append(",\"totals\":[");
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
