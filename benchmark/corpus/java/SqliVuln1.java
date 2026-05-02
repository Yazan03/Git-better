// VULN: CWE-89 — SQL injection via Statement.executeQuery() with concatenation
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

public class SqliVuln1 {

    public static String findUser(String username) throws Exception {
        Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost/app", "root", "");
        Statement stmt = conn.createStatement();
        String query = "SELECT email FROM users WHERE username = '" + username + "'";
        ResultSet rs = stmt.executeQuery(query);
        return rs.next() ? rs.getString("email") : null;
    }

    public static void main(String[] args) throws Exception {
        System.out.println(findUser(args[0]));
    }
}
