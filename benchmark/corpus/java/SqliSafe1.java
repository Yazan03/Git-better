// SAFE: PreparedStatement with bound parameter prevents SQL injection
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class SqliSafe1 {

    public static String findUser(String username) throws Exception {
        Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost/app", "root", "");
        PreparedStatement stmt = conn.prepareStatement(
                "SELECT email FROM users WHERE username = ?");
        stmt.setString(1, username);
        ResultSet rs = stmt.executeQuery();
        return rs.next() ? rs.getString("email") : null;
    }

    public static void main(String[] args) throws Exception {
        System.out.println(findUser(args[0]));
    }
}
