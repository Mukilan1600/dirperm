import org.json.JSONException;
import org.json.JSONObject;
import permission.DirectoryPermissions;
import permission.PermissionEntry;
import permission.PermissionManager;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.crypto.Data;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

public class UpdatePermissionDB extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");

        BufferedReader reader = req.getReader();
        StringBuilder reqStr = new StringBuilder();
        PrintWriter out = resp.getWriter();
        String line;
        int maxDepth=0;
//
//        while((line=reader.readLine())!=null)
//                reqStr.append(line);
//        JSONObject reqJSON = new JSONObject(reqStr.toString());
//        String folderName = reqJSON.getString("folder_name");
//        List<DirectoryPermissions> directoryPermissions = PermissionManager.getPermissions(folderName);
//        String query = "INSERT INTO permissions(folder_name, depth, object_name, sid_type_id, access_type_id, can_write, can_read, can_read_execute, can_delete, full_control) values (?,?,?,?,?,?,?,?,?,?)";
//        try (Connection conn = DatabaseManager.getConnection();PreparedStatement statement = conn.prepareStatement(query)){
//            Statement connStatement = conn.createStatement();
//            connStatement.executeUpdate("truncate permissions");
//            for(DirectoryPermissions permissions: directoryPermissions){
//                maxDepth = Math.max(maxDepth, permissions.getDepth());
//                for(PermissionEntry  permissionEntry: permissions.getPermissionEntries()) {
//                    statement.setString(1, permissions.getFolderName());
//                    statement.setInt(2, permissions.getDepth());
//                    statement.setString(3, permissionEntry.getUserName());
//                    statement.setInt(4, permissionEntry.getSidType().getSIDTypeID());
//                    statement.setInt(5, permissionEntry.getAccessType().getAccessTypeID());
//                    statement.setBoolean(6, permissionEntry.isWrite());
//                    statement.setBoolean(7, permissionEntry.isRead());
//                    statement.setBoolean(8, permissionEntry.isReadNExecute());
//                    statement.setBoolean(9, permissionEntry.isDelete());
//                    statement.setBoolean(10, permissionEntry.isFullControl());
//                    statement.executeUpdate();
//                }
//            }
//
//        } catch (SQLException e) {
//            System.out.println(e.getMessage());
//        }

        JSONObject respJSON = new JSONObject();
        respJSON.put("msg","Permissions added to database");
        respJSON.put("max_depth",maxDepth);
        out.write(respJSON.toString());
        out.flush();

    }
}
