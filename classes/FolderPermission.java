import java.sql.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import com.fasterxml.jackson.databind.ObjectMapper;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.fasterxml.jackson.module.afterburner.AfterburnerModule;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import permission.DirectoryPermissions;
import permission.PermissionEntry;
import permission.PermissionManager;

public class FolderPermission extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)throws IOException
    {
        int depth = Integer.parseInt(request.getParameter("depth"));
        String folderName = request.getParameter("folder_name");
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        PrintWriter out = response.getWriter();

        List<DirectoryPermissions> directories =  PermissionManager.getDirectoryPermissionsAtDepth(folderName, depth);
        String query = "INSERT INTO permissions(folder_name, object_name, sid_type_id, access_type_id, can_write, can_read, can_read_execute, can_delete, full_control) values (?,?,?,?,?,?,?,?,?)";
        try(Connection conn = DatabaseManager.getConnection()){
            boolean autoCommit = conn.getAutoCommit();
            conn.setAutoCommit(false);
            try(PreparedStatement statement = conn.prepareStatement(query);Statement connStatement = conn.createStatement()) {
                int batchLimit = 100;
                connStatement.executeUpdate("truncate permissions");
                for (DirectoryPermissions directoryPermissions : directories) {
                    for (PermissionEntry permissionEntry : directoryPermissions.getPermissionEntries()) {
                        statement.setString(1, directoryPermissions.getFolderName());
                        statement.setString(2, permissionEntry.getUserName());
                        statement.setInt(3, permissionEntry.getSidType().getSIDTypeID());
                        statement.setInt(4, permissionEntry.getAccessType().getAccessTypeID());
                        statement.setBoolean(5, permissionEntry.isWrite());
                        statement.setBoolean(6, permissionEntry.isRead());
                        statement.setBoolean(7, permissionEntry.isReadNExecute());
                        statement.setBoolean(8, permissionEntry.isDelete());
                        statement.setBoolean(9, permissionEntry.isFullControl());
                        statement.addBatch();
                        batchLimit--;
                        if (batchLimit == 0) {
                            batchLimit = 100;
                            statement.executeBatch();
                            statement.clearBatch();
                        }
                    }
                }
                statement.executeBatch();
            }finally {
                conn.commit();
                conn.setAutoCommit(autoCommit);
            }
        }catch (SQLException e){
            e.printStackTrace();
        }
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModule(new AfterburnerModule());
        out.print(objectMapper.writeValueAsString(directories));
        out.flush();
    }

    @Override
    public void doPost(HttpServletRequest request,HttpServletResponse response)throws IOException, ServletException
    {
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        PrintWriter out = response.getWriter();
        StringBuilder reqStr = new StringBuilder();
        String line = null;
        BufferedReader reader = request.getReader();
        while((line=reader.readLine())!=null){
            reqStr.append(line);
        }
        try{
            JSONObject reqObj = new JSONObject(reqStr.toString());
            PermissionEntry grantEntry = new PermissionEntry(reqObj.getJSONArray("entries").getJSONObject(0)),
                                denyEntry =  new PermissionEntry(reqObj.getJSONArray("entries").getJSONObject(1));
            PermissionManager.setDirectoryPermissions(reqObj.getString("folderName"),denyEntry.getUserName(),grantEntry,denyEntry);
            out.write(reqObj.getString("folderName"));
            out.flush();
        }catch(JSONException e){
            response.setStatus(400);
            out.println("{"+"\""+"err"+"\""+":\""+e.getMessage()+"\"}");
            out.flush();
        }
    }

}

