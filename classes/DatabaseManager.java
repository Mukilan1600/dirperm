import permission.DirectoryPermissions;
import permission.PermissionEntry;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class DatabaseManager {
    public static Connection getConnection() throws SQLException {
        String dbURL = "jdbc:mysql:// localhost:3306/", dbName = "DirPerm";
        String dbUsername = "root";
        String dbPassword = "";
        return DriverManager.getConnection(dbURL+dbName, dbUsername, dbPassword);
    }

    public static List<String> getDirectoriesAtDepth(int depth){
        List<String> directories = new ArrayList<>();
        String query = "SELECT DISTINCT(folder_name) FROM permissions WHERE depth=?";
        try(Connection conn = getConnection();PreparedStatement statement = conn.prepareStatement(query)) {
            statement.setInt(1,depth);
            try(ResultSet res = statement.executeQuery()) {
                while(res.next()){
                    directories.add(res.getString("folder_name"));
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return directories;
    }

    public static List<DirectoryPermissions> getDirectoryPermissions(List<String> directories){
        List<DirectoryPermissions> directoryPermissions = new ArrayList<>();
        String query = "SELECT object_name, sid_type, access_type, can_write, can_read, can_read_execute, can_delete, full_control FROM permissions p JOIN accessTypes a ON a.access_type_id=p.access_type_id JOIN sidTypes s ON s.sid_type_id=p.sid_type_id WHERE folder_name=?";
        List<PermissionEntry> permissionEntries;
        try(Connection conn = getConnection();PreparedStatement statement = conn.prepareStatement(query)){
            for(String directory: directories){
                permissionEntries = new ArrayList<>();
                statement.setString(1, directory);
                try(ResultSet rs = statement.executeQuery()) {
                    while (rs.next()) {
                        String objectName = rs.getString("object_name");
                        PermissionEntry.AccessType accessType = PermissionEntry.AccessType.valueOf(rs.getString("access_type"));
                        PermissionEntry.SIDType sidType = PermissionEntry.SIDType.valueOf(rs.getString("sid_type"));
                        boolean write = rs.getBoolean("can_write"), read = rs.getBoolean("can_read"), readnexec = rs.getBoolean("can_read_execute"), delete = rs.getBoolean("can_delete"), fullControl = rs.getBoolean("full_control");
                        permissionEntries.add(new PermissionEntry(objectName, sidType, accessType, write, read, readnexec, delete, fullControl));

                    }
                }
                directoryPermissions.add(new DirectoryPermissions(directory, permissionEntries));
            }
        }catch (SQLException e){
            e.printStackTrace();
        }
        return directoryPermissions;
    }
}
