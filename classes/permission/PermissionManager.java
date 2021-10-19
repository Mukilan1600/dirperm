package permission;
import java.util.*;

public class PermissionManager {
      static{
            System.loadLibrary(("native"));
      }

      public static void main(String[] args){
            getPermissions("D:\\apache-tomcat-8.5.71\\webapps\\dirperm\\WEB-INF\\classes\\asd");
      }

      public static List<DirectoryPermissions> getPermissions(String folderName){
            List<DirectoryPermissions> permissions = new ArrayList<>();
            permissions.add(new DirectoryPermissions(folderName, 0));
            permissions.addAll(getSubDirectories(folderName));
            List<PermissionEntry> directoryPermissions;
            for(DirectoryPermissions directory: permissions){
                  directoryPermissions = getDirectoryPermissions(directory.folderName);
                  if(directoryPermissions!=null)
                        directory.setPermissionEntries(directoryPermissions);
                  else
                        directory.setPermissionEntries(new ArrayList<>());
            }
            return permissions;
      }

      public static native List<DirectoryPermissions> getSubDirectories(String folderName);
      public static native List<PermissionEntry> getDirectoryPermissions(String fileName);
      public static native void setDirectoryPermissions(String fileName, String userName, PermissionEntry grantEntry, PermissionEntry denyEntry);
}
