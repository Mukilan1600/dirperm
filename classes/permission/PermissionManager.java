package permission;
import java.util.*;

public class PermissionManager {
      static{
            System.loadLibrary(("native"));
      }

      public static void main(String[] args){
//            setDirectoryPermissions("D:\\apache-tomcat-8.5.71\\webapps\\dirperm\\WEB-INF\\classes\\asd","MUKIL-PT4388\\temp", new PermissionEntry("MUKIL-PT4388/temp", PermissionEntry.SIDType.USER, PermissionEntry.AccessType.GRANT, true, true, false, false, false),new PermissionEntry("MUKIL-PT4388/temp", PermissionEntry.SIDType.USER, PermissionEntry.AccessType.DENY, false, false, false, false, false), true);
            List<DirectoryPermissions> dirs =  getDirectoryPermissionsAtDepth("D:\\apache-tomcat-8.5.71\\webapps\\dirperm\\WEB-INF\\classes\\asd", 1);
//            for(DirectoryPermissions dir: dirs)
//                  System.out.println(dir.getPermissionEntries().size());
      }

      public static native List<DirectoryPermissions> getDirectoryPermissionsAtDepth(String folderName, int depth);
      public static native void setDirectoryPermissions(String fileName, String userName, PermissionEntry grantEntry, PermissionEntry denyEntry, boolean replace);
}
