package permission;

import java.util.*;

public class DirectoryPermissions{
    private String folderName;
    private List<PermissionEntry> permissionEntries;

    public DirectoryPermissions(String folderName, List<PermissionEntry> permissionEntries){
        this.folderName = folderName;
        this.permissionEntries = permissionEntries;
    }

    public String getFolderName(){
        return folderName;
    }

    public List<PermissionEntry> getPermissionEntries(){
        return permissionEntries;
    }

    public void setFolderName(String folderName){
        this.folderName = folderName;
    }

    public void setPermissionEntries(List<PermissionEntry> permissionEntries){
        this.permissionEntries = permissionEntries;
    }
}