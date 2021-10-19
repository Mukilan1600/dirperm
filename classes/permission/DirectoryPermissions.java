package permission;

import java.util.*;

public class DirectoryPermissions{
    String folderName;
    int depth;
    List<PermissionEntry> permissionEntries;

    public DirectoryPermissions(String folderName, List<PermissionEntry> permissionEntries){
        this.folderName = folderName;
        this.permissionEntries = permissionEntries;
    }

    public DirectoryPermissions(String folderName, int depth){
        this.folderName = folderName;
        this.depth = depth;
    }

    public String getFolderName(){
        return folderName;
    }

    public int getDepth() {
        return depth;
    }

    public void setDepth(int depth) {
        this.depth = depth;
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