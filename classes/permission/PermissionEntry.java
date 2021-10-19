package permission;

import java.io.Serializable;
import org.json.JSONObject;

public class PermissionEntry implements Serializable {

      public enum AccessType{
            GRANT(0),
            DENY(1);

            private final int accessTypeID;

            AccessType(int accessTypeID){
                  this.accessTypeID = accessTypeID;
            }

            public int getAccessTypeID(){
                  return this.accessTypeID;
            }
      }

      public enum SIDType{
            USER(0),
            GROUP(1);

            private final int SIDTypeID;

            SIDType(int SIDTypeID){
                  this.SIDTypeID = SIDTypeID;
            }

            public int getSIDTypeID() {
                  return SIDTypeID;
            }
      }

      private String userName;
      private AccessType accessType;
      private SIDType sidType;
      private boolean write, read, readNExecute, delete, fullControl;

      public PermissionEntry(){

      }

      public PermissionEntry(String userName, SIDType sidType, AccessType accessType, boolean write, boolean read, boolean readNExecute, boolean delete, boolean fullControl){
            this.userName = userName;
            this.sidType = sidType;
            this.accessType = accessType;
            this.write = write;
            this.read = read;
            this.readNExecute = readNExecute;
            this.delete = delete;
            this.fullControl = fullControl;
      }

      public PermissionEntry(String userName, String domainName, SIDType sidType, AccessType accessType, boolean write, boolean read, boolean readNExecute, boolean delete, boolean fullControl){
            this.userName = domainName + "/" + userName;
            this.sidType = sidType;
            this.accessType = accessType;
            this.write = write;
            this.read = read;
            this.readNExecute = readNExecute;
            this.delete = delete;
            this.fullControl = fullControl;
      }

      public PermissionEntry(JSONObject obj){
            this.userName = obj.getString("userName");
            this.accessType = AccessType.valueOf(obj.getString("accessType"));
            this.write = obj.getBoolean("write");
            this.read = obj.getBoolean("read");
            this.readNExecute = obj.getBoolean("readNExecute");
            this.delete = obj.getBoolean("delete");
            this.fullControl = obj.getBoolean("fullControl");
      }

      public String toString() {
            String str="";
            str+= "User name: " + userName + "\n";
            str+= "Access type: " + accessType.toString() + "\n";
            str+= "Write: " + write + "\n";
            str+= "Read: " + read + "\n";
            str+= "ReadNExecute: " + readNExecute + "\n";
            return str;
      }

      public boolean isFullControl() {
            return fullControl;
      }

      public void setFullControl(boolean fullControl) {
            this.fullControl = fullControl;
      }

      public String getUserName() {
            return userName;
      }

      public void setUserName(String userName) {
            this.userName = userName;
      }

      public AccessType getAccessType() {
            return accessType;
      }

      public void setAccessType(AccessType accessType) {
            this.accessType = accessType;
      }

      public SIDType getSidType() {
            return sidType;
      }

      public void setSidType(SIDType sidType) {
            this.sidType = sidType;
      }

      public boolean isWrite() {
            return write;
      }

      public void setWrite(boolean write) {
            this.write = write;
      }

      public boolean isRead() {
            return read;
      }

      public void setRead(boolean read) {
            this.read = read;
      }

      public boolean isReadNExecute() {
            return readNExecute;
      }

      public void setReadNExecute(boolean readNExecute) {
            this.readNExecute = readNExecute;
      }

      public boolean isDelete() {
            return delete;
      }

      public void setDelete(boolean delete) {
            this.delete = delete;
      }
}
