#include <iostream>
#include "permission_PermissionManager.h"
#include <windows.h>
#include <tchar.h>
#include "accctrl.h"
#include "aclapi.h"
#include "sddl.h"

typedef std::basic_string<TCHAR> tstring;

void _PrintLastError()
{
      DWORD dwErrorCode = 0;

      dwErrorCode = GetLastError();
      LPSTR error_message = nullptr;
      FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                     NULL, dwErrorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&error_message, 0, NULL);
      _tprintf(TEXT("Error: %s\n"), error_message);
}

void _GetSubDirectories(WIN32_FIND_DATA file, int depth, std::string fileName, JNIEnv *env, jobject obj_list, jmethodID mtd_list_add, jclass cls_dir_perm, jmethodID mtd_dir_perm_const)
{

      if ((file.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && _tcscmp(file.cFileName, TEXT(".")) && _tcscmp(file.cFileName, TEXT("..")))
      {
            WIN32_FIND_DATA ffd;
            std::string newFileNameS = fileName + "\\" + std::string(file.cFileName);
            env->CallBooleanMethod(obj_list, mtd_list_add, env->NewObject(cls_dir_perm, mtd_dir_perm_const, env->NewStringUTF(newFileNameS.c_str()), depth));
            std::string fname = newFileNameS + "\\*";
            HANDLE fh = FindFirstFile((LPCSTR)fname.c_str(), &ffd);

            do
            {
                  _GetSubDirectories(ffd, depth + 1, newFileNameS, env, obj_list, mtd_list_add, cls_dir_perm, mtd_dir_perm_const);
            } while (FindNextFile(fh, &ffd));

            FindClose(fh);
      }
}

JNIEXPORT jobject JNICALL Java_permission_PermissionManager_getSubDirectories(JNIEnv *env, jclass thisClass, jstring folderNameJ)
{
      const char *folderName = env->GetStringUTFChars(folderNameJ, NULL);
      jclass cls_list = env->FindClass("java/util/ArrayList");
      jmethodID mtd_list_const = env->GetMethodID(cls_list, "<init>", "()V");
      jmethodID mtd_list_add = env->GetMethodID(cls_list, "add", "(Ljava/lang/Object;)Z");
      jobject obj_list = env->NewObject(cls_list, mtd_list_const);

      jclass cls_dir_perm = env->FindClass("permission/DirectoryPermissions");
      jmethodID mtd_dir_perm_const = env->GetMethodID(cls_dir_perm, "<init>", "(Ljava/lang/String;I)V");

      WIN32_FIND_DATA ffd;
      std::string folderNameS = std::string(folderName);
      std::string folderNameReg = folderNameS + "\\*";
      HANDLE fh = FindFirstFile((LPCSTR)folderNameReg.c_str(), &ffd);

      do
      {
            _GetSubDirectories(ffd, 1, folderNameS, env, obj_list, mtd_list_add, cls_dir_perm, mtd_dir_perm_const);
      } while (FindNextFile(fh, &ffd));

      FindClose(fh);

      env->ReleaseStringUTFChars(folderNameJ, folderName);

      return obj_list;
}

JNIEXPORT jobject JNICALL Java_permission_PermissionManager_getDirectoryPermissions(JNIEnv *env, jclass thisObject, jstring fileNameJ)
{
      const char *fileName = env->GetStringUTFChars(fileNameJ, NULL);

      PACL dacl;
      PSECURITY_DESCRIPTOR sd;
      SID *pSid = NULL;
      BOOL rtn = TRUE;
      DWORD dw_name = 0, dw_domain = 0;
      LPTSTR name = NULL, domain = NULL;
      SID_NAME_USE eUse = SidTypeUnknown;
      ACCESS_ALLOWED_ACE *ace;
      long mask;

      rtn = GetNamedSecurityInfo((LPSTR)fileName, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &sd);
      if (rtn != ERROR_SUCCESS)
      {
            std::cout << rtn << std::endl;
            // _PrintLastError();
            return NULL;
      }

      jclass cls_access_type = env->FindClass("permission/PermissionEntry$AccessType");
      jfieldID fld_access_type_grant = env->GetStaticFieldID(cls_access_type, "GRANT", "Lpermission/PermissionEntry$AccessType;");
      jfieldID fld_access_type_deny = env->GetStaticFieldID(cls_access_type, "DENY", "Lpermission/PermissionEntry$AccessType;");
      jobject obj_acc_grant = env->GetStaticObjectField(cls_access_type, fld_access_type_grant);
      jobject obj_acc_deny = env->GetStaticObjectField(cls_access_type, fld_access_type_deny);

      jclass cls_sid_type = env->FindClass("permission/PermissionEntry$SIDType");
      jfieldID fld_sid_type_user = env->GetStaticFieldID(cls_sid_type, "USER", "Lpermission/PermissionEntry$SIDType;");
      jfieldID fld_sid_type_group = env->GetStaticFieldID(cls_sid_type, "GROUP", "Lpermission/PermissionEntry$SIDType;");
      jobject obj_sid_type_user = env->GetStaticObjectField(cls_sid_type, fld_sid_type_user);
      jobject obj_sid_type_group = env->GetStaticObjectField(cls_sid_type, fld_sid_type_group);

      jclass cls_permission_entry = env->FindClass("permission/PermissionEntry");
      jmethodID mtd_perm_ent_const = env->GetMethodID(cls_permission_entry, "<init>", "(Ljava/lang/String;Ljava/lang/String;Lpermission/PermissionEntry$SIDType;Lpermission/PermissionEntry$AccessType;ZZZZZ)V");

      jclass cls_list = env->FindClass("java/util/ArrayList");
      jmethodID mtd_list_const = env->GetMethodID(cls_list, "<init>", "()V");
      jmethodID mtd_list_add = env->GetMethodID(cls_list, "add", "(Ljava/lang/Object;)Z");
      jobject obj_list = env->NewObject(cls_list, mtd_list_const);
      jobject obj_permission_entry;
      jobject access_type;
      jobject sid_type;

      for (int i = 0; i < dacl->AceCount; i++)
      {
            dw_name = 0;
            dw_domain = 0;
            GetAce(dacl, i, (PVOID *)&ace);
            if (ace->Header.AceFlags & INHERIT_ONLY_ACE)
                  continue;
            if (ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE)
            {
                  access_type = obj_acc_grant;
                  pSid = (SID *)&((PACCESS_ALLOWED_ACE)ace)->SidStart;
                  mask = ((PACCESS_ALLOWED_ACE)ace)->Mask;
            }
            if (ace->Header.AceType == ACCESS_DENIED_ACE_TYPE)
            {
                  access_type = obj_acc_deny;
                  pSid = (SID *)&((PACCESS_DENIED_ACE)ace)->SidStart;
                  mask = ((PACCESS_DENIED_ACE)ace)->Mask;
            }
            rtn = LookupAccountSid(NULL, pSid, name, (LPDWORD)&dw_name, domain, (LPDWORD)&dw_domain, &eUse);
            name = (LPTSTR)GlobalAlloc(GMEM_FIXED, dw_name);
            if (name == NULL)
            {
                  std::cout << "name";
                  _PrintLastError();
                  return NULL;
            }
            domain = (LPTSTR)GlobalAlloc(GMEM_FIXED, dw_domain);
            if (domain == NULL)
            {
                  std::cout << "domain";
                  _PrintLastError();
                  return NULL;
            }
            rtn = LookupAccountSid(NULL, pSid, name, (LPDWORD)&dw_name, domain, (LPDWORD)&dw_domain, &eUse);
            if (rtn == FALSE)
            {
                  std::cout << "lookacc";
                  _PrintLastError();
                  return NULL;
            }

            switch (eUse)
            {
            case SidTypeUser:
                  sid_type = obj_sid_type_user;
                  break;
            default:
                  sid_type = obj_sid_type_group;
                  break;
            }

            obj_permission_entry = env->NewObject(cls_permission_entry,
                                                  mtd_perm_ent_const,
                                                  env->NewStringUTF((char *)name),
                                                  env->NewStringUTF((char *)domain),
                                                  sid_type,
                                                  access_type,
                                                  (mask & (FILE_ADD_FILE | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA)) == (FILE_ADD_FILE | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA),
                                                  (mask & (FILE_LIST_DIRECTORY | FILE_READ_EA | FILE_READ_ATTRIBUTES | READ_CONTROL)) == (FILE_LIST_DIRECTORY | FILE_READ_EA | FILE_READ_ATTRIBUTES | READ_CONTROL),
                                                  (mask & (FILE_LIST_DIRECTORY | FILE_READ_EA | FILE_READ_ATTRIBUTES | READ_CONTROL | FILE_TRAVERSE)) == (FILE_LIST_DIRECTORY | FILE_READ_EA | FILE_READ_ATTRIBUTES | READ_CONTROL | FILE_TRAVERSE),
                                                  (mask & DELETE) == DELETE,
                                                  (mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS);

            env->CallBooleanMethod(obj_list, mtd_list_add, obj_permission_entry);
      }

      env->ReleaseStringUTFChars(fileNameJ, fileName);
      if (name != NULL)
            name = (LPTSTR)GlobalFree(name);
      if (domain != NULL)
            domain = (LPTSTR)GlobalFree(domain);
      if (sd != NULL)
            sd = (PSECURITY_DESCRIPTOR)LocalFree(sd);

      return obj_list;
}

bool GetBooleanObjectField(JNIEnv *env, jobject obj, jclass cls, const char *name)
{
      jmethodID mtd_temp = env->GetMethodID(cls, name, "()Z");
      return env->CallBooleanMethod(obj, mtd_temp);
}

long MakeAccessMask(JNIEnv *env, jclass cls_perm, jobject obj)
{
      bool is_read = GetBooleanObjectField(env, obj, cls_perm, "getRead"),
           is_write = GetBooleanObjectField(env, obj, cls_perm, "getWrite"),
           is_exec = GetBooleanObjectField(env, obj, cls_perm, "getReadNExecute"),
           is_delete = GetBooleanObjectField(env, obj, cls_perm, "getDelete");
      long acc_mask = 0;
      if (is_exec)
      {
            acc_mask |= FILE_GENERIC_EXECUTE | FILE_GENERIC_READ;
      }
      if (is_read)
      {
            acc_mask |= FILE_GENERIC_READ;
      }
      if (is_write)
      {
            acc_mask |= FILE_GENERIC_WRITE;
      }
      if (is_delete)
      {
            acc_mask |= DELETE;
      }
      return acc_mask;
}

JNIEXPORT void JNICALL Java_permission_PermissionManager_setDirectoryPermissions(JNIEnv *env, jclass thisClass, jstring fileNameJ, jstring userNameJ, jobject obj_grnt_entry, jobject obj_deny_entry)
{

      const char *fileName = env->GetStringUTFChars(fileNameJ, NULL), *userName = env->GetStringUTFChars(userNameJ, NULL);

      PACL dacl, nacl;
      BOOL rtn = TRUE;
      PTRUSTEE user_trustee = (PTRUSTEE)GlobalAlloc(GMEM_FIXED, sizeof(TRUSTEE));

      rtn = GetNamedSecurityInfo((LPSTR)fileName, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, NULL);

      if (rtn != ERROR_SUCCESS)
      {
            _PrintLastError();
            return;
      }

      EXPLICIT_ACCESS exp_access;
      ZeroMemory(&exp_access, sizeof(EXPLICIT_ACCESS));
      jclass cls_perm_ent = env->GetObjectClass(obj_grnt_entry);

      jclass cls_access_type = env->FindClass("permission/PermissionEntry$AccessType");
      jfieldID fld_access_type_grant = env->GetStaticFieldID(cls_access_type, "GRANT", "Lpermission/PermissionEntry$AccessType;");
      jobject obj_acc_grant = env->GetStaticObjectField(cls_access_type, fld_access_type_grant);

      long grnt_acc_mask = MakeAccessMask(env, cls_perm_ent, obj_grnt_entry), deny_acc_mask = MakeAccessMask(env, cls_perm_ent, obj_deny_entry);

      // std::cout << "break" << std::endl;
      // BuildExplicitAccessWithName(&exp_access, (LPSTR)userName, grnt_acc_mask, REVOKE_ACCESS, SUB_CONTAINERS_AND_OBJECTS_INHERIT);
      // rtn = SetEntriesInAcl(1, &exp_access, dacl, &nacl);
      // if (rtn != ERROR_SUCCESS)
      // {
      //       _PrintLastError();
      //       return;
      // }

      BuildExplicitAccessWithName(&exp_access, (LPSTR)userName, grnt_acc_mask, GRANT_ACCESS, SUB_CONTAINERS_AND_OBJECTS_INHERIT);
      rtn = SetEntriesInAcl(1, &exp_access, dacl, &nacl);
      if (rtn != ERROR_SUCCESS)
      {
            _PrintLastError();
            return;
      }

      if (deny_acc_mask > 0)
      {
            BuildExplicitAccessWithName(&exp_access, (LPSTR)userName, deny_acc_mask, DENY_ACCESS, SUB_CONTAINERS_AND_OBJECTS_INHERIT);
            rtn = SetEntriesInAcl(1, &exp_access, dacl, &nacl);
            if (rtn != ERROR_SUCCESS)
            {
                  _PrintLastError();
                  return;
            }
      }

      rtn = SetNamedSecurityInfo((LPSTR)fileName, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, nacl, NULL);
      if (rtn != ERROR_SUCCESS)
      {
            _PrintLastError();
            return;
      }

      if (nacl != NULL)
            LocalFree((HLOCAL)nacl);
      if (user_trustee != NULL)
            GlobalFree(user_trustee);
}