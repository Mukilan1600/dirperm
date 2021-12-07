#include <iostream>
#include "permission_PermissionManager.h"
#include <windows.h>
#include <tchar.h>
#include "accctrl.h"
#include "aclapi.h"
#include "sddl.h"

void _PrintLastError(DWORD dwErrorCode)
{
      LPSTR error_message = nullptr;
      FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                     NULL, dwErrorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&error_message, 0, NULL);
      _tprintf(TEXT("Error: %s\n"), error_message);
}

void _PrintLastError()
{
      DWORD dwErrorCode = 0;

      dwErrorCode = GetLastError();
      LPSTR error_message = nullptr;
      FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                     NULL, dwErrorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&error_message, 0, NULL);
      _tprintf(TEXT("Error: %s\n"), error_message);
}

jobject _getDirectoryPermissions(JNIEnv *env, jstring fileNameJ)
{
      const char *fileName = env->GetStringUTFChars(fileNameJ, NULL);
      // wchar_t wtext[200];
      // mbstowcs(wtext, fileName, strlen(fileName)+1);
      // LPWSTR fileNameT = wtext;

      PACL dacl;
      PSECURITY_DESCRIPTOR sd;
      PINHERITED_FROMW ifrom;
      SID *pSid = NULL;
      BOOL rtn = TRUE;
      DWORD dw_name = 0, dw_domain = 0;
      LPTSTR name = NULL, domain = NULL;
      SID_NAME_USE eUse = SidTypeUnknown;
      ACCESS_ALLOWED_ACE *ace;

      GENERIC_MAPPING g_ObjMap = {
          FILE_GENERIC_READ,
          FILE_GENERIC_WRITE,
          FILE_GENERIC_EXECUTE,
          FILE_ALL_ACCESS};

      long mask;

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

      rtn = GetNamedSecurityInfo((LPSTR)fileName, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &sd);
      if (rtn != ERROR_SUCCESS)
      {
            _PrintLastError();
            obj_list = NULL;
            goto Cleanup;
      }

      ifrom = (PINHERITED_FROMW)LocalAlloc(LPTR, (1 + dacl->AceCount) * sizeof(INHERITED_FROM));
      if (ifrom == NULL)
      {
            std::cout << "ifrom alloc" << std::endl;
            _PrintLastError();
            obj_list = NULL;
            goto Cleanup;
      }

      // rtn = GetInheritanceSourceW(fileNameT, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, TRUE, NULL, 0, dacl, NULL, &g_ObjMap, ifrom);
      // if (rtn != ERROR_SUCCESS)
      // {
      //       std::cout << rtn << std::endl;
      //       _PrintLastError(rtn);
      //       obj_list = NULL;
      //       goto Cleanup;
      // }

      for (int i = 0; i < dacl->AceCount; i++)
      {
            dw_name = 0;
            dw_domain = 0;
            GetAce(dacl, i, (PVOID *)&ace);
            // printf("%s %ls \n", fileName, ifrom[i].AncestorName);
            // std::cout << fileName << " " << ifrom[i].AncestorName << std::endl;
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
                  obj_list = NULL;
                  goto Cleanup;
            }
            domain = (LPTSTR)GlobalAlloc(GMEM_FIXED, dw_domain);
            if (domain == NULL)
            {
                  std::cout << "domain";
                  _PrintLastError();
                  obj_list = NULL;
                  goto Cleanup;
            }
            rtn = LookupAccountSid(NULL, pSid, name, (LPDWORD)&dw_name, domain, (LPDWORD)&dw_domain, &eUse);
            if (rtn == FALSE)
            {
                  std::cout << "lookacc";
                  _PrintLastError();
                  obj_list = NULL;
                  goto Cleanup;
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

Cleanup:
      env->ReleaseStringUTFChars(fileNameJ, fileName);
      if (name != NULL)
            GlobalFree(name);
      if (domain != NULL)
            GlobalFree(domain);
      if (sd != NULL)
            LocalFree(sd);

      return obj_list;
}

void _GetSubDirectoriesAtDepth(WIN32_FIND_DATA file, int depth, std::string fileName, JNIEnv *env, jobject obj_list, jmethodID mtd_list_add, jclass cls_dir_perm, jmethodID mtd_dir_perm_const)
{

      if ((file.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && _tcscmp(file.cFileName, TEXT(".")) && _tcscmp(file.cFileName, TEXT("..")))
      {
            WIN32_FIND_DATA ffd;
            std::string newFileNameS = fileName + "\\" + std::string(file.cFileName);
            jstring newFileNameJ = env->NewStringUTF(newFileNameS.c_str());
            if (depth == 0)
            {
                  jobject permissions = _getDirectoryPermissions(env, newFileNameJ);
                  if (permissions != NULL)
                        env->CallBooleanMethod(obj_list, mtd_list_add, env->NewObject(cls_dir_perm, mtd_dir_perm_const, newFileNameJ, permissions));
            }
            else if (depth > 0)
            {
                  std::string fname = newFileNameS + "\\*";
                  HANDLE fh = FindFirstFile((LPCSTR)fname.c_str(), &ffd);

                  do
                  {
                        _GetSubDirectoriesAtDepth(ffd, depth - 1, newFileNameS, env, obj_list, mtd_list_add, cls_dir_perm, mtd_dir_perm_const);
                  } while (FindNextFile(fh, &ffd));

                  FindClose(fh);
            }
            env->DeleteLocalRef(newFileNameJ);
      }
}

JNIEXPORT jobject JNICALL Java_permission_PermissionManager_getDirectoryPermissionsAtDepth(JNIEnv *env, jclass thisClass, jstring folderNameJ, jint depth)
{
      const char *folderName = env->GetStringUTFChars(folderNameJ, NULL);
      jclass cls_list = env->FindClass("java/util/ArrayList");
      jmethodID mtd_list_const = env->GetMethodID(cls_list, "<init>", "()V");
      jmethodID mtd_list_add = env->GetMethodID(cls_list, "add", "(Ljava/lang/Object;)Z");
      jobject obj_list = env->NewObject(cls_list, mtd_list_const);

      jclass cls_dir_perm = env->FindClass("permission/DirectoryPermissions");
      jmethodID mtd_dir_perm_const = env->GetMethodID(cls_dir_perm, "<init>", "(Ljava/lang/String;Ljava/util/List;)V");
      if (depth == 0)
      {
            env->CallBooleanMethod(obj_list, mtd_list_add, env->NewObject(cls_dir_perm, mtd_dir_perm_const, folderNameJ, _getDirectoryPermissions(env, folderNameJ)));
      }
      else
      {
            WIN32_FIND_DATA ffd;
            std::string folderNameS = std::string(folderName);
            std::string folderNameReg = folderNameS + "\\*";
            HANDLE fh = FindFirstFile((LPCSTR)folderNameReg.c_str(), &ffd);

            do
            {
                  _GetSubDirectoriesAtDepth(ffd, depth - 1, folderNameS, env, obj_list, mtd_list_add, cls_dir_perm, mtd_dir_perm_const);
            } while (FindNextFile(fh, &ffd));

            FindClose(fh);
      }

      env->ReleaseStringUTFChars(folderNameJ, folderName);
      return obj_list;
}

bool GetBooleanObjectField(JNIEnv *env, jobject obj, jclass cls, const char *name)
{
      jmethodID mtd_temp = env->GetMethodID(cls, name, "()Z");
      return env->CallBooleanMethod(obj, mtd_temp);
}

long MakeAccessMask(JNIEnv *env, jclass cls_perm, jobject obj)
{
      bool is_read = GetBooleanObjectField(env, obj, cls_perm, "isRead"),
           is_write = GetBooleanObjectField(env, obj, cls_perm, "isWrite"),
           is_exec = GetBooleanObjectField(env, obj, cls_perm, "isReadNExecute"),
           is_delete = GetBooleanObjectField(env, obj, cls_perm, "isDelete"),
           is_full_control = GetBooleanObjectField(env, obj, cls_perm, "isFullControl");
      ;
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
      if (is_full_control)
      {
            acc_mask |= FILE_ALL_ACCESS;
      }
      return acc_mask;
}

JNIEXPORT void JNICALL Java_permission_PermissionManager_setDirectoryPermissions(JNIEnv *env, jclass thisClass, jstring fileNameJ, jstring userNameJ, jobject obj_grant_entry, jobject obj_deny_entry, jboolean replace)
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
      jclass cls_perm_ent = env->GetObjectClass(obj_grant_entry);

      // jclass cls_access_type = env->FindClass("permission/PermissionEntry$AccessType");
      // jfieldID fld_access_type_grant = env->GetStaticFieldID(cls_access_type, "GRANT", "Lpermission/PermissionEntry$AccessType;");
      // jobject obj_acc_grant = env->GetStaticObjectField(cls_access_type, fld_access_type_grant);
      long grnt_acc_mask = MakeAccessMask(env, cls_perm_ent, obj_grant_entry), deny_acc_mask = MakeAccessMask(env, cls_perm_ent, obj_deny_entry);

      BuildExplicitAccessWithName(&exp_access, (LPSTR)userName, grnt_acc_mask, replace ? SET_ACCESS : GRANT_ACCESS, SUB_CONTAINERS_AND_OBJECTS_INHERIT);
      rtn = SetEntriesInAcl(1, &exp_access, dacl, &nacl);
      if (rtn != ERROR_SUCCESS)
      {
            _PrintLastError();
            return;
      }

      BuildExplicitAccessWithName(&exp_access, (LPSTR)userName, deny_acc_mask, DENY_ACCESS, SUB_CONTAINERS_AND_OBJECTS_INHERIT);
      rtn = SetEntriesInAcl(1, &exp_access, nacl, &dacl);
      if (rtn != ERROR_SUCCESS)
      {
            _PrintLastError();
            return;
      }

      rtn = SetNamedSecurityInfo((LPSTR)fileName, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, dacl, NULL);
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