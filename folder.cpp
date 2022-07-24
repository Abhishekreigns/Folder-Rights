#include <iostream>
#include <Windows.h>
#include <aclapi.h>
#include <vector>
#include "com_reigns_FolderJNI.h"
using namespace std;

vector<ACCESS_ALLOWED_ACE*> pDaclAces;

//Showing the list of permissions allowed or denied for each user or group
void showEntries(ACCESS_ALLOWED_ACE* ace) {

	


	if (GENERIC_ALL & ace->Mask) {
		wcout << "FULL CONTROL" << "\n";
	}
	if (FILE_READ_ACCESS & ace->Mask) {
		cout << "READ" << "\n";

	}
	if (FILE_LIST_DIRECTORY & ace->Mask && FILE_READ_ACCESS & ace->Mask && FILE_TRAVERSE & ace->Mask) {
		cout <<"LIST FOLDER CONTENTS" << "\n";
	}
	if (FILE_LIST_DIRECTORY & ace->Mask && FILE_READ_ACCESS & ace->Mask
		&& FILE_TRAVERSE & ace->Mask && FILE_ADD_FILE & ace->Mask) {
		cout << "MODIFY" << "\n";
	}
	if ( FILE_ADD_FILE & ace->Mask) {
		cout <<"WRITE " << "\n";
	}
	
	if (FILE_TRAVERSE & ace->Mask && FILE_READ_ACCESS & ace->Mask ) {
		cout <<"READ & EXECUTE " <<"\n";
		
	}
	if (DELETE & ace->Mask) {
		cout <<"DELETE " << "\n";
	}
	
}

BOOL directoryExists(string directory) {
	
	DWORD path = GetFileAttributes(directory.c_str());
	//Checking if the path is valid
	if (path == INVALID_FILE_ATTRIBUTES || GetLastError() == ERROR_PATH_NOT_FOUND) {
		wcout << "\nDirectory doesn't exist!";
		return false;
	}
	//Checking if the valid path is a directory rather than a file.
	if (!(path & FILE_ATTRIBUTE_DIRECTORY)) {
		cout << "\nThis is not a directory!";
		return false;
	}
	return true;
}
void showFolderRights(string dir) {

	LPCSTR dirPath = dir.c_str();
	PSID pSidOwner, pSidGroup;
	PACL pDacl;
	PSECURITY_DESCRIPTOR pSd;
	//Checking if the directory exists
	/*if (CreateFile(dirPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL) == INVALID_HANDLE_VALUE)
	{
		cout << "\nFile or directory doesn't exist";
		cout << "\nExiting...";
		return;
	}*/

	//Getting DACL and security descriptor of the file/directory, a DACL contains individual ACEs
	if (GetNamedSecurityInfo(dirPath,
		SE_FILE_OBJECT,
		OWNER_SECURITY_INFORMATION |
		DACL_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION,
		&pSidOwner,
		&pSidGroup,
		&pDacl,
		NULL,
		&pSd
	) != ERROR_SUCCESS) {
		cout << "\nError retreiving NamedSecurity info, see code: " << GetLastError();
		cout << "\nExiting...";
		return;
	}

	//Getting ACE details from pointer to DACL(pDacl), an ACE contains each allowed and denied permission
	//to a user or group.
	LPTSTR oname ;
	DWORD namelen;
	LPTSTR doname;
	DWORD domainnamelen;
	SID_NAME_USE peUse;
	ACCESS_ALLOWED_ACE* ace;
	cout << "ACE Count: " << (*pDacl).AceCount << "\n";
	SID* sid;
	
	unsigned long i, mask;
	char* stringsid;
	for (int i = 0; i < (*pDacl).AceCount; i++) {
		
		//Getting Individual ACE from DACL
		BOOL b = GetAce(pDacl, i, (PVOID*)&ace);
		if (((ACCESS_ALLOWED_ACE*)ace)->Header.AceType == ACCESS_ALLOWED_ACE_TYPE)
		{
			sid = (SID*)&((ACCESS_ALLOWED_ACE*)ace)->SidStart;

			//Getting buffer lengths of account name and domain name using lookupaccountSid
			LookupAccountSid(NULL, sid, oname, (LPDWORD)&namelen, doname, (LPDWORD)&domainnamelen, &peUse);
			//Getting the account name and domain name using the lengths received earlier
			LookupAccountSid(NULL, sid, oname, &namelen, doname, &domainnamelen, &peUse);


			//Displaying the names 
			cout << " SID: "<< doname << " / " << oname << "\n  ";
			wcout << "    \nALLOWED ACCESS  to the Following: \n ";
			mask = ((ACCESS_ALLOWED_ACE*)ace)->Mask;
			pDaclAces.push_back(ace);
			//Showing the list of permissions allowed to the acctname
			showEntries(pDaclAces[i]);
			
		}

		else if (((ACCESS_DENIED_ACE*)ace)->Header.AceType == ACCESS_DENIED_ACE_TYPE) {
			sid = (SID*)&((ACCESS_DENIED_ACE*)ace)->SidStart;

			//Getting buffer lengths of account name and domain name using lookupaccountSid
			LookupAccountSid(NULL, sid, oname, (LPDWORD)&namelen, doname, (LPDWORD)&domainnamelen, &peUse);
			//Getting the account name and domain name using the lengths received earlier
			LookupAccountSid(NULL, sid, oname, &namelen, doname, &domainnamelen, &peUse);

			//Displaying the names 
			wcout << "SID: "<< doname << "/" << oname << "\n";
			wcout << "     \nDENIED ACCESS  to the Following: \n  ";
			mask = ((ACCESS_DENIED_ACE*)ace)->Mask;
			pDaclAces.push_back(ace);
			//Showing the list of permissions denied to the acctname
			showEntries(pDaclAces[i]);
		}
		else printf("Other ACE\n");


		/*wcout << "ACE: mask:" << ace->Mask << " \n sidStart:"
			<< ace->SidStart << "\n header type="
			<< ace->Header.AceType << " \nheader flags=" 
			<< ace->Header.AceFlags << "\n";*/
		wcout << "\n";
	}


	

}
void changePermissions(string dir) {

	LPCSTR dirPath = dir.c_str();
	PSID pSidOwner, pSidGroup;
	PACL pDacl,pUpdatedDacl;
	PSECURITY_DESCRIPTOR pSd;
	EXPLICIT_ACCESS ea;
	
	if (GetNamedSecurityInfo(dirPath,
		SE_FILE_OBJECT,
		DACL_SECURITY_INFORMATION,
		&pSidOwner,
		&pSidGroup,
		&pDacl,
		NULL,
		&pSd
	) != ERROR_SUCCESS) {
		wcout << "Error retreiving the security info in modifying rights, see code:" << GetLastError();
		LocalFree(pSd);
		return;
	}
	else {
		wcout << "\nSetting Permission...";
	}
	LPTSTR name = (LPTSTR)"Anonymous logon";
	ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
	ea.grfAccessMode = GRANT_ACCESS;
	ea.grfAccessPermissions =  GENERIC_ALL;
	ea.grfInheritance = CONTAINER_INHERIT_ACE | SUB_CONTAINERS_ONLY_INHERIT| SUB_CONTAINERS_AND_OBJECTS_INHERIT;
	ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
	ea.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
	ea.Trustee.ptstrName = name;

	DWORD dwRes=SetEntriesInAcl(1, &ea, pDacl, &pUpdatedDacl);
	if (ERROR_SUCCESS != dwRes) {
		printf("SetEntriesInAcl Error %u\n", dwRes);
		return;
	}

	if (SetNamedSecurityInfo((LPSTR)dirPath,
		SE_FILE_OBJECT,
		DACL_SECURITY_INFORMATION,
		NULL,
		NULL,
		pUpdatedDacl,
		NULL) != ERROR_SUCCESS) {

		wcout << "\nSetting error:, see code" << GetLastError();
		return;
	}

	wcout << "\nDone setting up the permissions!!";



}

JNIEXPORT void JNICALL Java_com_reigns_FolderJNI_showFolderRights
(JNIEnv *env, jobject obj, jstring directory)
{

	const char* dir = env->GetStringUTFChars(directory, 0);
	
	if (!directoryExists(dir)) return;
	showFolderRights(dir);
	//changePermissions(dir);
	//showFolderRights(dir);
   

	env->ReleaseStringUTFChars(directory, dir);

}
