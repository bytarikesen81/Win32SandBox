#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

BOOL CALLBACK scanner(HMODULE hModule, LPCSTR lpType, LPSTR lpName, LONG_PTR lParam){
	DWORD resSize;
	CHAR* resFileName;
	HANDLE hFile;
	HGLOBAL rcData;
	HRSRC hRc;
	
	//1- Find the resource by its name
	hRc = FindResourceA(hModule, lpName, lpType);
	if (hRc == NULL) {
		printf("\nUnable to find the data of the resource named %s. Windows system error code: %d", lpName, GetLastError());
		return FALSE;
	}
	
	//2- Load the resource
	rcData = LoadResource(hModule, hRc);
	if (rcData == NULL) {
		printf("\nUnable to load the resource named %s. Windows system error code: %d", lpName, GetLastError());
		CloseHandle(hRc);
		return FALSE;
	}

	//3- Estimate size of the resource
	resSize = SizeofResource(hModule, hRc);
	if (rcData == 0) {
		printf("\nFailed to calculate byte size of the resource named %s. Windows system error code: %d", lpName, GetLastError());
		FreeResource(rcData);
		CloseHandle(hRc);
		return FALSE;
	}

	//4- Analyze file structure
	resFileName = (CHAR*)malloc(sizeof(CHAR) * (strlen(lpName) + 5));
	sprintf(resFileName, "%s.bin", lpName);

	//5- Create file object for the target resource in which resource data will be located
	hFile = CreateFile(resFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	
	//6- Start file output stream
	WriteFile(hFile, rcData, resSize, NULL, NULL);

	//7- Notice the user by visualising a prompt
	printf("\n Res saved: %s", resFileName);
	
	//8- Release handles and allocated resources
	free(resFileName);
	CloseHandle(hFile);
	FreeResource(rcData);
	CloseHandle(hRc);

	return TRUE;
}

int main(int argc, char** argv) {
	HMODULE hProgram;
	DWORD errVal;
	CHAR lpFileName[256];

	//I- Intro screen
	system("cls");
	system("color 3");
	printf("      ::::    :::       ::::::::::         :::   :::       ::::::::\n");
	printf("     :+:+:   :+:       :+:               :+:+: :+:+:     :+:    :+:\n");
	printf("    :+:+:+  +:+       +:+              +:+ +:+:+ +:+    +:+    +:+ \n");
	printf("   +#+ +:+ +#+       +#++:++#         +#+  +:+  +#+    +#+    +:+   \n");
	printf("  +#+  +#+#+#       +#+              +#+       +#+    +#+    +#+    \n");
	printf(" #+#   #+#+#       #+#              #+#       #+#    #+#    #+#     \n");
	printf("###    ####       ##########       ###       ###     ########       \n");

	//1- Arguments check
	if ( (argv[1] == NULL || argv[2] == NULL) || (argv[3] != NULL)) {
		printf("\nUsage: nemo.exe {IMAGE PATH (.exe, .dll or etc.)} {OUTPUT PATH}");
		return -1;
	}
	
	//2- Set output directory
	CreateDirectory(argv[2], NULL);
	if (SetCurrentDirectoryA(argv[2]) == FALSE) {
		printf("\nAn error occurred during the creation of the output directory. WINDOWS SYSTEM ERROR CODE: %d", GetLastError());
		return -2;
	}
	
	//3- Load memory image of the given file into the virtual memory space of the cracker
	hProgram = LoadLibraryA((CHAR*)argv[1]);
	if (!hProgram || hProgram == INVALID_HANDLE_VALUE) {
		errVal = GetLastError();

		if (errVal == 126) printf("\nSpecified path for the image file couldn't be found.");
		else printf("\nAn error occurred. WINDOWS SYSTEM ERROR CODE: %d", errVal);
		
		return -1;
	}

	//4- Gather module name, then initialize progress screen
 	GetModuleFileNameA(hProgram, lpFileName, 256);
	system("cls");
	printf("\nIMAGE FILE NAME: %s\n------------------------------------\n", lpFileName);
	

	//******************************** 5- GENERAL SCAN ********************************//

	//Scan for accel resources
	printf("\nACCELERATOR TABLE RESOURCES: \n------------------------------------");
	if (EnumResourceNames(hProgram, MAKEINTRESOURCE(RT_ACCELERATOR), scanner, 0) == FALSE)
		printf("\n No accel table resources found.\n");

	//Scan for animated cursor resources
	printf("\nANIMATED CURSOR RESOURCES: \n------------------------------------");
	if (EnumResourceNames(hProgram, MAKEINTRESOURCE(RT_ANICURSOR), scanner, 0) == FALSE)
		printf("\n No animated cursor resources found.\n");

	//Scan for animated icon resources
	printf("\nANIMATED ICON RESOURCES: \n------------------------------------");
	if (EnumResourceNames(hProgram, MAKEINTRESOURCE(RT_ANIICON), scanner, 0) == FALSE)
		printf("\n No animated icon resources found.\n");

	//Scan for bitmap resources
	printf("\nBITMAP RESOURCES: \n------------------------------------");
	if (EnumResourceNames(hProgram, MAKEINTRESOURCE(RT_BITMAP), scanner, 0) == FALSE)
		printf("\n No bitmap resources found.\n");

	//Scan for cursor resources
	printf("\nCURSOR RESOURCES: \n------------------------------------");
	if (EnumResourceNames(hProgram, MAKEINTRESOURCE(RT_CURSOR), scanner, 0) == FALSE)
		printf("\n No cursor resources found.\n");

	//Scan for dialog box resources
	printf("\nDIALOGBOX RESOURCES: \n------------------------------------");
	if (EnumResourceNames(hProgram, MAKEINTRESOURCE(RT_DIALOG), scanner, 0) == FALSE)
		printf("\n No dialogbox resources found.\n");

	//Scan for dlginclude resources
	printf("\nDLGINCLUDE RESOURCES: \n------------------------------------");
	if (EnumResourceNames(hProgram, MAKEINTRESOURCE(RT_DLGINCLUDE), scanner, 0) == FALSE)
		printf("\n No dialog include resources found.\n");

	//Scan for font resources
	printf("\nFONT RESOURCES: \n------------------------------------");
	if (EnumResourceNames(hProgram, MAKEINTRESOURCE(RT_FONT), scanner, 0) == FALSE)
		printf("\n No font resources found.\n");

	//Scan for font directory resources
	printf("\nFONT DIRECTORY RESOURCES: \n------------------------------------");
	if (EnumResourceNames(hProgram, MAKEINTRESOURCE(RT_FONTDIR), scanner, 0) == FALSE)
		printf("\n No font directory resources found.\n");

	//Scan for group cursor resources
	printf("\nGROUP CURSOR RESOURCES: \n------------------------------------");
	if (EnumResourceNames(hProgram, MAKEINTRESOURCE(RT_GROUP_CURSOR), scanner, 0) == FALSE)
		printf("\n No group cursor resources found.\n");

	//Scan for group font resources
	printf("\nGROUP ICON RESOURCES: \n------------------------------------");
	if (EnumResourceNames(hProgram, MAKEINTRESOURCE(RT_GROUP_ICON), scanner, 0) == FALSE)
		printf("\n No group icon resources found.\n");

	//Scan for HTML resources
	printf("\nHTML RESOURCES: \n------------------------------------");
	if (EnumResourceNames(hProgram, MAKEINTRESOURCE(RT_HTML), scanner, 0) == FALSE)
		printf("\n No html resources found.\n");

	//Scan for icon resources
	printf("\nICON RESOURCES: \n------------------------------------");
	if (EnumResourceNames(hProgram, MAKEINTRESOURCE(RT_ICON), scanner, 0) == FALSE)
		printf("\n No icon resources found.\n");

	//Scan for icon resources
	printf("\nMANIFEST RESOURCES: \n------------------------------------");
	if (EnumResourceNames(hProgram, MAKEINTRESOURCE(RT_MANIFEST), scanner, 0) == FALSE)
		printf("\n No manifest resources found.\n");

	//Scan for menu resources
	printf("\nMENU RESOURCES: \n------------------------------------");
	if (EnumResourceNames(hProgram, MAKEINTRESOURCE(RT_MENU), scanner, 0) == FALSE)
		printf("\n No menu resources found.\n");

	//Scan for message table resources
	printf("\nMESSAGE TABLE RESOURCES: \n------------------------------------");
	if (EnumResourceNames(hProgram, MAKEINTRESOURCE(RT_MESSAGETABLE), scanner, 0) == FALSE)
		printf("\n No message table resources found.\n");

	//Scan for plug and play resources
	printf("\nPLUG AND PLAY RESOURCES: \n------------------------------------");
	if (EnumResourceNames(hProgram, MAKEINTRESOURCE(RT_PLUGPLAY), scanner, 0) == FALSE)
		printf("\n No plug&play resources found.\n");

	//Scan for additional data resources
	printf("\nPROGRAM DATA RESOURCES: \n------------------------------------");
	if (EnumResourceNames(hProgram, MAKEINTRESOURCE(RT_RCDATA), scanner, 0) == FALSE)
		printf("\n No program data resources found.\n");

	//Scan for string resources
	printf("\nSTRING RESOURCES: \n------------------------------------");
	if (EnumResourceNames(hProgram, MAKEINTRESOURCE(RT_STRING), scanner, 0) == FALSE)
		printf("\n No string resources found.\n");

	//Scan for version resources
	printf("\nVERSION RESOURCES: \n------------------------------------");
	if (EnumResourceNames(hProgram, MAKEINTRESOURCE(RT_VERSION), scanner, 0) == FALSE)
		printf("\n No version resources found.\n");

	//Scan for VXD resources
	printf("\nVXD RESOURCES: \n------------------------------------");
	if (EnumResourceNames(hProgram, MAKEINTRESOURCE(RT_VXD), scanner, 0) == FALSE)
		printf("\n No VXD resources found.\n");

	//6- Release handles and allocated resources
	CloseHandle((HANDLE)hProgram);
	return 0;
}