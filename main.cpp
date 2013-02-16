#include <iostream>
#include <fstream>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#define HEADER_SIZE 0x000004C

using namespace std;

struct msshlnk_field {
	const char* const name;
	int size;
	int repeat;
	const char* const formatstr;
	void (*prettyfunc)(void*);
};

uint32_t _linkflags;
uint32_t _linkinfoflags;
uint16_t _idlist_size;

const char* const str_linkflags[32] = {
	"A  HasLinkTargetIDList",
	"B  HasLinkInfo",
	"C  HasName",
	"D  HasRelativePath",
	"E  HasWorkingDir",
	"F  HsArgument",
	"G  HasIconLocation",
	"H  IsUnicode",
	"I  ForceNoLinkInfo",
	"J  HasExpString",
	"K  RunInSpearateProcess",
	"L  Unused1",
	"M  HasDarwingID",
	"N  RunAsUser",
	"O  HasExpIcon"
	"P  NoPidlAlias",
	"Q  Unused2",
	"R  RunWithShimLayer",
	"S  ForceNoLinkTrack",
	"T  EnableTargetMetadata",
	"U  DisableLinkPathTracking",
	"V  DisableKnownFolerTracking",
	"W  DisableKnownFolerAlias",
	"X  AllowLinkToLink",
	"Y  UnaliasOnSave",
	"Z  PreferEnvironmentPath",
	"AA KeepLocalIDListForUNCTarget",
	NULL
};

const char* const str_fileattributes[32] = {
	"A  FILE_ATTRIBUTE_READONLY",
	"B  FILE_ATTRIBUTE_HIDDEN",
	"C  FILE_ATTRIBUTE_SYSTEM",
	"D  Reserved1",
	"E  FILE_ATTRIBUTE_DIRECTORY",
	"F  FILE_ATTRIBUTE_ARCHIVE",
	"G  Reserved2",
	"H  FILE_ATTRIBUTE_NORMAL",
	"I  FILE_ATTRIBUTE_TEMPORARY",
	"J  FILE_ATTRIBUTE_SPARSE_FILE",
	"K  FILE_ATTRIBUTE_REPARSE_POINT",
	"L  FILE_ATTRIBUTE_COMPRESSED",
	"M  FILE_ATTRIBUTE_OFFLINE",
	"N  FILE_ATTRIBUTE_NOT_CONTENT_INDEXED",
	"O  FILE_ATTRIBUTE_ENCRYPTED",
	NULL
};

const char* const str_linkinfoflags[32] = {
	"A  VolumeIDAndLocalBasePath",
	"B  CommonNetworkRelativeLinkAndPathSuffix",
	NULL
};

void parse_linkflags(void* data) {
	uint32_t* u = (uint32_t*)data;
	_linkflags = *u;
	for (int i=0; i<32; i++) {
		if (str_linkflags[i] == 0)
			continue;
		if (*u & (1 << i))
			printf("\n    Bit%-2d %s", i, str_linkflags[i]);
	}
}

void parse_linkinfoflags(void* data) {
	uint32_t* u = (uint32_t*)data;
	_linkinfoflags = *u;
	for (int i=0; i<32; i++) {
		if (str_linkinfoflags[i] == 0)
			continue;
		if (*u & (1 << i))
			printf("\n    Bit%-2d %s", i, str_linkinfoflags[i]);
	}
}


void parse_fileattributes(void* data) {
	uint32_t* u = (uint32_t*)data;
	for (int i=0; i<32; i++) {
		if (str_fileattributes[i] == 0)
			continue;
		if (*u & (1 << i))
			printf("\n    Bit%-2d %s", i, str_fileattributes[i]);
	}
}

const char* const str_commonnetworkrelativelinkflags[32] = {
	"A Valid Device",
	"B ValidNetType",
	NULL,
};

void parse_commonworkrelativelinkflags(void* data) {
	uint32_t* u = (uint32_t*)data;
	for (int i=0; i<32; i++) {
		if (str_commonnetworkrelativelinkflags[i] == 0)
			continue;
		if (*u & (1 << i))
			printf("\n    Bit%-2d %s", i, str_commonnetworkrelativelinkflags[i]);
	}
}

struct msshlnk_field shlnk_header_fileds[] = {
	{"HeaderSize    ", 4, 0, "0x%08X",    NULL },
	{"LinkCLSID     ", 4, 4, "0x%08X",    NULL },
	{"LinkFlags     ", 4, 0, "0x%08X",    &parse_linkflags },
	{"FileAttributes", 4, 0, "0x%08X",    &parse_fileattributes },
	{"CreationTime  ", 8, 0, "0x%016llX", NULL },
	{"AccessTime    ", 8, 0, "0x%016llX", NULL },
	{"WriteTime     ", 8, 0, "0x%016llX", NULL },
	{"FileZise      ", 4, 0, "%d bytes" , NULL },
	{"IconIndex     ", 4, 0, "%d",        NULL },
	{"ShowCommand   ", 4, 0, "%d",        NULL },
	{"HotKey        ", 2, 0, "%d",        NULL },
	{"Reserved1     ", 2, 0, "%d",        NULL },
	{"Reserved2     ", 4, 0, "%d",        NULL },
	{"Reserved3     ", 4, 0, "%d",        NULL },
	{ NULL,            0, 0, NULL,        NULL}
};

struct msshlnk_field link_info_fields[] = {
	{ "LinkInfoSize                   ", 4, 0, "%d", NULL},
	{ "LinkInfoHeaderSize             ", 4, 0, "%d", NULL},
	{ "LinkInfoFlags                  ", 4, 0, "%d", &parse_linkinfoflags},  
	{ "VolumeIDOffset                 ", 4, 0, "%d", NULL},
	{ "LocalBasePathOffset            ", 4, 0, "%d", NULL},
	{ "CommonNetworkRelativeLinkOffset", 4, 0, "%d", NULL},
	{ "CommonPathSuffixOffset         ", 4, 0, "%d", NULL},  
// 	{ "LocalBasePathOffsetUnicode     ", 4, 0, "%d", NULL},
// 	{ "CommonPathSuffixOffsetUnicode  ", 4, 0, "%d", NULL},
	{ NULL,                 0, 0, NULL, NULL},
};

struct msshlnk_field common_network_relative_fields[] {
	{ "CommonNetworkRelativeLinkSize ", 4, 0, "%d", NULL},
	{ "CommonNetworkRelativeLinkFlags", 4, 0, "%d", &parse_commonworkrelativelinkflags},
	
	{ NULL,                             0, 0, NULL, NULL}
};

void read_generic_field(fstream& fin, const struct msshlnk_field* field) {
	int repeat = field->repeat;
	union {
		uint8_t  u8;
		int8_t   s8;
		uint16_t u16;
		int16_t  s16;
		uint32_t u32;
		int32_t  s32;
		uint64_t u64;
		int64_t  s64;
	} u;
	memset(&u, 0, sizeof(u));

	printf("%s : ", field->name);
	do {
		fin.read((char*)&u, field->size);
		printf(field->formatstr, u);
		printf(" ");
		if (field->prettyfunc)
		  field->prettyfunc(&u);
		if (!repeat)
			break;
	} while (--repeat);
	printf("\n");
}

bool read_itemid(fstream& fin) {
	union {
		unsigned char buf[4096];
		uint16_t u16;
	} u;
	memset(&u, 0, sizeof(u));
	
	fin.read((char*)u.buf, 2);
	if (u.u16 == 0)
		return false;
	fin.read((char*)u.buf+2, u.u16-2);
	printf("size: %d\n", u.u16);
	printf("string data: ", &u.buf[2]);
	for (int i=0; i<u.u16; i++)
		printf("%c", isprint(u.buf[i+2]) ? u.buf[i+2] : '.');
	printf("\n");
	printf("binary data: ");
	for (int i=0; i<u.u16; i++)
		printf("%02X ", u.buf[i+2]);
	printf("\n");
	return true;
}


int main() {
	fstream fin("Alfresco demo-20121128.wmv.lnk", fstream::in | fstream::binary);

	// Read ShellLinkHeader
	int idx=0;
	while (shlnk_header_fileds[idx].name) {
		read_generic_field(fin, &shlnk_header_fileds[idx]);
		idx++;
	}

#define HAS_LINK_TARGET_ID_LIST (1<<0)
	if (_linkflags & HAS_LINK_TARGET_ID_LIST) {
		printf("\nTARGET_ID_LIST\n");

		// Read IDListTarget
		fin.read((char*)&_idlist_size, 2);
		while (read_itemid(fin));
	}

#define HAS_LINK_INFO           (1<<1)
#define LINKINFO_VolumeIDAndLocalBasePath               (1<<0)
#define LINKINFO_CommonNetworkRelativeLinkAndPathSuffix (1<<1)
	if (_linkflags & HAS_LINK_TARGET_ID_LIST) {
		printf("\nLINK_INFO\n");
		// Read LinkInfo
		int idx=0;
		while (link_info_fields[idx].name) {
			read_generic_field(fin, &link_info_fields[idx]);
			idx++;
		}

		if (_linkinfoflags & LINKINFO_VolumeIDAndLocalBasePath) {
			printf("Parsing of VolumeID not implemented\n");
			printf("Parsing of LocalBasePath not implemented\n");
			exit(1);
		}

		if (_linkinfoflags & LINKINFO_CommonNetworkRelativeLinkAndPathSuffix) {
			printf("\nCOMMON_NETWORK_RELATIVE_LINK\n");
			idx = 0;
			while (common_network_relative_fields[idx].name) {
				read_generic_field(fin, &common_network_relative_fields[idx]);
				idx++;
			}
		}

	}

}