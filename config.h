#ifndef _CONFIG_H_
#define _CONFIG_H_



/* our embeded engineers should control the bin file version of released firmware. */
#define RELEASED_FIRMWARE_BIN_FILE_VERSION_MAJOR       1
#define RELEASED_FIRMWARE_BIN_FILE_VERSION_MINOR       0
#define RELEASED_FIRMWARE_BIN_FILE_VERSION_REVISION    0



/* it is developer name of embeded engineers. */
#define DEVELOPER_NAME    "HCL"



/*
		the bin file name of original firmware and released firmware is defined here,
	you can modify the two name if it is needed.
*/
#define ORIGINAL_FIRMWARE_BIN_FILE_NAME     "user_application.bin"

#define RELEASED_FIRMWARE_BIN_FILE_NAME     "user_application_release_by_embeded_engineer.bin"



/*
		the bin file of released firmware should be encrypted twice,
	so it needs two encryption key,
	KEY_FOR_CHIP is only used by our embedded engineers.
	KEY_FOR_PLATFORM is used by our platform engineers and our embedded engineers.
		the size must not larger than AES_KEYLEN bytes(include last '\0'),
	there are AES128 and AES192 and AES256,
	their AES_KEYLEN is different,
	which we are using can be found in aes.h.
		once our product is officially sold,
	we can not modify KEY_FOR_CHIP any more,
	because product which contains old bootloader can not get right firmware!
	but KEY_FOR_PLATFORM can be modified.
*/
#define KEY_FOR_CHIP        "KEYFORCHIP"     /* our embedded engineers SHOULD NOT let other people know the key! */
#define KEY_FOR_PLATFORM    "KEYFORPLATFORM" /* our embedded engineers SHOULD let platform engineers know the key! */



/* the bin file structure of released firmware is defined below. */
#define RELEASED_FIRMWARE_BIN_FILE_HEADER_FIXED_PREFIX_0    ((unsigned char)0xCC)
#define RELEASED_FIRMWARE_BIN_FILE_HEADER_FIXED_PREFIX_1    ((unsigned char)0xDD)
#define RELEASED_FIRMWARE_BIN_FILE_HEADER_FIXED_PREFIX_2    ((unsigned char)0xEE)
#define RELEASED_FIRMWARE_BIN_FILE_HEADER_FIXED_PREFIX_3    ((unsigned char)0xFF)
typedef struct {
	unsigned char fixed_prefix_0;
	unsigned char fixed_prefix_1;
	unsigned char fixed_prefix_2;
	unsigned char fixed_prefix_3;

	unsigned short release_year;
	unsigned char  release_month;
	unsigned char  release_day;
	unsigned char  release_hour;
	unsigned char  release_minute;

	unsigned char version_major;
	unsigned char version_minor;
	unsigned char version_revision;

	unsigned char developer_name[3 + 16 + 8];

	/* int(4 bytes) but long(8 bytes in LinuxX64) */
	unsigned int firmware_length;
	unsigned int firmware_crc32;

	/* the encrypted firmware location is started from here. */
} RELEASED_FIRMWARE_BIN_FILE_HEADER;



#endif
