#include <stdbool.h>
#include <stdio.h>
#include <time.h>

#include "config.h"
#include "aes.h"
#include "crc.h"

/*
		the code can only be used by our embedded engineers,
	we should be on the MCU program(original bin file) for two layers of encryption,
	then we can release encrypted bin file to platform engineers.
		at first, we release the encrypted bin file to platform engineers,
	they should decrypt the bin file for one time using key_for_platform[AES_KEYLEN],
	then they can send the bin file to MCU by USB communication.
		at last, MCU decrypt the bin file received,
	and to firmware update.
		by two layers of encryption,
	we implement secure firmware updates.
		attention:
				our embedded engineers know key_for_chip[AES_KEYLEN] and key_for_platform[AES_KEYLEN],
			but platform engineers can only know key_for_platform[AES_KEYLEN]!
				there are AES128 and AES192 and AES256,
			their AES_KEYLEN is different,
			which we are using can be found in aes.h.
*/

static struct AES_ctx         AES_ctx_encrypted_for_chip;
static const unsigned char    key_for_chip[AES_KEYLEN]     = KEY_FOR_CHIP;

static struct AES_ctx         AES_ctx_encrypted_for_platform;
static const unsigned char    key_for_platform[AES_KEYLEN] = KEY_FOR_PLATFORM;

static RELEASED_FIRMWARE_BIN_FILE_HEADER    released_firmware_bin_file_header = {
	/* these are fixed value. */
	.fixed_prefix_0 = RELEASED_FIRMWARE_BIN_FILE_HEADER_FIXED_PREFIX_0,
	.fixed_prefix_1 = RELEASED_FIRMWARE_BIN_FILE_HEADER_FIXED_PREFIX_1,
	.fixed_prefix_2 = RELEASED_FIRMWARE_BIN_FILE_HEADER_FIXED_PREFIX_2,
	.fixed_prefix_3 = RELEASED_FIRMWARE_BIN_FILE_HEADER_FIXED_PREFIX_3,

	/* these are default value. */
	.release_year   = 2019,
	.release_month  = 1,
	.release_day    = 1,
	.release_hour   = 0,
	.release_minute = 0,

	/* these are fixed value. */
	.version_major    = RELEASED_FIRMWARE_BIN_FILE_VERSION_MAJOR,
	.version_minor    = RELEASED_FIRMWARE_BIN_FILE_VERSION_MINOR,
	.version_revision = RELEASED_FIRMWARE_BIN_FILE_VERSION_REVISION,

	/* it is fixed value. */
	.developer_name = DEVELOPER_NAME,

	/* these are default value. */
	.firmware_length = 0,
	.firmware_crc32  = 0
};

int main(void)
{
	int            i;
	time_t         original_time;
	struct tm     *translated_time;
	const char    *original_firmware_bin_file_name;
	const char    *released_firmware_bin_file_name;
	FILE          *original_firmware_bin_file;
	FILE          *released_firmware_bin_file;
	size_t         read_items_amount;
	size_t         write_items_amount;
	bool           is_original_firmware_bin_file_read_complete = false;
	unsigned char  data_buf[AES_BLOCKLEN];

	/* select bin firmware to be encrypted for release. */
	original_firmware_bin_file_name = ORIGINAL_FIRMWARE_BIN_FILE_NAME;
	released_firmware_bin_file_name = RELEASED_FIRMWARE_BIN_FILE_NAME;

	/* get original time. */
	original_time = time(NULL);
	if (-1 == original_time) {
		perror("time()");

		return -1;
	}
	/* get translated time. */
	translated_time = localtime(&original_time);
	/* update global time. */
	released_firmware_bin_file_header.release_year   = translated_time->tm_year + 1900;
	released_firmware_bin_file_header.release_month  = translated_time->tm_mon + 1;
	released_firmware_bin_file_header.release_day    = translated_time->tm_mday;
	released_firmware_bin_file_header.release_hour   = translated_time->tm_hour;
	released_firmware_bin_file_header.release_minute = translated_time->tm_min;

	/* open bin file of original firmware. */
	original_firmware_bin_file = fopen(original_firmware_bin_file_name, "r");
	if (NULL == original_firmware_bin_file) {
		(void)printf("fopen() of original bin file: %s\n", original_firmware_bin_file_name);
		perror("    ");

		return -1;
	}

	/* open bin file of released firmware. */
	released_firmware_bin_file = fopen(released_firmware_bin_file_name, "w");
	if (NULL == released_firmware_bin_file) {
		perror("fopen() of released bin file");

		return -1;
	}

	/*
			modify file position pointer of bin file of released firmware to actual firmware position,
		file header will be written at last.
	*/
	if (fseek(released_firmware_bin_file, sizeof(RELEASED_FIRMWARE_BIN_FILE_HEADER), SEEK_SET)) {
		perror("fseek() of released bin file");

		return -1;
	}

	/* prepare for global firmware_crc32. */
	crc32_batch_prepare(&released_firmware_bin_file_header.firmware_crc32);
	
	/* initialize two key for further encryption. */
	AES_init_ctx(&AES_ctx_encrypted_for_chip,     &key_for_chip[0]);
	AES_init_ctx(&AES_ctx_encrypted_for_platform, &key_for_platform[0]);

	//(void)printf("two layers of encryption start.\n");
	while (!is_original_firmware_bin_file_read_complete) {
		/* read bin file of original firmware. */
		read_items_amount = fread(&data_buf[0], 1, AES_BLOCKLEN, original_firmware_bin_file);
		if (AES_BLOCKLEN != read_items_amount) {
			if (ferror(original_firmware_bin_file)) {
				perror("fread()");

				return -1;
			}

			if (feof(original_firmware_bin_file)) {
				clearerr(original_firmware_bin_file);

				is_original_firmware_bin_file_read_complete = true;
			} else {
				(void)printf("fread() unknown error\n");

				return -1;
			}
		}

		/* we have gotten read_items_amount bytes(0 ~ AES_BLOCKLEN). */
		if (read_items_amount) {
			/*
					the data length must be equal to AES_BLOCKLEN bytes,
				if it is not enough,
				the remainder must be filled with 0xFF,
				because we always use firmware which size is multiple of AES_BLOCKLEN,
				it will be downloaded to FLASH of MCU,
				empty FLASH content is all 0xFF,
				so it is not affectable if last several data is 0xFF.
			*/
			if (AES_BLOCKLEN > read_items_amount) {
				for (i = read_items_amount; i < AES_BLOCKLEN; i++) {
					data_buf[i] = 0xFF;
				}
			}

			/* update global firmware_length by plus AES_BLOCKLEN. */
			released_firmware_bin_file_header.firmware_length += AES_BLOCKLEN;

			/*
					we should record CRC32 value of bin file of original firmware,
				because MCU can only calculate CRC32 of original firmware rather than released firmware,
				MCU will compare the two CRC32 to check whether download data is complete.
			*/
			crc32_batch_calculating(&data_buf[0], AES_BLOCKLEN, &released_firmware_bin_file_header.firmware_crc32);

			/* it should be AES_ctx_encrypted_for_chip for first encryption. */
			AES_ECB_encrypt(&AES_ctx_encrypted_for_chip,     &data_buf[0]);
			/* it should be AES_ctx_encrypted_for_platform for last encryption. */
			AES_ECB_encrypt(&AES_ctx_encrypted_for_platform, &data_buf[0]);

			/* write bin file of released firmware. */
			write_items_amount = fwrite(&data_buf[0], 1, AES_BLOCKLEN, released_firmware_bin_file);
			if (AES_BLOCKLEN != write_items_amount) {
				if (ferror(released_firmware_bin_file)) {
					perror("fwrite()");

					return -1;
				}
			}
		}
	}
	//(void)printf("two layers of encryption finish.\n");

	/* 
			get back to the start of bin file of released firmware,
		because we are goint to write file header.
	*/
	if (fseek(released_firmware_bin_file, 0, SEEK_SET)) {
		perror("fseek() of released bin file");

		return -1;
	}

	/* finish for global firmware_crc32. */
	crc32_batch_finish(&released_firmware_bin_file_header.firmware_crc32);
	
	//(void)printf("write file header start.\n");
	/* write bin file for file header. */
	write_items_amount = fwrite(&released_firmware_bin_file_header, 1, sizeof(RELEASED_FIRMWARE_BIN_FILE_HEADER), released_firmware_bin_file);
	if (sizeof(RELEASED_FIRMWARE_BIN_FILE_HEADER) != write_items_amount) {
		if (ferror(released_firmware_bin_file)) {
			perror("fwrite()");

			return -1;
		}
	}
	//(void)printf("write file header finish.\n");

	/* close bin file of released firmware. */
	if (fclose(released_firmware_bin_file)) {
		perror("fclose() of released bin file");

		return -1;
	}

	/* close bin file of original firmware. */
	if (fclose(original_firmware_bin_file)) {
		perror("fclose() of original bin file");

		return -1;
	}

	(void)printf("encrypted released bin file of firmware has been successfully generated!\n");
	(void)printf("    file name: %s\n", released_firmware_bin_file_name);
	(void)printf("    year: %d; month: %d; day: %d; hour: %d; minute: %d\n",
		released_firmware_bin_file_header.release_year,
		released_firmware_bin_file_header.release_month,
		released_firmware_bin_file_header.release_day,
		released_firmware_bin_file_header.release_hour,
		released_firmware_bin_file_header.release_minute);
	(void)printf("    version: %d.%d.%d\n",
		released_firmware_bin_file_header.version_major,
		released_firmware_bin_file_header.version_minor,
		released_firmware_bin_file_header.version_revision);
	(void)printf("    developer: %s\n",
		released_firmware_bin_file_header.developer_name);
	(void)printf("    firmware length: %d bytes\n",
		released_firmware_bin_file_header.firmware_length);
	(void)printf("    firmware CRC32: 0x%08x\n",
		released_firmware_bin_file_header.firmware_crc32);

	return 0;
}
