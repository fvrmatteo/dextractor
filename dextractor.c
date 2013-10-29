#include <stdio.h>
#include <stdlib.h>

typedef unsigned int boolean;
#define true 1
#define false 0

//This method verifies (or try to verifies) the integrity of a given DEX package
boolean verifyIntegrity(FILE *fp) {
	//to be implemented
	return true;
}

void extractBytes(FILE *fp, int from, int length, char *title) {
	if(fseek(fp, from, 0) == -1) {
		printf("Error setting the file pointer!\n\n");
		exit(1);
	}
	unsigned int i;
	printf("%s", title);
	for(i = 0; i < length; i++) {
		printf("%02x ", (unsigned char)fgetc(fp));
	}
	printf("\n");
}

unsigned int bytesToInt(FILE *fp, int from, int length) {
	if(fseek(fp, from, 0) == -1) {
		printf("Error setting the file pointer!\n\n");
		exit(1);
	}
	unsigned int i;
	unsigned char *bytes = (unsigned char *)malloc(sizeof(unsigned char) * length);
	for(i = 0; i < length; i++) {
		bytes[i] = (unsigned char)fgetc(fp);
	}
	unsigned int mid = length / 2;
	unsigned char temp;
	unsigned int last = length - 1;
	for(i = 0; i < mid; i++) {
		temp = bytes[i];
		bytes[i] = bytes[last];
		bytes[last--] = temp;
	}
	unsigned int value = bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3];
	return value;
}

void header(FILE *fp) {
	printf("Header information:\n");
	char *title = "  [+] Magic: ";
	extractBytes(fp, 0, 8, title);
	title = "  [+] Checksum: ";
	extractBytes(fp, 8, 4, title);
	title = "  [+] Signature: ";
	extractBytes(fp, 12, 20, title);
	title = "  [+] File Size: ";
	extractBytes(fp, 32, 4, title);
	title = "  [+] Header Size: ";
	extractBytes(fp, 36, 4, title);
	title = "  [+] Endian Tag: ";
	extractBytes(fp, 40, 4, title);
	title = "  [+] Link Size: ";
	extractBytes(fp, 44, 4, title);
	title = "  [+] Link Offset: ";
	extractBytes(fp, 48, 4, title);
	title = "  [+] Map Offset: ";
	extractBytes(fp, 52, 4, title);
	title = "  [+] String Ids Size: ";
	extractBytes(fp, 56, 4, title);
	title = "  [+] String Ids Offset: ";
	extractBytes(fp, 60, 4, title);
	title = "  [+] Type Ids Size: ";
	extractBytes(fp, 64, 4, title);
	title = "  [+] Type Ids Offset: ";
	extractBytes(fp, 68, 4, title);
	title = "  [+] Proto Ids Size: ";
	extractBytes(fp, 72, 4, title);
	title = "  [+] Proto Ids Offset: ";
	extractBytes(fp, 76, 4, title);
	title = "  [+] Field Ids Size: ";
	extractBytes(fp, 80, 4, title);
	title = "  [+] Field Ids Ofset: ";
	extractBytes(fp, 84, 4, title);
	title = "  [+] Method Ids Size: ";
	extractBytes(fp, 88, 4, title);
	title = "  [+] Method Ids Offset: ";
	extractBytes(fp, 92, 4, title);
	title = "  [+] Class Defs Size: ";
	extractBytes(fp, 96, 4, title);
	title = "  [+] Class Defs Offset: ";
	extractBytes(fp, 100, 4, title);
	title = "  [+] Data Size: ";
	extractBytes(fp, 104, 4, title);
	title = "  [+] Data Offset: ";
	extractBytes(fp, 108, 4, title);
	printf("\n");
}

void strings(FILE *fp) {
	unsigned int count = bytesToInt(fp, 56, 4);
	printf("[+] Strings count: %d", count);
	char *title = "\n[+] String Offset: ";
	extractBytes(fp, 60, 4, title);
	unsigned int string_offset = bytesToInt(fp, 60, 4);
	printf("[+] String list:");
	unsigned int i, j;
	unsigned int offset_start, offset_end, string_length;
	offset_start = bytesToInt(fp, string_offset, 4);
	for(i = 0; i < count - 1; i++) {
		string_offset += 4;
		offset_end = bytesToInt(fp, string_offset, 4);
		string_length = offset_end - offset_start;
		if(fseek(fp, offset_start, 0) == -1) {
			printf("Error setting the file pointer!\n\n");
			exit(1);
		}
		printf("\n  [%d] ", i);
		unsigned char c;
		for(j = 0; j < string_length; j++) {
			c = fgetc(fp);
			if((int)c >= 0 && (int)c <= 31) {

			} else {
				printf("%c", c);
			}
		}
		offset_start = offset_end;
	}
	printf("\n\n");
}

void methods(FILE *fp) {
	//to be implemented
}

void clear() {
	if(system("cls")) {
		system("clear");
	}
}

int main() {
	printf("\n[~] DEX Information Extractor v1 [~]\n\n");
	char *dexFile;
	printf("DEX name: ");
	scanf("%s", dexFile);
	clear();
	FILE *fp;
	fp = fopen(dexFile, "r");
	if(fp == NULL) {
		printf("\nFile not found!\n\n");
		exit(1);
	}
	if(!verifyIntegrity(fp)) {
		printf("DEX integrity: CORRUPTED\nThe DEX file seems to be modified, keep an open eye!\n\n");
	} else {
		printf("DEX integrity: OK\n\n");
	}
	unsigned int choice;
	boolean running = true;
	while(running) {
		printf("Select an option:\n 1) Header\n 2) Strings\n 3) Methods\n 4) Exit\n\nChoice: ");
		scanf("%i", &choice);
		clear();
		switch(choice) {
			case 1: 
				header(fp);
				break;
			case 2: 
				strings(fp);
				break;
			case 3:
				methods(fp);
				break;
			case 4: 
				running = false;
				break;
			default: 
				printf("You have entered an invalid choice!\n\n");
			
			break;
		}
	}
	return 0;
}
