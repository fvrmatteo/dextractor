#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned int boolean;
#define true 1
#define false 0

/* Global Variables */
char **strings_array;
char **types_array;

//This method verifies (or try to verifies) the integrity of a given DEX package
boolean verifyIntegrity(FILE *fp) {
	//to be implemented
	return true;
}

void clear() {
	if(system("cls")) {
		system("clear");
	}
	//uncomment this if compiled on Windows: system("cls"), and comment the line above
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

void extractBytes(FILE *fp, int from, int length, char *title, boolean decimal, boolean revert) {
	if(fseek(fp, from, 0) == -1) {
		printf("Error setting the file pointer!\n\n");
		exit(1);
	}
	unsigned int i;
	printf("%s", title);
	if(revert) {
		unsigned char *c = (char *)malloc(length * sizeof(unsigned char));
		for(i = 0; i < length; i++) {
			c[i] = (unsigned char)fgetc(fp);
		}
		unsigned int mid = length / 2;
		unsigned char temp;
		unsigned int last = length - 1;
		for(i = 0; i < mid; i++) {
			temp = c[i];
			c[i] = c[last];
			c[last--] = temp;
		}
		for(i = 0; i < length; i++) {
			printf("%02x ", c[i]);
		}
	} else {
		for(i = 0; i < length; i++) {
			printf("%02x ", (unsigned char)fgetc(fp));
		}
	}
	
	if(decimal) {
		printf("\tDecimal [%d]", bytesToInt(fp, from, length));
	}
	printf("\n");
}

void header(FILE *fp) {
	printf("Header information:\n");
	char *title = "  [+] Magic: ";
	extractBytes(fp, 0, 8, title, false, false);
	title = "  [+] Checksum: ";
	extractBytes(fp, 8, 4, title, false, false);
	title = "  [+] Signature: ";
	extractBytes(fp, 12, 20, title, false, false);
	title = "  [+] File Size: ";
	extractBytes(fp, 32, 4, title, true, true);
	title = "  [+] Header Size: ";
	extractBytes(fp, 36, 4, title, true, true);
	title = "  [+] Endian Tag: ";
	extractBytes(fp, 40, 4, title, false, false);
	title = "  [+] Link Size: ";
	extractBytes(fp, 44, 4, title, true, true);
	title = "  [+] Link Offset: ";
	extractBytes(fp, 48, 4, title, false, true);
	title = "  [+] Map Offset: ";
	extractBytes(fp, 52, 4, title, false, true);
	title = "  [+] String Ids Size: ";
	extractBytes(fp, 56, 4, title, true, true);
	title = "  [+] String Ids Offset: ";
	extractBytes(fp, 60, 4, title, false, true);
	title = "  [+] Type Ids Size: ";
	extractBytes(fp, 64, 4, title, true, true);
	title = "  [+] Type Ids Offset: ";
	extractBytes(fp, 68, 4, title, false, true);
	title = "  [+] Proto Ids Size: ";
	extractBytes(fp, 72, 4, title, true, true);
	title = "  [+] Proto Ids Offset: ";
	extractBytes(fp, 76, 4, title, false, true);
	title = "  [+] Field Ids Size: ";
	extractBytes(fp, 80, 4, title, true, true);
	title = "  [+] Field Ids Offset: ";
	extractBytes(fp, 84, 4, title, false, true);
	title = "  [+] Method Ids Size: ";
	extractBytes(fp, 88, 4, title, true, true);
	title = "  [+] Method Ids Offset: ";
	extractBytes(fp, 92, 4, title, false, true);
	title = "  [+] Class Defs Size: ";
	extractBytes(fp, 96, 4, title, true, true);
	title = "  [+] Class Defs Offset: ";
	extractBytes(fp, 100, 4, title, false, true);
	title = "  [+] Data Size: ";
	extractBytes(fp, 104, 4, title, true, true);
	title = "  [+] Data Offset: ";
	extractBytes(fp, 108, 4, title, false, true);
	printf("\n");
}

void strings(FILE *fp) {
	unsigned int count = bytesToInt(fp, 56, 4);
	printf("[+] Strings count: %d", count);
	char *title = "\n[+] String Offset: ";
	extractBytes(fp, 60, 4, title, false, false);
	unsigned int string_offset = bytesToInt(fp, 60, 4);
	printf("[+] String list:");
	unsigned int i, j, x;
	unsigned int offset_start, offset_end, string_length;
	unsigned char *current_string;
	offset_start = bytesToInt(fp, string_offset, 4);
	for(i = 0; i < count - 1; i++) {
		x = 0;
		string_offset += 4;
		offset_end = bytesToInt(fp, string_offset, 4);
		string_length = offset_end - offset_start;
		if(fseek(fp, offset_start, 0) == -1) {
			printf("Error setting the file pointer!\n\n");
			exit(1);
		}
		printf("\n  [%d] ", i);
		unsigned char c;
		current_string = (char *)malloc(sizeof(unsigned char) * string_length);
		for(j = 0; j < string_length; j++) {
			c = fgetc(fp);
			if((int)c >= 0 && (int)c <= 31 || c == '!' || c == '"' || c == '#' || c == '%' || c == '\'' || (c == '(' && j == 0) || c == '&' || (c == ' ' && j == 0)) {
				//to be completed, for now it's ok
			} else {
				current_string[x] = c;
				x++;
				printf("%c", c);
			}
		}
		strings_array[i] = current_string;
		offset_start = offset_end;
	}
	printf("\n\n");
}

void types(FILE *fp) {
	printf("[+] Java Types & Classes:");
	unsigned int count = bytesToInt(fp, 64, 4);
	unsigned int i, j;
	unsigned int type_id_list_offset = bytesToInt(fp, 68, 4);
	for(i = 0; i < count; i++) {
		j = bytesToInt(fp, type_id_list_offset, 4);
		printf("\n  [%d] %s", i, strings_array[j]);
		types_array[i] = strings_array[j];
		type_id_list_offset += 4;
	}
	printf("\n\n");
}

void protos(FILE *fp) {
	printf("[+] Methods Prototypes:");
	unsigned int count = bytesToInt(fp, 72, 4);
	unsigned int proto_id_struct_offset = bytesToInt(fp, 76, 4);
	unsigned int shorty_idx, return_type_idx, parameters_offset_start, parameters_offset_end;
	unsigned int i;
	for(i = 0; i < count; i++) {
		shorty_idx = bytesToInt(fp, proto_id_struct_offset, 4);
		return_type_idx = bytesToInt(fp, proto_id_struct_offset + 4, 4);
		//parameters_offset_start = bytesToInt(fp, proto_id_struct_offset + 8, 4);
		//parameters_offset_end = bytesToInt(fp, proto_id_struct_offset + 20, 4);
		//to be completed, have to value some things
		proto_id_struct_offset += 12;
		printf("\n  [%d] ShortyDescriptor(%s) Return Type(%s) Parameters()", i, strings_array[shorty_idx], types_array[return_type_idx]);
	}
	printf("\n\n");
}

void methods(FILE *fp) {
	//to be implemented
}

void initialize_arrays(FILE *fp) {
	//Strings array
	unsigned int count = bytesToInt(fp, 56, 4);
	strings_array = (char **)malloc(count * sizeof(char *));
	strings(fp);
	//Types array
	count = bytesToInt(fp, 64, 4);
	types_array = (char **)malloc(count * sizeof(char *));
	types(fp);
	clear(); //<-- horrible
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
	initialize_arrays(fp);
	unsigned int choice;
	boolean running = true;
	while(running) {
		printf("Select an option:\n 1) Header\n 2) Strings\n 3) Types\n 4) Prototypes\n 5) Exit\n\nChoice: ");
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
				types(fp);
				break;
			case 4:
				protos(fp);
				break;
			case 5: 
				fclose(fp);
				running = false;
				break;
			default: 
				printf("You have entered an invalid choice!\n\n");
			break;
		}
	}
	return 0;
}