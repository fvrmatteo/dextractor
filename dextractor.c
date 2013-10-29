#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned int boolean;
#define true 1
#define false 0

char **strings_array;
char **types_array;
char **protos_array;

//This method verifies (or try to verifies) the integrity of a given DEX package
boolean verifyIntegrity(FILE *fp) {
	//to be implemented
	return true;
}

/* Utility Functions */

void clear() {
	if(system("cls")) {
		system("clear");
	}
}

unsigned short bytesToUshort(FILE *fp, int from) {
	if(fseek(fp, from, 0) == -1) {
		printf("Error setting the file pointer!\n\n");
		exit(1);
	}
	unsigned int i;
	unsigned char bytes[2];
	for(i = 0; i < 2; i++) {
		bytes[i] = (unsigned char)fgetc(fp);
	}
	return (bytes[1] << 8 | bytes[0]);
}

unsigned int bytesToUint(FILE *fp, int from) {
	if(fseek(fp, from, 0) == -1) {
		printf("Error setting the file pointer!\n\n");
		exit(1);
	}
	unsigned int i;
	unsigned char bytes[4];
	for(i = 0; i < 4; i++) {
		bytes[i] = (unsigned char)fgetc(fp);
	}
	return bytes[3] << 24 | bytes[2] << 16 | bytes[1] << 8 | bytes[0];
}

char *strconcat(char *s1, char *s2) {
	size_t old_size;
	char *t;
	old_size = strlen(s1);
	t = malloc(old_size + strlen(s2) + 1);
	strcpy(t, s1);
	strcpy(t + old_size, s2);
	return t;
}

/* Functions used to extract information from DEX structure */

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
		printf("\t\033[22;37mDecimal [\033[22;31m%d\033[22;37m]", bytesToUint(fp, from));
	}
	printf("\n");
}

void header(FILE *fp) {
	printf("\033[22;32mHeader information:\n\n");
	char *title = "  \033[22;37m[\033[01;37m+\033[22;37m] Magic: \033[22;31m";
	extractBytes(fp, 0, 8, title, false, false);
	title = "  \033[22;37m[\033[01;37m+\033[22;37m] Checksum: \033[22;31m";
	extractBytes(fp, 8, 4, title, false, false);
	title = "  \033[22;37m[\033[01;37m+\033[22;37m] Signature: \033[22;31m";
	extractBytes(fp, 12, 20, title, false, false);
	title = "  \033[22;37m[\033[01;37m+\033[22;37m] File Size: \033[22;31m";
	extractBytes(fp, 32, 4, title, true, true);
	title = "  \033[22;37m[\033[01;37m+\033[22;37m] Header Size: \033[22;31m";
	extractBytes(fp, 36, 4, title, true, true);
	title = "  \033[22;37m[\033[01;37m+\033[22;37m] Endian Tag: \033[22;31m";
	extractBytes(fp, 40, 4, title, false, false);
	title = "  \033[22;37m[\033[01;37m+\033[22;37m] Link Size: \033[22;31m";
	extractBytes(fp, 44, 4, title, true, true);
	title = "  \033[22;37m[\033[01;37m+\033[22;37m] Link Offset: \033[22;31m";
	extractBytes(fp, 48, 4, title, false, true);
	title = "  \033[22;37m[\033[01;37m+\033[22;37m] Map Offset: \033[22;31m";
	extractBytes(fp, 52, 4, title, false, true);
	title = "  \033[22;37m[\033[01;37m+\033[22;37m] String Ids Size: \033[22;31m";
	extractBytes(fp, 56, 4, title, true, true);
	title = "  \033[22;37m[\033[01;37m+\033[22;37m] String Ids Offset: \033[22;31m";
	extractBytes(fp, 60, 4, title, false, true);
	title = "  \033[22;37m[\033[01;37m+\033[22;37m] Type Ids Size: \033[22;31m";
	extractBytes(fp, 64, 4, title, true, true);
	title = "  \033[22;37m[\033[01;37m+\033[22;37m] Type Ids Offset: \033[22;31m";
	extractBytes(fp, 68, 4, title, false, true);
	title = "  \033[22;37m[\033[01;37m+\033[22;37m] Proto Ids Size: \033[22;31m";
	extractBytes(fp, 72, 4, title, true, true);
	title = "  \033[22;37m[\033[01;37m+\033[22;37m] Proto Ids Offset: \033[22;31m";
	extractBytes(fp, 76, 4, title, false, true);
	title = "  \033[22;37m[\033[01;37m+\033[22;37m] Field Ids Size: \033[22;31m";
	extractBytes(fp, 80, 4, title, true, true);
	title = "  \033[22;37m[\033[01;37m+\033[22;37m] Field Ids Offset: \033[22;31m";
	extractBytes(fp, 84, 4, title, false, true);
	title = "  \033[22;37m[\033[01;37m+\033[22;37m] Method Ids Size: \033[22;31m";
	extractBytes(fp, 88, 4, title, true, true);
	title = "  \033[22;37m[\033[01;37m+\033[22;37m] Method Ids Offset: \033[22;31m";
	extractBytes(fp, 92, 4, title, false, true);
	title = "  \033[22;37m[\033[01;37m+\033[22;37m] Class Defs Size: \033[22;31m";
	extractBytes(fp, 96, 4, title, true, true);
	title = "  \033[22;37m[\033[01;37m+\033[22;37m] Class Defs Offset: \033[22;31m";
	extractBytes(fp, 100, 4, title, false, true);
	title = "  \033[22;37m[\033[01;37m+\033[22;37m] Data Size: \033[22;31m";
	extractBytes(fp, 104, 4, title, true, true);
	title = "  \033[22;37m[\033[01;37m+\033[22;37m] Data Offset: \033[22;31m";
	extractBytes(fp, 108, 4, title, false, true);
	printf("\n");
}

void strings(FILE *fp) {
	unsigned int count = bytesToUint(fp, 56);
	unsigned int string_offset = bytesToUint(fp, 60);
	printf("\033[22;32mStrings:\n");
	unsigned int i, j, x;
	unsigned int offset_start, offset_end, string_length;
	unsigned char *current_string;
	offset_start = bytesToUint(fp, string_offset);
	for(i = 0; i < count - 1; i++) {
		x = 0;
		string_offset += 4;
		offset_end = bytesToUint(fp, string_offset);
		string_length = offset_end - offset_start;
		if(fseek(fp, offset_start, 0) == -1) {
			printf("Error setting the file pointer!\n\n");
			exit(1);
		}
		printf("\n  \033[22;37m[\033[01;37m%d\033[22;37m] ", i);
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
	printf("\033[22;32mJava Types & Classes:\n");
	unsigned int count = bytesToUint(fp, 64);
	unsigned int i, j;
	unsigned int type_id_list_offset = bytesToUint(fp, 68);
	for(i = 0; i < count; i++) {
		j = bytesToUint(fp, type_id_list_offset);
		printf("\n  \033[22;37m[\033[01;37m%d\033[22;37m] %s", i, strings_array[j]);
		types_array[i] = strings_array[j];
		type_id_list_offset += 4;
	}
	printf("\n\n");
}

void protos(FILE *fp) {
	printf("\033[22;32mPrototypes:\n");
	unsigned int count = bytesToUint(fp, 72);
	unsigned int proto_id_struct_offset = bytesToUint(fp, 76);
	unsigned int shorty_idx, return_type_idx, parameters_offset_start, parameters_offset_end;
	unsigned int i;
	for(i = 0; i < count; i++) {
		shorty_idx = bytesToUint(fp, proto_id_struct_offset);
		return_type_idx = bytesToUint(fp, proto_id_struct_offset + 4);
		//parameters_offset_start = bytesToUint(fp, proto_id_struct_offset + 8, 4);
		//parameters_offset_end = bytesToUint(fp, proto_id_struct_offset + 20, 4);
		//to be completed, have to value some things

		/* Save the prototype information in the protos_array */
		char *prototype_information = "ShortyDescriptor(\033[22;31m";
		prototype_information = strconcat(prototype_information, strings_array[shorty_idx]);
		prototype_information = strconcat(prototype_information, "\033[22;37m) Return Type(\033[22;31m");
		prototype_information = strconcat(prototype_information, types_array[return_type_idx]);
		prototype_information = strconcat(prototype_information, "\033[22;37m) Parameters()");
		protos_array[i] = prototype_information;
		/* Save end */
		proto_id_struct_offset += 12;
		printf("\n  \033[22;37m[\033[01;37m%d\033[22;37m] ShortyDescriptor(\033[22;31m%s\033[22;37m) Return Type(\033[22;31m%s\033[22;37m) Parameters()", i, strings_array[shorty_idx], types_array[return_type_idx]);
	}
	printf("\n\n");
}

void fields(FILE *fp) {
	printf("\033[22;32mFields:\n");
	unsigned int count = bytesToUint(fp, 80);
	unsigned int field_id_struct_offset = bytesToUint(fp, 84);
	unsigned int i;
	unsigned short class_idx, type_idx;
	unsigned int name_idx;
	for(i = 0; i < count; i++) {
		class_idx = bytesToUshort(fp, field_id_struct_offset);
		type_idx = bytesToUshort(fp, field_id_struct_offset + 2);
		name_idx = bytesToUint(fp, field_id_struct_offset + 4);
		field_id_struct_offset += 8;
		printf("\n  \033[22;37m[\033[01;37m%d\033[22;37m] Class(\033[22;31m%s\033[22;37m) Type(\033[22;31m%s\033[22;37m) Name(\033[22;31m%s\033[22;37m)", i, types_array[class_idx], types_array[type_idx], strings_array[name_idx]);
	}
	printf("\n\n");
}

void methods(FILE *fp) {
	printf("\033[22;32mMethods:\n");
	unsigned int count = bytesToUint(fp, 88);
	unsigned int method_struct_offset = bytesToUint(fp, 92);
	unsigned int i;
	unsigned short class_idx, proto_idx;
	unsigned int name_idx;
	for(i = 0; i < count; i++) {
		class_idx = bytesToUshort(fp, method_struct_offset);
		proto_idx = bytesToUshort(fp, method_struct_offset + 2);
		name_idx = bytesToUint(fp, method_struct_offset + 4);
		method_struct_offset += 8;
		printf("\n  \033[22;37m[\033[01;37m%d\033[22;37m] Class(\033[22;31m%s\033[22;37m) Prototype(%s) Name(\033[22;31m%s\033[22;37m)", i, types_array[class_idx], protos_array[proto_idx], strings_array[name_idx]);
	}
	printf("\n\n");
}

void initialize_arrays(FILE *fp) {
	//Strings array
	unsigned int count = bytesToUint(fp, 56);
	strings_array = (char **)malloc(count * sizeof(char *));
	strings(fp);
	//Types array
	count = bytesToUint(fp, 64);
	types_array = (char **)malloc(count * sizeof(char *));
	types(fp);
	//Prototypes array
	count = bytesToUint(fp, 72);
	protos_array = (char **)malloc(count * sizeof(char *));
	protos(fp);
	clear(); //<-- horrible
}

int main() {
	printf("\n\033[22;32m[~] DEX Information Extractor v1 [~]\n\n");
	char *dexFile;
	printf("\033[22;37mDEX name: \033[22;31m");
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
		printf("\033[22;32mSelect an option:\n\033[22;37m\n 1) Header\n 2) Strings\n 3) Types\n 4) Prototypes\n 5) Fields\n 6) Methods\n 7) Exit\n\n\033[22;32mChoice: \033[22;31m");
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
				fields(fp);
				break;
			case 6:
				methods(fp);
				break;
			case 7: 
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
