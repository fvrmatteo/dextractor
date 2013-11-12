#include "dextractor.h"

/* Utility Functions */

void clear() {
	system("clear");
}

void setOffset(FILE *fp, unsigned int offset) {
	if(fseek(fp, offset, 0) == -1) {
		printf("Error setting the file pointer!\n\n");
		exit(1);
	}
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

int potenza(int base, int esponente) {
	unsigned int i, res = 1;
	for(i = 0; i < esponente; i++) {
		res *= base;
	}
	return res;
}

unsigned short bytesToUshort(FILE *fp, unsigned int from) {
	setOffset(fp, from);
	unsigned int i;
	unsigned char bytes[2];
	for(i = 0; i < 2; i++) {
		bytes[i] = (unsigned char)fgetc(fp);
	}
	return (bytes[1] << 8 | bytes[0]);
}

unsigned int bytesToUint(FILE *fp, int from) {
	setOffset(fp, from);
	unsigned int i;
	unsigned char bytes[4];
	for(i = 0; i < 4; i++) {
		bytes[i] = (unsigned char)fgetc(fp);
	}
	return bytes[3] << 24 | bytes[2] << 16 | bytes[1] << 8 | bytes[0];
}

int * byteToBits(char byte) {
	unsigned int i;
	int *bits = (int *)malloc(sizeof(int) * 8);
	unsigned char mask = 1;
	for(i = 0; i < 8; i++) {
		bits[i] = (byte & (mask << i)) != 0;
	}
	return bits;
}

int uleb128ToUint(FILE *fp, int *from) {
	setOffset(fp, *from);
	int *bits, *temp = (int *)malloc(sizeof(int) * 8);
	int count = 1, i, j, a, y, z = 0, somma = 0;
	//aumenta il count finchè trova byte con il bit più significativo settato a 1
	while((bits = byteToBits(fgetc(fp)))[7] == 1) {
		count++;
	}
	int **converted = (int **)malloc(sizeof(int *) * count);
	fseek(fp, *from, 0);
	//aggiorno il puntatore al prossimo byte per una lettura futura
	*from += count;
	//inizializzo l'array "converted"
	for(i = 0; i < count; i++) {
		converted[i] = (int *)malloc(sizeof(int) * 7);
	}
	//inserisce nell'array "converted" tutti i byte che compongono il numero
	for(i = 0; i < count; i++) {
		temp = byteToBits(fgetc(fp));
		for(j = 0; j < 7; j++) {
			converted[i][j] = temp[j];
		}
	}
	//rovescia l'array (little-endian)
	for(i = 0; i < count; i++) {
		y = 6;
		for(j = 0; j < 4; j++) {
			a = converted[i][j];
			converted[i][j] = converted[i][y];
			converted[i][y--] = a;
		}
	}
	//calcola il numero
	for(i = 0; i < count; i++) {
		for(j = 6; j >= 0; j--) {
			if(converted[i][j] == 1) {
				somma += potenza(2, z);
			}
			z++;
		}
	}
	return somma;
}

/* Integrity Checks */

boolean verifyIntegrity(FILE *fp) {
	//Check the header size (it has always to be 70 byte long = 112 decimal)
	if(header_struct.header_size != 112) {
		header_corruption = true;
	}
	//Check if "method hiding" process is used
	unsigned int i, j, previous_idx_diff = -1, previous_code_off = -1;
	for(i = 0; i < header_struct.class_defs_size; i++) {
		for(j = 0; j < class_data_item_array[i].direct_method_size; j++) {
			if(direct_method_array[i][j].method_idx_diff == 0 && previous_code_off != -1 && (previous_code_off == direct_method_array[i][j].code_off || previous_idx_diff == 2)) {
				method_hiding = true;
			}
			previous_code_off = direct_method_array[i][j].code_off;
			previous_idx_diff = direct_method_array[i][j].method_idx_diff;
		}
		previous_code_off = -1;
		previous_idx_diff = -1;
		for(j = 0; j < class_data_item_array[i].virtual_method_size; j++) {
			if(virtual_method_array[i][j].method_idx_diff == 0 && previous_code_off != -1 && (previous_code_off == virtual_method_array[i][j].code_off || previous_idx_diff == 2)) {
				method_hiding = true;
			}
			previous_code_off = virtual_method_array[i][j].code_off;
			previous_idx_diff = virtual_method_array[i][j].method_idx_diff;
		}
	}

	//1) Class name > 255 chars
	//2) Detection of bad opcodes
	//3) Illegal pointers to type, strings, methods (pointer > table_size: alert)

	//Display the report
	printf("REPORT: ");
	if(header_corruption) {
		printf("\n- The DEX header is corrupted!\n");
	}
	if(method_hiding) {
		printf("\n- \"Method hiding\" process identified!\n");
	}
	if(!method_hiding && !header_corruption) {
		printf(" all seems to be OK!\n");
	}
	printf("\n");
}

void fixIntegrity(FILE *fp) {
	if(header_corruption) {
		header_struct.header_size = 112;
	}
	if(method_hiding) {
		unsigned int i, j, previous_idx_diff = -1, previous_code_off = -1;
		for(i = 0; i < header_struct.class_defs_size; i++) {
			for(j = 0; j < class_data_item_array[i].direct_method_size; j++) {
				if(direct_method_array[i][j].method_idx_diff == 0 && previous_code_off != -1 && (previous_code_off == direct_method_array[i][j].code_off || previous_idx_diff == 2)) {
					//fix method_idx and code_off
				}
				previous_code_off = direct_method_array[i][j].code_off;
				previous_idx_diff = direct_method_array[i][j].method_idx_diff;
			}
			previous_code_off = -1;
			previous_idx_diff = -1;
			for(j = 0; j < class_data_item_array[i].virtual_method_size; j++) {
				if(virtual_method_array[i][j].method_idx_diff == 0 && previous_code_off != -1 && (previous_code_off == virtual_method_array[i][j].code_off || previous_idx_diff == 2)) {
					//fix method_idx and code_off
				}
				previous_code_off = virtual_method_array[i][j].code_off;
				previous_idx_diff = virtual_method_array[i][j].method_idx_diff;
			}
		}
	}
	if(class_name_corruption) {
		//rename the class truncating part of it (total_chars < 255)
	}
	if(illegal_pointer) {
		//fix the pointer, by now I don't how
	}
	if(bad_opcodes) {
		//convert all invalid opcodes to 00
	}
}

/* Functions used to extract information from DEX structure */

void extractBytes(FILE *fp, unsigned int from, unsigned int length, char *title, boolean decimal, boolean revert) {
	setOffset(fp, from);
	unsigned int i;
	printf("%s", title);
	if(revert) {
		unsigned char *c = (unsigned char *)malloc(length * sizeof(unsigned char));
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
	header_struct.checksum = bytesToUint(fp, 8);
	header_struct.file_size = bytesToUint(fp, 32);
	header_struct.header_size = bytesToUint(fp, 36);
	header_struct.endian_tag = bytesToUint(fp, 40);
	header_struct.link_size = bytesToUint(fp, 44);
	header_struct.link_off = bytesToUint(fp, 48);
	header_struct.map_off = bytesToUint(fp, 52);
	header_struct.string_ids_size = bytesToUint(fp, 56);
	header_struct.string_ids_off = bytesToUint(fp, 60);
	header_struct.type_ids_size = bytesToUint(fp, 64);
	header_struct.type_ids_off = bytesToUint(fp, 68);
	header_struct.proto_ids_size = bytesToUint(fp, 72);
	header_struct.proto_ids_off = bytesToUint(fp, 76);
	header_struct.field_ids_size = bytesToUint(fp, 80);
	header_struct.field_ids_off = bytesToUint(fp, 84);
	header_struct.method_ids_size = bytesToUint(fp, 88);
	header_struct.method_ids_off = bytesToUint(fp, 92);
	header_struct.class_defs_size = bytesToUint(fp, 96);
	header_struct.class_defs_off = bytesToUint(fp, 100);
	header_struct.data_size = bytesToUint(fp, 104);
	header_struct.data_off = bytesToUint(fp, 108);
}

void header_view(FILE *fp) {
	printf("\033[22;32mHeader information:\n\n");
	extractBytes(fp, 0, 8, "  \033[22;37m[\033[01;37m+\033[22;37m] Magic: \033[22;31m", false, false);
	extractBytes(fp, 8, 4, "  \033[22;37m[\033[01;37m+\033[22;37m] Checksum: \033[22;31m", false, false);
	extractBytes(fp, 12, 20, "  \033[22;37m[\033[01;37m+\033[22;37m] Signature: \033[22;31m", false, false);
	extractBytes(fp, 32, 4, "  \033[22;37m[\033[01;37m+\033[22;37m] File Size: \033[22;31m", true, true);
	extractBytes(fp, 36, 4, "  \033[22;37m[\033[01;37m+\033[22;37m] Header Size: \033[22;31m", true, true);
	extractBytes(fp, 40, 4, "  \033[22;37m[\033[01;37m+\033[22;37m] Endian Tag: \033[22;31m", false, false);
	extractBytes(fp, 44, 4, "  \033[22;37m[\033[01;37m+\033[22;37m] Link Size: \033[22;31m", true, true);
	extractBytes(fp, 48, 4, "  \033[22;37m[\033[01;37m+\033[22;37m] Link Offset: \033[22;31m", false, true);
	extractBytes(fp, 52, 4, "  \033[22;37m[\033[01;37m+\033[22;37m] Map Offset: \033[22;31m", false, true);
	extractBytes(fp, 56, 4, "  \033[22;37m[\033[01;37m+\033[22;37m] String Ids Size: \033[22;31m", true, true);
	extractBytes(fp, 60, 4, "  \033[22;37m[\033[01;37m+\033[22;37m] String Ids Offset: \033[22;31m", false, true);
	extractBytes(fp, 64, 4, "  \033[22;37m[\033[01;37m+\033[22;37m] Type Ids Size: \033[22;31m", true, true);
	extractBytes(fp, 68, 4, "  \033[22;37m[\033[01;37m+\033[22;37m] Type Ids Offset: \033[22;31m", false, true);
	extractBytes(fp, 72, 4, "  \033[22;37m[\033[01;37m+\033[22;37m] Proto Ids Size: \033[22;31m", true, true);
	extractBytes(fp, 76, 4, "  \033[22;37m[\033[01;37m+\033[22;37m] Proto Ids Offset: \033[22;31m", false, true);
	extractBytes(fp, 80, 4, "  \033[22;37m[\033[01;37m+\033[22;37m] Field Ids Size: \033[22;31m", true, true);
	extractBytes(fp, 84, 4, "  \033[22;37m[\033[01;37m+\033[22;37m] Field Ids Offset: \033[22;31m", false, true);
	extractBytes(fp, 88, 4, "  \033[22;37m[\033[01;37m+\033[22;37m] Method Ids Size: \033[22;31m", true, true);
	extractBytes(fp, 92, 4, "  \033[22;37m[\033[01;37m+\033[22;37m] Method Ids Offset: \033[22;31m", false, true);
	extractBytes(fp, 96, 4, "  \033[22;37m[\033[01;37m+\033[22;37m] Class Defs Size: \033[22;31m", true, true);
	extractBytes(fp, 100, 4, "  \033[22;37m[\033[01;37m+\033[22;37m] Class Defs Offset: \033[22;31m", false, true);
	extractBytes(fp, 104, 4, "  \033[22;37m[\033[01;37m+\033[22;37m] Data Size: \033[22;31m", true, true);
	extractBytes(fp, 108, 4, "  \033[22;37m[\033[01;37m+\033[22;37m] Data Offset: \033[22;31m", false, true);
	printf("\n");
}

void strings(FILE *fp) {
	FILE *out = fopen("strings.txt", "a+");
	unsigned int string_offset = header_struct.string_ids_off;
	unsigned int i, j;
	unsigned int offset_start, offset_end, string_length;
	unsigned char *current_string;
	strings_array = (char **)malloc(header_struct.string_ids_size * sizeof(char *));
	offset_start = bytesToUint(fp, string_offset);
	for(i = 0; i < header_struct.string_ids_size; i++) {
		j = 0;
		string_offset += 4;
		offset_end = bytesToUint(fp, string_offset);
		string_length = offset_end - offset_start;
		setOffset(fp, offset_start);
		unsigned char c;
		current_string = (unsigned char *)malloc(sizeof(unsigned char) * string_length);
		while((c = fgetc(fp)) != '\0') {
			if(c == '\0') {
				break;
			} else {
				if((int)c < 0 || (int)c > 31 && c != '!' && c != '"' && c != '#' && c != '%' && c != '\'' && c != '&' && (c != ' ' || j != 0)) {
					current_string[j++] = c;
				}
			}
		}
		strings_array[i] = current_string;
		fprintf(out, "\033[22;37m[\033[01;37m%d\033[22;37m]%s\n", i, current_string);
		offset_start = offset_end;
	}
	fclose(out);
}

void strings_view() {
	printf("\033[22;32mStrings:\n");
	unsigned int i;
	for(i = 0; i < header_struct.string_ids_size; i++) {
		printf("\n  \033[22;37m[\033[01;37m%d\033[22;37m] %s", i, strings_array[i]);
	}
	
	printf("\n\n");
}

void types(FILE *fp) {
	FILE *out = fopen("types.txt", "a+");
	unsigned int i, j;
	unsigned int type_id_list_offset = header_struct.type_ids_off;
	types_array = (char **)malloc(header_struct.type_ids_size * sizeof(char *));
	for(i = 0; i < header_struct.type_ids_size; i++) {
		j = bytesToUint(fp, type_id_list_offset);
		types_array[i] = strings_array[j];
		type_id_list_offset += 4;
		fprintf(out, "%s\n", types_array[i]);
	}
	fclose(out);
}

void types_view() {
	printf("\033[22;32mTypes:\n");
	unsigned int i;
	for(i = 0; i < header_struct.type_ids_size; i++) {
		printf("\n  \033[22;37m[\033[01;37m%d\033[22;37m] %s", i, types_array[i]);
	}
	printf("\n\n");
}

void protos(FILE *fp) {
	unsigned int proto_id_struct_offset = header_struct.proto_ids_off;
	unsigned int i;
	protoID_array = (struct protoID *)malloc(sizeof(struct protoID) * header_struct.proto_ids_size);
	for(i = 0; i < header_struct.proto_ids_size; i++) {
		protoID_array[i].shorty_idx = bytesToUint(fp, proto_id_struct_offset);
		protoID_array[i].return_type_idx = bytesToUint(fp, proto_id_struct_offset + 4);
		protoID_array[i].parameters_off = bytesToUint(fp, proto_id_struct_offset + 8);
		proto_id_struct_offset += 12;
	}
}

void protos_view() {
	FILE *out = fopen("protos.txt", "a+");
	printf("\033[22;32mPrototypes:\n");
	unsigned int i;
	for(i = 0; i < header_struct.proto_ids_size; i++) {
		printf("\033[22;37m[\033[01;37m%d\033[22;37m] ShortyDescriptor(\033[22;31m%s\033[22;37m) Return Type(\033[22;31m%s\033[22;37m) Parameters()\n", i, strings_array[protoID_array[i].shorty_idx], types_array[protoID_array[i].return_type_idx]);
		fprintf(out, "\n  \033[22;37m[\033[01;37m%d\033[22;37m] ShortyDescriptor(\033[22;31m%s\033[22;37m) Return Type(\033[22;31m%s\033[22;37m) Parameters()", i, strings_array[protoID_array[i].shorty_idx], types_array[protoID_array[i].return_type_idx]);
	}
	fclose(out);
	printf("\n\n");
}

void fields(FILE *fp) {
	FILE *out = fopen("fields.txt", "a+");
	unsigned int field_id_struct_offset = header_struct.field_ids_off;
	unsigned int i;
	fieldID_array = (struct fieldID *)malloc(sizeof(struct fieldID) * header_struct.field_ids_size);
	for(i = 0; i < header_struct.field_ids_size; i++) {
		fieldID_array[i].class_idx = bytesToUshort(fp, field_id_struct_offset);
		fieldID_array[i].type_idx = bytesToUshort(fp, field_id_struct_offset + 2);
		fieldID_array[i].name_idx = bytesToUint(fp, field_id_struct_offset + 4);
		field_id_struct_offset += 8;
		fprintf(out, "\033[22;37m[\033[01;37m%d\033[22;37m] Class(\033[22;31m%s\033[22;37m) Type(\033[22;31m%s\033[22;37m) Name(\033[22;31m%s\033[22;37m)\n", i, types_array[fieldID_array[i].class_idx], types_array[fieldID_array[i].type_idx], strings_array[fieldID_array[i].name_idx]);
	}
	fclose(out);
}

void fields_view() {
	printf("\033[22;32mFields:\n");
	unsigned int i;
	for(i = 0; i < header_struct.field_ids_size; i++) {
		printf("\n  \033[22;37m[\033[01;37m%d\033[22;37m] Class(\033[22;31m%s\033[22;37m) Type(\033[22;31m%s\033[22;37m) Name(\033[22;31m%s\033[22;37m)", i, types_array[fieldID_array[i].class_idx], types_array[fieldID_array[i].type_idx], strings_array[fieldID_array[i].name_idx]);
	}
	printf("\n\n");
}

void methods(FILE *fp) {
	FILE *out = fopen("methods.txt", "a+");
	unsigned int method_struct_offset = header_struct.method_ids_off;
	unsigned int i;
	methodID_array = (struct methodID *)malloc(sizeof(struct methodID) * header_struct.method_ids_size);
	for(i = 0; i < header_struct.method_ids_size; i++) {
		methodID_array[i].class_idx = bytesToUshort(fp, method_struct_offset);
		methodID_array[i].proto_idx = bytesToUshort(fp, method_struct_offset + 2);
		methodID_array[i].name_idx = bytesToUint(fp, method_struct_offset + 4);
		method_struct_offset += 8;
		//Prototype to be printed
		fprintf(out, "\n  \033[22;37m[\033[01;37m%d\033[22;37m] Class(\033[22;31m%s\033[22;37m) Prototype() Name(\033[22;31m%s\033[22;37m)", i, types_array[methodID_array[i].class_idx], strings_array[methodID_array[i].name_idx]);
	
	}
	fclose(out);
}

void methods_view() {
	printf("\033[22;32mMethods:\n");
	unsigned int i;
	for(i = 0; i < header_struct.method_ids_size; i++) {
		//Prototype to be printed
		printf("\033[22;37m[\033[01;37m%d\033[22;37m] Class(\033[22;31m%s\033[22;37m) Prototype() Name(\033[22;31m%s\033[22;37m)\n", i, types_array[methodID_array[i].class_idx], strings_array[methodID_array[i].name_idx]);
	}
	printf("\n\n");
}

char * access_flags_table(unsigned int flag) {
	switch(flag) {
		case 0x1: return "public";
		case 0x2: return "private";
		case 0x4: return "protected";
		case 0x8: return "static";
		case 0x10: return "final";
		case 0x20: return "synchronized";
		case 0x40: return "volatile";
		case 0x80: return "transient";
		case 0x100: return "native";
		case 0x200: return "interface";
		case 0x400: return "abstract";
		case 0x800: return "strictfp";
		case 0x1000: return "ACC_SYNTHETIC";
		case 0x2000: return "ACC_ANNOTATION";
		case 0x4000: return "ACC_ENUM";
		case 0x10000: return "constructor";
		case 0x20000: return "ACC_DECLARED_SYNCHRINIZED";
	}
	return "Not identified";
}

void class_defs(FILE *fp) {
	unsigned int class_defs_offset = header_struct.class_defs_off;
	unsigned int i;
	class_data_array = (struct class_def *)malloc(header_struct.class_defs_size * sizeof(struct class_def));
	for(i = 0; i < header_struct.class_defs_size; i++) {
		class_data_array[i].class_idx = bytesToUint(fp, class_defs_offset);
		//access_flags to be fixed
		class_data_array[i].access_flags = bytesToUint(fp, class_defs_offset + 4);
		class_data_array[i].superclass_idx = bytesToUint(fp, class_defs_offset + 8);
		class_data_array[i].interfaces_off = bytesToUint(fp, class_defs_offset + 12);
		class_data_array[i].source_file_idx = bytesToUint(fp, class_defs_offset + 16);
		class_data_array[i].annotations_off = bytesToUint(fp, class_defs_offset + 20);
		class_data_array[i].class_data_off = bytesToUint(fp, class_defs_offset + 24);
		class_data_array[i].static_values_off = bytesToUint(fp, class_defs_offset + 28);
		class_defs_offset += 32;
	}
}

void class_defs_view() {
	printf("\033[22;32mClasses Definitions:\n");
	unsigned int i;
	for(i = 0; i < header_struct.class_defs_size; i++) {
		printf("\n  \033[22;37m[\033[01;37m%d\033[22;37m] Class: \033[22;31m%s\n", i, types_array[class_data_array[i].class_idx]);
		//access_flags_table() need to be fixed, bytes representation is ok
		printf("  \033[22;37m[\033[01;37m+\033[22;37m] Access Flag: \033[22;31m%s\n", access_flags_table(class_data_array[i].access_flags));
		printf("  \033[22;37m[\033[01;37m+\033[22;37m] Superclass: \033[22;31m%s\n", types_array[class_data_array[i].superclass_idx]);
		printf("  \033[22;37m[\033[01;37m+\033[22;37m] Source File: \033[22;31m%s\n", strings_array[class_data_array[i].source_file_idx]);
		printf("  \033[22;37m[\033[01;37m+\033[22;37m] Annotation Offset: \033[22;31m%d\n", class_data_array[i].annotations_off);
		printf("  \033[22;37m[\033[01;37m+\033[22;37m] Class Data Offset: \033[22;31m%d\n", class_data_array[i].class_data_off);
		printf("  \033[22;37m[\033[01;37m+\033[22;37m] Static Values Offset: \033[22;31m%d\n", class_data_array[i].static_values_off);
	}
	printf("\n\n");
}

void class_data_item(FILE *fp) {
	unsigned int i, j, counter = 0;
	struct encoded_field static_field, instance_fields;
	struct encoded_method direct_method, virtual_method;

	class_data_item_array = (struct class_data_item *)malloc(header_struct.class_defs_size * sizeof(struct class_data_item));

	static_field_array = (struct encoded_field **)malloc(header_struct.class_defs_size * sizeof(struct encoded_field *));
	instance_field_array = (struct encoded_field **)malloc(header_struct.class_defs_size * sizeof(struct encoded_field *));
	virtual_method_array = (struct encoded_method **)malloc(header_struct.class_defs_size * sizeof(struct encoded_method *));
	direct_method_array = (struct encoded_method **)malloc(header_struct.class_defs_size * sizeof(struct encoded_method *));

	for(i = 0; i < header_struct.class_defs_size; i++) {

		counter = class_data_array[i].class_data_off;

		class_data_item_array[i].static_fields_size = uleb128ToUint(fp, &counter);
		class_data_item_array[i].instance_fields_size = uleb128ToUint(fp, &counter);
		class_data_item_array[i].direct_method_size = uleb128ToUint(fp, &counter);
		class_data_item_array[i].virtual_method_size = uleb128ToUint(fp, &counter);

		static_field_array[i] = (struct encoded_field *)malloc(sizeof(struct encoded_field) * class_data_item_array[i].static_fields_size);
		instance_field_array[i] = (struct encoded_field *)malloc(sizeof(struct encoded_field) * class_data_item_array[i].instance_fields_size);
		direct_method_array[i] = (struct encoded_method *)malloc(sizeof(struct encoded_method) * class_data_item_array[i].direct_method_size);
		virtual_method_array[i] = (struct encoded_method *)malloc(sizeof(struct encoded_method) * class_data_item_array[i].virtual_method_size);

		for(j = 0; j < class_data_item_array[i].static_fields_size; j++) {
			static_field.field_idx_diff = uleb128ToUint(fp, &counter);
			static_field.access_flags = uleb128ToUint(fp, &counter);
			static_field_array[i][j] = static_field;
		}

		for(j = 0; j < class_data_item_array[i].instance_fields_size; j++) {
			instance_fields.field_idx_diff = uleb128ToUint(fp, &counter);
			instance_fields.access_flags = uleb128ToUint(fp, &counter);
			instance_field_array[i][j] = instance_fields;
		}

		for(j = 0; j < class_data_item_array[i].direct_method_size; j++) {
			direct_method.method_idx_diff = uleb128ToUint(fp, &counter);
			direct_method.access_flags = uleb128ToUint(fp, &counter);
			direct_method.code_off = uleb128ToUint(fp, &counter);
			direct_method_array[i][j] = direct_method;
		}

		for(j = 0; j < class_data_item_array[i].virtual_method_size; j++) {
			virtual_method.method_idx_diff = uleb128ToUint(fp, &counter);
			virtual_method.access_flags = uleb128ToUint(fp, &counter);
			virtual_method.code_off = uleb128ToUint(fp, &counter);
			virtual_method_array[i][j] = virtual_method;
		}
	}
}

void class_data_item_view() {
	printf("\033[22;32mClass Data Items:\033[22;37m\n");
	unsigned int i, j;
	for(i = 0; i < header_struct.class_defs_size; i++) {
		printf("\n\n  \033[22;37m[\033[01;37m%d\033[22;37m] %s\n\n", i, types_array[class_data_array[i].class_idx]);
		printf("  Static Fields Size: \033[22;31m%d\033[22;37m\n", class_data_item_array[i].static_fields_size);
		printf("  Instance Fields Size: \033[22;31m%d\033[22;37m\n", class_data_item_array[i].instance_fields_size);
		printf("  Direct Methods Size: \033[22;31m%d\033[22;37m\n", class_data_item_array[i].direct_method_size);
		printf("  Virtual Methods Size: \033[22;31m%d\033[22;37m\n", class_data_item_array[i].virtual_method_size);

		
		for(j = 0; j < class_data_item_array[i].static_fields_size; j++) {
			if(j == 0) {
				printf("\n  \033[22;32mStatic Fields:\033[22;37m \n");
			}
			printf("\n    field_idx_diff: \033[22;31m%d\033[22;37m\n", static_field_array[i][j].field_idx_diff);
			printf("    access_flags: \033[22;31m%s\033[22;37m\n", access_flags_table(static_field_array[i][j].access_flags));
		}

		for(j = 0; j < class_data_item_array[i].instance_fields_size; j++) {
			if(j == 0) {
				printf("\n  \033[22;32mInstance Fields:\033[22;37m \n");
			}
			printf("\n    field_idx_diff: \033[22;31m%d\033[22;37m\n", instance_field_array[i][j].field_idx_diff);
			printf("    access_flags: \033[22;31m%s\033[22;37m\n", access_flags_table(instance_field_array[i][j].access_flags));
		}

		for(j = 0; j < class_data_item_array[i].direct_method_size; j++) {
			if(j == 0) {
				printf("\n  \033[22;32mDirect Methods:\033[22;37m \n");
			}
			printf("\n    method_idx_diff: \033[22;31m%d\033[22;37m\n", direct_method_array[i][j].method_idx_diff);
			printf("    access_flags: \033[22;31m%s\033[22;37m\n", access_flags_table(direct_method_array[i][j].access_flags));
			printf("    code_off: \033[22;31m%d\033[22;37m\n", direct_method_array[i][j].code_off);
		}

		for(j = 0; j < class_data_item_array[i].virtual_method_size; j++) {
			if(j == 0) {
				printf("\n  \033[22;32mVirtual Methods:\033[22;37m \n");
			}
			printf("\n    method_idx_diff: \033[22;31m%d\033[22;37m\n", virtual_method_array[i][j].method_idx_diff);
			printf("    access_flags: \033[22;31m%s\033[22;37m\n", access_flags_table(virtual_method_array[i][j].access_flags));
			printf("    code_off: \033[22;31m%d\033[22;37m\n", virtual_method_array[i][j].code_off);
		}
	}
	printf("\n\n");
}

void code_item(FILE *fp) {
	unsigned int i, j, z, y, totByte;
	unsigned int offset = 0;
	code_item_array = (struct code_item **)malloc(sizeof(struct code_item *) * header_struct.class_defs_size);
	for(i = 0; i < header_struct.class_defs_size; i++) {
		code_item_array[i] = (struct code_item *)malloc(sizeof(struct code_item) * (class_data_item_array[i].direct_method_size + class_data_item_array[i].virtual_method_size));
		for(j = 0; j < class_data_item_array[i].direct_method_size; j++) {
			if((offset = direct_method_array[i][j].code_off) > 0) {
				code_item_array[i][j].registers_size = bytesToUshort(fp, offset);
				code_item_array[i][j].ins_size = bytesToUshort(fp, offset + 2);
				code_item_array[i][j].outs_size = bytesToUshort(fp, offset + 4);
				code_item_array[i][j].tries_size = bytesToUshort(fp, offset + 6);
				code_item_array[i][j].debug_info_off = bytesToUint(fp, offset + 8);
				code_item_array[i][j].insns_size = bytesToUint(fp, offset + 12);
				code_item_array[i][j].insns = (unsigned char *)malloc(code_item_array[i][j].insns_size * sizeof(unsigned char) * 2);
				//bytecode extraction
				totByte = code_item_array[i][j].insns_size * 2;
				setOffset(fp, offset + 16);
				for(y = 0; y < totByte; y++) {
					code_item_array[i][j].insns[y] = fgetc(fp);
				}
				if(code_item_array[i][j].tries_size > 0) {
					code_item_array[i][j].padding = bytesToUshort(fp, offset + 16 + code_item_array[i][j].insns_size);
				}
			}
		}
		for(z = 0; z < class_data_item_array[i].virtual_method_size; z++) {
			if((offset = virtual_method_array[i][z].code_off) > 0) {
				code_item_array[i][j].registers_size = bytesToUshort(fp, offset);
				code_item_array[i][j].ins_size = bytesToUshort(fp, offset + 2);
				code_item_array[i][j].outs_size = bytesToUshort(fp, offset + 4);
				code_item_array[i][j].tries_size = bytesToUshort(fp, offset + 6);
				code_item_array[i][j].debug_info_off = bytesToUint(fp, offset + 8);
				code_item_array[i][j].insns_size = bytesToUint(fp, offset + 12);
				code_item_array[i][j].insns = (unsigned char *)malloc(code_item_array[i][j].insns_size * sizeof(unsigned char) * 2);
				//bytecode extraction
				totByte = code_item_array[i][j].insns_size * 2;
				setOffset(fp, offset + 16);
				for(y = 0; y < totByte; y++) {
					code_item_array[i][j].insns[y] = fgetc(fp);
				}
				if(code_item_array[i][j].tries_size > 0) {
					code_item_array[i][j].padding = bytesToUshort(fp, offset + 16 + code_item_array[i][j].insns_size);
				}
				j++;
			}
		}
	}
}

void code_item_view() {
	printf("\033[22;32mClass Code Items:\033[22;37m\n");
	unsigned int i, j;
	for(i = 0; i < header_struct.class_defs_size; i++) {
		printf("\n\n  \033[22;37m[\033[01;37m%d\033[22;37m] %s\n", i, types_array[class_data_array[i].class_idx]);
		for(j = 0; j < class_data_item_array[i].direct_method_size; j++) {
			if(j == 0) {
				printf("\n  \033[22;32mDirect Methods:\033[22;37m \n");
			}
			printf("    [+] Registers Size: \033[22;31m%d\033[22;37m\n", code_item_array[i][j].registers_size);
			printf("    [+] Ins Size: \033[22;31m%d\033[22;37m\n", code_item_array[i][j].ins_size);
			printf("    [+] Outs Size: \033[22;31m%d\033[22;37m\n", code_item_array[i][j].outs_size);
			printf("    [+] Tries Size: \033[22;31m%d\033[22;37m\n", code_item_array[i][j].tries_size);
			printf("    [+] Debug Info Offset: \033[22;31m%d\033[22;37m\n", code_item_array[i][j].debug_info_off);
			printf("    [+] Insns Size: \033[22;31m%d\033[22;37m\n", code_item_array[i][j].insns_size);
			printf("    [+] Padding: \033[22;31m%d\033[22;37m\n\n", code_item_array[i][j].padding);
		}
		for(j = class_data_item_array[i].direct_method_size; j < (class_data_item_array[i].virtual_method_size + class_data_item_array[i].direct_method_size); j++) {
			if(j == class_data_item_array[i].direct_method_size) {
				printf("\n  \033[22;32mVirtual Methods:\033[22;37m \n");
			}
			printf("    [+] Registers Size: \033[22;31m%d\033[22;37m\n", code_item_array[i][j].registers_size);
			printf("    [+] Ins Size: \033[22;31m%d\033[22;37m\n", code_item_array[i][j].ins_size);
			printf("    [+] Outs Size: \033[22;31m%d\033[22;37m\n", code_item_array[i][j].outs_size);
			printf("    [+] Tries Size: \033[22;31m%d\033[22;37m\n", code_item_array[i][j].tries_size);
			printf("    [+] Debug Info Offset: \033[22;31m%d\033[22;37m\n", code_item_array[i][j].debug_info_off);
			printf("    [+] Insns Size: \033[22;31m%d\033[22;37m\n", code_item_array[i][j].insns_size);
			printf("    [+] Padding: \033[22;31m%d\033[22;37m\n\n", code_item_array[i][j].padding);
		}
	}
	printf("\n\n");
}

/*void decompile() {
	unsigned int i, j, z, size;
	char *opcode = malloc(sizeof(char) * 50);
	char parameter[2];
	for(i = 0; i < header_struct.class_defs_size; i++) {
		for(j = 0; j < (class_data_item_array[i].direct_method_size + class_data_item_array[i].virtual_method_size); j++) {
			if((size = code_item_array[i][j].insns_size) > 0) {
				for(z = 0; z < size; z++) {
					switch((unsigned int)code_item_array[i][j].insns[z]) {
						case 0: 
							opcode = "nop";
							break;
						case 1: 
							opcode = "move ";
							sprintf(parameter, "%02x", code_item_array[i][j].insns[++z]);
							opcode = strconcat(opcode, parameter);
							opcode = strconcat(opcode, ", ");
							sprintf(parameter, "%02x", code_item_array[i][j].insns[++z]);
							opcode = strconcat(opcode, parameter);
							break;
						case 2:
							opcode = "move/from16 ";
							sprintf(parameter, "%02x", code_item_array[i][j].insns[++z]);
							opcode = strconcat(opcode, parameter);
							opcode = strconcat(opcode, ", ");
							sprintf(parameter, "%02x", code_item_array[i][j].insns[++z]);
							opcode = strconcat(opcode, parameter);
							break;
						case 3:
							opcode = "move/16 ";
							sprintf(parameter, "%02x", code_item_array[i][j].insns[++z]);
							opcode = strconcat(opcode, parameter);
							opcode = strconcat(opcode, ", ");
							sprintf(parameter, "%02x", code_item_array[i][j].insns[++z]);
							opcode = strconcat(opcode, parameter);
							break;
						case 4:
							opcode = "move-wide ";
							break;
						case 5:
							opcode = "move-wide/from16 ";
							sprintf(parameter, "%02x", code_item_array[i][j].insns[++z]);
							opcode = strconcat(opcode, parameter);
							opcode = strconcat(opcode, ", ");
							sprintf(parameter, "%02x", code_item_array[i][j].insns[++z]);
							opcode = strconcat(opcode, parameter);
							break;
						case 6:
							break;
					}
					printf("%s\n", opcode);
				}
			}
		}
	}
}*/

void initialize(FILE *fp) {
	//Header
	header(fp);
	//Strings array
	strings(fp);
	//Types array
	types(fp);
	//Fields
	fields(fp);
	//Prototypes array
	protos(fp);
	//Methods
	methods(fp);
	//Class Data array
	class_defs(fp);
	//Class Data Item array
	class_data_item(fp);
	//Code Item
	code_item(fp);
}

void deleteTemp() {
	system("rm -f header.txt strings.txt types.txt protos.txt fields.txt methods.txt");
}

void search() {
	printf("\033[22;37mType the string to search:\033[22;31m ");
	char string[80];
	scanf("%s", string);
	char *command = "grep \"";
	command = strconcat(command, string);
	printf("\nSelect where to search:\n\033[22;37m 1) Strings\n 2) Types\n 3) Protos\n 4) Fields\n 5) Methods\n\nChoice: ");
	unsigned int choice;
	scanf("%i", &choice);
	printf("\n\n\033[22;32mOutput:\n\n");
	switch(choice) {
		case 1:
			command = strconcat(command, "\" strings.txt");
			break;
		case 2:
			command = strconcat(command, "\" types.txt");
			break;
		case 3:
			command = strconcat(command, "\" protos.txt");
			break;
		case 4:
			command = strconcat(command, "\" fields.txt");
			break;
		case 5:
			command = strconcat(command, "\" methods.txt");
			break;
		default:
			command = strconcat(command, "\" strings.txt");
			printf("Wrong input: selected \"strings.txt\"!\n\n");
	}
	system(command);
	printf("\n\n");
}

int main() {
	printf("\n\033[22;32m[~] DEX Information Extractor v1 {by Nihilus} [~]\n\n");
	printf("\033[22;37mDEX name: \033[22;31m");
	char *dexFile;
	scanf("%s", dexFile);
	clear();
	FILE *fp;
	fp = fopen(dexFile, "r");
	if(fp == NULL) {
		printf("\nFile not found!\n\n");
		exit(1);
	}
	initialize(fp);
	verifyIntegrity(fp);
	unsigned int choice;
	boolean running = true;
	while(running) {
		printf("\033[22;32mSelect an option:\n\033[22;37m\n 1) Header\n 2) Strings\n 3) Types\n 4) Prototypes\n 5) Fields\n 6) Methods\n 7) Class Defs\n 8) Class Items\n 9) Code Item\n 10) Search\n 0) Exit\n\n\033[22;32mChoice: \033[22;31m");
		scanf("%i", &choice);
		clear();
		switch(choice) {
			case 1: 
				header_view(fp);
				break;
			case 2: 
				strings_view();
				break;
			case 3:
				types_view();
				break;
			case 4:
				protos_view();
				break;
			case 5:
				fields_view();
				break;
			case 6:
				methods_view();
				break;
			case 7:
				class_defs_view();
				break;
			case 8:
				class_data_item_view();
				break;
			case 9:
				code_item_view();
				break;
			/*case 10:
				decompile();*/
				break;
			case 10:
				search();
				break;
			case 0: 
				deleteTemp();
				fclose(fp);
				running = false;
				break;
			default: 
				printf("You have entered an invalid choice!\n\n");
		}
	}
	return 0;
}
