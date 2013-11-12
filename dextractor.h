#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned int boolean;
#define true 1
#define false 0

boolean header_corruption = false, method_hiding = false, class_name_corruption = false, bad_opcodes = false, illegal_pointer = false;

char **strings_array;
char **types_array;

/* Header */

struct header_struct {
	unsigned char magic[8];
	int checksum;
	unsigned char signature[20];
	unsigned int file_size;
	unsigned int header_size;
	unsigned int endian_tag;
	unsigned int link_size;
	unsigned int link_off;
	unsigned int map_off;
	unsigned int string_ids_size;
	unsigned int string_ids_off;
	unsigned int type_ids_size;
	unsigned int type_ids_off;
	unsigned int proto_ids_size;
	unsigned int proto_ids_off;
	unsigned int field_ids_size;
	unsigned int field_ids_off;
	unsigned int method_ids_size;
	unsigned int method_ids_off;
	unsigned int class_defs_size;
	unsigned int class_defs_off;
	unsigned int data_size;
	unsigned int data_off;
} header_struct;

/* ProtoID */

struct protoID {
	unsigned int shorty_idx;
	unsigned int return_type_idx;
	unsigned int parameters_off;
};
struct protoID *protoID_array;

/* FieldID */

struct fieldID {
	unsigned short class_idx;
	unsigned short type_idx;
	unsigned int name_idx;
};
struct fieldID *fieldID_array;

/* MethodID */

struct methodID {
	unsigned short class_idx;
	unsigned short proto_idx;
	unsigned int name_idx;
};
struct methodID *methodID_array;

/* Class Def */

struct class_def {
	unsigned int class_idx;
	unsigned int access_flags;
	unsigned int superclass_idx;
	unsigned int interfaces_off;
	unsigned int source_file_idx;
	unsigned int annotations_off;
	unsigned int class_data_off;
	unsigned int static_values_off;
};
struct class_def *class_data_array;

/* Class Data Item */

struct class_data_item {
	unsigned int static_fields_size;
	unsigned int instance_fields_size;
	unsigned int direct_method_size;
	unsigned int virtual_method_size;
};
struct class_data_item *class_data_item_array;

/* Encoded Field */

struct encoded_field {
	unsigned int field_idx_diff;
	unsigned int access_flags;
};
struct encoded_field **static_field_array, **instance_field_array;

/* Encoded Method */

struct encoded_method {
	unsigned int method_idx_diff;
	unsigned int access_flags;
	unsigned int code_off;
};
struct encoded_method **direct_method_array, **virtual_method_array;

/* Code Item */

struct code_item {
	unsigned short registers_size;
	unsigned short ins_size;
	unsigned short outs_size;
	unsigned short tries_size;
	unsigned int debug_info_off;
	unsigned int insns_size;
	unsigned char *insns;
	unsigned short padding;
	//try_item
	unsigned int start_addr;
	unsigned short insn_count;
	unsigned short handler_off;
	//encoded_catch_handler_list
	unsigned int size_handler_list;
	//encoded_catch_handler
	unsigned int size_handler;
	//encoded_type_addr_type
	unsigned int type_idx;
	unsigned int addr;
	unsigned int catch_all_addr;
};
struct code_item **code_item_array;