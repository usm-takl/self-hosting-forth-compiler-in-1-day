#include<stdio.h>
#include<stdlib.h>
#include<inttypes.h>
#include<windows.h>
#include<sys/stat.h>

static uint8_t *mem;

#define import           (mem+0x200)
#define import_limit     (mem+0x300)
#define startup          (mem+0x300)
#define startup_limit    (mem+0x320)
#define c_to_ft          (mem+0x320)
#define c_to_ft_limit    (mem+0x330)
#define word_definitions (mem+0x400)

#define ftmain (*(uint64_t *)(mem+0x3a8))
#define state  (*(uint64_t *)(mem+0x3b0))
#define fin    (*(FILE **)(mem+0x3b8))
#define token  ((char *)(mem+0x3c0))
#define mrd1   (*(uint8_t **)(mem+0x3e0))
#define mrd2   (*(uint8_t **)(mem+0x3e8))
#define ep     (*(uint8_t **)(mem+0x3f0))

#define WORD_SIZE(word) (((uint64_t *)(word))[-1])
#define WORD_HEAD(word) ((uint8_t *)(word)-WORD_SIZE(word))
#define WORD_NAME(word) ((char *)WORD_HEAD(word))
#define WORD_IMMEDIATE(word) (*(uint64_t *)(WORD_HEAD(word)+32))
#define WORD_BODY(word) (WORD_HEAD(word)+40)

#define B(b) (*(uint8_t *)ep=(uint8_t)(b),ep+=1)
#define D(d) (*(uint32_t *)ep=(uint32_t)(d),ep+=4)
#define Q(q) (*(uint64_t *)ep=(uint64_t)(q),ep+=8)

static void begin_def(const char *name, int immediate) {
  ep = mrd2;
  strncpy((char *)ep, name, 32); ep+=32;
  Q(immediate);
}

static void end_def(void) {
  Q(ep - mrd2 + 8);
  mrd2 = ep;
  ep = 0;
}

#define WORD_PREV(word) ((uint8_t *)(word)-WORD_SIZE(word))

static uint8_t *find_word(const char *name) {
  uint8_t *word = mrd2;
  while (WORD_SIZE(word)) {
    if (!strcmp(WORD_NAME(word), name)) return word;
    word = WORD_PREV(word);
  }
  return 0;
}

static void def_cfun(const char *name, void *cfun, int immediate) {
  begin_def(name, immediate);
  B(0x48),B(0x89),B(0xe5);         // MOV RBP, RSP
  B(0x48),B(0x83),B(0xec),B(0x20); // SUB RSP, 32
  B(0x48),B(0x83),B(0xe4),B(0xf0); // AND RSP, ~0xf0
  B(0x48),B(0xb8),Q(cfun);         // MOV RAX, cfun
  B(0xff),B(0xd0);                 // CALL RAX
  B(0x48),B(0x89),B(0xec);         // MOV RSP, RBP
  B(0xc3);                         // RET
  end_def();
}

static uint8_t *sp;

static void execute(uint8_t *word) {
  sp = ((uint8_t *(*)(uint8_t *,uint8_t *))c_to_ft)(WORD_BODY(word),sp);
}

static void write_hex(uint8_t *outp, uint8_t *limit, const char *data) {
  for (int i = 0; data[i]; i += 3, ++outp) {
    if (limit <= outp) {
      printf("error: too many data: write_hex\n");
      exit(EXIT_FAILURE);
    }
    *outp = strtol(&data[i], 0, 16);
  }
}

static void parse_name(void) {
  token[0] = '\0';
  fscanf(fin, "%31s%*[^ \t\n\r]", token);
  getc(fin);
}

static void perform_compilation_semantics(uint8_t *word) {
  if (WORD_IMMEDIATE(word)) {
    execute(word);
  } else {
    B(0xe8),D(WORD_BODY(word) - (ep + 4)); // CALL rel32
  }
}

static void perform_interpretation_semantics(uint8_t *word) {
  execute(word);
}

static void text_interpreter(void) {
  while (1) {
    parse_name();
    if (token[0] == '\0') return;

    uint8_t *word = find_word(token);
    if (word) {
      if (state) {
        perform_compilation_semantics(word);
      } else {
        perform_interpretation_semantics(word);
      }
      continue;
    }

    char *p;
    long long i = strtoll(token, &p, 0);
    if (!*p) {
      if (state) {
        B(0x48),B(0x83),B(0xeb),B(0x08); // SUB RBX, 8
        B(0x48),B(0xb8),Q(i);            // MOV RAX, i
        B(0x48),B(0x89),B(0x03);         // MOV [RBX], RAX
      } else {
        sp -= 8;
        *(int64_t *)sp = i;
      }
      continue;
    }

    printf("undefined word: %s\n", token);
    exit(EXIT_FAILURE);
  }
}

static void colon(void) {
  parse_name();
  begin_def(token, 0);
  state = 1;
}

static void semicolon(void) {
  B(0xc3);
  end_def();
  state = 0;
}

static void paren(void) {
  while (1) {
    int c = getc(fin);
    if (c == EOF || c == ')') return;
  }
}

static void X(void) {
  parse_name();
  B(strtol(token, 0, 0));
}

static void print_rcx_as_int(uint64_t n) {
  printf("%" PRId64, n);
  fflush(stdout);
}

static void s_quote(void) {
  B(0x48),B(0x83),B(0xeb),B(0x08); // SUB RBX, 8
  B(0x48),B(0x8d),B(0x05),D(8);    // LEA RAX, [RIP+8]
  B(0x48),B(0x89),B(0x03);         // MOV [RBX], RAX
  B(0xe9),D(0);                    // JMP REL32
  uint8_t *rel32 = ep;

  while (1) {
    int c = getc(fin);
    if (c == EOF || c == '"') break;
    if (c == '\\') c = getc(fin); // \" を " として出力できるようにする
    B(c);
  }
  B(0);

  *(uint32_t *)(rel32 - 4) = ep - rel32;
}

static void print_rcx_as_cstr(const char *s) {
  printf("%s", s);
  fflush(stdout);
}

static void save(const char *filename) {
  IMAGE_DOS_HEADER *idh = (IMAGE_DOS_HEADER *)mem;
  idh->e_magic = 0x5a4d; // MZ
  idh->e_lfanew = sizeof(IMAGE_DOS_HEADER);

  IMAGE_NT_HEADERS64 *inh = (IMAGE_NT_HEADERS64 *)(idh + 1);
  inh->Signature = 0x4550; // PE
  inh->FileHeader.Machine = 0x8664; // x86_64
  inh->FileHeader.NumberOfSections = 1;
  inh->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
  inh->FileHeader.Characteristics = 2; // executable
  inh->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  inh->OptionalHeader.AddressOfEntryPoint = startup - mem + 0x1000;
  inh->OptionalHeader.ImageBase = 0x400000;
  inh->OptionalHeader.SectionAlignment = 0x1000;
  inh->OptionalHeader.FileAlignment = 0x200;
  inh->OptionalHeader.MajorSubsystemVersion = 5;
  inh->OptionalHeader.SizeOfImage = 0x1000 + 0xa0000 + 0xa0000;
  inh->OptionalHeader.SizeOfHeaders =
    idh->e_lfanew + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER);
  inh->OptionalHeader.Subsystem = 3; // CUI
  inh->OptionalHeader.NumberOfRvaAndSizes = 16;
  inh->OptionalHeader.DataDirectory[1].Size = 1;
  inh->OptionalHeader.DataDirectory[1].VirtualAddress = 0x1200;

  IMAGE_SECTION_HEADER *ish = (IMAGE_SECTION_HEADER *)(inh + 1);
  memcpy(ish->Name, ".idata\0\0", 8);
  ish->Misc.VirtualSize = 0xa0000 + 0xa0000;
  ish->VirtualAddress = 0x1000;
  ish->SizeOfRawData = 0xa0000;
  ish->PointerToRawData = 0x200;
  ish->Characteristics = 0xe0000060;

  static const char *import_image =
    //0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
    "70 12 00 00 00 00 00 00 00 00 00 00 30 12 00 00 " // 40120x
    "90 12 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " // 40121x
    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " // 40122x
    "6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 00 00 00 " // 40123x kernel32.dll
    "00 00 4c 6f 61 64 4c 69 62 72 61 72 79 41 00 00 " // 40124x LoadLibraryA
    "00 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 00 " // 40125x GetProcAddress
    "00 00 45 78 69 74 50 72 6f 63 65 73 73 00 00 00 " // 40126x ExitProcess
    "40 12 00 00 00 00 00 00 4f 12 00 00 00 00 00 00 " // 40127x INT
    "60 12 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " // 40128x INT
    "40 12 00 00 00 00 00 00 4f 12 00 00 00 00 00 00 " // 40129x IAT
    "60 12 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " // 4012ax IAT
    ;
  write_hex(import, import_limit, import_image);
  
  static const char *startup_image =
    "bb 00 10 4a 00 " // MOV EBX, 0x4a1000
    "b8 a8 13 40 00 " // MOV EAX, 0x4013a8 (ftmain)
    "ff 10 "          // CALL [RAX]
    "b8 a0 12 40 00 " // MOV EAX, 0x4012a0 (ExitProcess)
    "ff 10 "          // CALL [RAX]
    ;
  write_hex(startup, startup_limit, startup_image);

  uint8_t *main_ = find_word("main");
  if (!main_) {
    printf("error: cannot find 'main'\n");
    exit(EXIT_FAILURE);
  }

  ftmain = WORD_BODY(main_) - mem + 0x401000;
  mrd1 = (uint8_t *)(mrd2 - mem + 0x401000);
  mrd2 = (uint8_t *)0x4a1400;

  FILE *fp = fopen(filename, "wb");
  fwrite(mem, 1, 0x200, fp);
  fwrite(mem, 1, 640 * 1024, fp);
  fclose(fp);
  chmod(filename, 0777);
}

void init() {
  mem = VirtualAlloc(0, 640 * 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  mrd2 = word_definitions;
  sp = mem + 640 * 1024;
  static const char *c_to_ft_image =
    "53 "       // PUSH RBX
    "55 "       // PUSH RBP
    "48 89 d3 " // MOV RBX, RDX
    "ff d1 "    // CALL RCX
    "48 89 d8 " // MOV RAX, RBX
    "5d "       // POP RBP
    "5b "       // POP RBX
    "c3 "       // RET
    ;
  write_hex(c_to_ft, c_to_ft_limit, c_to_ft_image);

  def_cfun(":", colon, 0);
  def_cfun(";", semicolon, 1);
  def_cfun("(", paren, 1);
  def_cfun("X", X, 1);
  def_cfun("print-rcx-as-int", print_rcx_as_int, 0);
  def_cfun("s\"", s_quote, 1);
  def_cfun("print-rcx-as-cstr", print_rcx_as_cstr, 0);

  begin_def("base+", 0);
  B(0x48),B(0x8d),B(0x05),D(mem - (ep + 4)); // LEA RAX, [RIP - mem]
  B(0x48),B(0x01),B(0x03);                   // ADD [RBX], RAX
  B(0xc3);
  end_def();
  // 以下、「init() に追加」とあったら、このコメントの上にコードを追加してくだい。
}

int main(int argc, char **argv) {
  init();
  fin = stdin;
  text_interpreter();
  if (1 < argc) save(argv[1]);
  return 0;
}
