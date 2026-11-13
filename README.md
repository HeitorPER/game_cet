# Game, CET, Match — WolvCTF 2024 · Pwn · `game_cet`

Bypass de **Intel CET** (IBT + Shadow Stack) por uma falha de **lógica**.
Este repositório implementa, em código, a cadeia de exploração descrita nos
slides e no roteiro de apresentação do grupo.

> **Equipe:** Heitor Peretti · Caio Miyaji · Pedro Cappelini · Daniel Nakano ·
> Lucas Sufredini · João Victor Mauad · Gustavo Bragaia

## Arquivos

| Arquivo    | O que é |
|------------|---------|
| `solve.py` | Exploit em pwntools. Implementa a cadeia completa (vazamento → forjar `system` no `banter` → disparo). Cada etapa aponta o slide correspondente. |
| `chal.c`   | Reconstrução do binário vulnerável (não é o fonte original — o CTF só entrega o binário). Serve para mostrar **onde está o bug** e **como se corrige**. |

## A ideia em uma frase

O "win" óbvio (`hear_taunt` → `execve`) e até o `execve` da GOT estão bloqueados
pelo CET (IBT exige `ENDBR64` no destino; não controlamos `RSI`/`RDX`). O caminho
que o CET **permite** é chamar `system("/bin/sh")` — um argumento só (o `RDI`, que
controlamos) e começa com `ENDBR64` na libc. Como `system` não está na GOT, nós o
**forjamos** dentro do global `banter` e chamamos o índice dele.

## A cadeia (mapeada aos slides)

1. **Bug (04-05):** `ptrs[(int)option - 1](arg)` — índice `strtol` com sinal e sem
   validação + `RDI = resto da linha`. Permite chamar qualquer ponteiro relativo
   ao binário (GOT, `banter`) com o 1º argumento controlado.
2. **Por que o win falha (06-10):** IBT barra `hear_taunt` (sem `ENDBR64`); `execve`
   da GOT falha por `RDX` não-nulo. Alvo ideal = função de **1 argumento**: `system`.
3. **Vazamento (11):** `printf` da GOT + format string. `%p` → base do binário (PIE);
   `%s` → ler a GOT → endereços reais da libc → identificar a libc → `system`.
4. **A sacada (12-13):** escrever o endereço de `system` no `banter` byte a byte —
   `taunt` grava um byte (OR), `lob` desloca 8 bits, 6 vezes.
5. **Disparo (14):** chamar o índice do `banter` com `RDI = "/bin/sh"` →
   `system("/bin/sh")`, **aprovado pelo IBT** → shell → flag.

```
wctf{y0u_c4nt_b3_s3r1ous_appr0ved_g4dg3t5_0nly}
```

## Como rodar

O repositório traz apenas o **fonte** (`chal.c`); o binário `./chal` precisa ser
compilado antes de rodar o exploit.

```bash
# 1) ambiente Python isolado (ver "Problemas conhecidos" sobre o unicorn)
python -m venv .venv
.venv/bin/pip install pwntools "unicorn==2.1.1"   # (opcional: LibcSearcher)

# 2) compilar o binario vulneravel com as protecoes + Intel CET
gcc chal.c -o chal -fcf-protection=full -fstack-protector-all \
    -Wl,-z,relro,-z,now -pie -fPIE -O1

# 3) rodar o exploit
.venv/bin/python solve.py          # local, contra ./chal
.venv/bin/python solve.py REMOTE   # remoto (ajuste HOST/PORT em solve.py)
.venv/bin/python solve.py GDB      # local sob gdb
```

Saída esperada no final: vazamento da base do PIE e da libc, `system` resolvido,
`popping a shell` e um shell interativo.

## Problemas conhecidos

Problemas que aparecem ao montar o ambiente e rodar o desafio:

- **`pip install` falha com `externally-managed-environment` (Arch/PEP 668).**
  Não é erro de permissão: o Python do sistema bloqueia instalação direta. Use um
  virtualenv (`python -m venv .venv` + `.venv/bin/pip ...`), como acima.

- **Instalação do pwntools travando por minutos (Python 3.14).** O pwntools puxa o
  `unicorn`; a versão que o pip escolhe por padrão não tem *wheel* pré-compilado
  para o Python 3.14 e cai numa compilação do zero (lenta). Fixar `unicorn==2.1.1`
  (que tem *wheel* universal) evita a compilação.

- **`FileNotFoundError: './chal'` ao rodar o `solve.py`.** O binário não existe até
  ser compilado — rode o passo 2 do "Como rodar" antes.

- **SIGSEGV na chamada indireta (até no uso normal do menu).** A reconstrução tinha
  uma desreferência a mais na linha do *dispatch* (`(*(code *)ptrs[i])(arg)`), que
  mandava executar os *bytes* da função em vez de chamá-la. O correto, como no
  binário original, é **uma** desreferência: `ptrs[i](arg)` — `ptrs[i]` já é o
  ponteiro (slot da GOT ou `banter`) a ser chamado.

## Offsets a confirmar contra o binário real

Os valores no `solve.py` estão confirmados contra o `chal` reconstruído deste
repositório. Contra o binário **original** do CTF, reconfirme:

- `PTRS_ADDR` / `BANTER_ADDR` — derivados automaticamente dos símbolos
  (`elf.symbols['ptrs']`, `['banter']`); se o binário estiver stripado, pegue os
  offsets com `objdump -d chal` / `readelf -s chal`.
- `FMT_OFFSET` / `ADDR_OFF` — onde o nosso buffer cai na pilha para o `%N$s`.
  Descubra mandando `%p|%p|%p|...` via `printf` e localizando um marcador; aqui a
  1ª qword do buffer aparece em `%8$` e cravamos o endereço no offset 16.
- `LIBC_PATH` — a libc do alvo. Sem ela (e localmente), o script usa a libc do
  próprio sistema; no remoto, identifique a versão pelos vazamentos no
  [libc.rip](https://libc.rip) / `LibcSearcher` (bloco comentado no `solve.py`).

Confirme as proteções com:

```bash
checksec --file=chal
readelf -n chal | grep -A1 'x86 feature'   # deve mostrar: IBT, SHSTK
```

## A moral

O CET **elevou a barra** (barrou `execve` direto e o ROP clássico), mas não é
mágica: uma falha de **lógica** ainda permite chamar um gadget *aprovado*. Hardware
protege contra uma classe de ataque; código seguro fecha o resto. Defesa em
profundidade.
