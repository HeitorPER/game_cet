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

```bash
pip install pwntools            # (e opcional: pip install LibcSearcher)

python3 solve.py                # local, contra ./chal
python3 solve.py REMOTE         # remoto (ajuste HOST/PORT em solve.py)
python3 solve.py GDB            # local sob gdb
```

## Offsets a confirmar contra o binário real

O binário `chal` original **não acompanha os slides**. Os pontos marcados com
`[AJUSTAR]` no `solve.py` precisam ser confirmados contra o binário:

- `PTRS_ADDR` / `BANTER_ADDR` — derivados automaticamente se os símbolos existirem
  (`elf.symbols['ptrs']`, `['banter']`); senão, pegue os offsets com
  `objdump -d chal` / `readelf -s chal`.
- `FMT_OFFSET` — posição do nosso buffer na pilha para o `%N$s`. Descubra mandando
  `%p|%p|%p|...` e localizando o marcador (há o helper `find_fmt_offset`).
- `KNOWN_OFFSET` — offset estático do ponteiro PIE vazado até a base do binário.
- `LIBC_PATH` — a libc do alvo. Sem ela, use os vazamentos no
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
