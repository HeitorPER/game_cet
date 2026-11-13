/* =============================================================================
 *  chal.c  —  reconstrucao do binario vulneravel do desafio "Game, CET, Match"
 *             (WolvCTF 2024 · Pwn · game_cet)
 *
 *  Este NAO e o fonte original (o CTF entrega so o binario `chal`). E uma
 *  reconstrucao fiel a engenharia reversa descrita nos slides, para a
 *  apresentacao poder mostrar exatamente ONDE esta o bug (slides 04-05) e
 *  COMO se corrige (slide 15).
 *
 *  Compilado no alvo com todas as protecoes + Intel CET:
 *    gcc chal.c -o chal -fcf-protection=full -fstack-protector-all \
 *        -Wl,-z,relro,-z,now -pie -fPIE -O1
 *  (-fcf-protection=full liga IBT (ENDBR64) + Shadow Stack -> secao
 *   .note.gnu.property com "IBT, SHSTK", visivel em `readelf -n chal`.)
 * ============================================================================= */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Global gravavel que fica a um offset FIXO da vtable `ptrs` (slide 05/12).
 * As opcoes lob/taunt montam um valor de 8 bytes aqui, byte a byte. */
unsigned long banter = 0;

/* ptrs[0]=swing  ptrs[1]=lob  ptrs[2]=taunt  ptrs[3]=hear_taunt (ver abaixo) */
typedef void (*code)(char *);

/* ptrs[0] — imprime um ponteiro: nosso vazamento (slide 05). */
void swing(char *arg) {
    printf("the ball sails over: %p\n", (void *)&banter);
}

/* ptrs[1] — desloca o banter 8 bits: abre espaco p/ o proximo byte (slide 05). */
void lob(char *arg) {
    banter <<= 8;
}

/* ptrs[2] — grava um byte no banter com OR (slide 05). */
void taunt(char *arg) {
    banter |= (unsigned long)atoi(arg);
}

/* ptrs[3] — o "win" obvio: da shell direto... mas NAO tem ENDBR64 no inicio
 * (funcao interna, nunca projetada p/ ser alvo de salto indireto), entao o IBT
 * ABORTA quando tentamos pular pra ca pela vtable (slides 06-08). */
void hear_taunt(char *arg) {
    char *argv[] = {"/bin/sh", NULL};
    execve("/bin/sh", argv, NULL);
}

/* A vtable do menu. Fica proxima do global `banter` na memoria. */
code ptrs[4] = { swing, lob, taunt, hear_taunt };

int main(void) {
    char buf[0x100];
    setvbuf(stdout, NULL, _IONBF, 0);

    while (1) {
        puts("1) serve  2) lob  3) taunt  4) hear taunt");
        ssize_t n = read(0, buf, 0xff);
        if (n <= 0) break;
        buf[n] = '\0';

        /* ---------------------------------------------------------------------
         *  O CORACAO DO BUG (slide 04):
         *   - strtol com sinal e SEM validar o retorno -> option pode ser
         *     negativo ou gigante: ptrs[(int)option - 1] alcanca QUALQUER
         *     ponteiro relativo a base (GOT, banter, ...).
         *   - `arg` (resto da linha) vira o 1o argumento (RDI) da funcao chamada.
         * ------------------------------------------------------------------- */
        char *rest;
        long option = strtol(buf, &rest, 10);   /* <-- sem checar faixa! */
        char *arg = (*rest) ? rest + 1 : rest;  /* pula o espaco separador    */

        /* Chamada INDIRETA (na pratica `call rdx`): o IBT exige que o destino
         * comece com ENDBR64. Funcoes da GOT comecam -> aceitas; hear_taunt
         * nao comeca -> abortado (slide 08). */
        (*(code *)ptrs[(int)option - 1])(arg);
    }
    return 0;
}

/* =============================================================================
 *  A CORRECAO (slide 15):
 *    1. Validar a faixa do indice ANTES de chamar a vtable  (mata a primitiva):
 *          if (option < 1 || option > 4) continue;
 *    2. Nunca passar entrada do usuario como format string:
 *          printf("%s", arg);   // e NAO printf(arg);
 *    3. Nao deixar um global gravavel (banter) virar destino de chamada
 *       vizinho da vtable.
 *
 *  Licao: o Intel CET ELEVOU a barra (barrou execve direto e o ROP classico),
 *  mas nao cobre uma falha de LOGICA. Hardware + codigo seguro = defesa em
 *  profundidade.
 * ============================================================================= */
