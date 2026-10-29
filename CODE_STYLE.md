# Code style

This document describes C code style.

## Table of Contents

- [Indentation](#indentation)
- [Line length](#line-length)
- [Spaces](#spaces)
- [Brackets](#brackets)
- [Parentheses](#parentheses)
- [Blocks](#blocks)
- [Static](#static)
- [Vertical whitespace](#vertical-whitespace)
- [Comparison](#comparison)
- [Naming](#naming)
- [Variables](#variables)
- [Functions](#functions)
- [Structures and enumerations](#structures-and-enumerations)
- [Comments](#comments)
- [Switch statement](#switch-statement)
- [Macros and preprocessor directives](#macros-and-preprocessor-directives)
- [Header/source files](#headersource-files)
- [Safety](#safety)
- [Debug](#debug)
- [Auto format](#auto-format)
- [Third party code](#third-party-code)


## Indentation

- Indentation is 4 spaces.
- Use spaces instead of tabs.
- Use single indentation after breaking up line.
```c
/* OK */
if (condition1 && condition2 && condition3 &&
    condition4) {
    return 0;
}

/* OK */
printf("This is debug log, parameter1 %d, parameter2 %d",
    parameter1, parameter2);

/* OK */
void my_func(long int a, const char *s, double d,
    int *res);

/* Wrong */
if (condition1 && condition2 && condition3 &&
        condition4) {
    return 0;
}

/* Wrong */
printf("This is debug log, parameter1 %d, parameter2 %d",
        parameter1, parameter2);

/* Wrong */
void my_func(long int a, const char *s, double d,
             int *res);

```

- Indentation is required for every opening bracket.
```c
/* OK */
if (a) {
    do_a();
} else {
    do_b();
    if (c) {
        do_c();
    }
}
```

## Line length

- Use 120 characters line length. Reason: avoid horizontal scrolling while reading the code.
- Where a statement breaks within the limit is up to the author: lines that fit need not be joined or re-wrapped.
```c
/* OK */
printf("parameter1: %d parameter2: %d parameter3: %d parameter4: %d parameter5: %d", parameter1, parameter2,
    parameter3, parameter4, parameter5);

/* Wrong */
printf("parameter1: %d parameter2: %d parameter3: %d parameter4: %d parameter5: %d", parameter1, parameter2, parameter3, parameter4, parameter5);
```

- Constant strings longer than one line should be closed on each line by a quote and opened again on the next line.
```c
/* OK */
printf("Hello world, this is a long string that we want to print "
    "and is more than 120 chars long so we need to split it");

/* Wrong */
printf("Hello world, this is a long string that we want to print and \
    is more than 120 chars long so we need to split it");
```

## Spaces

- Use single space between `if/while/for/do` keyword and opening parenthesis.
```c
/* OK */
if (condition)
while (condition)
for (init; condition; step)
do {} while (condition)

/* Wrong */
if(condition)
while(condition)
for(init;condition;step)
do {} while(condition)
```

- Use single space before and after an assignment, binary and ternary operators (=  +  -  <  >  *  /  %  |  &  ^  <=  >=  ==  !=  ?  :).
```c
int32_t a;

a = 3 + 4;              /* OK */
for (a = 0; a < 5; a++) /* OK */
bits |= BIT5;           /* OK */

a=3+4;                  /* Wrong */
a = 3+4;                /* Wrong */
for (a=0;a<5;a++)       /* Wrong */
bits|=BIT5;             /* Wrong */
```

- Do not use space after unary operators (&  *  +  -  ~  !).
- Do not use space around the . and -> structure member operators.
- Do not use space before the postfix increment / decrement unary operators and after the prefix increment / decrement unary operators.
```c
res = !x;               /* OK */
ptr->x;                 /* OK */
++i;                    /* OK */

res = ! x;              /* Wrong */
ptr -> x;               /* Wrong */
++ i;                   /* Wrong */
```

- Do not use space between function name and opening parenthesis.
- Do not use space between opening parenthesis and first parameter.
- Use single space after every comma.
```c
int32_t a = sum(4, 3);              /* OK */

int32_t a = sum (4, 3);             /* Wrong */
int32_t a = sum( 4, 3 );            /* Wrong */
int32_t a = sum(4,3);               /* Wrong */
```
- Do not add trailing spaces.

## Brackets

- Opening curly bracket is always at the same line as reserved keyword (`for`, `while`, `do`, `switch`, `if`, ...).
```c
size_t i;

for (i = 0; i < 5; i++) {           /* OK */
}

for (i = 0; i < 5; i++){            /* Wrong */
}

for (i = 0; i < 5; i++)             /* Wrong */
{
}
```

- Every `if/for/while` statement should have brackets, even if it takes only one line.
```c
/* OK */
if (c) {
    for (int i = 0; i < 10; i++) {
        do_a();
    }
}

/* OK */
if (a) {
    do_a();
}

/* Wrong */
if (c)
    for (int i = 0; i < 10; i++)
        do_a();

/* Wrong */
if (a)
    do_a();
```

- In case of `if` or `if-else-if` statement, `else` must be in the same line as closing bracket of first statement.
```c
/* OK */
if (a) {
} else if (b) {
} else {
}

/* Wrong */
if (a) {
}
else {
}

/* Wrong */
if (a) {
}
else
{
}
```

- In case of `do-while` statement, `while` part must be in the same line as closing bracket of `do` part.
```c
/* OK */
do {
    int32_t a;
    a = do_a();
    do_b(a);
} while (check());

/* Wrong */
do
{
/* ... */
} while (check());

/* Wrong */
do {
/* ... */
}
while (check());
```

- Then part of `if` statement should be in a separate line.
```c
/* OK */
if (fd) {
    fclose(fp);
}

/* Wrong */
if (fd) fclose(fp);
```

- Opening curly bracket for function should be on the same level as closing.
```c
/* OK */
void my_func(void)
{
}

/* Wrong */
void my_func(void) {
}
```

- for and while without a statement should be in one-line with empty brackets.
```c
/* OK */
for (i = 0; i < *p; i++) {}

/* Wrong */
for (i = 0; i < *p; i++);
```

## Parentheses

- Do not overuse parentheses.
```c
/* OK */
if ((a & b) > 0 && c > 0 && d) {
}

/* Wrong */
if ((a & b) > 0 && (c > 0) && (d)) {
}

/* Wrong */
if ((my_func(a))) {
}

/* Wrong */
ptr = &(p->next);
```

- Use parentheses when assigning in a condition expression of if/for/while.
```c
/* OK */
for (i = 0; (ret = my_func()); i++)

/* Wrong */
for (i = 0; ret = my_func(); i++)
```

- Use sizeof with parentheses.
```c
/* OK */
sizeof(a)

/* Wrong */
sizeof a
```

## Blocks

- Avoid many nested blocks. Reason: many nested blocks decrease readability.
```c
/* OK */
while (condition1) {
    if (!condition2) {
        continue;
    }

    if (condition3 && condition4) {
        x = 10;
    }
}

/* Wrong */
while (condition1) {
    if (condition2) {
        if (condition3) {
            if (condition4) {
                x = 10;
            }
        }
    }
}
```

- Do not use `else` after return in `if` block.
```c
/* OK */
if (condition) {
    return;
}

/* else */

/* Wrong */
if (condition) {
    return;
} else {
}
```

## Static

- Use static when declaring functions and variables which are used only in scope of the file. The functions and variables that are not declared as static may cause name collisions.
```c
/* OK */
static int var = INIT;

static int my_func(void)
{
    return var;
}

int main(void)
{
    my_func();
    return 0;
}

/* Wrong */
int var = INIT;

int my_func(void)
{
    return var;
}

int main(void)
{
    my_func();
    return 0;
}
```

## Vertical whitespace

- Do not separate with more than one blank line between sections, functions etc.
```c
/* OK */
void func(void)
{
    printf("code block 1");

    printf("code block 2");
}

/* Wrong */
void func(void)
{
    printf("code block 1");


    printf("code block 2");
}
```

- Do not add blank line at the beginning or end of function.

## Comparison

- Compare variable against zero, except if it is treated as `boolean` type.
- Do not compare `boolean-treated` variables against zero/one/false/true. Use NOT (`!`) instead.
- Compare pointers against `NULL` value.
- Do not place constant before variable in comparison statement.
```c
size_t length = 5;  /* Counter variable */
uint8_t is_ok = 0;  /* Boolean-treated variable */
void *ptr = NULL;   /* Pointer variable */

if (length > 0)     /* OK, length is treated as counter variable containing multi values, not only 0 or 1 */
if (length == 0)    /* OK, length is treated as counter variable containing multi values, not only 0 or 1 */
if (length)         /* Wrong, length is not treated as boolean */
if (0 == length)    /* Wrong, in case of length = 0 mistake compiler generates warning to add parentheses */

if (is_ok)          /* OK, variable is treated as boolean */
if (!is_ok)         /* OK */
if (is_ok == 1)     /* Wrong */
if (is_ok == false) /* Wrong, use ! for negative check */

if (ptr == NULL)    /* OK */
if (!ptr)           /* Wrong */
```

## Naming

- Use only lowercase characters for variables/functions/types with optional underscore `_` character.
- Do not use `__` or `_` prefix for variables/functions/macros/types. This is reserved for C language itself.

## Variables

- Variable name must be lowercase with optional underscore `_` character.
- Variable should not include the data type, rather the meaning of the information in the data.

```c
/* OK */
int32_t a;
int32_t my_var;
int32_t myvar;

/* Wrong */
int32_t A;
int32_t myVar;
int32_t MYVar;
int32_t i32_var;
bool bFlag;
```

- Always declare local variables at the beginning of the block, before first executable statement.
- Do not declare variable after first executable statement.
```c
void foo(void)
{
    int32_t a;

    a = bar();
    int32_t b;      /* Wrong, there is already executable statement */
}
```

- You may declare new variables inside next indent level.
```c
int32_t a, b;

a = foo();
if (a) {
    int32_t c, d;   /* OK, c and d are in if-statement scope */

    c = foo();
    int32_t e;      /* Wrong, there was already executable statement inside block */
}
```

- Add one empty line after variables declaration.
```c
/* OK */
void foo(void)
{
    int32_t a, b;

    a = bar();
}

/* Wrong */
void foo(void)
{
    int32_t a, b;
    a = bar();
}
```

- Declare pointer variables with asterisk aligned to variable.
```c
/* OK */
char *a, *b;

/* Wrong */
char* a;
char * a;
```

- Do not align variable assignments.
```c
/* OK */
int a = 1;
int abc = 2;

/* Wrong */
int a   = 1;
int abc = 2;
```

- Use true/false for boolean variables.
```c
/* OK */
bool a = true;

/* Wrong */
bool a = 1;
```

## Functions

- Function name must be lowercase, optionally separated with underscore `_` character.
```c
/* OK */
void my_func(void);
void myfunc(void);

/* Wrong */
void MYFunc(void);
void myFunc(void);
```

- Function names related to component should contain component name followed by operation.
```c
/* OK */
typedef struct {
    //...
} my_component_t;

void my_component_init(void);
int my_component_get_by_name(my_component_t *comp, char *name);
```

- When function returns pointer, align asterisk to function name.
```c
/* OK */
const char *my_func(void);
my_struct_t *my_func(int32_t a, int32_t b);

/* Wrong */
const char* my_func(void);
my_struct_t * my_func(void);
```

- Do not align function prototypes. This usually breaks when new function is added.
```c
/* OK */
void set(int32_t a);
const char *get(void);

/* Wrong */
void        set(int32_t a);
my_type_t   get(void);
my_ptr_t*   get_ptr(void);

```

- Functions should not exceed 80 lines of code.

- In functions returning a pointer, return NULL on fail.

- In functions that only have success/fail, use 0 for success and -1 for failure (instead of TRUE and FALSE).

- In functions with many error reasons, use negative values for the reason.

- In functions where negative return value is valid, add another parameter to return the value.

- In functions that return boolean values (is_big, is_directory, is_download) return false or true.

```c
/* OK */
int my_func(void)
{
    if (error) {
        return -1;
    }

    return 0;
}

bool is_done(void)
{
    if (done) {
        return true;
    }

    return false;
}

void *my_func(void)
{
    return is_ok ? ptr : NULL;
}

/* Wrong */
int my_func(void)
{
    if (error) {
        return FALSE;
    }

    return TRUE;
}
```

- Return statements should not have parentheses and should not have a space after them.
```c
 /* OK */
return 0;
return;

/* Wrong */
return (0);
return ;

```

- Do not call return at the end of a function returning void.
```c
/* OK */
void my_func(void)
{
    printf("hello");
}

/* Wrong */
void my_func(void)
{
    printf("hello");
    return;
}
```

- Do not align function parameters.
```c
/* OK */
void my_function(int param1, char *param2, int param3, BOOL param4,
    BOOL param5);

/* Wrong*/
void my_function( int param1,
                  char *param2,
                  int param3,
                  BOOL param4,
                  BOOL param5 );
```

- Function should have input parameters first and then output parameters.
```c
/* OK */
void my_func(int in, int *out);

/* Wrong */
void my_fuc(int *out, int in);
```

- Function without parameters should be declared with `void` type.
```c
/* OK */
void my_func(void);

/* Wrong, the function can be called as my_func(1, 2, 3) without error */
void my_func();
```

- Do not cast function returning void * as it is safely promoted to any other pointer type.
```c
/* OK */
my_struct_t *s = malloc(sizeof(my_struct_t));

/* Wrong */
my_struct_t *s = (my_struct_t *)malloc(sizeof(my_struct_t));

```

- Do not check if pointer is NULL for `free` function since NULL value is allowed.
```c
/* OK */
void *p = NULL;

free(p);

/* Wrong */
if (p != NULL) {
    free(p);
}
```

- If typedef is introduced for function pointer, use `_fn` suffix
```c

typedef uint8_t (*my_func_typedef_fn)(uint8_t p1, const char *p2);

```

- Forward declaration in the C file should only be added if used before implemented.
```c

/* OK */
void func(void);

int main(void)
{
    func();
    return 0;
}

void my_func(void)
{
}

/* Wrong */
void func(void);

void my_func(void)
{
}

int main(void)
{
    func();
    return 0;
}

```

- Implement error handling only once, by setting all variables to zero at the beginning, and performing a goto to exit the function. If no error handling is required (i.e. no memory to release, no files to close, etc) - plain return should be used. Do not use goto for anything other than error handling.

```c
/* OK */
int my_func(char *file_name)
{
    void *p1, *p2 = NULL;
    FILE *fp = NULL;
    int ret = -1;

    p1 = malloc(256);
    if (p1 == NULL) {
        return -1;
    }

    fp = fopen(file_name);
    if (fp == NULL) {
        goto exit;
    }

    p2 = malloc(512);
    if (p2 == NULL) {
        goto exit;
    }

    //...

    ret = 0;

exit:
    // reverse order
    free(p2);
    if (fp)
        fclose(fp);
    free(p1);
    return ret;
}

/* Wrong */
int my_func(char *file_name)
{
    void *p1, *p2;
    FILE *fp;

    p1 = malloc(256);
    if (p1 == NULL) {
        return -1;
    }

    fp = fopen(file_name);
    if (fp == NULL) {
        free(p1);
        return -1;
    }

    p2 = malloc(512);
    if (p2 == NULL) {
        free(p1);
        fclose(fp);
        return -1;
    }

    //...

    free(p1);
    fclose(fp);
    free(p2);

    return 0;
}
```

- Use “exit early” strategy for handling errors or checking preconditions.
```c
/* OK */
void my_func(void)
{
    if (!condition) {
        return;
    }

    if (func1() < 0) {
        return;
    }

    if (func2() < 0) {
        return;
    }

    x = 10;
}

/* Wrong */
void my_func(void)
{
    if (condition) {
        if (func1() == 0) {
            if (func2() == 0) {
                x = 10;
            }
        }
    }
}
```

## Structures and enumerations

- Structure or enumeration name must be lowercase with optional underscore `_` character between words.
- Structure fields must be lowercase with underscores without m_ prefix.
- Opening curly bracket for initializations is always at the same line.
```c
/* OK */
struct_name_t name = {
    .a = 5,
    .b = 6,
};

/* Wrong */
struct_name_t name =
{
    .a = 5,
    .b = 6,
};
```

- If structure is declared with *name only*, it *must not* contain `_t` suffix after its name.
- If structure is declared with *typedef only*, it *has to* contain `_t` suffix after its name.
- If structure is declared with *name and typedef*, it *must not* contain `_t` for basic name and it *must* contain `_t` suffix after its name for typedef part.

```c
/* OK */
struct struct_name {
    char *a;
    char b;
};

/* OK */
typedef struct {
    char *a;
    char b;
} struct_name_t;

/* OK */
typedef struct struct_name {    /* No _t */
    char *a;
    char b;
    char c;
} struct_name_t;    /* _t */


/* Wrong */
typedef struct {
    int32_t a;
    int32_t b;
} a;

/* Wrong */
struct name_t {
    int32_t a;
    int32_t b;
};

/* Wrong */
struct name t
{
    int32_t a;
    int32_t b;
};
```

- All enumeration members should be uppercase.

```c
/* OK */
typedef enum {
    MY_ENUM_TESTA,
    MY_ENUM_TESTB,
} my_enum_t;


/* Wrong */
typedef enum {
    my_enum_testa,
    my_enum_testb,
} my_enum_t;
```

- Trailing comma should be added after the last element of structure initialization (this helps clang-format to properly format structures). Unless structure is very simple and short.
```c
/* OK */
typedef struct {
    int a, b;
} str_t;

/* OK */
str_t s = {
    .a = 1,
    .b = 2,   /* Comma here */
}

/* OK, no trailing commas - good only for small and simple structures */
static const my_struct_t my_var = { .type_data = { .par1 = 0, .par2 = 1 } };
```

## Comments

- Use `/* comment */` or `//` for single-line comment.
- Add single space after `/*` or `//`.
```c
// This is comment (ok)
/* This is comment (ok) */

//This is comment (wrong)
```

- For multi-line comments use `space+asterisk` for every line.
```c
/*
 * This is multi-line comments,
 * written in 2 lines (ok)
 */

/**
 * Wrong
 */

/*
*  Wrong
*/

/* Wrong
 */
```

- Do not use comments for obvious logic. The code should explain itself.
```c
/* OK */
/* Clear basic rate flag and convert 500 kbps to 100 kbps units */
rate[i] = (rate[i] & 0x7f) * 5;

/* OK */
/* Temporary workaround for some issue */
a = 12;

/* Wrong */
/* Check file exists */
if (access(file_name, R_OK) == 0) {
}

/* Wrong */
/* Set init value */
a = 12;
```

### Switch statement

- Do not add *indent* for `case` statement.
- Use *single indent* for `break` statement in each `case` or `default` statement.
- Do not add space before `:`. If there is one line case, use one space after `:`.
```c
/* OK */
switch (check()) {
case 0:
    do_a();
    break;
case 1:
    do_b();
    break;
default:
    break;
}

/* OK */
switch (check()) {
case 0: do_a(); break;
case 1: do_b(); break;
default: break;
}

/* Wrong */
switch (check()) {
    case 0:
        do_a();
        break;
    case 1:
        do_b();
        break;
    default:
        break;
}
```

- Always include `default` statement.
```c
/* OK */
switch (var) {
case 0:
    do_job();
    break;
default:
    break;
}

/* Wrong, default is missing */
switch (var) {
case 0:
    do_job();
    break;
}
```

- If local variables are required, use curly brackets and put `break` statement inside.
- Put opening curly bracket in the same line as `case` statement.

```c
/* OK */
switch (n) {
case 0: {
    int32_t a, b;
    char c;

    a = 5;
    /* ... */
    break;
}
}

/* Wrong */
switch (n) {
case 0:
    {
        int32_t a;
        break;
    }
}

/* Wrong, break shall be inside */
switch (n) {
case 0: {
    int32_t a;
}
    break;
}
```

## Macros and preprocessor directives

- Always use macros instead of literal constants, especially for numbers.
```c
/* OK */
#define WD_TIMEOUT_SEC 5

int timeout = WD_TIMEOUT_SEC;

/* Wrong */
int timeout = 5;
```
- All macros must be fully uppercase, with optional underscore `_` character.
- Use the same spacing as for functions.
```c
/* OK */
#define SQUARE(x) ((x) * (x))

/* Wrong */
#define square(x) ((x) * (x))
#define SQUARE( x ) (( x ) * ( x ))
```

- Always protect input parameters with parentheses.
```c
/* OK */
#define MIN(x, y) ((x) < (y) ? (x) : (y))

/* Wrong */
#define MIN(x, y) x < y ? x : y
```

- Always protect final macro evaluation with parentheses.
```c
/* OK */
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define SUM(x, y) ((x) + (y))

/* Wrong */
#define MIN(x, y) (x) < (y) ? (x) : (y)
#define SUM(x, y) (x) + (y)
```

- When macro uses multiple statements, protect these using `do {} while (0)` statement. This allows to use them inside if-else statements.
```c
/* OK */
#define DO_A_AND_B() \ do {\ do_a();\ do_b();\ } while (0)


/* Wrong */
#define DO_A_AND_B() \ {\ do_a();\ do_b();\ }
```

- Avoid using `#ifdef` or `#ifndef`. Use `defined()` or `!defined()` instead.
```c
/* OK */
#ifdef defined(XYZ)
/* do something */
#endif /* defined(XYZ) */

/* Wrong */
#ifdef XYZ
/* do something */
#endif /* XYZ */
```

- Always document `if/elif/else/endif` statements.
```c
/* OK */
#if defined(XYZ)
/* Do if XYZ defined */
#else /* defined(XYZ) */
/* Do if XYZ not defined */
#endif /* !defined(XYZ) */

/* Wrong */
#if defined(XYZ)
/* Do if XYZ defined */
#else
/* Do if XYZ not defined */
#endif
```

- Do not indent sub statements inside `#if` statement
```c
/* OK */
#if defined(XYZ)
#if defined(ABC)
/* do when ABC defined */
#endif /* defined(ABC) */
#else /* defined(XYZ) */
/* Do when XYZ not defined */
#endif /* !defined(XYZ) */

/* Wrong */
#if defined(XYZ)
    #if defined(ABC)
        /* do when ABC defined */
    #endif /* defined(ABC) */
#else /* defined(XYZ) */
    /* Do when XYZ not defined */
#endif /* !defined(XYZ) */
```

## Header/source files


- Always use `<` and `>` for C Standard Library include files, e.g. `#include <stdlib.h>`
- Always use `""` for custom libraries, eg. `#include "my_library.h"`
- Every file (*header* or *source*) must include license.
- Use the same license as already used by project/library.
- Header file must include guard `#ifndef`.
- Header file must include `C++` check.
- Include external header files outside `C++` check.
- Include external header files in following order: component header, application headers, system headers.
```c
/* foo.c */

#include "foo.h" /* place component header first to make sure it is self-contained */

#include "bar.h" /* application headers */

#include <stdio.h> /* system headers */

```
- Header file must include only every other header file in order to compile correctly, but not more (.c should include the rest if required).
- Header file must only expose module public variables/types/functions.
- Header files must be self-contained, i.e., they must be able to compile without relying on another include line to come before them.
- Use lowercase characters with underscores for file names.
- Use *.h and *.c for file extensions.
- Use `extern` for global module variables in header file, define them in source file later.

```c
/* file.h ... */
#ifndef ...

extern int32_t my_variable; /* This is global variable declaration in header */

#endif

/* file.c ... */
int32_t my_variable;        /* Actually defined in source */
```
- Never include `.c` files in another `.c` file

- Header file example (no license for sake of an example).
```c
/* License comes here */
#ifndef TEMPLATE_HDR_H
#define TEMPLATE_HDR_H

/* Include headers */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* File content here */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* TEMPLATE_HDR_H */
```

## Safety

- Always use safe version of functions.
```c
/* OK */
snprintf(temp_str, sizeof(temp_str), "%s", long_string);
strncpy(temp_str, long_string, sizeof(temp_str) - 1);

/* Wrong */
sprintf(temp_str, "%s", long_string);
strcpy(temp_str, long_string);
```

## Debug

 - Debug messages should have consistent format, contain function name, line and description. Error messages should contain "failed" or "error” words so they can be quickly spotted during debugging.
```c
printf("%s:%d debug message\n", __func__, __LINE__);
printf("%s:%d failed to get interface flags, error: %d (%s)\n", __func__,
    __LINE__, res, strerror(errno));
```

## Auto format

Use auto-format of the code by clang-format tool. The formatting rules are specified in `.clang-format` configuration file in the root of the project. Most of the editors support clang-format as plugin. For example, VScode comes with pre-installed clang-format tool and automatically detects `.clang-format` file.


## Third party code

- When modifying an external code which came from an external project e.g. kernel, open-source package or a specific vendor, you should always adhere to the coding style of this project. Reason: it is easier to read a C file if its coding style is consistent. Mixing several styles reduces readability.

