TITLE CipherLab 32 - Cryptography and Password Security Toolkit (x86, MASM, Irvine32)
; ============================================================================
;  Project   : CipherLab 32
;  Course    : EL-2003 Computer Organization and Assembly Language Lab (Fall 2026)
;  Authors   : Muhammad Zain Abbas (22K-5028), Ghazi Abbas (22K-5041)
;  Section   : BDS-3A
;  Assembler : MASM (ml.exe from VS Build Tools 2022, edited in VS Code) + Irvine32
;
;  Description
;  -----------
;  A menu-driven console toolkit that implements classic cryptography and
;  security utilities completely in x86 assembly language:
;     1. Caesar cipher - encrypt
;     2. Caesar cipher - decrypt
;     3. Vigenere cipher - encrypt
;     4. Vigenere cipher - decrypt
;     5. XOR stream cipher (hex dump + automatic round-trip verification)
;     6. Letter-frequency histogram + automatic Caesar code-breaker
;     7. Password strength analyser (character classes, pool size, entropy)
;     8. Checksum calculator (djb2 hash, additive sum, XOR-fold)
;  The menu is dispatched through a jump table (array of procedure addresses).
; ============================================================================

INCLUDE Irvine32.inc

BUFSZ = 256                      ; size of every text buffer (255 chars + 0)
KEYSZ = 64                       ; size of every key buffer  (63 chars + 0)

; ----------------------------------------------------------------------------
;  Macros
; ----------------------------------------------------------------------------
mColor MACRO clr                 ; change the console text colour
    push eax
    mov  eax, clr
    call SetTextColor
    pop  eax
ENDM

.data
; ---- buffers ----
inBuf     BYTE BUFSZ DUP(0)      ; user text
outBuf    BYTE BUFSZ DUP(0)      ; result text
tmpBuf    BYTE BUFSZ DUP(0)      ; scratch (XOR round trip)
rawKey    BYTE KEYSZ DUP(0)      ; key as typed
keyBuf    BYTE KEYSZ DUP(0)      ; Vigenere key: letters only, upper case
keyLen    DWORD 0                ; length of keyBuf

; ---- working variables ----
modeFlag  DWORD 0                ; 0 = encrypt, 1 = decrypt
textLen   DWORD 0                ; length of the last text read
guessKey  DWORD 0                ; Caesar key estimated by frequency analysis
bitsVal   DWORD 0                ; password entropy estimate (bits)
freq      DWORD 26 DUP(0)        ; letter frequency table A..Z

; ---- password analyser flags ----
hasLo     BYTE 0
hasUp     BYTE 0
hasDg     BYTE 0
hasSy     BYTE 0
repFlag   BYTE 0

; ---- jump table: one entry per menu option '1'..'8' ----
menuTable DWORD DoCaesarEnc, DoCaesarDec, DoVigEnc, DoVigDec
          DWORD DoXor, DoFreq, DoPass, DoHash

; ---- strings ----
sBar      BYTE "============================================================", 0
sTitle    BYTE "   CIPHERLAB 32  -  Cryptography & Password Security Toolkit", 0
sSub      BYTE "   x86 Assembly (MASM / Irvine32)  |  EL-2003 COAL Lab", 0
sM1       BYTE "   [1] Caesar cipher      - Encrypt", 0
sM2       BYTE "   [2] Caesar cipher      - Decrypt", 0
sM3       BYTE "   [3] Vigenere cipher    - Encrypt", 0
sM4       BYTE "   [4] Vigenere cipher    - Decrypt", 0
sM5       BYTE "   [5] XOR cipher         - Hex dump + round trip", 0
sM6       BYTE "   [6] Frequency analysis - Histogram + auto-crack Caesar", 0
sM7       BYTE "   [7] Password strength analyser", 0
sM8       BYTE "   [8] Checksum calculator (djb2 / sum / XOR-fold)", 0
sM0       BYTE "   [0] Exit", 0
sChoice   BYTE "   Select an option > ", 0

pText     BYTE "Enter text            : ", 0
pKeyWord  BYTE "Enter key word        : ", 0
pShift    BYTE "Enter shift (1 - 25)  : ", 0
pXorKey   BYTE "Enter XOR key string  : ", 0
pPass     BYTE "Enter a password      : ", 0

rCipher   BYTE "Result (ciphertext)   : ", 0
rPlain    BYTE "Result (plaintext)    : ", 0
rHex      BYTE "Ciphertext (hex bytes): ", 0
rBack     BYTE "Decrypted back (XOR)  : ", 0
rCracked  BYTE "Cracked plaintext     : ", 0

eEmpty    BYTE "  [!] Nothing was entered. Returning to menu.", 0
eShift    BYTE "  [!] Shift must be an integer between 1 and 25.", 0
eKey      BYTE "  [!] Key must contain at least one letter / character.", 0
eNoLetter BYTE "  [!] No letters found - frequency analysis not possible.", 0
eChoice   BYTE "  [!] Invalid option. Press 0-8.", 0
sBye      BYTE "  Goodbye! Stay secure.", 0

sColon    BYTE " : ", 0
sSpace    BYTE "  ", 0
sMostFreq BYTE "Most frequent letter  : ", 0
sAssumed  BYTE "   (assumed to be 'E')", 0
sEstKey   BYTE "Estimated Caesar key  : ", 0
sLen      BYTE "Length                : ", 0
sLower    BYTE "Has lower-case (a-z)  : ", 0
sUpper    BYTE "Has upper-case (A-Z)  : ", 0
sDigit    BYTE "Has digits (0-9)      : ", 0
sSymbol   BYTE "Has symbols / spaces  : ", 0
sRepeat   BYTE "3 identical in a row  : ", 0
sPool     BYTE "Character pool size   : ", 0
sEntropy  BYTE "Estimated entropy     : ", 0
sBits     BYTE " bits", 0
sRating   BYTE "Strength rating       : ", 0
sMeter    BYTE "Strength meter        : [", 0
sYes      BYTE "Yes", 0
sNo       BYTE "No", 0
rVW       BYTE "VERY WEAK", 0
rWK       BYTE "WEAK", 0
rMD       BYTE "MODERATE", 0
rST       BYTE "STRONG", 0
rVS       BYTE "VERY STRONG", 0
sDjb      BYTE "djb2 hash (hex)       : ", 0
sSum      BYTE "Additive checksum     : ", 0
sXorFold  BYTE "XOR-fold checksum (h) : ", 0
sPoolVal  DWORD 0
ratClr    DWORD 0                ; colour of the rating
ratPtr    DWORD 0                ; offset of the rating text
xorFold   BYTE 0                 ; XOR-fold checksum result
xKeyLen   DWORD 0                ; XOR key length

.code
; ============================================================================
;  main : display the menu, read a key, dispatch through the jump table
; ============================================================================
main PROC
MainLoop:
    call ShowMenu
    call ReadChar                ; AL = key pressed (no echo, no Enter needed)
    call WriteChar               ; echo it
    call Crlf
    call Crlf
    cmp  al, '0'
    je   Quit
    cmp  al, '1'
    jb   BadChoice
    cmp  al, '8'
    ja   BadChoice
    sub  al, '1'                 ; '1'..'8'  ->  0..7
    movzx eax, al
    call DWORD PTR menuTable[eax*4] ; indirect call through the jump table
    jmp  PauseKey
BadChoice:
    mColor lightRed
    mov  edx, OFFSET eChoice
    call WriteString
    call Crlf
PauseKey:
    mColor lightGray
    call Crlf
    call WaitMsg                 ; "Press any key to continue..."
    jmp  MainLoop
Quit:
    mColor lightGreen
    mov  edx, OFFSET sBye
    call WriteString
    call Crlf
    mColor lightGray
    exit
main ENDP

; ============================================================================
;  ShowMenu : clear the screen and draw the main menu
; ============================================================================
ShowMenu PROC USES eax edx
    call Clrscr
    mColor lightCyan
    mov  edx, OFFSET sBar
    call WriteString
    call Crlf
    mColor yellow
    mov  edx, OFFSET sTitle
    call WriteString
    call Crlf
    mColor lightGray
    mov  edx, OFFSET sSub
    call WriteString
    call Crlf
    mColor lightCyan
    mov  edx, OFFSET sBar
    call WriteString
    call Crlf
    mColor white
    mov  edx, OFFSET sM1
    call WriteString
    call Crlf
    mov  edx, OFFSET sM2
    call WriteString
    call Crlf
    mov  edx, OFFSET sM3
    call WriteString
    call Crlf
    mov  edx, OFFSET sM4
    call WriteString
    call Crlf
    mov  edx, OFFSET sM5
    call WriteString
    call Crlf
    mov  edx, OFFSET sM6
    call WriteString
    call Crlf
    mov  edx, OFFSET sM7
    call WriteString
    call Crlf
    mov  edx, OFFSET sM8
    call WriteString
    call Crlf
    mColor lightRed
    mov  edx, OFFSET sM0
    call WriteString
    call Crlf
    mColor lightCyan
    mov  edx, OFFSET sBar
    call WriteString
    call Crlf
    mColor yellow
    mov  edx, OFFSET sChoice
    call WriteString
    mColor lightGray
    ret
ShowMenu ENDP

; ============================================================================
;  PromptRead : print a prompt and read a line
;  Receives : EDX = offset of prompt, EBX = offset of buffer, ECX = max chars
;  Returns  : EAX = number of characters read (0 = empty line)
; ============================================================================
PromptRead PROC USES ecx edx
    mColor lightGray
    call WriteString             ; EDX already holds the prompt
    mColor white
    mov  edx, ebx                ; EDX = buffer for ReadString
    call ReadString              ; ECX = max chars, returns EAX = length
    mColor lightGray
    ret
PromptRead ENDP

; ============================================================================
;  GetText : ask for a message, store in inBuf, remember its length
;  Returns  : EAX = length (0 if empty; error message already printed)
; ============================================================================
GetText PROC USES ebx ecx edx
    mov  edx, OFFSET pText
    mov  ebx, OFFSET inBuf
    mov  ecx, BUFSZ - 1
    call PromptRead
    mov  textLen, eax
    cmp  eax, 0
    jne  GTok
    call ErrEmpty
    xor  eax, eax
GTok:
    ret
GetText ENDP

ErrEmpty PROC USES edx
    mColor lightRed
    mov  edx, OFFSET eEmpty
    call WriteString
    call Crlf
    mColor lightGray
    ret
ErrEmpty ENDP

; ============================================================================
;  GetShift : read the Caesar shift
;  Returns  : EAX = shift (1..25) or 0 if invalid (error already printed)
; ============================================================================
GetShift PROC USES edx
    mov  edx, OFFSET pShift
    mColor lightGray
    call WriteString
    mColor white
    call ReadInt                 ; EAX = signed value, OF set if invalid
    jo   GSbad
    cmp  eax, 1
    jl   GSbad
    cmp  eax, 25
    jg   GSbad
    mColor lightGray
    ret
GSbad:
    mColor lightRed
    mov  edx, OFFSET eShift
    call WriteString
    call Crlf
    mColor lightGray
    xor  eax, eax
    ret
GetShift ENDP

; ============================================================================
;  ShowOut : print a label followed by outBuf (in green)
;  Receives : EDX = offset of label
; ============================================================================
ShowOut PROC USES edx
    mColor lightGray
    call WriteString
    mColor lightGreen
    mov  edx, OFFSET outBuf
    call WriteString
    call Crlf
    mColor lightGray
    ret
ShowOut ENDP

; ============================================================================
;  CaesarShift : rotate every letter by EBX positions (0..25)
;  Receives : ESI = source string, EDI = destination, EBX = shift
;  Non-letters are copied unchanged, case is preserved.
; ============================================================================
CaesarShift PROC USES eax ebx ecx esi edi
CS1:
    mov  al, [esi]
    cmp  al, 0
    je   CSdone
    cmp  al, 'A'
    jb   CScopy
    cmp  al, 'Z'
    jbe  CSupper
    cmp  al, 'a'
    jb   CScopy
    cmp  al, 'z'
    ja   CScopy
    mov  cl, 'a'                 ; lower-case base
    jmp  CSrot
CSupper:
    mov  cl, 'A'                 ; upper-case base
CSrot:
    sub  al, cl                  ; 0..25
    movzx eax, al
    add  eax, ebx                ; + shift (max 25 + 25 = 50)
    cmp  eax, 26
    jb   CSok
    sub  eax, 26                 ; wrap around the alphabet
CSok:
    add  al, cl                  ; back to ASCII
CScopy:
    mov  [edi], al
    inc  esi
    inc  edi
    jmp  CS1
CSdone:
    mov  BYTE PTR [edi], 0
    ret
CaesarShift ENDP

; ============================================================================
;  NormalizeKey : copy letters of rawKey into keyBuf in upper case
;  Returns  : EAX = number of letters (also stored in keyLen)
; ============================================================================
NormalizeKey PROC USES ebx esi edi
    mov  esi, OFFSET rawKey
    mov  edi, OFFSET keyBuf
    xor  ebx, ebx
NK1:
    mov  al, [esi]
    cmp  al, 0
    je   NKdone
    cmp  al, 'a'
    jb   NK2
    cmp  al, 'z'
    ja   NK2
    sub  al, 32                  ; lower -> upper
NK2:
    cmp  al, 'A'
    jb   NKskip
    cmp  al, 'Z'
    ja   NKskip
    mov  [edi], al
    inc  edi
    inc  ebx
NKskip:
    inc  esi
    jmp  NK1
NKdone:
    mov  BYTE PTR [edi], 0
    mov  keyLen, ebx
    mov  eax, ebx
    ret
NormalizeKey ENDP

; ============================================================================
;  Vigenere : encrypt (EBX=0) or decrypt (EBX=1) with keyBuf
;  Receives : ESI = source, EDI = destination, EBX = mode
;  The key index only advances on letters, so spaces/punctuation are ignored.
; ============================================================================
Vigenere PROC USES eax ebx ecx edx esi edi
    xor  ecx, ecx                ; ECX = position inside the key
VG1:
    mov  al, [esi]
    cmp  al, 0
    je   VGdone
    cmp  al, 'A'
    jb   VGcopy
    cmp  al, 'Z'
    jbe  VGup
    cmp  al, 'a'
    jb   VGcopy
    cmp  al, 'z'
    ja   VGcopy
    mov  ah, 'a'
    jmp  VGrot
VGup:
    mov  ah, 'A'
VGrot:
    sub  al, ah                  ; letter index 0..25
    movzx edx, BYTE PTR keyBuf[ecx]
    sub  dl, 'A'                 ; key letter index 0..25
    cmp  ebx, 0
    jne  VGdec
    add  al, dl                  ; encrypt: p + k
    cmp  al, 26
    jb   VGok
    sub  al, 26
    jmp  VGok
VGdec:
    sub  al, dl                  ; decrypt: p - k
    jae  VGok                    ; no borrow -> already 0..25
    add  al, 26
VGok:
    add  al, ah                  ; back to ASCII
    inc  ecx                     ; next key letter
    cmp  ecx, keyLen
    jb   VGcopy
    xor  ecx, ecx                ; wrap key index
VGcopy:
    mov  [edi], al
    inc  esi
    inc  edi
    jmp  VG1
VGdone:
    mov  BYTE PTR [edi], 0
    ret
Vigenere ENDP

; ============================================================================
;  XorCrypt : out[i] = in[i] XOR key[i mod keylen]   (symmetric)
;  Receives : ESI = source, EDI = destination, ECX = length (> 0),
;             EDX = key string, EBX = key length (> 0)
; ============================================================================
XorCrypt PROC USES eax ebx ecx edx esi edi ebp
    xor  ebp, ebp                ; EBP = key index
XC1:
    mov  al, [esi]
    xor  al, [edx + ebp]
    mov  [edi], al
    inc  esi
    inc  edi
    inc  ebp
    cmp  ebp, ebx
    jb   XC2
    xor  ebp, ebp
XC2:
    loop XC1
    ret
XorCrypt ENDP

; ============================================================================
;  PrintHex : print ECX bytes starting at ESI as two-digit hex numbers
; ============================================================================
PrintHex PROC USES eax ebx ecx esi
    mColor lightGreen
PH1:
    mov  ebx, 1                  ; WriteHexB: one byte -> 2 hex digits
    movzx eax, BYTE PTR [esi]
    call WriteHexB
    mov  al, ' '
    call WriteChar
    inc  esi
    loop PH1
    call Crlf
    mColor lightGray
    ret
PrintHex ENDP

; ============================================================================
;  Menu option procedures
; ============================================================================
RunCaesar PROC                   ; modeFlag: 0 = encrypt, 1 = decrypt
    call GetText
    cmp  eax, 0
    je   RCend
    call GetShift
    cmp  eax, 0
    je   RCend
    cmp  modeFlag, 0
    je   RCgo
    mov  ebx, 26                 ; decrypting by k = encrypting by 26 - k
    sub  ebx, eax
    jmp  RCdo
RCgo:
    mov  ebx, eax
RCdo:
    mov  esi, OFFSET inBuf
    mov  edi, OFFSET outBuf
    call CaesarShift
    call Crlf
    cmp  modeFlag, 0
    jne  RCplain
    mov  edx, OFFSET rCipher
    jmp  RCshow
RCplain:
    mov  edx, OFFSET rPlain
RCshow:
    call ShowOut
RCend:
    ret
RunCaesar ENDP

DoCaesarEnc PROC
    mov  modeFlag, 0
    call RunCaesar
    ret
DoCaesarEnc ENDP

DoCaesarDec PROC
    mov  modeFlag, 1
    call RunCaesar
    ret
DoCaesarDec ENDP

RunVigenere PROC
    call GetText
    cmp  eax, 0
    je   RVend
    mov  edx, OFFSET pKeyWord
    mov  ebx, OFFSET rawKey
    mov  ecx, KEYSZ - 1
    call PromptRead
    call NormalizeKey            ; EAX = number of letters in the key
    cmp  eax, 0
    jne  RVgo
    mColor lightRed
    mov  edx, OFFSET eKey
    call WriteString
    call Crlf
    mColor lightGray
    jmp  RVend
RVgo:
    mov  esi, OFFSET inBuf
    mov  edi, OFFSET outBuf
    mov  ebx, modeFlag
    call Vigenere
    call Crlf
    cmp  modeFlag, 0
    jne  RVplain
    mov  edx, OFFSET rCipher
    jmp  RVshow
RVplain:
    mov  edx, OFFSET rPlain
RVshow:
    call ShowOut
RVend:
    ret
RunVigenere ENDP

DoVigEnc PROC
    mov  modeFlag, 0
    call RunVigenere
    ret
DoVigEnc ENDP

DoVigDec PROC
    mov  modeFlag, 1
    call RunVigenere
    ret
DoVigDec ENDP

DoXor PROC
    call GetText
    cmp  eax, 0
    je   DXend
    mov  edx, OFFSET pXorKey
    mov  ebx, OFFSET rawKey
    mov  ecx, KEYSZ - 1
    call PromptRead              ; EAX = key length
    cmp  eax, 0
    jne  DXgo
    mColor lightRed
    mov  edx, OFFSET eKey
    call WriteString
    call Crlf
    mColor lightGray
    jmp  DXend
DXgo:
    mov  xKeyLen, eax            ; remember the key length
    mov  ebx, eax                ; EBX = key length
    mov  edx, OFFSET rawKey      ; EDX = key
    mov  ecx, textLen            ; ECX = message length
    mov  esi, OFFSET inBuf
    mov  edi, OFFSET outBuf
    call XorCrypt                ; encrypt
    call Crlf
    mColor lightGray
    mov  edx, OFFSET rHex
    call WriteString
    mov  esi, OFFSET outBuf
    mov  ecx, textLen
    call PrintHex
    ; ---- decrypt again with the same key to prove XOR is symmetric ----
    mov  ebx, xKeyLen            ; same key length again
    mov  edx, OFFSET rawKey
    mov  ecx, textLen
    mov  esi, OFFSET outBuf
    mov  edi, OFFSET tmpBuf
    call XorCrypt
    mov  eax, textLen
    mov  BYTE PTR tmpBuf[eax], 0 ; terminate the recovered text
    mov  edx, OFFSET rBack
    call WriteString
    mColor lightGreen
    mov  edx, OFFSET tmpBuf
    call WriteString
    call Crlf
    mColor lightGray
DXend:
    ret
DoXor ENDP

; ----------------------------------------------------------------------------
;  DoFreq : count letters, draw histogram, guess Caesar key assuming E is the
;           most common letter, then decrypt with the guess
; ----------------------------------------------------------------------------
DoFreq PROC
    call GetText
    cmp  eax, 0
    je   DFend
    ; ---- clear the frequency table (REP STOSD) ----
    cld
    mov  edi, OFFSET freq
    mov  ecx, 26
    xor  eax, eax
    rep  stosd
    ; ---- count letters, ignoring case ----
    mov  esi, OFFSET inBuf
DF1:
    mov  al, [esi]
    cmp  al, 0
    je   DFcounted
    cmp  al, 'a'
    jb   DF2
    cmp  al, 'z'
    ja   DF2
    sub  al, 32                  ; to upper case
DF2:
    cmp  al, 'A'
    jb   DFnext
    cmp  al, 'Z'
    ja   DFnext
    sub  al, 'A'
    movzx eax, al
    inc  freq[eax*4]
DFnext:
    inc  esi
    jmp  DF1
DFcounted:
    ; ---- draw histogram and find the maximum ----
    call Crlf
    xor  esi, esi                ; ESI = letter index
    xor  edi, edi                ; EDI = highest count so far
    xor  ebx, ebx                ; EBX = index of that letter
DF3:
    cmp  esi, 26
    jae  DFhistDone
    mov  eax, freq[esi*4]
    cmp  eax, 0
    je   DF5
    cmp  eax, edi
    jbe  DF4
    mov  edi, eax
    mov  ebx, esi
DF4:
    mColor lightCyan
    mov  eax, esi
    add  al, 'A'
    call WriteChar
    mColor lightGray
    mov  edx, OFFSET sColon
    call WriteString
    mov  eax, freq[esi*4]
    call WriteDec
    mov  edx, OFFSET sSpace
    call WriteString
    mColor lightGreen
    mov  ecx, freq[esi*4]
    cmp  ecx, 40
    jbe  DFbar
    mov  ecx, 40                 ; cap the bar length
DFbar:
    mov  al, '#'
    call WriteChar
    loop DFbar
    call Crlf
DF5:
    inc  esi
    jmp  DF3
DFhistDone:
    mColor lightGray
    cmp  edi, 0
    jne  DFcrack
    mColor lightRed
    mov  edx, OFFSET eNoLetter
    call WriteString
    call Crlf
    mColor lightGray
    jmp  DFend
DFcrack:
    call Crlf
    mov  edx, OFFSET sMostFreq
    call WriteString
    mColor yellow
    mov  eax, ebx
    add  al, 'A'
    call WriteChar
    mColor lightGray
    mov  edx, OFFSET sAssumed
    call WriteString
    call Crlf
    ; key = (index - 4) mod 26 = (index + 22) mod 26   ('E' has index 4)
    mov  eax, ebx
    add  eax, 22
    cmp  eax, 26
    jb   DFkey
    sub  eax, 26
DFkey:
    mov  guessKey, eax
    mov  edx, OFFSET sEstKey
    call WriteString
    mColor yellow
    call WriteDec
    mColor lightGray
    call Crlf
    ; decrypt with shift (26 - key) mod 26
    mov  ebx, 26
    sub  ebx, guessKey
    cmp  ebx, 26
    jb   DFdec
    xor  ebx, ebx
DFdec:
    mov  esi, OFFSET inBuf
    mov  edi, OFFSET outBuf
    call CaesarShift
    mov  edx, OFFSET rCracked
    call ShowOut
DFend:
    ret
DoFreq ENDP

; ----------------------------------------------------------------------------
;  ShowFlag : print a label (EDX) followed by Yes / No depending on AL
; ----------------------------------------------------------------------------
ShowFlag PROC USES edx
    push eax
    mColor lightGray
    call WriteString
    pop  eax
    cmp  al, 0
    je   SFno
    mColor lightGreen
    mov  edx, OFFSET sYes
    jmp  SFout
SFno:
    mColor lightRed
    mov  edx, OFFSET sNo
SFout:
    call WriteString
    call Crlf
    mColor lightGray
    ret
ShowFlag ENDP

; ----------------------------------------------------------------------------
;  DoPass : password analyser.  entropy ~= length * floor(log2(pool size))
;           (BSR gives floor(log2)); halved if 3 identical characters repeat
; ----------------------------------------------------------------------------
DoPass PROC
    mov  edx, OFFSET pPass
    mov  ebx, OFFSET inBuf
    mov  ecx, BUFSZ - 1
    call PromptRead
    mov  textLen, eax
    cmp  eax, 0
    jne  DPgo
    call ErrEmpty
    ret
DPgo:
    mov  hasLo, 0
    mov  hasUp, 0
    mov  hasDg, 0
    mov  hasSy, 0
    mov  repFlag, 0
    mov  esi, OFFSET inBuf
    mov  bl, 0                   ; BL = previous character
    mov  bh, 0                   ; BH = current run length
DP1:
    mov  al, [esi]
    cmp  al, 0
    je   DPscanned
    cmp  al, bl                  ; same as previous character?
    jne  DPnew
    inc  bh
    cmp  bh, 3
    jb   DPclass
    mov  repFlag, 1              ; 3 or more identical characters in a row
    jmp  DPclass
DPnew:
    mov  bl, al
    mov  bh, 1
DPclass:
    cmp  al, 'a'
    jb   DPc1
    cmp  al, 'z'
    ja   DPc1
    mov  hasLo, 1
    jmp  DPnext
DPc1:
    cmp  al, 'A'
    jb   DPc2
    cmp  al, 'Z'
    ja   DPc2
    mov  hasUp, 1
    jmp  DPnext
DPc2:
    cmp  al, '0'
    jb   DPc3
    cmp  al, '9'
    ja   DPc3
    mov  hasDg, 1
    jmp  DPnext
DPc3:
    mov  hasSy, 1
DPnext:
    inc  esi
    jmp  DP1
DPscanned:
    ; ---- pool size ----
    xor  edx, edx
    cmp  hasLo, 0
    je   DPp1
    add  edx, 26
DPp1:
    cmp  hasUp, 0
    je   DPp2
    add  edx, 26
DPp2:
    cmp  hasDg, 0
    je   DPp3
    add  edx, 10
DPp3:
    cmp  hasSy, 0
    je   DPp4
    add  edx, 33
DPp4:
    mov  sPoolVal, edx
    bsr  eax, edx                ; EAX = floor(log2(pool))
    imul eax, textLen            ; bits = length * log2(pool)
    cmp  repFlag, 0
    je   DPbits
    shr  eax, 1                  ; penalty: halve the entropy
DPbits:
    mov  bitsVal, eax
    ; ---- report ----
    call Crlf
    mov  edx, OFFSET sLen
    call WriteString
    mov  eax, textLen
    call WriteDec
    call Crlf
    mov  edx, OFFSET sLower
    mov  al, hasLo
    call ShowFlag
    mov  edx, OFFSET sUpper
    mov  al, hasUp
    call ShowFlag
    mov  edx, OFFSET sDigit
    mov  al, hasDg
    call ShowFlag
    mov  edx, OFFSET sSymbol
    mov  al, hasSy
    call ShowFlag
    mov  edx, OFFSET sRepeat
    mov  al, repFlag
    call ShowFlag
    mov  edx, OFFSET sPool
    call WriteString
    mov  eax, sPoolVal
    call WriteDec
    call Crlf
    mov  edx, OFFSET sEntropy
    call WriteString
    mov  eax, bitsVal
    call WriteDec
    mov  edx, OFFSET sBits
    call WriteString
    call Crlf
    ; ---- rating (colour + text) ----
    mov  eax, bitsVal
    cmp  eax, 28
    jb   DPvw
    cmp  eax, 36
    jb   DPwk
    cmp  eax, 60
    jb   DPmd
    cmp  eax, 80
    jb   DPst
    mov  ratPtr, OFFSET rVS
    mov  ratClr, lightGreen
    jmp  DPshow
DPvw:
    mov  ratPtr, OFFSET rVW
    mov  ratClr, lightRed
    jmp  DPshow
DPwk:
    mov  ratPtr, OFFSET rWK
    mov  ratClr, lightMagenta
    jmp  DPshow
DPmd:
    mov  ratPtr, OFFSET rMD
    mov  ratClr, yellow
    jmp  DPshow
DPst:
    mov  ratPtr, OFFSET rST
    mov  ratClr, lightGreen
DPshow:
    mov  edx, OFFSET sRating
    call WriteString
    mColor ratClr
    mov  edx, ratPtr
    call WriteString
    call Crlf
    ; ---- meter: one '=' per 4 bits (max 25) ----
    mColor lightGray
    mov  edx, OFFSET sMeter
    call WriteString
    mColor ratClr
    mov  ecx, bitsVal
    shr  ecx, 2
    cmp  ecx, 25
    jbe  DPm1
    mov  ecx, 25
DPm1:
    cmp  ecx, 0
    je   DPm3
DPm2:
    mov  al, '='
    call WriteChar
    loop DPm2
DPm3:
    mColor lightGray
    mov  al, ']'
    call WriteChar
    call Crlf
    ret
DoPass ENDP

; ----------------------------------------------------------------------------
;  DoHash : djb2 (h = h*33 + c), additive sum and XOR-fold of the message
; ----------------------------------------------------------------------------
DoHash PROC
    call GetText
    cmp  eax, 0
    je   DHend
    mov  esi, OFFSET inBuf
    mov  ebx, 5381               ; djb2 seed
    xor  edi, edi                ; additive checksum
    xor  dl, dl                  ; XOR-fold byte
DH1:
    movzx eax, BYTE PTR [esi]
    cmp  al, 0
    je   DHdone
    add  edi, eax
    xor  dl, al
    mov  ecx, ebx
    shl  ebx, 5                  ; h * 32
    add  ebx, ecx                ; + h  = h * 33
    add  ebx, eax                ; + c
    inc  esi
    jmp  DH1
DHdone:
    mov  xorFold, dl             ; save the XOR-fold byte
    call Crlf
    mColor lightGray
    mov  edx, OFFSET sDjb
    call WriteString
    mColor lightGreen
    mov  eax, ebx
    call WriteHex                ; 8 hex digits
    call Crlf
    mColor lightGray
    mov  edx, OFFSET sSum
    call WriteString
    mColor lightGreen
    mov  eax, edi
    call WriteDec
    call Crlf
    mColor lightGray
    mov  edx, OFFSET sXorFold
    call WriteString
    mColor lightGreen
    movzx eax, xorFold
    mov  ebx, 1
    call WriteHexB               ; one byte -> 2 hex digits
    call Crlf
    mColor lightGray
DHend:
    ret
DoHash ENDP

END main
