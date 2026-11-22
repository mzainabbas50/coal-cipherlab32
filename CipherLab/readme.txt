CipherLab 32 - Cryptography and Password Security Toolkit
EL-2003 COAL Lab, Fall 2026, Section BDS-3A
Authors: Muhammad Zain Abbas (22K-5028), Ghazi Abbas (22K-5041)

FILES
  CipherLab.asm  - complete source code (x86, MASM, Irvine32)
  build.bat      - command-line build helper (optional)
  readme.txt     - this file

HOW TO ASSEMBLE AND RUN (see Guide_VSCode_Setup_and_Demo_Video.docx for VS Code)
  1. Open the Irvine32 Visual Studio project you use in the lab
     (Irvine\Project_Template\ or the project from Lab 01/02).
  2. In Solution Explorer remove the template's main .asm file
     and add CipherLab.asm (right-click Source Files > Add > Existing Item).
  3. Make sure the platform is x86 (Win32), not x64.
  4. Press Ctrl+F5 (Start Without Debugging). A console window opens.

HOW TO ASSEMBLE FROM THE COMMAND LINE (optional)
  Run build.bat from the "x86 Native Tools Command Prompt for VS 2022".
  Edit IRVINE at the top of build.bat if Irvine32 is not in C:\Irvine.

HOW TO USE
  Press a single key 1-8 to choose a tool, 0 to exit.
  1/2 Caesar encrypt/decrypt   - text + shift (1-25)
  3/4 Vigenere encrypt/decrypt - text + key word
  5   XOR cipher               - text + key string (shows hex bytes, then decrypts back)
  6   Frequency analysis       - paste a Caesar-encrypted English paragraph (60+ letters work best)
  7   Password analyser        - type a password
  8   Checksum calculator      - type text (djb2, sum, XOR-fold)

SAMPLE TESTS
  Option 1: Hello, World!  shift 3          ->  Khoor, Zruog!
  Option 3: ATTACK AT DAWN key LEMON        ->  LXFOPV EF RNHR
  Option 5: HELLO key K                     ->  03 0E 07 07 04
  Option 7: Hello123                        ->  pool 62, 40 bits, MODERATE
  Option 8: abc                             ->  djb2 0B885C8B, sum 294, XOR-fold 60
