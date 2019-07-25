#include <stdio.h>

  /* For CMAC Calculation */
//  unsigned char const_Rb;
//  unsigned char const_Zero;
  /* Basic Functions */

  void xor_128(unsigned char *a, unsigned char *b, unsigned char *out);
  void print_hex(char *str, unsigned char *buf, int len);
  void print128(unsigned char *bytes);
  void print96(unsigned char *bytes);
  void leftshift_onebit(unsigned char *input,unsigned char *output);
  void generate_subkey(unsigned char *key, unsigned char *K1, unsigned char *K2);
  void padding ( unsigned char *lastb, unsigned char *pad, int length );
  void AES_CMAC ( unsigned char *key, unsigned char *input, int length, unsigned char *mac );
