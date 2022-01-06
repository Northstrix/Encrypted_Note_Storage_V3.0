/*
Encrypted Note Storage V3.0
Distributed under the MIT License
© Copyright Maxim Bortnikov 2022
For more information please visit
https://github.com/Northstrix/Encrypted_Note_Storage_V3.0
Required libraries:
https://github.com/zhouyangchao/AES
https://github.com/peterferrie/serpent
https://github.com/ulwanski/sha512
https://github.com/bitluni/ESP32Lib
*/
#include <sys/random.h>
#include "mbedtls/md.h"
#include "sha512.h"
#include "aes.h"
#include "serpent.h"
#include "SPIFFS.h"
char *keys[]=
{"9a93d3e3e81ef9a9195fffffd41ae7a7a5b8262f33fe44b199559591a0e195c6"};// Serpent's key
int count;
byte tmp_st[8];
char dsp[8];
bool clr;
int m;
String dec_st;
uint8_t back_key[32];
uint8_t back_s_key[32];
uint8_t key[32] = {
   0xb7,0x64,0x71,0x2b,
   0x81,0x4b,0xf1,0x7c,
   0xaf,0x3a,0x1f,0x63,
   0xe2,0x87,0x32,0x0e,
   0x56,0x0d,0xcf,0xdc,
   0xe9,0x88,0x4a,0x55,
   0xe1,0xec,0x11,0xb2,
   0x97,0xc3,0x78,0x94
};

uint8_t second_key[32] = {
   0xbf,0x91,0x36,0x23,
   0x53,0x6a,0xb5,0xdb,
   0x92,0x72,0xe8,0xad,
   0x3b,0xba,0x57,0x38,
   0x17,0x5d,0x20,0x7c,
   0x70,0x26,0xe7,0x65,
   0x41,0x10,0xc5,0xe5,
   0x82,0x69,0xce,0x76
};

void back_k(){
  for(int i = 0; i<32; i++){
    back_key[i] = key[i];
  }
}

void rest_k(){
  for(int i = 0; i<32; i++){
    key[i] = back_key[i];
  }
}

void back_s_k(){
  for(int i = 0; i<32; i++){
    back_s_key[i] = second_key[i];
  }
}

void rest_s_k(){
  for(int i = 0; i<32; i++){
    second_key[i] = back_s_key[i];
  }
}

void incr_key(){
  if(key[0] == 255){
    key[0] = 0;
    if(key[1] == 255){
      key[1] = 0;
      if(key[2] == 255){
        key[2] = 0;
        if(key[3] == 255){
          key[3] = 0;

  if(key[4] == 255){
    key[4] = 0;
    if(key[5] == 255){
      key[5] = 0;
      if(key[6] == 255){
        key[6] = 0;
        if(key[7] == 255){
          key[7] = 0;
          
  if(key[8] == 255){
    key[8] = 0;
    if(key[9] == 255){
      key[9] = 0;
      if(key[10] == 255){
        key[10] = 0;
        if(key[11] == 255){
          key[11] = 0;

  if(key[12] == 255){
    key[12] = 0;
    if(key[13] == 255){
      key[13] = 0;
      if(key[14] == 255){
        key[14] = 0;
        if(key[15] == 255){
          key[15] = 0;
        }
        else{
          key[15]++;
        }
        }
      else{
        key[14]++;
      }
    }
    else{
      key[13]++;
    }
  }
  else{
    key[12]++;
  }
          
        }
        else{
          key[11]++;
        }
        }
      else{
        key[10]++;
      }
    }
    else{
      key[9]++;
    }
  }
  else{
    key[8]++;
  }
          
        }
        else{
          key[7]++;
        }
        }
      else{
        key[6]++;
      }
    }
    else{
      key[5]++;
    }
  }
  else{
    key[4]++;
  }
          
        }
        else{
          key[3]++;
        }
        }
      else{
        key[2]++;
      }
    }
    else{
      key[1]++;
    }
  }
  else{
    key[0]++;
  }
}

void incr_second_key(){
  if(second_key[0] == 255){
    second_key[0] = 0;
    if(second_key[1] == 255){
      second_key[1] = 0;
      if(second_key[2] == 255){
        second_key[2] = 0;
        if(second_key[3] == 255){
          second_key[3] = 0;

  if(second_key[4] == 255){
    second_key[4] = 0;
    if(second_key[5] == 255){
      second_key[5] = 0;
      if(second_key[6] == 255){
        second_key[6] = 0;
        if(second_key[7] == 255){
          second_key[7] = 0;
          
  if(second_key[8] == 255){
    second_key[8] = 0;
    if(second_key[9] == 255){
      second_key[9] = 0;
      if(second_key[10] == 255){
        second_key[10] = 0;
        if(second_key[11] == 255){
          second_key[11] = 0;

  if(second_key[12] == 255){
    second_key[12] = 0;
    if(second_key[13] == 255){
      second_key[13] = 0;
      if(second_key[14] == 255){
        second_key[14] = 0;
        if(second_key[15] == 255){
          second_key[15] = 0;
        }
        else{
          second_key[15]++;
        }
        }
      else{
        second_key[14]++;
      }
    }
    else{
      second_key[13]++;
    }
  }
  else{
    second_key[12]++;
  }
          
        }
        else{
          second_key[11]++;
        }
        }
      else{
        second_key[10]++;
      }
    }
    else{
      second_key[9]++;
    }
  }
  else{
    second_key[8]++;
  }
          
        }
        else{
          second_key[7]++;
        }
        }
      else{
        second_key[6]++;
      }
    }
    else{
      second_key[5]++;
    }
  }
  else{
    second_key[4]++;
  }
          
        }
        else{
          second_key[3]++;
        }
        }
      else{
        second_key[2]++;
      }
    }
    else{
      second_key[1]++;
    }
  }
  else{
    second_key[0]++;
  }
}

void read_f(String name){
  File file = SPIFFS.open(name);
  if(!file){
    Serial.println("Failed to open file for reading");
    return;
  }
  Serial.println("File Content:");
  while(file.available()){
    Serial.write(file.read());
  }
  file.close();
}

void write_f(String name, String cont){
  File file = SPIFFS.open(name, FILE_WRITE);
 
  if (!file) {
    Serial.println("There was an error opening the file for writing");
    return;
  }
  if (file.print(cont)) {
    Serial.println("File was written");
  } else {
    Serial.println("File write failed");
  }
 
  file.close();
}

int gen_r_num(){
  char rnd_nmbr[128];
  char key[128];
  //String h = "";
  int res = 0;
  for(int i = 0; i<128; i++){
    int c = esp_random()%4;
    c += esp_random()%4;
    c += esp_random()%4;
    c += esp_random()%4;
    c += esp_random()%4;    
    int d = esp_random()%4;
    d += esp_random()%4;
    d += esp_random()%4;
    d += esp_random()%4;
    d += esp_random()%4;
    int z = esp_random()%4;
    z += esp_random()%4;
    z += esp_random()%4;
    z += esp_random()%4;
    z += esp_random()%4;
    int x = esp_random()%4;
    x += esp_random()%4;
    x += esp_random()%4;
    x += esp_random()%4;
    x += esp_random()%4;
    //Serial.println(z);
    //Serial.println(x);
    //Serial.println(c);
    //Serial.println(d);
    if(c != 0 && d != 0)
    res = (16*c)+d;
    if(c != 0 && d == 0)
    res = 16*c;
    if(c == 0 && d != 0)
    res = d;
    if(c == 0 && d == 0)
    res = 0;
    rnd_nmbr[i] = char(res);
    //Serial.println(res);
    if(z != 0 && x != 0)
    res = (16*z)+x;
    if(z != 0 && x == 0)
    res = 16*z;
    if(z == 0 && x != 0)
    res = x;
    if(z == 0 && x == 0)
    res = 0;
    key[i] = char(res);
    //Serial.println(res);
    //h += getChar(c);
    //h += getChar(d);
  }
  byte hmacResult[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
 
  const size_t payloadLength = strlen(rnd_nmbr);
  const size_t keyLength = strlen(key);            
 
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
  mbedtls_md_hmac_starts(&ctx, (const unsigned char *) key, keyLength);
  mbedtls_md_hmac_update(&ctx, (const unsigned char *) rnd_nmbr, payloadLength);
  mbedtls_md_hmac_finish(&ctx, hmacResult);
  mbedtls_md_free(&ctx);
  /*
  for(int i=0; i<32; i++){
  Serial.print(hmacResult[i] + " ");
  }
  */
  //Serial.print("Hash: ");
  int y = esp_random()%32;
  int rn = (int)hmacResult[y];
  return rn;
}

int getNum(char ch)
{
    int num=0;
    if(ch>='0' && ch<='9')
    {
        num=ch-0x30;
    }
    else
    {
        switch(ch)
        {
            case 'A': case 'a': num=10; break;
            case 'B': case 'b': num=11; break;
            case 'C': case 'c': num=12; break;
            case 'D': case 'd': num=13; break;
            case 'E': case 'e': num=14; break;
            case 'F': case 'f': num=15; break;
            default: num=0;
        }
    }
    return num;
}

char getChar(int num){
  char ch;
    if(num>=0 && num<=9)
    {
        ch = char(num+48);
    }
    else
    {
        switch(num)
        {
            case 10: ch='a'; break;
            case 11: ch='b'; break;
            case 12: ch='c'; break;
            case 13: ch='d'; break;
            case 14: ch='e'; break;
            case 15: ch='f'; break;
        }
    }
    return ch;
}

size_t hex2bin (void *bin, char hex[]) {
  size_t len, i;
  int x;
  uint8_t *p=(uint8_t*)bin;
  
  len = strlen (hex);
  
  if ((len & 1) != 0) {
    return 0; 
  }
  
  for (i=0; i<len; i++) {
    if (isxdigit((int)hex[i]) == 0) {
      return 0; 
    }
  }
  
  for (i=0; i<len / 2; i++) {
    sscanf (&hex[i * 2], "%2x", &x);
    p[i] = (uint8_t)x;
  } 
  return len / 2;
}

void split_by_eight(char plntxt[], int k, int str_len, bool add_aes){
  char plt_data[] = {0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 8; i++){
      if(i+k > str_len - 1)
      break;
      plt_data[i] = plntxt[i+k];
  }
  char t_encr[16];
  for(int i = 0; i<8; i++){
      t_encr[i] = plt_data[i];
  }
  for(int i = 8; i<16; i++){
      t_encr[i] = gen_r_num();
  }
  encr_AES(t_encr, add_aes);
}

void encr_AES(char t_enc[], bool add_aes){
  uint8_t text[16];
  for(int i = 0; i<16; i++){
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint32_t key_bit[3] = {128, 192, 256};
  aes_context ctx;
  aes_set_key(&ctx, key, key_bit[m]);
  aes_encrypt_block(&ctx, cipher_text, text);
  /*
  for (int i = 0; i < 16; ++i) {
    Serial.printf("%02x", cipher_text[i]);
  }
  */
  char L_half[16];
  for(int i = 0; i<8; i++){
    L_half[i] = cipher_text[i];
  }
  char R_half[16];
  for(int i = 0; i<8; i++){
    R_half[i] = cipher_text[i+8];
  }
  for(int i = 8; i<16; i++){
    L_half[i] = gen_r_num();
    R_half[i] = gen_r_num();
  }
  serp_enc(L_half, add_aes);
  serp_enc(R_half, add_aes);
}

void serp_enc(char res[], bool add_aes){
  int tmp_s[16];
  for(int i = 0; i < 16; i++){
      tmp_s[i] = res[i];
  }
  /*
   for (int i = 0; i < 16; i++){
     Serial.print(res[i]);
  }
  Serial.println();
  */
  uint8_t ct1[32], pt1[32], key[64];
  int plen, clen, b, j;
  serpent_key skey;
  serpent_blk ct2;
  uint32_t *p;
  
  for (b=0; b<sizeof(keys)/sizeof(char*); b++) {
    hex2bin (key, keys[b]);
  
    // set key
    memset (&skey, 0, sizeof (skey));
    p=(uint32_t*)&skey.x[0][0];
    
    serpent_setkey (&skey, key);
    //Serial.printf ("\nkey=");
    /*
    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      Serial.printf ("%08X ", p[j]);
    }
    */
    for(int i = 0; i < 16; i++){
        ct2.b[i] = tmp_s[i];
    }
  serpent_encrypt (ct2.b, &skey, SERPENT_ENCRYPT);
  if(add_aes == false){
    for (int i=0; i<16; i++) {
      if(ct2.b[i]<16)
        Serial.print("0");
      Serial.print(ct2.b[i],HEX);
    }
  }
  if(add_aes == true)
  encr_sec_AES(ct2.b);
  }
}

void encr_sec_AES(byte t_enc[]){
  uint8_t text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for(int i = 0; i<16; i++){
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint32_t second_key_bit[3] = {128, 192, 256};
  int i = 0;
  aes_context ctx;
  aes_set_key(&ctx, second_key, second_key_bit[m]);
  aes_encrypt_block(&ctx, cipher_text, text);
  for (i = 0; i < 16; ++i) {
    Serial.printf("%02x", cipher_text[i]);
  }
}

void split_dec(char ct[], int ct_len, int p, bool ch, bool add_r){
  int br = false;
  byte res[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 32; i+=2){
    if(i+p > ct_len - 1){
      br = true;
      break;
    }
    if (i == 0){
    if(ct[i+p] != 0 && ct[i+p+1] != 0)
    res[i] = 16*getNum(ct[i+p])+getNum(ct[i+p+1]);
    if(ct[i+p] != 0 && ct[i+p+1] == 0)
    res[i] = 16*getNum(ct[i+p]);
    if(ct[i+p] == 0 && ct[i+p+1] != 0)
    res[i] = getNum(ct[i+p+1]);
    if(ct[i+p] == 0 && ct[i+p+1] == 0)
    res[i] = 0;
    }
    else{
    if(ct[i+p] != 0 && ct[i+p+1] != 0)
    res[i/2] = 16*getNum(ct[i+p])+getNum(ct[i+p+1]);
    if(ct[i+p] != 0 && ct[i+p+1] == 0)
    res[i/2] = 16*getNum(ct[i+p]);
    if(ct[i+p] == 0 && ct[i+p+1] != 0)
    res[i/2] = getNum(ct[i+p+1]);
    if(ct[i+p] == 0 && ct[i+p+1] == 0)
    res[i/2] = 0;
    }
  }
    if(br == false){
      if(add_r == true){
      uint8_t ret_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
      uint8_t cipher_text[16] = {0};
      for(int i = 0; i<16; i++){
        int c = int(res[i]);
        cipher_text[i] = c;
      }
      uint32_t second_key_bit[3] = {128, 192, 256};
      int i = 0;
      aes_context ctx;
      aes_set_key(&ctx, second_key, second_key_bit[m]);
      aes_decrypt_block(&ctx, ret_text, cipher_text);
      for (i = 0; i < 16; ++i) {
        res[i] = (char)ret_text[i];
      }
      }
      uint8_t ct1[32], pt1[32], key[64];
      int plen, clen, i, j;
      serpent_key skey;
      serpent_blk ct2;
      uint32_t *p;
  
  for (i=0; i<sizeof(keys)/sizeof(char*); i++) {
    hex2bin (key, keys[i]);
  
    // set key
    memset (&skey, 0, sizeof (skey));
    p=(uint32_t*)&skey.x[0][0];
    
    serpent_setkey (&skey, key);
    //Serial.printf ("\nkey=");

    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      //Serial.printf ("%08X ", p[j]);
    }

    for(int i = 0; i <16; i++)
      ct2.b[i] = res[i];
    /*
    Serial.printf ("\n\n");
    for(int i = 0; i<16; i++){
    Serial.printf("%x", ct2.b[i]);
    Serial.printf(" ");
    */
    }
    //Serial.printf("\n");
    serpent_encrypt (ct2.b, &skey, SERPENT_DECRYPT);
    if (ch == false){
    for (int i=0; i<8; i++) {
      tmp_st[i] = char(ct2.b[i]);
    }
    }
    if (ch == true){
      decr_AES(ct2.b);
    }
  }
}

void decr_AES(byte sh[]){
  uint8_t ret_text[16];
  for(int i = 0; i<8; i++){
    ret_text[i] = tmp_st[i];
  }
  for(int i = 0; i<8; i++){
    ret_text[i+8] = sh[i];
  }
      uint8_t cipher_text[16] = {0};
      for(int i = 0; i<16; i++){
        int c = int(ret_text[i]);
        cipher_text[i] = c;
      }
      uint32_t key_bit[3] = {128, 192, 256};
      int i = 0;
      aes_context ctx;
      aes_set_key(&ctx, key, key_bit[m]);
      aes_decrypt_block(&ctx, ret_text, cipher_text);
      for (i = 0; i < 8; ++i) {
        dec_st += (char(ret_text[i]));
        dsp[i] = (char(ret_text[i]));
      }
}

void split_by_eight_for_AES(char plntxt[], int k, int str_len){
  char res[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for(int i = 0; i < 8; i++){
      if(i+k > str_len - 1)
      break;
      res[i] = plntxt[i+k];
  }
  for(int i = 8; i<16; i++){
    res[i] = gen_r_num();
  }
  encr_AES_only(res);
}

void encr_AES_only(char t_enc[]){
  uint8_t text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for(int i = 0; i<16; i++){
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint32_t key_bit[3] = {128, 192, 256};
  int i = 0;
  aes_context ctx;
  aes_set_key(&ctx, key, key_bit[m]);
  aes_encrypt_block(&ctx, cipher_text, text);
  for (i = 0; i < 16; ++i) {
    Serial.printf("%02x", cipher_text[i]);
  }
}

void split_dec_for_AES(char ct[], int ct_len, int p){
  int br = false;
  byte res[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 32; i+=2){
    if(i+p > ct_len - 1){
      br = true;
      break;
    }
    if (i == 0){
    if(ct[i+p] != 0 && ct[i+p+1] != 0)
    res[i] = 16*getNum(ct[i+p])+getNum(ct[i+p+1]);
    if(ct[i+p] != 0 && ct[i+p+1] == 0)
    res[i] = 16*getNum(ct[i+p]);
    if(ct[i+p] == 0 && ct[i+p+1] != 0)
    res[i] = getNum(ct[i+p+1]);
    if(ct[i+p] == 0 && ct[i+p+1] == 0)
    res[i] = 0;
    }
    else{
    if(ct[i+p] != 0 && ct[i+p+1] != 0)
    res[i/2] = 16*getNum(ct[i+p])+getNum(ct[i+p+1]);
    if(ct[i+p] != 0 && ct[i+p+1] == 0)
    res[i/2] = 16*getNum(ct[i+p]);
    if(ct[i+p] == 0 && ct[i+p+1] != 0)
    res[i/2] = getNum(ct[i+p+1]);
    if(ct[i+p] == 0 && ct[i+p+1] == 0)
    res[i/2] = 0;
    }
  }
    if(br == false){
      uint8_t ret_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
      uint8_t cipher_text[16] = {0};
      for(int i = 0; i<16; i++){
        int c = int(res[i]);
        cipher_text[i] = c;
      }
      uint32_t key_bit[3] = {128, 192, 256};
      int i = 0;
      aes_context ctx;
      aes_set_key(&ctx, key, key_bit[m]);
      aes_decrypt_block(&ctx, ret_text, cipher_text);
      for (i = 0; i < 8; ++i) {
        Serial.print(char(ret_text[i]));
        dsp[i] = char(ret_text[i]);
      }
   }
}

void split_by_eight_for_Serpent_only(char plntxt[], int k, int str_len){
  char res[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 8; i++){
      if(i+k > str_len - 1)
      break;
      res[i] = plntxt[i+k];
  }
  for (int i = 8; i < 16; i++){
      res[i] = gen_r_num();
  }
  int tmp_s[16];
  for(int i = 0; i < 16; i++){
      tmp_s[i] = res[i];
  }
  /*
   for (int i = 0; i < 8; i++){
     Serial.print(res[i]);
  }
  Serial.println();
  */
  uint8_t ct1[32], pt1[32], key[64];
  int plen, clen, b, j;
  serpent_key skey;
  serpent_blk ct2;
  uint32_t *p;
  
  for (b=0; b<sizeof(keys)/sizeof(char*); b++) {
    hex2bin (key, keys[b]);
  
    // set key
    memset (&skey, 0, sizeof (skey));
    p=(uint32_t*)&skey.x[0][0];
    
    serpent_setkey (&skey, key);
    //Serial.printf ("\nkey=");
    /*
    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      Serial.printf ("%08X ", p[j]);
    }
    */
    for(int i = 0; i < 16; i++){
        ct2.b[i] = tmp_s[i];
    }
  serpent_encrypt (ct2.b, &skey, SERPENT_ENCRYPT);
    for (int i=0; i<16; i++) {
      if(ct2.b[i]<16)
        Serial.print("0");
      Serial.print(ct2.b[i],HEX);
  }
  }
}

void split_dec_for_Serpent_only(char ct[], int ct_len, int p){
  int br = false;
  byte res[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 32; i+=2){
    if(i+p > ct_len - 1){
      br = true;
      break;
    }
    if (i == 0){
    if(ct[i+p] != 0 && ct[i+p+1] != 0)
    res[i] = 16*getNum(ct[i+p])+getNum(ct[i+p+1]);
    if(ct[i+p] != 0 && ct[i+p+1] == 0)
    res[i] = 16*getNum(ct[i+p]);
    if(ct[i+p] == 0 && ct[i+p+1] != 0)
    res[i] = getNum(ct[i+p+1]);
    if(ct[i+p] == 0 && ct[i+p+1] == 0)
    res[i] = 0;
    }
    else{
    if(ct[i+p] != 0 && ct[i+p+1] != 0)
    res[i/2] = 16*getNum(ct[i+p])+getNum(ct[i+p+1]);
    if(ct[i+p] != 0 && ct[i+p+1] == 0)
    res[i/2] = 16*getNum(ct[i+p]);
    if(ct[i+p] == 0 && ct[i+p+1] != 0)
    res[i/2] = getNum(ct[i+p+1]);
    if(ct[i+p] == 0 && ct[i+p+1] == 0)
    res[i/2] = 0;
    }
  }
    if(br == false){
      uint8_t ct1[32], pt1[32], key[64];
      int plen, clen, i, j;
      serpent_key skey;
      serpent_blk ct2;
      uint32_t *p;
  
  for (i=0; i<sizeof(keys)/sizeof(char*); i++) {
    hex2bin (key, keys[i]);
  
    // set key
    memset (&skey, 0, sizeof (skey));
    p=(uint32_t*)&skey.x[0][0];
    
    serpent_setkey (&skey, key);
    //Serial.printf ("\nkey=");

    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      //Serial.printf ("%08X ", p[j]);
    }

    for(int i = 0; i <16; i++)
      ct2.b[i] = res[i];
    /*
    Serial.printf ("\n\n");
    for(int i = 0; i<16; i++){
    Serial.printf("%x", ct2.b[i]);
    Serial.printf(" ");
    */
    }
    //Serial.printf("\n");
    serpent_encrypt (ct2.b, &skey, SERPENT_DECRYPT);
    for (int i=0; i<8; i++) {
      dec_st += char(ct2.b[i]);
      dsp[i] = char(ct2.b[i]);
    }
  }
}

#include <ESP32Lib.h>
#include <Ressources/CodePage437_8x14.h>

//pin configuration
const int redPin = 14;
const int greenPin = 19;
const int bluePin = 27;
const int hsyncPin = 32;
const int vsyncPin = 33;

//VGA Device
VGA3Bit vga;

void setup() {
  Serial.begin(115200);
  if (!SPIFFS.begin(true)) {
    Serial.println("An Error has occurred while mounting SPIFFS");
    return;
  }
  m = 2;
  dec_st = "";
  vga.init(vga.MODE640x400, redPin, greenPin, bluePin, hsyncPin, vsyncPin);
  vga.setFont(CodePage437_8x14);
  pinMode(5, INPUT);
  clr = false; // White text color by default
  //clr = true; // Green text color by default
}

void loop() {
    for(int i = 0; i<8; i++){
      dsp[i] = 0;
    }
    Serial.println();
    back_k();
    back_s_k();
    vga.clear();
    vga.setCursor(0,0);
    if(clr == false)
      vga.setTextColor(vga.RGB(255, 255, 255), vga.RGB(0, 0, 0)); // White text color
    else
      vga.setTextColor(vga.RGB(0, 255, 0), vga.RGB(0, 0, 0)); // Green text color
    Serial.println("What do you want to do?");
    Serial.println("1.Encrypt data in counter mode with AES + Serpent + AES");
    Serial.println("2.Decrypt data in counter mode with AES + Serpent + AES");
    Serial.println("3.Encrypt data with AES in counter mode");
    Serial.println("4.Decrypt data with AES in counter mode");
    Serial.println("5.Encrypt data with Serpent");
    Serial.println("6.Decrypt data with Serpent");
    Serial.println("7.Set AES to 128-bit mode");
    Serial.println("8.Set AES to 192-bit mode");
    Serial.println("9.Set AES to 256-bit mode");
    Serial.println("10.Hash data with SHA-512");
    Serial.println("11.Increment key (IV) specified number times");
    Serial.println("12.Test RNG");
    Serial.println("13.Derive part of the key from the string");
    Serial.println("14.Generate random ASCII strings");
    Serial.println("15.Set text color to Green");
    Serial.println("16.Set text color to White");
    Serial.println("17.Save record");
    Serial.println("18.Load record");
    Serial.println("19.Remove record");
    Serial.println("20.List all stored records");
    Serial.println("21.Compare strings");
    vga.println("What do you want to do?");
    vga.println("1.Encrypt data in counter mode with AES + Serpent + AES");
    vga.println("2.Decrypt data in counter mode with AES + Serpent + AES");
    vga.println("3.Encrypt data with AES in counter mode");
    vga.println("4.Decrypt data with AES in counter mode");
    vga.println("5.Encrypt data with Serpent");
    vga.println("6.Decrypt data with Serpent");
    vga.println("7.Set AES to 128-bit mode");
    vga.println("8.Set AES to 192-bit mode");
    vga.println("9.Set AES to 256-bit mode");
    vga.println("10.Hash data with SHA-512");
    vga.println("11.Increment key (IV) specified number times");
    vga.println("12.Test RNG");
    vga.println("13.Derive part of the key from the string");
    vga.println("14.Generate random ASCII strings");
    vga.println("15.Set text color to Green");
    vga.println("16.Set text color to White");
    vga.println("17.Save record");
    vga.println("18.Load record");
    vga.println("19.Remove record");
    vga.println("20.List all stored records");
    vga.println("21.Compare strings");
    while (!Serial.available()) {}
    int x = Serial.parseInt();
    if(x == 1){
      vga.clear();
      vga.setCursor(0,0);
      Serial.println("Enter plaintext:");
      vga.println("Enter plaintext:");
      String inp_str;
      while (!Serial.available()) {}
      inp_str = Serial.readString();
      int str_len = inp_str.length() + 1;
      char char_array[str_len];
      inp_str.toCharArray(char_array, str_len);
      vga.clear();
      vga.setCursor(0,0);
      Serial.println("Ciphertext:");
      vga.println("Encrypting the note with AES + Serpent + AES in counter mode");
      int p = 0;
      while(str_len > p+1){
        incr_key();
        incr_second_key();
        split_by_eight(char_array, p, str_len, true);
        p+=8;
        vga.print(".");
      }
      rest_k();
      rest_s_k();
    }
    if(x == 2){
      dec_st = "";
      String ct;
      vga.clear();
      vga.setCursor(0,0);
      Serial.println("Paste ciphertext");
      vga.println("Paste ciphertext");
      while (!Serial.available()) {}
      ct = Serial.readString();
      int ct_len = ct.length() + 1;
      char ct_array[ct_len];
      ct.toCharArray(ct_array, ct_len);
      int ext = 0;
      count = 0;
      bool ch = false;
      bool d = false;
      vga.clear();
      vga.setCursor(0,0);
      vga.println("Decrypted note:");
      vga.println("");
      while(ct_len > ext){
      if(count%2 == 1 && count !=0)
        ch = true;
      else{
        ch = false;
          incr_key();
          incr_second_key();
          if(d != false && ct_len > ext){
            for(int i = 0; i<8; i++){
              vga.print(dsp[i]);
            }
          }
          d = true;
      }
      split_dec(ct_array, ct_len, 0+ext, ch, true);
      ext+=32;
      count++;
      }
      rest_k();
      rest_s_k();
      Serial.println("Decrypted note:");
      Serial.println(dec_st);
      dec_st = "";
      vga.println("");
      vga.println("");
      vga.println("Decryption is done successfully! Press the button to get back to the menu.");
      while(digitalRead(5) != 0){}
    }
  if(x == 3){
    Serial.println("Enter plaintext:");
    vga.clear();
    vga.setCursor(0,0);
    vga.println("Enter plaintext:");
    String input;
    while (!Serial.available()) {}
    input = Serial.readString();
    int str_len = input.length() + 1;
    char input_arr[str_len];
    input.toCharArray(input_arr, str_len);
    int p = 0;
    vga.clear();
    vga.setCursor(0,0);
    vga.println("Encrypting the note with AES in counter mode");
    while(str_len > p+1){
      incr_key();
      split_by_eight_for_AES(input_arr, p, str_len);
      p+=8;
      vga.print(".");
    }
    rest_k();
  }
  if(x == 4){
     String ct;
     vga.clear();
     vga.setCursor(0,0);
     Serial.println("Paste ciphertext");
     vga.println("Paste ciphertext");
     while (!Serial.available()) {}
     ct = Serial.readString();
     int ct_len = ct.length() + 1;
     char ct_array[ct_len];
     ct.toCharArray(ct_array, ct_len);
     int ext = 0;
     Serial.println("Decrypted note:");
     vga.clear();
     vga.setCursor(0,0);
     vga.println("Decrypted note:");
     vga.println("");
     while(ct_len > ext){
       incr_key();
       split_dec_for_AES(ct_array, ct_len, 0+ext);
       ext+=32;
       if(ct_len > ext){
        for(int i = 0; i<8; i++){
            vga.print(dsp[i]);
        }
       }
     }
     rest_k();
     vga.println("");
     vga.println("");
     vga.println("Decryption is done successfully! Press the button to get back to the menu.");
     while(digitalRead(5) != 0){}
   }
    if(x == 5){
      Serial.println("Enter plaintext:");
      vga.clear();
      vga.setCursor(0,0);
      vga.println("Enter plaintext:");
      String str;
      while (!Serial.available()) {}
      str = Serial.readString();
      int str_len = str.length() + 1;
      char char_array[str_len];
      str.toCharArray(char_array, str_len);
      Serial.println("Ciphertext:");
      vga.clear();
      vga.setCursor(0,0);
      vga.println("Encrypting the note with Serpent");
      int p = 0;
      while( str_len > p+1){
        split_by_eight_for_Serpent_only(char_array, p, str_len);
        p+=8;
        vga.print(".");
      }
    }
    if(x == 6){
      dec_st = "";
      String ct;
      vga.clear();
      vga.setCursor(0,0);
      Serial.println("Paste ciphertext");
      vga.println("Paste ciphertext");
      while (!Serial.available()) {}
      ct = Serial.readString();
      int ct_len = ct.length() + 1;
      char ct_array[ct_len];
      ct.toCharArray(ct_array, ct_len);
      int ext = 0;
      Serial.println("Decrypted note:");
      vga.clear();
      vga.setCursor(0,0);
      vga.println("Decrypted note:");
      vga.println("");
      while(ct_len > ext){
        split_dec_for_Serpent_only(ct_array, ct_len, 0+ext);
        ext+=32;
        if(ct_len > ext){
          for(int i = 0; i<8; i++){
              vga.print(dsp[i]);
          }
        }
      }
      Serial.println(dec_st);
      dec_st = "";
      vga.println("");
      vga.println("");
      vga.println("Decryption is done successfully! Press the button to get back to the menu.");
      while(digitalRead(5) != 0){}
    }
    if(x == 7)
      m = 0;
    if(x == 8)
      m = 1;
    if(x == 9)
      m = 2;
    if(x == 10){
      Serial.print("Enter the note to hash:");
      vga.clear();
      vga.setCursor(0,0);
      vga.println("Enter the note to hash:");
      String input;
      while (!Serial.available()) {}
      input = Serial.readString();
      Serial.println(input);
      int str_len = input.length() + 1;
      char input_arr[str_len];
      vga.clear();
      vga.setCursor(0,0);
      vga.print("Note: ");
      input.toCharArray(input_arr, str_len);
      for(int i = 0; i < str_len - 1; i++)
        vga.print(input_arr[i]);
      std::string str = "";
      if(str_len > 1){
        for(int i = 0; i<str_len-1; i++){
          str += input_arr[i];
        }
      }
      String h = sha512( str ).c_str();
      Serial.println("Hash:");
      Serial.println(h);
      str_len = h.length() + 1;
      char h_arr[str_len];
      h.toCharArray(h_arr, str_len);
      vga.println("");
      vga.println("");
      vga.print("Hash: ");
      for(int i = 0; i < str_len - 1; i++)
        vga.print(h_arr[i]);
      vga.println("");
      vga.println("");
      vga.println("Hashing is done successfully! Press the button to get back to the menu.");
      while(digitalRead(5) != 0){}
    }
    if(x == 11){
      vga.clear();
      vga.setCursor(0,0);
      vga.println("How many times do you want to increment the key?");
      Serial.println("How many times do you want to increment the key?");
      while (!Serial.available()) {}
      int itr = Serial.parseInt();
      for(int i = 0; i < itr; i++){
        incr_key();
      }
    }
    if(x == 12){
     vga.clear();
     vga.setCursor(0,0);
     vga.println("Testing RNG");
     vga.println("");
     for(int cnt = 0; cnt < 24; cnt++){
      for (int i = 0; i < 20; ++i) {
        Serial.printf("%02x", gen_r_num());
        vga.print(gen_r_num());
        vga.print(" ");
      }
      Serial.println();
      vga.println("");
     }
    }
    if(x == 13){
      vga.clear();
      vga.setCursor(0,0);
      vga.println("Enter the string to derive a part of the key from:");
      Serial.println("Enter the string to derive a part of the key from:");
      String input;
      while (!Serial.available()) {}
      input = Serial.readString();
      int str_len = input.length() + 1;
      char input_arr[str_len];
      input.toCharArray(input_arr, str_len);
      std::string str = "";
      vga.clear();
      vga.setCursor(0,0);
      vga.println("Deriving the part of the key");
      vga.println("");
      if(str_len > 1){
        for(int i = 0; i<str_len-1; i++){
          str += input_arr[i];
        }
      }
      String h = sha512( str ).c_str();
      int h_len = h.length() + 1;
      char h_array[h_len];
      h.toCharArray(h_array, h_len);
      byte res[16] = {0};
      for (int i = 0; i < 32; i+=2){
      if (i == 0){
      if(h_array[i] != 0 && h_array[i+1] != 0)
      res[i] = 16*getNum(h_array[i])+getNum(h_array[i+1]);
      if(h_array[i] != 0 && h_array[i+1] == 0)
      res[i] = 16*getNum(h_array[i]);
      if(h_array[i] == 0 && h_array[i+1] != 0)
      res[i] = getNum(h_array[i+1]);
      if(h_array[i] == 0 && h_array[i+1] == 0)
      res[i] = 0;
      }
      else{
      if(h_array[i] != 0 && h_array[i+1] != 0)
      res[i/2] = 16*getNum(h_array[i])+getNum(h_array[i+1]);
      if(h_array[i] != 0 && h_array[i+1] == 0)
      res[i/2] = 16*getNum(h_array[i]);
      if(h_array[i] == 0 && h_array[i+1] != 0)
      res[i/2] = getNum(h_array[i+1]);
      if(h_array[i] == 0 && h_array[i+1] == 0)
      res[i/2] = 0;
      }
     }
     uint8_t ct1[32], pt1[32], key[64];
     int plen, clen, i, j;
     serpent_key skey;
     serpent_blk ct2;
     uint32_t *p;
     for (i=0; i<sizeof(keys)/sizeof(char*); i++) {
      hex2bin (key, keys[i]);
      memset (&skey, 0, sizeof (skey));
      p=(uint32_t*)&skey.x[0][0];
      serpent_setkey (&skey, key);
      for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
        if ((j % 8)==0) putchar('\n');
      }
      for(int i = 0; i <16; i++)
        ct2.b[i] = res[i];
      }
      for(int i = 0; i<576; i++){
        serpent_encrypt (ct2.b, &skey, SERPENT_DECRYPT);
        vga.print(".");
      }
      key[0] = ct2.b[0];
      key[1] = ct2.b[1];
      key[3] = ct2.b[2];
      key[4] = ct2.b[3];
      key[6] = ct2.b[4];
      key[7] = ct2.b[5];
      key[8] = ct2.b[12];
      second_key[0] = ct2.b[6];
      second_key[1] = ct2.b[7];
      second_key[3] = ct2.b[8];
      second_key[4] = ct2.b[9];
      second_key[6] = ct2.b[10];
      second_key[7] = ct2.b[11];
      second_key[8] = ct2.b[13];
      Serial.print("Key derived successfully. Verification number: ");
      Serial.println(ct2.b[14]);
    }
    if(x == 14){
      Serial.println("How many strings do you want?");
      vga.clear();
      vga.setCursor(0,0);
      vga.println("How many strings do you want?");
      while (!Serial.available()) {}
      int nmbr = Serial.parseInt();
      Serial.println("Random ASCII strings:");
      vga.clear();
      vga.setCursor(0,0);
      vga.println("Random ASCII strings:");
      for(int sn = 0; sn < nmbr; sn++){
      int pt = 80 + gen_r_num();
      for(int i = 0; i < pt; i++){
        int r = gen_r_num();
        if(r>32 && r<127){
          Serial.print(char(r));
          vga.print(char(r));
        }
      }
      Serial.println();
      vga.println("");
      }
    }
    if(x == 15){
      clr = true;
    }
    if(x == 16){
      clr = false;
    }
    if(x == 17){
      String cf;
      Serial.println("Enter the name of the new file");
      vga.clear();
      vga.setCursor(0,0);
      vga.println("Enter the name of the new file");
      while (!Serial.available()) {}
      cf = Serial.readString();
      String cont;
      Serial.println("Enter the content of the new file");
      vga.clear();
      vga.setCursor(0,0);
      vga.println("Enter the content of the new file");
      while (!Serial.available()) {}
      cont = Serial.readString();
      write_f("/" + cf, cont);
    }
    if(x == 18){
      String opn;
      Serial.println("Enter the name of the file to open");
      vga.clear();
      vga.setCursor(0,0);
      vga.println("Enter the name of the file to open");
      while (!Serial.available()) {}
      opn = Serial.readString();
      read_f("/" + opn);
    }
    if(x == 19){
      String rm;
      Serial.println("Enter the name of the file to remove");
      vga.clear();
      vga.setCursor(0,0);
      vga.println("Enter the name of the file to remove");
      while (!Serial.available()) {}
      rm = Serial.readString();
      SPIFFS.remove("/" + rm);
    }
    if(x == 20){
      File root = SPIFFS.open("/");
      File file = root.openNextFile();
      vga.clear();
      vga.setCursor(0,0);
      vga.println("Stored files:");
      while(file){
        Serial.print("FILE: ");
        Serial.println(file.name());
        vga.println(file.name());
        file = root.openNextFile();
      }
      vga.println("");
      vga.println("");
      vga.println("Press the button to get back to the menu.");
      while(digitalRead(5) != 0){}
    }
    if(x == 21){
      vga.clear();
      vga.setCursor(0,0);
      Serial.println("Enter first string:");
      vga.println("Enter first string:");
      String inp_str;
      String inp_sec_str;
      while (!Serial.available()) {}
      inp_str = Serial.readString();
      int str_len = inp_str.length() + 1;
      char char_array[str_len];
      inp_str.toCharArray(char_array, str_len);
      vga.clear();
      vga.setCursor(0,0);
      Serial.println("Enter second string:");
      vga.println("Enter second string:");
      while (!Serial.available()) {}
      inp_sec_str = Serial.readString();
      int sec_str_len = inp_sec_str.length() + 1;
      char sec_char_arr[sec_str_len];
      inp_sec_str.toCharArray(sec_char_arr, sec_str_len);
      int lng = str_len - 1;
      if(str_len == sec_str_len){
        bool eq = true;
        for(int i = 0; i<lng; i++){
          if(char_array[i] != sec_char_arr[i]){
            eq = false;
          }
        }
        vga.clear();
        vga.setCursor(0,0);
        vga.print("String N1: ");
        for(int i = 0; i<lng; i++)
          vga.print(char_array[i]);
        vga.println("");
        vga.print("String N2: ");
        for(int i = 0; i<lng; i++)
          vga.print(sec_char_arr[i]);
        vga.println("");
        vga.println("");
        if(eq == true){
          Serial.println("Strings are equal!");
          vga.print("Strings are equal! ");
        }
        else{
          Serial.println("Strings aren't equal!");
          vga.print("Strings aren't equal! ");
        }
      }
      else{
        vga.clear();
        vga.setCursor(0,0);
        Serial.println("Strings aren't equal!");
        vga.println("Strings aren't equal!");
        vga.println("");
        vga.println("");
      }
      vga.println("Press the button to get back to the menu.");
      while(digitalRead(5) != 0){}
    }
}
