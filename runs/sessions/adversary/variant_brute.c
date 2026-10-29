#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int ROTR=0, ROLR=0, D=0, CA=0, CX=0, EO=0; // flags

static inline uint8_t rol(uint8_t x,int n,int r){
    n&=7; if(r) n=(8-n)&7;
    return (uint8_t)(((x<<n)|(x>>((8-n)&7)))&0xFF);
}
static inline uint8_t f(uint8_t k,uint8_t x){ return (uint8_t)(((x^k)+k)&0xFF); }
static inline uint8_t g(uint8_t k,uint8_t y){ return (uint8_t)(((y+k)&0xFF)^k); }
static inline uint8_t h(uint8_t k,uint8_t c){ return (uint8_t)(((c^k)-k)&0xFF); }
static inline uint8_t finv(uint8_t k,uint8_t z){ return (uint8_t)(((z-k)&0xFF)^k); }

static inline void rotbuf(uint8_t *b,int L,int n){
    n%=L; if(n<0)n+=L;
    uint8_t t[32];
    if(!ROTR){ for(int i=0;i<L;i++) t[i]=b[(i+n)%L]; }
    else { for(int i=0;i<L;i++) t[i]=b[(i-n+L*2)%L]; }
    memcpy(b,t,L);
}
static inline void middle(uint8_t *b,int L){
    for(int i=0;i<L;i++) b[i]=rol(b[i],5,ROLR);
    rotbuf(b,L,13);
    if(!CA){ uint8_t s=0; for(int i=0;i<L;i++){s=(uint8_t)(s+b[i]); b[i]=s;} }
    else { uint8_t s=0; for(int i=L-1;i>=0;i--){s=(uint8_t)(s+b[i]); b[i]=s;} }
    rotbuf(b,L,21);
    for(int i=0;i<L;i++) b[i]=(uint8_t)((b[i]+158)&0xFF);
    for(int i=0;i<L;i++) b[i]^=60;
    if(!CX){ uint8_t s=0; for(int i=0;i<L;i++){s^=b[i]; b[i]=s;} }
    else { uint8_t s=0; for(int i=L-1;i>=0;i--){s^=b[i]; b[i]=s;} }
    for(int i=0;i<L;i++) b[i]=rol(b[i],3,ROLR);
    rotbuf(b,L,7);
}
static inline void inv_middle(uint8_t *b,int L){
    rotbuf(b,L,-7);
    for(int i=0;i<L;i++) b[i]=rol(b[i],5,ROLR); // inverse of rol3
    if(!CX){ uint8_t p=0; for(int i=0;i<L;i++){uint8_t x=b[i]; b[i]^=p; p=x;} }
    else { uint8_t p=0; for(int i=L-1;i>=0;i--){uint8_t x=b[i]; b[i]^=p; p=x;} }
    for(int i=0;i<L;i++) b[i]^=60;
    for(int i=0;i<L;i++) b[i]=(uint8_t)((b[i]-158)&0xFF);
    rotbuf(b,L,-21);
    if(!CA){ uint8_t p=0; for(int i=0;i<L;i++){uint8_t x=b[i]; b[i]=(uint8_t)(x-p); p=x;} }
    else { uint8_t p=0; for(int i=L-1;i>=0;i--){uint8_t x=b[i]; b[i]=(uint8_t)(x-p); p=x;} }
    rotbuf(b,L,-13);
    for(int i=0;i<L;i++) b[i]=rol(b[i],3,ROLR); // inverse of rol5
}
static inline void enc(uint8_t *m,uint8_t *c,int L,const uint8_t *key){
    uint8_t b[32];
    for(int i=0;i<L;i++) b[i]=f(key[i%4],m[i]);
    middle(b,L);
    for(int i=0;i<L;i++){ int j=(i+D)%4; c[i]= g(key[j],b[i]); }
}
static inline void dec(uint8_t *c,uint8_t *m,int L,const uint8_t *key){
    uint8_t b[32];
    for(int i=0;i<L;i++){ int j=(i+D)%4; b[i]=h(key[j],c[i]); }
    inv_middle(b,L);
    for(int i=0;i<L;i++) m[i]=finv(key[i%4],b[i]);
}

int main(int argc,char**argv){
    ROTR=atoi(argv[1]); ROLR=atoi(argv[2]); D=atoi(argv[3]);
    CA=atoi(argv[4]); CX=atoi(argv[5]); EO=atoi(argv[6]);
    uint8_t M[4]={0,1,2,3};
    uint8_t C[4]={0xed,0x0d,0xa4,0xf6};
    uint8_t target[24];
    const char *th="1c4e21e4d01b6c1afc003c23077ff7c8d949c1bc14630528";
    for(int i=0;i<24;i++){ unsigned v; sscanf(th+2*i,"%2x",&v); target[i]=(uint8_t)v; }
    uint32_t total=1u<<28;
    long long count=0;
    uint8_t key[4]; uint8_t out[24];
    for(uint32_t idx=0; idx<total; idx++){
        key[0]=idx&127; key[1]=(idx>>7)&127; key[2]=(idx>>14)&127; key[3]=(idx>>21)&127;
        uint8_t c4[4];
        enc(M,c4,4,key);
        if(c4[0]==C[0]&&c4[1]==C[1]&&c4[2]==C[2]&&c4[3]==C[3]){
            count++;
            if(count<=200){
                dec(target,out,24,key);
                printf("MATCH key %02x %02x %02x %02x  pt ",key[0],key[1],key[2],key[3]);
                for(int i=0;i<24;i++) printf("%02x",out[i]);
                printf("  ascii ");
                for(int i=0;i<24;i++) putchar((out[i]>=32&&out[i]<127)?out[i]:'.');
                printf("\n");
            }
        }
    }
    printf("TOTAL %lld\n",count);
    return 0;
}
