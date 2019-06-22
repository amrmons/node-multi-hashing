#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "facet_one.h"
#include "facet_two.h"
#include "facet_three.h"
#include "facet_four.h"
#include "facet_five.h"
#include "facet_six.h"

void HoneyBee( const char *in, unsigned int sz, unsigned char * output )
{
	memcpy( output, &in[0],     36 );
	memcpy( output + 36, &in[sz-28], 28 );  
}

void honeycomb_hash(const char* input, char* output)
{	
    facet_one_context		ctx_one;
    facet_two_context		ctx_two;
    facet_three_context     ctx_three;
    facet_four_context		ctx_four;
    facet_five_context		ctx_five;
    facet_six_context     	ctx_six;
    
    uint8_t hash[12*64] = {0};
    uint8_t honey[64] = {0};
    size_t i = 0;
    HoneyBee( input, 80, honey );
    facet_one_init(&ctx_one);
    facet_one(&ctx_one, input, 80 );
    facet_one_close(&ctx_one, hash);
    facet_four_init(&ctx_four);
    facet_four(&ctx_four, input, 80);
    facet_four_close(&ctx_four, hash + 64*1);
    
    for(i = 0; i < 64; i++)
        hash[(2*64)+i] = honey[i]^hash[(1*64)+i];
    
    for(i = 0; i < 64; i++)
        hash[(3*64)+i] = hash[i]^hash[(2*64)+i];	
    
    facet_two_init( &ctx_two );
    facet_two( &ctx_two, hash + 64*3, 64 );
    facet_two_close( &ctx_two, hash + 64*4 );
    facet_five_init(&ctx_five);
    facet_five (&ctx_five, input, 80);
    facet_five_close(&ctx_five, hash + 64*5);
    
    for(i = 0; i < 64; i++)
        hash[(6*64)+i] = honey[i]^hash[(5*64)+i];
    
    for(i = 0; i < 64; i++)
        hash[(7*64)+i] = hash[(4*64)+i]^hash[(6*64)+i];	
    
    facet_three_init(  &ctx_three  );
    facet_three(  &ctx_three, hash + 64*7, 64   );
    facet_three_close(   &ctx_three, hash + 64*8   );
    facet_six_init(&ctx_six);
    facet_six( &ctx_six, input, 80 );
    facet_six_close(&ctx_six, hash + 64*9);
    
    for(i = 0; i < 64; i++)
        hash[(10*64)+i] = honey[i]^hash[(9*64)+i];
    
    for(i = 0; i < 64; i++)
        hash[(11*64)+i] = hash[(8*64)+i]^hash[(10*64)+i];
	
    memcpy(output, hash + 11, 32);
}
