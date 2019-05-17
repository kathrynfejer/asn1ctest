#include <stdio.h>
#include <sys/types.h>
#include "Keypair.h"   /* keypair ASN.1 type  */

int save_to_file(unsigned char *buffer, size_t bytes_to_write, const char *filename)
{
    FILE *file_ptr = fopen(filename, "wb");
    int ret = 0;
    int close_ret = 0;

    if (NULL == file_ptr){
        return -1;
    }

    size_t bytes_written = fwrite(buffer, 1, bytes_to_write, file_ptr);

    if (bytes_to_write != bytes_written) {
        ret = -1;
        goto cleanup;
    }

    ret = (int) bytes_written;

cleanup:
    close_ret = fclose(file_ptr);
    if (0 != close_ret) {
       ret = -1;
    }
    return ret;
}

int read_from_file(const char *filename, unsigned char *buffer, size_t bytes_to_read)
{
    FILE *file_ptr = fopen(filename, "rb");
    int ret = 0;
    int close_ret = 0;

    if (NULL == file_ptr){
        return -1;
    }
    size_t bytes_read = fread(buffer, 1, bytes_to_read, file_ptr);
    if (bytes_to_read != bytes_read && !feof(file_ptr)) {
       ret = -1;
       goto cleanup;
    }

    fgetc(file_ptr);
    if(!feof(file_ptr)){
        ret = -1;
        goto cleanup;
    }

    ret = (int)bytes_read;

cleanup:
    close_ret = fclose(file_ptr);
    if (0 != close_ret) {
        ret = -1;
    }
    return ret;

}

static int
write_out(const void *buffer, size_t size, void *app_key) {
    unsigned char *out_fp = app_key;
    size_t wrote;

    wrote = memcpy(out_fp, buffer, size);

    if (wrote == size)
        return 0;
    else
        return -1;
}

int asn1_keypair_create(unsigned char* pubkey, unsigned char* privkey, unsigned char* keypair_out) {
    struct Keypair *keypair;
    asn_enc_rval_t ec;

    /* Allocate the Keypair */
    keypair = calloc(1, sizeof(struct Keypair)); /* not malloc! */
    if(NULL == keypair) {
      goto error;
    }


    OCTET_STRING_t privatekey = {.size = 32, .buf = privkey};
    keypair->privkeyversion = 1;
    keypair->privatekey = privatekey;

    const unsigned int oid[] = { 1, 2, 840, 10045, 3, 1, 7};
    // set oid
    int ret = OBJECT_IDENTIFIER_set_arcs(&(keypair->publickeyoid), oid, sizeof(oid[0]), sizeof(oid)/sizeof(oid[0]));
    assert(0 == ret);

    BIT_STRING_t publickey = {.size = 65, .buf = pubkey};
    keypair->publickey=publickey;
    ec = der_encode_to_buffer(&asn_DEF_Keypair,
            keypair, keypair_out, 121);
    if(ec.encoded == -1) {
        fprintf(stderr, "Could not encode keypair\n");
        goto error;
    }

    /* Also print the constructed keypair XER encoded (XML) */
    xer_fprint(stdout, &asn_DEF_Keypair, keypair);
    free(keypair);
    return 0;

error:
    free(keypair);
    return -1;
}

int main(int ac, char **av){
    uint8_t pubkey[65] = {0};
    uint8_t privkey[32] = {0};
    unsigned char asn1_keypair[121] = {0};

    read_from_file(av[1], (unsigned char*)pubkey, 65);
    read_from_file(av[2], (unsigned char*)privkey, 32);

    asn1_keypair_create(pubkey, privkey, asn1_keypair);
}
