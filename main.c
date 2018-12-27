#include <stdio.h>
#include <sys/types.h>
#include "Keypair.h"   /* keypair ASN.1 type  */

int xtt_save_to_file(unsigned char *buffer, size_t bytes_to_write, const char *filename)
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

int xtt_read_from_file(const char *filename, unsigned char *buffer, size_t bytes_to_read)
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
    FILE *out_fp = app_key;
    size_t wrote;

    wrote = fwrite(buffer, 1, size, out_fp);

    if (wrote == size)
        return 0;
    else
        return -1;
}

int main(int ac, char **av) {
    struct Keypair *keypair;
    asn_enc_rval_t ec;

    /* Allocate the Keypair */
    keypair = calloc(1, sizeof(struct Keypair)); /* not malloc! */
    if(NULL == keypair) {
      exit(71); /* better, EX_OSERR */
    }

    /* Initialize the keypair members */
    uint8_t pubkey[65] = {0};
    uint8_t privkey[32] = {0};

    xtt_read_from_file(av[1], (unsigned char*)pubkey, 65);
    xtt_read_from_file(av[2], (unsigned char*)privkey, 32);

    OCTET_STRING_t privatekey = {.size = 32, .buf = privkey};
    keypair->privkeyversion = 1;
    keypair->privatekey = privatekey;

    const unsigned int oid[] = { 1, 2, 840, 10045, 3, 1, 7};
    // set oid
    int ret = OBJECT_IDENTIFIER_set_arcs(&(keypair->publickeyoid), &oid, 7);
    assert(0 == ret);

    BIT_STRING_t publickey = {.size = 65, .buf = pubkey};
    keypair->publickey=publickey;

    /* BER encode the data if filename is given */
    if(ac < 4) {
      fprintf(stderr, "Specify filename for BER output\n");
    } else {
      const char *filename = av[3];
      FILE *fp = fopen(filename, "wb");   /* for BER output */

      if(!fp) {
        perror(filename);
        exit(71); /* better, EX_OSERR */
      }

      /* Encode the keypair type as BER (DER) */
      ec = der_encode(&asn_DEF_Keypair,
            keypair, write_out, fp);
      fclose(fp);
      if(ec.encoded == -1) {
        fprintf(stderr,
          "Could not encode keypair (at %s)\n",
          ec.failed_type ? ec.failed_type->name : "unknown");
        exit(65); /* better, EX_DATAERR */
      } else {
        fprintf(stderr, "Created %s with BER encoded keypair\n",
          filename);
      }
    }

    /* Also print the constructed keypair XER encoded (XML) */
    xer_fprint(stdout, &asn_DEF_Keypair, keypair);

    return 0; /* Encoding finished successfully */
}
