#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <gmp.h>
#include <pcs.h>

#define LOG_LEVEL LOG_LEVEL_INFO
#include <log.h>

/* Test import/export functions */
void test1(void)
{
    log_info("Constructing keys");
    pcs_master_key *mk = pcs_gen_master_key();
    pcs_public_key *pk = pcs_gen_public_key(mk);
    pcs_private_key *vk = pcs_gen_private_key(mk);
    pcs_del_master_key(mk);

    /* Output */
    FILE *fd;
    char *output;

    log_info("Outputting private key to file");
    fd = fopen("tmp/test1.private.key", "w");
    output = pcs_export_private_key(vk);
    fprintf(fd, "%s\n", output);
    free(output);
    fclose(fd);

    log_info("Outputting public key to file");
    fd = fopen("tmp/test1.public.key", "w");
    output = pcs_export_public_key(pk);
    fprintf(fd, "%s\n", output);
    free(output);
    fclose(fd);

    pcs_del_public_key(pk);
    pcs_del_private_key(vk);
}

void test2(void)
{
    log_info("Constructing keys");
    pcs_public_key *pk = pcs_gen_public_key(NULL);
    pcs_private_key *vk = pcs_gen_private_key(NULL);

    FILE *fd;
    char input[512];

    log_info("Getting private key from file");
    fd = fopen("tmp/test1.private.key", "r");
    fscanf(fd, "%s", input);
    pcs_import_private_key(vk, input);
    fclose(fd);

    log_info("Getting public key from file");
    fd = fopen("tmp/test1.public.key", "r");
    fscanf(fd, "%s", input);
    pcs_import_public_key(pk, input);
    fclose(fd);

    pcs_del_public_key(pk);
    pcs_del_private_key(vk);
}

int main(void)
{
    log_info("Running test 1");
    test1();

    log_info("Running test 2");
    test2();
}
