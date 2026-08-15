/*
 * TPMLIB_DecodeBlob oracle harness.
 *
 * Runs the vendored C libtpms (libtpms/src/tpm_library.c: TPMLIB_DecodeBlob,
 * TPMLIB_GetPlaintext, TPMLIB_Base64Decode) over a fixed corpus of tagged
 * INITSTATE blobs and prints one tab-separated record per scenario:
 *
 *     <name>\t<input hex>\t<TPM_RESULT>\t<decoded hex, or '-' on failure>
 *
 * Every record carries its own input, so the Rust tests replay byte-identical
 * data without restating the corpus.  Only TPMLIB_BLOB_TYPE_INITSTATE is
 * exercised: upstream indexes its tag table with the raw blob type, so any
 * other value reads out of bounds and has no behaviour worth pinning.
 *
 * Driven by scripts/generate_decode_blob_oracle.py.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libtpms/tpm_library.h>

#define BEGIN_TAG "-----BEGIN INITSTATE-----"
#define END_TAG   "-----END INITSTATE-----"

struct scenario {
    const char *name;
    const char *input;
    size_t length;
};

/* The recorded input is the whole literal; TPMLIB_DecodeBlob only ever sees
   the C string it starts with, so scenarios may embed NUL bytes. */
#define SCENARIO(name, literal) {name, literal, sizeof(literal) - 1}

static const struct scenario scenarios[] = {
    SCENARIO("valid", BEGIN_TAG "\nQUJD\n" END_TAG),
    SCENARIO("tags_adjacent", BEGIN_TAG "QUJD" END_TAG),
    SCENARIO("whitespace_after_begin", BEGIN_TAG " \t\r\n QUJD\n" END_TAG),
    SCENARIO("wrapped_lines", BEGIN_TAG "\nQUJD\nRUZH\nSElK\n" END_TAG),
    SCENARIO("spaces_and_tabs_inside", BEGIN_TAG "\nQ U\tJ D\n" END_TAG),
    SCENARIO("crlf_inside", BEGIN_TAG "\r\nQU\r\nJD\r\n" END_TAG),
    SCENARIO("vertical_tab_and_formfeed_inside", BEGIN_TAG "\nQ\vU\fJD\n" END_TAG),
    SCENARIO("padding_none", BEGIN_TAG "\nQUJDRUZH\n" END_TAG),
    SCENARIO("padding_one", BEGIN_TAG "\nQUJDRUY=\n" END_TAG),
    SCENARIO("padding_two", BEGIN_TAG "\nQUJDRA==\n" END_TAG),
    SCENARIO("three_chars_plus_padding", BEGIN_TAG "\nQUJ=\n" END_TAG),
    SCENARIO("non_canonical_trailing_bits", BEGIN_TAG "\nQR==\n" END_TAG),
    SCENARIO("full_alphabet", BEGIN_TAG "\naA0+/z==\n" END_TAG),
    SCENARIO("plus_and_slash", BEGIN_TAG "\n+/+/\n" END_TAG),
    SCENARIO("prefix_and_suffix_text", "junk before\n" BEGIN_TAG "\nQUJD\n" END_TAG "\njunk after\n"),
    SCENARIO("missing_begin_tag", "QUJD\n" END_TAG),
    SCENARIO("truncated_begin_tag", "-----BEGIN INITSTATE----\nQUJD\n" END_TAG),
    SCENARIO("missing_end_tag", BEGIN_TAG "\nQUJD\n"),
    SCENARIO("truncated_end_tag", BEGIN_TAG "\nQUJD\n-----END INITSTATE----"),
    SCENARIO("end_tag_before_begin_tag", END_TAG "\nQUJD\n" BEGIN_TAG "\nQUJD\n"),
    SCENARIO("adjacent_end_then_begin_tag", END_TAG BEGIN_TAG "QUJD"),
    SCENARIO("empty_payload", BEGIN_TAG END_TAG),
    SCENARIO("newline_only_payload", BEGIN_TAG "\n" END_TAG),
    SCENARIO("whitespace_only_payload", BEGIN_TAG "  \t\r\n  " END_TAG),
    SCENARIO("invalid_characters_dropped", BEGIN_TAG "\nQU!JD\n" END_TAG),
    SCENARIO("dashes_dropped", BEGIN_TAG "\nQ-U-J-D\n" END_TAG),
    SCENARIO("high_bytes_dropped", BEGIN_TAG "\nQU" "\x80" "\xff" "JD\n" END_TAG),
    SCENARIO("only_invalid_characters", BEGIN_TAG "\n!!!!\n" END_TAG),
    SCENARIO("length_one", BEGIN_TAG "\nQ\n" END_TAG),
    SCENARIO("length_two", BEGIN_TAG "\nQQ\n" END_TAG),
    SCENARIO("length_three", BEGIN_TAG "\nQUJ\n" END_TAG),
    SCENARIO("length_six", BEGIN_TAG "\nQUJDRA\n" END_TAG),
    SCENARIO("length_seven_with_padding", BEGIN_TAG "\nQUJDRA=\n" END_TAG),
    SCENARIO("padding_only", BEGIN_TAG "\n====\n" END_TAG),
    SCENARIO("padding_group_after_data", BEGIN_TAG "\nAAAA====\n" END_TAG),
    SCENARIO("padding_then_data", BEGIN_TAG "\nQQ==QUJD\n" END_TAG),
    SCENARIO("padding_inside_group", BEGIN_TAG "\nQQ=A\n" END_TAG),
    SCENARIO("padding_mid_string", BEGIN_TAG "\nQQ==QQ==\n" END_TAG),
    SCENARIO("leading_padding", BEGIN_TAG "\n=QUJD\n" END_TAG),
    SCENARIO("one_char_three_padding", BEGIN_TAG "\nQ===\n" END_TAG),
    SCENARIO("two_blocks", BEGIN_TAG "\nQUJD\n" END_TAG "\n" BEGIN_TAG "\nRUZH\n" END_TAG),
    SCENARIO("second_end_tag_ignored", BEGIN_TAG "\nQUJD\n" END_TAG "\nRUZH\n" END_TAG),
    SCENARIO("nested_begin_tag", BEGIN_TAG "\n" BEGIN_TAG "\nQUJD\n" END_TAG),
    SCENARIO("nested_begin_tag_balanced", BEGIN_TAG "\n" BEGIN_TAG "\nQU\n" END_TAG),
    SCENARIO("nul_before_begin_tag", "\0" BEGIN_TAG "\nQUJD\n" END_TAG),
    SCENARIO("nul_after_begin_tag", BEGIN_TAG "\0QUJD\n" END_TAG),
    SCENARIO("nul_inside_payload", BEGIN_TAG "\nQU\0JD\n" END_TAG),
    SCENARIO("nul_before_end_tag", BEGIN_TAG "\nQUJD\n\0" END_TAG),
    SCENARIO("valid_then_nul_and_trailing_bytes", BEGIN_TAG "\nQUJD\n" END_TAG "\0junk after"),
    SCENARIO("valid_then_nul_and_second_block",
             BEGIN_TAG "\nQUJD\n" END_TAG "\0" BEGIN_TAG "\nRUZH\n" END_TAG),
    SCENARIO("plain_text", "hello world"),
    SCENARIO("empty_input", ""),
    SCENARIO("tag_text_only", BEGIN_TAG),
    SCENARIO("large_wrapped_blob",
     BEGIN_TAG "\n"
     "CzBVep/E6Q4zWH2ix+wRNluApcrvFDleg6jN8hc8YYar0PUaP2SJrtP4HUJnjLHW\n"
     "+yBFao+02f4jSG2St9wBJktwlbrfBClOc5i94gcsUXabwOUKL1R5nsPoDTJXfKHG\n"
     "6xA1Wn+kye4TOF2Cp8zxFjtgharP9Bk+Y4it0vccQWaLsNX6H0RpjrPY/SJHbJG2\n"
     "2wAlSm+Uud4DKE1yl7zhBitQdZq/5AkuU3idwucMMVZ7oMXqDzRZfqPI7RI3XIGm\n"
     "y/AVOl+Eqc7zGD1ih6zR9htAZYqv1PkeQ2iNstf8IUZrkLXa/yRJbpO43QInTHGW\n"
     "u+AFKk90mb7jCC1Sd5zB\n" END_TAG),
};

static void print_hex(const unsigned char *data, size_t length)
{
    for (size_t i = 0; i < length; i++)
        printf("%02x", data[i]);
}

int main(void)
{
    for (size_t i = 0; i < sizeof(scenarios) / sizeof(scenarios[0]); i++) {
        const struct scenario *scenario = &scenarios[i];
        unsigned char *result = NULL;
        size_t result_len = 0;
        TPM_RESULT res;

        res = TPMLIB_DecodeBlob((char *)scenario->input, TPMLIB_BLOB_TYPE_INITSTATE, &result,
                                &result_len);

        printf("%s\t", scenario->name);
        print_hex((const unsigned char *)scenario->input, scenario->length);
        printf("\t%u\t", (unsigned)res);
        if (res == 0 && result != NULL) {
            print_hex(result, result_len);
        } else if (result != NULL) {
            fprintf(stderr, "error: %s returned %u with a non-NULL result\n", scenario->name,
                    (unsigned)res);
            return 1;
        } else {
            printf("-");
        }
        printf("\n");
        free(result);
    }
    fflush(stdout);
    return 0;
}
