#include <stdio.h>
#include <glib.h>

typedef struct pcaprec_hdr_s {
        guint32 ts_sec;         /* timestamp seconds */
        guint32 ts_usec;        /* timestamp microseconds */
        guint32 incl_len;       /* number of octets of packet saved in file */
        guint32 orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

void init_dissect();
void dissect(const guint8* data, pcaprec_hdr_t * ph, int encap, 
             int cnt, FILE *stream, gboolean details);

