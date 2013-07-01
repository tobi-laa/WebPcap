#include "webpcap_dissection.h"

int count;

int main(int argc, char *argv[]) {
    gboolean details;
    guint8 * buff;
    FILE * pf;
    pcaprec_hdr_t * ph;
    
    if (argc <= 1) {
        fprintf(stdout,"Usage: %s [--summary,--details]\n", argv[0]);
        return 1;
    }
    if (!strcmp(argv[1],"--details")) {
        details = TRUE;
    }
    else if (!strcmp(argv[1],"--summary")) {
        details = FALSE;
    }
    else {
        fprintf(stdout,"Usage: %s [--summary,--details]\n", argv[0]);
        return 1;
    }
    
    init_dissect();
    
    buff = malloc(65535);
    ph = malloc(16);
    pf = fopen ("log.pcap", "r");    
    
    if (pf == NULL)
        return;
    if (fread(buff, 1, 24, pf) == NULL) /* just skip the header */
        return;
    
    while (fread(buff, 1, 16, pf) != NULL) { /* get pcap header */
        memcpy(ph, buff, 16);
                
        if (ph->incl_len < 0 || ph->incl_len > 65535)
            return;
        
        if (fread(buff, 1, ph->incl_len, pf) == NULL)
            return;        
               
        dissect(buff, ph, 1, count++, stdout, details);
    }
    return 1;
}