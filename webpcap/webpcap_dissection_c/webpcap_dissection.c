#include <wireshark/config.h>
#include <epan/epan.h>
#include <epan/epan_dissect.h>
#include <epan/timestamp.h>
#include <epan/prefs.h>
#include <epan/dissectors/packet-data.h>
#include <locale.h>
#include <pcap.h>
#include <glib.h>
#include "disabled_protos.h"
#include "webpcap_dissection.h"

typedef struct _detail_data {
    epan_dissect_t edt;
    FILE *stream;
    guint8 indent;
    guint8 count;
} detail_data;

e_prefs * prefs_p;
column_info cinfo; 
guint32 cum_bytes;
static nstime_t first_ts;

guint32 colwidth[] = {5, 0, 25, 25, 10, 5, 30};

void open_failure_message(const char *filename, int err, gboolean for_writing);
void failure_message(const char *msg_format, va_list ap);
void read_failure_message(const char *filename, int err);
void write_failure_message(const char *filename, int err);
void print_summary(packet_info* pi, guint32* colwidth, FILE *stream);
void print_details(proto_node *node, gpointer data);

static void log_func_ignore (const gchar *log_domain _U_, 
                             GLogLevelFlags log_level _U_, 
                             const gchar *message _U_, 
                             gpointer user_data _U_) {
}

/* functions to log epan_init errors */
void open_failure_message(const char *filename, int err, gboolean for_writing) {
    fprintf(stderr, "filename: %s, err: %d\n", filename, err);
}

void failure_message(const char *msg_format, va_list ap) {
    fprintf(stderr, msg_format, ap);
    fprintf(stderr, "\n");
}

void read_failure_message(const char *filename, int err) {
    fprintf(stderr, "An error occurred while reading from the file \"%s\": %s.",
            filename, g_strerror(err));
}

void write_failure_message(const char *filename, int err) {
    fprintf(stderr, "An error occurred while writing to the file \"%s\": %s.", 
            filename, g_strerror(err));
} 

void init_dissect() {  
    int   log_flags;  
    /* setup permissions */
    init_process_policies();   
    
    char *gpf_path, *pf_path;
    char *gdp_path, *dp_path;
    int   gpf_open_errno, gpf_read_errno;
    int    pf_open_errno, pf_read_errno;
    int   gdp_open_errno, gdp_read_errno;
    int    dp_open_errno, dp_read_errno;
    
    log_flags =
        G_LOG_LEVEL_WARNING |
        G_LOG_LEVEL_MESSAGE |
        G_LOG_LEVEL_INFO |
        G_LOG_LEVEL_DEBUG;

    g_log_set_handler(NULL,
                      (GLogLevelFlags)log_flags,
                      log_func_ignore, NULL /* user_data */);
    g_log_set_handler("CaptureChild",
                      (GLogLevelFlags)log_flags,
                      log_func_ignore, NULL /* user_data */);

    /* initialize timestamp info */
    timestamp_set_type(TS_RELATIVE);
    timestamp_set_precision(TS_PREC_AUTO);
    timestamp_set_seconds_type(TS_SECONDS_DEFAULT);
    
     /* initialize epan */
    epan_init(register_all_protocols, register_all_protocol_handoffs, NULL, NULL, 
               failure_message, open_failure_message, 
               read_failure_message, write_failure_message);
        
    prefs_p = read_prefs(&gpf_open_errno, &gpf_read_errno, &gpf_path, &pf_open_errno, &pf_read_errno, &pf_path);    
    build_column_format_array(&cinfo, prefs_p->num_cols, TRUE);
    
    /* Read the disabled protocols file. */
    read_disabled_protos_list(&gdp_path, &gdp_open_errno, &gdp_read_errno,
                               &dp_path, &dp_open_errno, &dp_read_errno);
    
    prefs_apply_all();    
    /* load all the modules */
    prefs_register_modules();
    
    /* set the locale */
    setlocale(LC_ALL, "");
    
    cleanup_dissection();
    init_dissection();
}
 
void dissect(const guint8* data, pcaprec_hdr_t * ph, int encap, int cnt, FILE *stream, gboolean details) {  
    nstime_t elapsed_time;
    nstime_t first_ts;
    epan_dissect_t edt;
    frame_data fdata;
    
    /* clear the timestamps */
    nstime_set_zero(&elapsed_time); 
    nstime_set_unset(&first_ts); 

    struct wtap_pkthdr whdr;
    whdr.pkt_encap =  wtap_pcap_encap_to_wtap_encap(encap);
    whdr.ts.secs = ph->ts_sec;
    whdr.ts.nsecs = ph->ts_usec;
    whdr.caplen = ph->incl_len;
    whdr.len = ph->orig_len;

    frame_data_init(&fdata, cnt, &whdr, 0, cum_bytes);
        
    epan_dissect_init(&edt, TRUE, details);
    
    frame_data_set_before_dissect(&fdata, &elapsed_time, &first_ts, NULL, NULL);
            
    epan_dissect_run(&edt, &whdr, data, &fdata, &cinfo);    
        
    frame_data_set_after_dissect(&fdata, &cum_bytes);  
        
    if (details) {
        proto_node *node = edt.tree; /* grab the top level tree node */

        /* collect data to be passed on */
        detail_data d;
        d.edt = edt;
        d.stream = stream;
        d.indent = 0;
        d.count = 0;
        
        proto_tree_children_foreach(node, print_details, &d);
    }
    else {
        epan_dissect_fill_in_columns(&edt, FALSE, TRUE); 
        packet_info * pi = &edt.pi;
        print_summary(pi, colwidth, stream);
    }        
    epan_dissect_cleanup(&edt);        
}

void print_summary(packet_info* pi, guint32* colwidth, FILE *stream) {
    int i;
    
    if (pi->cinfo->num_cols < 7)
        return;   
    
    fprintf(stream, 
            "<div onclick=\"processClick(this, %s)\" class=\"row %s\">\n",
            pi->cinfo->col_data[0], pi->cinfo->col_data[4]);
    
    for (i = 0; i < pi->cinfo->num_cols; i++) {
        if (i == 1) /* FIXME */
            continue; /* skip timestamps for now */
        fprintf(stream, "    <div class=\"col %dp\">%s</div>\n", 
                colwidth[i], pi->cinfo->col_data[i]);
    }
    fprintf(stream, "</div>\n");
}

void print_details(proto_node *node, gpointer data) {
    int             i;
    gchar           label_str[ITEM_LABEL_LENGTH];    
    detail_data    *d;
    d = (detail_data *) data;
    gchar           indent[d->indent + 1];
    field_info     *fi; 
    fi = PNODE_FINFO(node);
    
    /* FIXME: currently skipping first entry which is some generic comment */
    if (d->count == 0 || fi == NULL) {
        d->count++;
        return;
    }
        
    for (i = 0; i < d->indent; i++) {
        indent[i] = ' ';
    }
    indent[d->indent] = '\0';
    
    d->count++;
    
    if (node->first_child != NULL) {    
        fprintf(d->stream, "%s<div>\n", indent);
        fprintf(d->stream, "%s    <input type=\"checkbox\" id=\"node%d\">\n", indent, d->count);
        fprintf(d->stream, "%s    <label for=\"node%d\"><span></span>", indent, d->count);        
    }  
    else
        fprintf(d->stream, "%s    ", indent);
        
    if (!fi->rep) {
        proto_item_fill_label(fi, label_str);
        fprintf(d->stream, "%s<br>", label_str);
    }
    else {
        fprintf(d->stream, "%s<br>", fi->rep->representation);
    }
        
    if (node->first_child != NULL) {
        fprintf(d->stream, "</label>\n");
        fprintf(d->stream, "%s    <div>\n", indent);
        d->indent += 4;
        proto_tree_children_foreach(node, print_details, data);
        d->indent -= 4;
        fprintf(d->stream, "%s    </div>\n", indent);
        fprintf(d->stream, "%s</div>\n", indent);
    }
    else
        fprintf(d->stream, "\n");   
}