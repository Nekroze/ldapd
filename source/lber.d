extern (C):

alias int ber_len_t;
alias int ber_slen_t;
alias int ber_int_t;
alias int ber_tag_t;

alias int* function () BER_ERRNO_FN;
alias void function (const(char)*) BER_LOG_PRINT_FN;
alias void* BER_MEMALLOC_FN;
alias void* BER_MEMCALLOC_FN;
alias void* BER_MEMREALLOC_FN;
alias void BER_MEMFREE_FN;
alias lber_memory_fns BerMemoryFunctions;
alias berelement BerElement;
alias sockbuf Sockbuf;
alias sockbuf_io Sockbuf_IO;
alias sockbuf_io_desc Sockbuf_IO_Desc;
alias berval BerValue;
alias berval* BerVarray;
alias int function (berelement*, void*, int) BERDecodeCallback;
alias int function (berelement*, void*) BEREncodeCallback;

extern __gshared char ber_pvt_opt_on;
extern __gshared Sockbuf_IO ber_sockbuf_io_tcp;
extern __gshared Sockbuf_IO ber_sockbuf_io_readahead;
extern __gshared Sockbuf_IO ber_sockbuf_io_fd;
extern __gshared Sockbuf_IO ber_sockbuf_io_debug;
extern __gshared Sockbuf_IO ber_sockbuf_io_udp;

struct lber_memory_fns
{
	void* function (ber_len_t, void*) bmf_malloc;
	void* function (ber_len_t, ber_len_t, void*) bmf_calloc;
	void* function (void*, ber_len_t, void*) bmf_realloc;
	void function (void*, void*) bmf_free;
}

struct sockbuf_io_desc
{
	int sbiod_level;
	Sockbuf* sbiod_sb;
	Sockbuf_IO* sbiod_io;
	void* sbiod_pvt;
	sockbuf_io_desc* sbiod_next;
}

struct sockbuf_io
{
	int function (Sockbuf_IO_Desc*, void*) sbi_setup;
	int function (Sockbuf_IO_Desc*) sbi_remove;
	int function (Sockbuf_IO_Desc*, int, void*) sbi_ctrl;
	ber_slen_t function (Sockbuf_IO_Desc*, void*, ber_len_t) sbi_read;
	ber_slen_t function (Sockbuf_IO_Desc*, void*, ber_len_t) sbi_write;
	int function (Sockbuf_IO_Desc*) sbi_close;
}

struct berval
{
	ber_len_t bv_len;
	char* bv_val;
}

struct berelement;


struct sockbuf;


void ber_error_print (const(char)* data);
void ber_bprint (const(char)* data, ber_len_t len);
void ber_dump (BerElement* ber, int inout_);
ber_tag_t ber_get_tag (BerElement* ber);
ber_tag_t ber_skip_tag (BerElement* ber, ber_len_t* len);
ber_tag_t ber_peek_tag (BerElement* ber, ber_len_t* len);
ber_tag_t ber_skip_element (BerElement* ber, berval* bv);
ber_tag_t ber_peek_element (const(BerElement)* ber, berval* bv);
ber_tag_t ber_get_int (BerElement* ber, ber_int_t* num);
ber_tag_t ber_get_enum (BerElement* ber, ber_int_t* num);
ber_tag_t ber_get_stringb (BerElement* ber, char* buf, ber_len_t* len);
ber_tag_t ber_get_stringbv (BerElement* ber, berval* bv, int options);
ber_tag_t ber_get_stringa (BerElement* ber, char** buf);
ber_tag_t ber_get_stringal (BerElement* ber, berval** bv);
ber_tag_t ber_get_bitstringa (BerElement* ber, char** buf, ber_len_t* len);
ber_tag_t ber_get_null (BerElement* ber);
ber_tag_t ber_get_boolean (BerElement* ber, ber_int_t* boolval);
ber_tag_t ber_first_element (BerElement* ber, ber_len_t* len, char** last);
ber_tag_t ber_next_element (BerElement* ber, ber_len_t* len, const(char)* last);
ber_tag_t ber_scanf (BerElement* ber, const(char)* fmt, ...);
int ber_decode_oid (berval* in_, berval* out_);
int ber_encode_oid (berval* in_, berval* out_);
int ber_put_enum (BerElement* ber, ber_int_t num, ber_tag_t tag);
int ber_put_int (BerElement* ber, ber_int_t num, ber_tag_t tag);
int ber_put_ostring (BerElement* ber, const(char)* str, ber_len_t len, ber_tag_t tag);
int ber_put_berval (BerElement* ber, berval* bv, ber_tag_t tag);
int ber_put_string (BerElement* ber, const(char)* str, ber_tag_t tag);
int ber_put_bitstring (BerElement* ber, const(char)* str, ber_len_t bitlen, ber_tag_t tag);
int ber_put_null (BerElement* ber, ber_tag_t tag);
int ber_put_boolean (BerElement* ber, ber_int_t boolval, ber_tag_t tag);
int ber_start_seq (BerElement* ber, ber_tag_t tag);
int ber_start_set (BerElement* ber, ber_tag_t tag);
int ber_put_seq (BerElement* ber);
int ber_put_set (BerElement* ber);
int ber_printf (BerElement* ber, const(char)* fmt, ...);
ber_slen_t ber_skip_data (BerElement* ber, ber_len_t len);
ber_slen_t ber_read (BerElement* ber, char* buf, ber_len_t len);
ber_slen_t ber_write (BerElement* ber, const(char)* buf, ber_len_t len, int zero);
void ber_free (BerElement* ber, int freebuf);
void ber_free_buf (BerElement* ber);
int ber_flush2 (Sockbuf* sb, BerElement* ber, int freeit);
int ber_flush (Sockbuf* sb, BerElement* ber, int freeit);
BerElement* ber_alloc ();
BerElement* der_alloc ();
BerElement* ber_alloc_t (int beroptions);
BerElement* ber_dup (BerElement* ber);
ber_tag_t ber_get_next (Sockbuf* sb, ber_len_t* len, BerElement* ber);
void ber_init2 (BerElement* ber, berval* bv, int options);
void ber_init_w_nullc (BerElement* ber, int options);
void ber_reset (BerElement* ber, int was_writing);
BerElement* ber_init (berval* bv);
int ber_flatten (BerElement* ber, berval** bvPtr);
int ber_flatten2 (BerElement* ber, berval* bv, int alloc);
int ber_remaining (BerElement* ber);
int ber_get_option (void* item, int option, void* outvalue);
int ber_set_option (void* item, int option, const(void)* invalue);
Sockbuf* ber_sockbuf_alloc ();
void ber_sockbuf_free (Sockbuf* sb);
int ber_sockbuf_add_io (Sockbuf* sb, Sockbuf_IO* sbio, int layer, void* arg);
int ber_sockbuf_remove_io (Sockbuf* sb, Sockbuf_IO* sbio, int layer);
int ber_sockbuf_ctrl (Sockbuf* sb, int opt, void* arg);
void* ber_memalloc (ber_len_t s);
void* ber_memrealloc (void* p, ber_len_t s);
void* ber_memcalloc (ber_len_t n, ber_len_t s);
void ber_memfree (void* p);
void ber_memvfree (void** vector);
void ber_bvfree (berval* bv);
void ber_bvecfree (berval** bv);
int ber_bvecadd (berval*** bvec, berval* bv);
berval* ber_dupbv (berval* dst, berval* src);
berval* ber_bvdup (berval* src);
berval* ber_mem2bv (const(char)*, ber_len_t len, int duplicate, berval* bv);
berval* ber_str2bv (const(char)*, ber_len_t len, int duplicate, berval* bv);
char* ber_strdup (const(char)*);
ber_len_t ber_strnlen (const(char)* s, ber_len_t len);
char* ber_strndup (const(char)* s, ber_len_t l);
berval* ber_bvreplace (berval* dst, const(berval)* src);
void ber_bvarray_free (BerVarray p);
int ber_bvarray_add (BerVarray* p, BerValue* bv);
int* ber_errno_addr ();