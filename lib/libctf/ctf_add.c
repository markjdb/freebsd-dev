#include "_libctf.h"

ctf_id_t
ctf_add_array(Ctf *ctf, unsigned int flags /*, XXX */)
{
}

ctf_id_t
ctf_add_const(Ctf *ctf, unsigned int flags, ctf_id_t id)
{
}

ctf_id_t
ctf_add_enum(Ctf *ctf, unsigned int flags, const char *name)
{
}

int
ctf_add_enumerator(Ctf *ctf, ctf_id_t id, const char *name, int value)
{
}

ctf_id_t
ctf_add_float(Ctf *ctf, unsigned int flags, const char *name,
    unsigned int encoding)
{
}

ctf_id_t
ctf_add_function(Ctf *ctf, unsigned int flags /*, XXX */)
{
}

ctf_id_t
ctf_add_integer(Ctf *ctf, unsigned int flags, unsigned int encoding)
{
}

int
ctf_add_member(Ctf *ctf, ctf_id_t id, const char *name, ctf_id_t type)
{
}

ctf_id_t
ctf_add_pointer(Ctf *ctf, unsigned int flags, ctf_id_t ref)
{
}

ctf_id_t
ctf_add_restrict(Ctf *ctf, unsigned int flags, ctf_id_t ref)
{
}

ctf_id_t
ctf_add_typedef(Ctf *ctf, unsigned int flags, const char *name, ctf_id_t ref)
{
}

ctf_id_t
ctf_add_volatile(Ctf *ctf, unsigned int flags, ctf_id_t ref)
{
}
