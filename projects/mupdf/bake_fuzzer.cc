#include <cstdint>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <mupdf/fitz.h>
#include <mupdf/pdf.h>

#define ALIGNMENT ((size_t)16)
#define KBYTE ((size_t)1024)
#define MBYTE (1024 * KBYTE)
#define GBYTE (1024 * MBYTE)
#define MAX_ALLOCATION (1 * GBYTE)

static size_t used;

static void *fz_limit_reached_ossfuzz(size_t oldsize, size_t size)
{
    if (oldsize == 0)
        fprintf(stderr, "limit: %zu Mbyte used: %zu Mbyte allocation: %zu: limit reached\n", MAX_ALLOCATION / MBYTE, used / MBYTE, size);
    else
        fprintf(stderr, "limit: %zu Mbyte used: %zu Mbyte reallocation: %zu -> %zu: limit reached\n", MAX_ALLOCATION / MBYTE, used / MBYTE, oldsize, size);
    fflush(0);
    return NULL;
}

static void *fz_malloc_ossfuzz(void *opaque, size_t size)
{
    char *ptr = NULL;

    if (size == 0)
        return NULL;
    if (size > SIZE_MAX - ALIGNMENT)
        return NULL;
    if (size + ALIGNMENT > MAX_ALLOCATION - used)
        return fz_limit_reached_ossfuzz(0, size + ALIGNMENT);

    ptr = (char *)malloc(size + ALIGNMENT);
    if (ptr == NULL)
        return NULL;

    memcpy(ptr, &size, sizeof(size));
    used += size + ALIGNMENT;

    return ptr + ALIGNMENT;
}

static void fz_free_ossfuzz(void *opaque, void *ptr)
{
    size_t size;

    if (ptr == NULL)
        return;
    if (ptr < (void *)ALIGNMENT)
        return;

    ptr = (char *)ptr - ALIGNMENT;
    memcpy(&size, ptr, sizeof(size));

    used -= size + ALIGNMENT;
    free(ptr);
}

static void *fz_realloc_ossfuzz(void *opaque, void *old, size_t size)
{
    size_t oldsize;
    char *ptr;

    if (old == NULL)
        return fz_malloc_ossfuzz(opaque, size);
    if (old < (void *)ALIGNMENT)
        return NULL;

    if (size == 0)
    {
        fz_free_ossfuzz(opaque, old);
        return NULL;
    }
    if (size > SIZE_MAX - ALIGNMENT)
        return NULL;

    old = (char *)old - ALIGNMENT;
    memcpy(&oldsize, old, sizeof(oldsize));

    if (size + ALIGNMENT > MAX_ALLOCATION - used + oldsize + ALIGNMENT)
        return fz_limit_reached_ossfuzz(oldsize + ALIGNMENT, size + ALIGNMENT);

    ptr = (char *)realloc(old, size + ALIGNMENT);
    if (ptr == NULL)
        return NULL;

    used -= oldsize + ALIGNMENT;
    memcpy(ptr, &size, sizeof(size));
    used += size + ALIGNMENT;

    return ptr + ALIGNMENT;
}

static fz_alloc_context fz_alloc_ossfuzz =
    {
        NULL,
        fz_malloc_ossfuzz,
        fz_realloc_ossfuzz,
        fz_free_ossfuzz};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 8)
        return 0; // data too small

    fz_context *ctx;
    fz_stream *stream;
    fz_document *doc;

    used = 0;

    ctx = fz_new_context(&fz_alloc_ossfuzz, nullptr, FZ_STORE_DEFAULT);
    stream = NULL;
    doc = NULL;

    fz_var(stream);
    fz_var(doc);

    fz_try(ctx)
    {
        fz_register_document_handlers(ctx);
        stream = fz_open_memory(ctx, data, size);
        doc = fz_open_document_with_stream(ctx, "pdf", stream);
        int bake_annots = 1;
        int bake_widgets = 1;

        pdf_document *pdf_doc = pdf_specifics(ctx, doc);
        if (pdf_doc)
        {
            pdf_bake_document(ctx, pdf_doc, bake_annots, bake_widgets);
        }
    }
    fz_always(ctx)
    {
        fz_drop_document(ctx, doc);
        fz_drop_stream(ctx, stream);
    }
    fz_catch(ctx)
    {
        fz_report_error(ctx);
        fz_log_error(ctx, "error rendering pages");
    }

    fz_flush_warnings(ctx);
    fz_drop_context(ctx);

    return 0;
}